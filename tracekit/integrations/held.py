"""The signer steps of an adapter that holds each call in the client until the signer lets it run (MCP, Browser Use):
decide, wait for a person on `ask`, consume, complete.

A signer that cannot be reached when a call is decided: the call runs unrecorded if register_run's `fail_modes` say
`open` for the adapter's class, else it is refused. Any other failure to decide or approve refuses the call. A failure
to record an outcome warns and changes nothing the caller sees.
"""
import asyncio
import itertools
import threading
import time
import uuid
import warnings

from tracekit.sdk.client import SignerUnavailable, fail_open
from tracekit.signer.rpc_schema import RPCError


class HeldCalls:
    CLASS = None   # the tool_class_hint sent with each call and the fail_modes entry that applies to it

    def __init__(self, signer, run, approval_wait_s=300):
        """`signer` is any `SignerAPI`; `run` is its `register_run` response (`run_id`, `run_token`, `fail_modes`)."""
        self.signer, self.wait_s = signer, approval_wait_s
        self.fail_modes = run.get("fail_modes")
        self.run = {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.stream, self._seq, self._lock = f"{self.CLASS}-{uuid.uuid4().hex}", itertools.count(), threading.Lock()

    async def _rpc(self, method, **req):
        req = {"request_id": uuid.uuid4().hex, **self.run, **req}

        def call():
            if method not in ("decide", "complete"):
                return getattr(self.signer, method)(req)
            # lean: one event at a time per adapter, so client_seq arrives in order; pipeline if it gets slow
            with self._lock:
                return getattr(self.signer, method)(dict(req, stream=self.stream, client_seq=next(self._seq)))
        return await asyncio.to_thread(call)

    async def _gate(self, call_id, tool, args):
        """(the refusal that replaces the call or None when it may run, the decision)"""
        try:
            d = await self._rpc("decide", tool_call_id=call_id, tool=tool, tool_class_hint=self.CLASS,
                                args_source="parsed", args=args)
        except SignerUnavailable as e:   # unreachable: the run's fail mode for this class
            return (None if fail_open(self.fail_modes, self.CLASS) else f"signer unavailable: {e}"), None
        except RPCError as e:   # a refusal (a run closed after its idle timeout: register a new run) never lets it run
            return f"signer refused the call: {e}", None
        hint = None
        if d["decision"] == "deny":
            return ", ".join(d["rule_ids"]) or "deny", d
        if d["decision"] == "ask":
            if self.wait_s <= 0:
                return "approval required, and this caller cannot wait for one", d
            try:
                hint = (await self._rpc("approval_request", tool_call_id=call_id))["approval_id"]
                state, deadline = "requested", time.monotonic() + self.wait_s
                while state == "requested" and deadline > time.monotonic():
                    left_ms = int(min(deadline - time.monotonic(), 300) * 1000)
                    state = (await asyncio.to_thread(self.signer.approval_wait, {**self.run, "approval_id": hint,
                                                                                 "timeout_ms": left_ms}))["state"]
            except (RPCError, SignerUnavailable) as e:   # once the policy asked, no fail mode applies
                state = f"{type(e).__name__}: {e}"
            if state != "approved":
                return f"{', '.join(d['rule_ids'])}: approval {state}", d
        # every call, allowed or approved: approval_consume is the signer's last word before it runs
        try:
            c = await self._rpc("approval_consume", tool_call_id=call_id, tool=tool, args_source="parsed", args=args,
                                **({"approval_id_hint": hint} if hint else {}))
        except (RPCError, SignerUnavailable) as e:
            c = {"ok": False, "rule_ids": [], "reason": str(e)}
        if not c["ok"]:
            return ", ".join(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else ""), d
        return None, d

    async def _complete(self, call_id, req, **outcome):
        """Record the outcome; a failure to record warns and leaves the call's result or exception as it was."""
        try:
            await self._rpc("complete", **req, **outcome)
        except Exception as e:
            warnings.warn(f"tracekit: outcome of {self.CLASS} tool call {call_id} not recorded: {e}", stacklevel=2)
