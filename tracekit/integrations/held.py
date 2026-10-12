"""The signer steps of an adapter that holds each call in the client until the signer lets it run (MCP, Browser Use):
decide, wait for a person on `ask`, consume, complete. When the consume returns the signer's copy of the arguments (an
approval with a T2 executor), the call runs those, not the ones the caller holds.

A signer that cannot be reached when a call is decided: the call runs unrecorded if register_run's `fail_modes` say
`open` for the adapter's class, else it is refused. Any other failure to decide or approve refuses the call. A failure
to record an outcome warns and changes nothing the caller sees. An approval no one answered by the end of the wait, or
whose wait the framework cancelled (its own timeout), is withdrawn (approval_abandon), so no one can answer it later.
"""
import asyncio
import itertools
import threading
import time
import uuid
import warnings

from tracekit.sdk.client import SignerUnavailable, fail_open, named_rules
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
            if method not in ("decide", "complete", "observe"):
                return getattr(self.signer, method)(req)
            # lean: one event at a time per adapter, so client_seq arrives in order; pipeline if it gets slow
            with self._lock:
                return getattr(self.signer, method)(dict(req, stream=self.stream, client_seq=next(self._seq)))
        return await asyncio.to_thread(call)

    async def _gate(self, call_id, tool, args):
        """(the refusal that replaces the call or None when it may run, the decision, the arguments to run)"""
        try:
            d = await self._rpc("decide", tool_call_id=call_id, tool=tool, tool_class_hint=self.CLASS,
                                args_source="parsed", args=args)
        except SignerUnavailable as e:   # unreachable: the run's fail mode for this class
            return (None if fail_open(self.fail_modes, self.CLASS) else f"signer unavailable: {e}"), None, args
        except RPCError as e:   # a refusal (a run closed after its idle timeout: register a new run) never lets it run
            return f"signer refused the call: {e}", None, args
        hint = None
        if d["decision"] == "deny":
            return named_rules(d["rule_ids"]) or "deny", d, args
        if d["decision"] == "ask":
            if self.wait_s <= 0:
                return f"{', '.join(d['rule_ids'])}: approval required, and this caller cannot wait for one", d, args
            request = asyncio.ensure_future(self._rpc("approval_request", tool_call_id=call_id))
            try:
                hint = (await asyncio.shield(request))["approval_id"]   # a cancel lets it finish, to withdraw it
                state, deadline = "requested", time.monotonic() + self.wait_s
                while state == "requested" and deadline > time.monotonic():
                    left_ms = int(min(deadline - time.monotonic(), 300) * 1000)
                    state = (await asyncio.to_thread(self.signer.approval_wait, {**self.run, "approval_id": hint,
                                                                                 "timeout_ms": left_ms}))["state"]
            except (RPCError, SignerUnavailable) as e:   # once the policy asked, no fail mode applies
                state = f"{type(e).__name__}: {e}"
            except asyncio.CancelledError:   # the framework stopped waiting (its own timeout): so does the approval
                if hint is None:   # cancelled while the approval was being opened
                    try:
                        hint = (await request)["approval_id"]
                    except (RPCError, SignerUnavailable):   # none was opened
                        pass
                await self._abandon(hint, "the caller stopped waiting for the approval")
                raise
            if state == "requested":
                await self._abandon(hint, f"no answer within the caller's {self.wait_s:g} s wait")
                return (f"{', '.join(d['rule_ids'])}: no one approved the call within {self.wait_s:g} s, so it did not "
                        "run and its approval was withdrawn; ask a person to approve it, then try again"), d, args
            if state != "approved":
                return f"{', '.join(d['rule_ids'])}: approval {state}", d, args
        # every call, allowed or approved: approval_consume is the signer's last word before it runs
        try:
            c = await self._rpc("approval_consume", tool_call_id=call_id, tool=tool, args_source="parsed", args=args,
                                **({"approval_id_hint": hint} if hint else {}))
        except (RPCError, SignerUnavailable) as e:
            c = {"ok": False, "rule_ids": [], "reason": str(e)}
        if not c["ok"]:
            return named_rules(c["rule_ids"]) + (f": {c['reason']}" if c.get("reason") else ""), d, args
        return None, d, c.get("args", args)

    async def _abandon(self, approval_id, reason):
        """Withdraw an approval the call no longer waits for; a failure warns (it then expires with the run)."""
        if approval_id is None:
            return
        try:
            await self._rpc("approval_abandon", approval_id=approval_id, reason=reason)
        except (RPCError, SignerUnavailable) as e:
            warnings.warn(f"tracekit: approval {approval_id} not withdrawn: {e}", stacklevel=2)

    async def _complete(self, call_id, req, **outcome):
        """Record the outcome; a failure to record warns and leaves the call's result or exception as it was."""
        try:
            await self._rpc("complete", **req, **outcome)
        except Exception as e:
            warnings.warn(f"tracekit: outcome of {self.CLASS} tool call {call_id} not recorded: {e}", stacklevel=2)
