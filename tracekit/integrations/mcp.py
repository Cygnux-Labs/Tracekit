"""MCP client (python `mcp` package): every `call_tool` on a ClientSession is decided by the signer before it is sent
to the server and recorded after.

    from tracekit.integrations.mcp import TracekitSession
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    session = TracekitSession(session, signer, run)   # an initialized ClientSession
    result = await session.call_tool("create_issue", {"title": "..."})   # recorded as mcp:<server>/create_issue

The server name comes from the session's initialize result. `deny` returns a CallToolResult with `isError: true` and
the refusal as its text, and the run goes on. `ask` requests an approval and waits up to `approval_wait_s` for a person
to decide in the signer; with `approval_wait_s=0` the call is refused instead. Every call that is not denied is sent
only after the signer's `approval_consume` agrees. A result with `isError: true` completes as an error; an exception
from the session propagates unchanged and completes as an error. Only calls made through the wrapped session are seen.
"""
import asyncio
import itertools
import re
import threading
import time
import uuid
import warnings

from mcp.types import CallToolResult, TextContent

from tracekit.format.canon import event_hash
from tracekit.sdk.client import SignerUnavailable, fail_open
from tracekit.signer.rpc_schema import RPCError

BLOCKED = "Tool call blocked by policy: "
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")


class TracekitSession:
    def __init__(self, session, signer, run, approval_wait_s=300):
        """`signer` is any `SignerAPI`; `run` is its `register_run` response (`run_id`, `run_token`, `fail_modes`)."""
        self._session, self.signer, self.wait_s = session, signer, approval_wait_s
        self.fail_modes = run.get("fail_modes")
        self.run = {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.stream, self._seq, self._lock = "mcp-" + uuid.uuid4().hex, itertools.count(), threading.Lock()

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def _rpc(self, method, **req):
        req = {"request_id": uuid.uuid4().hex, **self.run, **req}

        def call():
            if method not in ("decide", "complete"):
                return getattr(self.signer, method)(req)
            # lean: one event at a time per session, so client_seq arrives in order; pipeline if it gets slow
            with self._lock:
                return getattr(self.signer, method)(dict(req, stream=self.stream, client_seq=next(self._seq)))
        return await asyncio.to_thread(call)

    async def _gate(self, call_id, tool, args):
        """(the refusal that replaces the call or None when it may be sent, the decision)"""
        try:
            d = await self._rpc("decide", tool_call_id=call_id, tool=tool, tool_class_hint="mcp", args_source="parsed",
                                args=args)
        except SignerUnavailable as e:   # unreachable: the run's fail mode for mcp calls
            return (None if fail_open(self.fail_modes, "mcp") else f"signer unavailable: {e}"), None
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

    async def call_tool(self, name, arguments=None, *a, **kw):
        server = getattr(self._session.server_info, "name", None)
        tool, args, call_id = f"mcp:{_UNSAFE.sub('_', server or '') or 'unknown'}/{name}", arguments or {}, uuid.uuid4().hex
        why, d = await self._gate(call_id, tool, args)
        if why is not None:
            return CallToolResult(content=[TextContent(type="text", text=BLOCKED + why)], is_error=True)
        if d is None:   # the signer unreachable and the run fails open: the call runs unrecorded
            return await self._session.call_tool(name, arguments, *a, **kw)
        req = {"tool_call_id": call_id, "decision_id": d["decision_id"],
               "args_digest": event_hash({"tool": tool, "args": args})}
        try:
            out = await self._session.call_tool(name, arguments, *a, **kw)
        except Exception as e:
            await self._complete(call_id, req, status="error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        await self._complete(call_id, req, status="error" if getattr(out, "is_error", False) else "ok",
                             result=event_hash(out.model_dump(mode="json", by_alias=True, exclude_none=True)))
        return out

    async def _complete(self, call_id, req, **outcome):
        """Record the outcome; a failure to record warns and leaves the call's result or exception as it was."""
        try:
            await self._rpc("complete", **req, **outcome)
        except Exception as e:
            warnings.warn(f"tracekit: outcome of MCP tool call {call_id} not recorded: {e}", stacklevel=2)
