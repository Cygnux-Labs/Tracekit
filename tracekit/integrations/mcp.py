"""MCP client (python `mcp` package): every `call_tool` on a ClientSession is decided by the signer before it is sent
to the server and recorded after.

    from tracekit.integrations.mcp import TracekitSession
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    session = TracekitSession(session, signer, run)   # an initialized ClientSession
    result = await session.call_tool("create_issue", {"title": "..."})   # recorded as mcp:<server>/create_issue

The server name comes from the session's initialize result (mcp 2: the session's server_info). An mcp 1.x session
doesn't keep it: pass `server=` (instrument() takes it from the initialize() calls made after it). With no name the
calls are recorded as mcp:unknown/<tool>, with a warning. `deny` returns a CallToolResult with `isError: true` and
the refusal as its text, and the run goes on. `ask` requests an approval and waits up to `approval_wait_s` for a person
to decide in the signer; with `approval_wait_s=0` the call is refused instead. Every call that is not denied is sent
only after the signer's `approval_consume` agrees, with the arguments it returns for an approval with a T2 executor. A result with `isError: true` completes as an error; an exception
from the session propagates unchanged and completes as an error. Only calls made through the wrapped session are seen.
"""
import re
import uuid
import warnings

from mcp.types import CallToolResult, TextContent

from tracekit.format.canon import event_hash
from tracekit.integrations.held import HeldCalls
from tracekit.sdk.client import result_field

BLOCKED = "Tool call blocked by policy: "
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")


class TracekitSession(HeldCalls):
    CLASS = "mcp"

    def __init__(self, session, signer, run, approval_wait_s=300, server=None):
        """`signer` is any `SignerAPI`; `run` is its `register_run` response (`run_id`, `run_token`, `fail_modes`);
        `server`: the server's name, else the session's server_info."""
        super().__init__(signer, run, approval_wait_s)
        self._session, self._server = session, server

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def call_tool(self, name, arguments=None, *a, **kw):
        server = self._server or getattr(getattr(self._session, "server_info", None), "name", None)
        if not server:
            warnings.warn("MCP: the session doesn't name its server, so its calls are recorded as mcp:unknown/<tool>: "
                          "pass TracekitSession(..., server=<name>), or call tracekit.instrument() before the "
                          "session's initialize() (mcp 1.x)", stacklevel=2)
        tool, args, call_id = f"mcp:{_UNSAFE.sub('_', server or '') or 'unknown'}/{name}", arguments or {}, uuid.uuid4().hex
        why, d, args = await self._gate(call_id, tool, args)
        if why is not None:
            # isError: mcp 1.x's field name, and mcp 2.x's alias of is_error (1.x ignores is_error=)
            return CallToolResult(content=[TextContent(type="text", text=BLOCKED + why)], isError=True)
        if d is None:   # the signer unreachable and the run fails open: the call runs unrecorded
            return await self._session.call_tool(name, arguments, *a, **kw)
        req = {"tool_call_id": call_id, "decision_id": d["decision_id"],
               "args_digest": event_hash({"tool": tool, "args": args})}
        try:
            out = await self._session.call_tool(name, args, *a, **kw)
        except Exception as e:
            await self._complete(call_id, req, status="error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        failed = getattr(out, "is_error", getattr(out, "isError", False))   # mcp 2.x, mcp 1.x
        await self._complete(call_id, req, status="error" if failed else "ok",
                             result=result_field(d.get("send_result"),
                                                 out.model_dump(mode="json", by_alias=True, exclude_none=True)))
        return out
