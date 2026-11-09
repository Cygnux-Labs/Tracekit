"""MCP client (python `mcp` package): every `call_tool` and `get_prompt` on a ClientSession is decided by the signer
before it is sent to the server and recorded after, and `read_resource` records what it returns as an observed input.

    from tracekit.integrations.mcp import TracekitSession
    run = signer.register_run({"request_id": "r1", "agent": {"name": "my-agent"}})
    session = TracekitSession(session, signer, run)   # an initialized ClientSession
    result = await session.call_tool("create_issue", {"title": "..."})   # recorded as mcp:<server>/create_issue

The server name comes from the session's initialize result (mcp 2: the session's server_info). An mcp 1.x session
doesn't keep it: pass `server=` (instrument() takes it from the initialize() calls made after it). With no name the
calls are recorded as mcp:unknown/<tool>, with a warning. `deny` returns a CallToolResult with `isError: true` and
the refusal as its text (`get_prompt` raises `RuntimeError`), and the run goes on. `ask` requests an approval and waits
up to `approval_wait_s` for a person to decide in the signer; with `approval_wait_s=0` the call is refused instead.
Every call that is not denied is sent only after the signer's `approval_consume` agrees, with the arguments it returns
for an approval with a T2 executor. A result with `isError: true` completes as an error; an exception from the session
propagates unchanged and completes as an error. `read_resource` records the result with `observe` (`source`
`mcp:<server>/resource`, `trust` `untrusted`); if the signer cannot record it, a warning is issued and the result is
returned unchanged. Only `call_tool`, `get_prompt` and `read_resource` calls made through the wrapped session are seen.
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
        return await self._call("call_tool", "", name, arguments, *a, **kw)

    async def get_prompt(self, name, arguments=None, *a, **kw):
        return await self._call("get_prompt", "prompt:", name, arguments, *a, **kw)

    async def read_resource(self, uri, *a, **kw):
        """Read a resource and record its result as an untrusted observed input; a failure to record warns and leaves
        the result as it was."""
        result = await self._session.read_resource(uri, *a, **kw)
        server = self._server_name()
        try:
            await self._rpc("observe", source=f"mcp:{server}/resource", trust="untrusted",
                            value=result.model_dump(mode="json", by_alias=True, exclude_none=True))
        except Exception as e:
            warnings.warn(f"tracekit: resource {uri} of mcp:{server} not recorded: {e}", stacklevel=2)
        return result

    def _server_name(self):
        server = self._server or getattr(getattr(self._session, "server_info", None), "name", None)
        if not server:
            warnings.warn("MCP: the session doesn't name its server, so its calls are recorded as mcp:unknown/<tool>: "
                          "pass TracekitSession(..., server=<name>), or call tracekit.instrument() before the "
                          "session's initialize() (mcp 1.x)", stacklevel=3)
        return _UNSAFE.sub("_", server or "") or "unknown"

    async def _call(self, method, prefix, name, arguments, *a, **kw):
        tool = f"mcp:{self._server_name()}/{prefix}{name}"
        args, call_id = arguments or {}, uuid.uuid4().hex
        why, d, args = await self._gate(call_id, tool, args)
        if why is not None:
            if method == "get_prompt":
                raise RuntimeError(BLOCKED + why)
            # isError: mcp 1.x's field name, and mcp 2.x's alias of is_error (1.x ignores is_error=)
            return CallToolResult(content=[TextContent(type="text", text=BLOCKED + why)], isError=True)
        send = getattr(self._session, method)
        if d is None:   # the signer unreachable and the run fails open: the call runs unrecorded
            return await send(name, arguments, *a, **kw)
        req = {"tool_call_id": call_id, "decision_id": d["decision_id"],
               "args_digest": event_hash({"tool": tool, "args": args})}
        try:
            out = await send(name, args, *a, **kw)
        except Exception as e:
            await self._complete(call_id, req, status="error", error=f"{type(e).__name__}: {e}"[:4096])
            raise
        failed = getattr(out, "is_error", getattr(out, "isError", False))   # mcp 2.x, mcp 1.x
        await self._complete(call_id, req, status="error" if failed else "ok",
                             result=result_field(d.get("send_result"),
                                                 out.model_dump(mode="json", by_alias=True, exclude_none=True)))
        return out
