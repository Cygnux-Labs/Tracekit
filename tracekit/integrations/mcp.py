"""MCP client (python `mcp` package): every `call_tool` on a ClientSession is decided by the signer before it is sent
to the server and recorded after.

    from tracekit.integrations.mcp import TracekitSession
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            session = TracekitSession(session, signer, run)
            result = await session.call_tool("list_accounts", {"customer": "C-9"})
"""
import re
import uuid
import warnings

from mcp.types import CallToolResult, TextContent

from tracekit.format.canon import event_hash
from tracekit.integrations.held import HeldCalls
from tracekit.sdk.client import result_field
from tracekit.integrations import version_check

BLOCKED = "Tool call blocked by policy: "
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")


class TracekitSession(HeldCalls):
    CLASS = "mcp"

    def __init__(self, session, signer, run, approval_wait_s=300, server=None):
        """`signer` is any `SignerAPI`; `run` is its `register_run` response (`run_id`, `run_token`, `fail_modes`);
        `server`: the server's name, else the session's server_info."""
        version_check.warn_untested("MCP client", "mcp>=2.3,<2.4")
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
        if why:
            return CallToolResult(content=[TextContent(type="text", text=BLOCKED + why)], isError=True)
        result = await self._session.call_tool(name, args, *a, **kw)
        self._complete(call_id, result)
        return result
