"""MCP client adapter: every tool call an agent makes through an MCP ``ClientSession`` is policy-checked before it is sent
to the server, and its result recorded (``pip install mcp``; works with any object that has ``async call_tool``).

    from tracekit_sdk import Tracer
    from tracekit.adapters.mcp import traced_session
    async with ClientSession(read, write) as session:
        session = traced_session(session, tracer, server="github")
        await session.call_tool("create_issue", {"title": "..."})     # recorded as mcp__github__create_issue

Tool names follow Claude Code's ``mcp__<server>__<tool>`` convention, so the default policy's MCP rules (flag) and
strict.yaml (hold for approval) apply unchanged. A denied call raises ``PermissionError`` and never reaches the server.
MCP reports tool failures as results (``isError: true``), not exceptions: the adapter keeps that behaviour for the caller
and records the call as failed. Only calls made through the wrapped session are seen."""
import re

_SAFE = re.compile(r"[^A-Za-z0-9_-]+")


def tool_name(server, name):
    return f"mcp__{_SAFE.sub('_', str(server or 'server'))}__{_SAFE.sub('_', str(name))}"


class _ToolReportedError(Exception):
    pass


class TracedSession:
    def __init__(self, session, tracer, server):
        self._session, self._tracer, self._server = session, tracer, server

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def call_tool(self, name, arguments=None, *args, **kwargs):
        result = None
        try:
            with self._tracer.tool(tool_name(self._server, name), dict(arguments or {})) as call:
                result = await self._session.call_tool(name, arguments, *args, **kwargs)
                dump = getattr(result, "model_dump", None)
                data = dump(mode="json", exclude_none=True, by_alias=True) if callable(dump) else result  # wire names (isError)
                call.result(data)
                if _is_error(result, data):
                    raise _ToolReportedError(str(data)[:500])  # recorded as ok=false
        except _ToolReportedError:
            pass
        return result


def _is_error(result, data):
    for attr in ("isError", "is_error"):  # the field name differs across mcp package versions
        if getattr(result, attr, None) is True:
            return True
    return isinstance(data, dict) and (data.get("isError") is True or data.get("is_error") is True)


def traced_session(session, tracer, server="server"):
    return TracedSession(session, tracer, server)
