#!/usr/bin/env python3
"""MCP tool calls gated and recorded at the client boundary. Uses an in-process stand-in for an MCP ClientSession
(anything with `async call_tool` works), so it runs without a server; with the `mcp` package you wrap the real
ClientSession the same way. The default policy flags MCP calls; this example adds a rule that denies deletes."""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tracekit.adapters.mcp import traced_session  # noqa: E402
from tracekit_sdk import Tracer  # noqa: E402

if "TRACEKIT_POLICY" not in os.environ:
    pol = os.path.join(tempfile.mkdtemp(), "policy.yaml")
    with open(pol, "w") as f:
        f.write("extends: default\nversion: mcp-example\ndeny:\n  - id: EX-MCP-DELETE\n    tool: 'mcp__.*__delete_.*'\n"
                "    pattern: '.*'\n    reason: no deletes through MCP\n")
    os.environ["TRACEKIT_POLICY"] = pol


class Session:  # stand-in for mcp.ClientSession
    async def call_tool(self, name, arguments=None):
        return {"content": [{"type": "text", "text": f"{name} ok"}], "isError": False}


async def main(t):
    s = traced_session(Session(), t, server="github")
    print(await s.call_tool("create_issue", {"title": "flaky test"}))
    try:
        await s.call_tool("delete_repo", {"name": "prod"})
    except PermissionError as e:
        print("denied:", e)


with Tracer(agent="mcp-example") as t:
    asyncio.run(main(t))
print("mcp example finished; session", t.session_id)
