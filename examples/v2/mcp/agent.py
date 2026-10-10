"""An MCP client on the v2 signer, offline: an in-process MCP server on the mcp package's in-memory transport, and a
scripted client (the mock model) that calls three of its tools. The dev signer allows `list_files`, denies
`tracekit_demo_denied` (the client gets an error result and goes on) and holds `tracekit_demo_ask` until a person
approves. Then the run is exported and verified.

    python examples/v2/mcp/agent.py [--scripted]
"""
import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import approver, export_and_verify   # noqa: E402

from mcp import Client as MCPClient   # noqa: E402
from mcp.server.mcpserver import MCPServer   # noqa: E402

from tracekit.integrations.mcp import TracekitSession   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402

SERVER = MCPServer("files")   # its tools are recorded as mcp:files/<tool>


@SERVER.tool()
def list_files() -> str:
    """List the files."""
    return "README.md  src/"


@SERVER.tool()
def tracekit_demo_denied() -> str:
    """Denied by the dev policy's demo rule (TK-DEMO-DENY)."""
    return "should never run"


@SERVER.tool()
def tracekit_demo_ask() -> str:
    """Held for a person by the dev policy's demo rule (TK-DEMO-ASK)."""
    return "ran once approved"


async def main(run):
    async with MCPClient(SERVER) as c:   # a real server: mcp.client.stdio or streamable_http, then the same wrapper
        session = TracekitSession(c.session, run.client, run.registered)
        for tool in ("list_files", "tracekit_demo_denied", "tracekit_demo_ask"):   # ask: waits in call_tool
            result = await session.call_tool(tool, {})
            print(f"{tool}: {'error: ' if result.is_error else ''}{result.content[0].text}")


with Client().run(agent="mcp-example") as run, approver(run.client, run.run_id):
    asyncio.run(main(run))
sys.exit(export_and_verify(run.run_id))
