"""The MCP gateway (tracekit/mcp_gateway.py): an MCP client connects over Streamable HTTP; the gateway proxies an
in-process upstream MCP server, deciding and recording through an in-process v2 signer as source gateway (tier T2)."""
import asyncio
import json
import os
import unittest

from adapter_contract import tmpdir
from test_executor import InProcess
from test_gateway import AGENT, SECRET, serve
from test_signer_service import records
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS

try:
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.mcpserver import MCPServer

    from tracekit import mcp_gateway
except ImportError:   # optional: the dev extra installs it
    HAVE_MCP = False
else:
    HAVE_MCP = True

MCP = CallerIdentity("mtls", "spiffe://acme/mcp", True)
UPSTREAM_KEY = "lin_api_upstream_0123456789"
RAN = []


def upstream():
    s = MCPServer("up")

    @s.tool()
    def echo(text: str) -> str:
        """Echo the text."""
        RAN.append("echo")
        return text

    @s.tool()
    def wipe(path: str) -> str:
        """Delete a path."""
        RAN.append("wipe")
        return "wiped"

    @s.tool()
    def whoami() -> str:
        """An upstream that echoes its credential."""
        RAN.append("whoami")
        return f"authorized as {UPSTREAM_KEY}"

    @s.resource("note://inbox")
    def inbox() -> str:
        return "mail from audit@vendor.example"
    return s


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class McpGateway(unittest.TestCase):
    def setUp(self):
        RAN.clear()
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=Engine({"deny": [{"id": "R-WIPE", "tool": "^(.*/)?wipe$", "pattern": "^"}]}),
                                   gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"}),
                                              "mtls:spiffe://acme/mcp": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume", "observe"]})
        self.closed = False
        self.addCleanup(self.close)
        for name, value in (("bearer", SECRET), ("up.header", "Bearer " + UPSTREAM_KEY)):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(value)
        cfg = os.path.join(self.dir, "mcp-gateway.yaml")
        with open(cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "signer": "unused",
                       "upstreams": [{"name": "up", "url": "http://127.0.0.1:9/mcp",
                                      "headers": {"authorization": "up.header"}}]}, f)
        self.signer = InProcess(self.s, MCP)
        self.port = serve(self, mcp_gateway.serve(mcp_gateway.load_config(cfg), self.signer, {"up": upstream()}))
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()

    def agent(self, fn):
        """fn(client) on an MCP client of the gateway, as the agent of self.run."""
        async def go():
            headers = {"authorization": "Bearer " + SECRET, "x-tracekit-run": f"{self.run['run_id']}.{self.run['run_token']}"}
            async with Client(streamable_http_client(f"http://127.0.0.1:{self.port}/mcp",
                                                     http_client=httpx2.AsyncClient(headers=headers))) as c:
                return await fn(c)
        return asyncio.run(go())

    def events(self):
        self.close()
        return [r["event"] for r in records(self.dir) if r["event"]["run_id"] == self.run["run_id"]]

    def test_tools_pass_through_and_a_call_is_decided_run_and_completed_t2(self):
        tools = self.agent(lambda c: c.list_tools())
        self.assertEqual(sorted(t.name for t in tools.tools), ["up__echo", "up__whoami", "up__wipe"])
        out = self.agent(lambda c: c.call_tool("up__echo", {"text": "hi"}))
        self.assertEqual((out.is_error, out.content[0].text, RAN), (False, "hi", ["echo"]))
        evs = [e for e in self.events() if e["type"] in ("policy.decision", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"]) for e in evs],
                         [("policy.decision", "gateway", "T2"), ("tool.result", "gateway", "T2")])
        self.assertEqual(evs[0]["data"]["tool"], "mcp:up/echo")

    def test_a_denied_tool_never_reaches_the_upstream(self):
        out = self.agent(lambda c: c.call_tool("up__wipe", {"path": "/"}))
        self.assertTrue(out.is_error)
        self.assertIn("R-WIPE", out.content[0].text)
        self.assertEqual(RAN, [])

    def test_the_signer_unreachable_fails_closed(self):
        self.signer.down = True
        out = self.agent(lambda c: c.call_tool("up__echo", {"text": "hi"}))
        self.assertTrue(out.is_error)
        self.assertIn("signer is unreachable", out.content[0].text)
        self.assertEqual(RAN, [])

    def test_upstream_credentials_never_reach_the_agent_or_the_records(self):
        out = self.agent(lambda c: c.call_tool("up__whoami", {}))
        self.assertEqual(RAN, ["whoami"])
        self.assertNotIn(UPSTREAM_KEY, out.content[0].text)
        self.assertIn("[REDACTED:executor_secret]", out.content[0].text)
        self.events()
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn(UPSTREAM_KEY, f.read())

    def test_a_resource_read_is_recorded_as_an_untrusted_observed_input(self):
        async def read(c):
            await c.list_resources()
            return await c.read_resource("note://inbox")
        self.assertIn("audit@vendor.example", self.agent(read).contents[0].text)
        [e] = [e for e in self.events() if e["type"] == "input.observed"]
        self.assertEqual((e["source"], e["tier"], e["data"]["source"], e["data"]["trust"]),
                         ("gateway", "T2", "mcp:up/resource", "untrusted"))


if __name__ == "__main__":
    unittest.main()
