"""LangSmith's Tool Gateway behind the MCP gateway (docs/integrations/langsmith-tool-gateway.md): the config's `url` and
`headers` reach a stand-in for the managed kit endpoint (a Streamable HTTP MCP server that wants `X-Api-Key` and
`X-Tenant-Id`), and each tool call is decided, run and completed through an in-process v2 signer, tier T2. The key stays
out of every record, the bundle and everything the agent sees."""
import asyncio
import json
import os
import threading
import unittest
import zipfile

import test_mcp_gateway as base
from adapter_contract import tmpdir
from factories import wait_for
from test_executor import InProcess
from test_gateway import AGENT, SECRET, serve
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS
from tracekit.verify import v2 as verify_v2

LANGSMITH_KEY = "lsv2_sk_0123456789abcdef"
TENANT = "6f1b2c3d-workspace"
POLICY = Engine({"deny": [{"id": "R-NO-DELETE", "tool": "^mcp:langsmith/delete_ticket$", "pattern": "^"}]})

if base.HAVE_MCP:
    import uvicorn
    from mcp.server.mcpserver import MCPServer


class KitStandIn:
    """An MCP server on /v1/managed-tools/kits/support/mcp that answers only with the right X-Api-Key; it records the
    headers of every request and each tool it runs."""

    def __init__(self):
        self.requests, self.ran = [], []
        mcp = MCPServer("kit")

        @mcp.tool()
        def create_ticket(title: str) -> str:
            """Create a ticket."""
            self.ran.append(("create_ticket", title))
            return "created " + title

        @mcp.tool()
        def delete_ticket(ticket_id: str) -> str:
            """Delete a ticket."""
            self.ran.append(("delete_ticket", ticket_id))
            return "deleted"

        app = mcp.streamable_http_app(streamable_http_path="/v1/managed-tools/kits/support/mcp")

        async def gate(scope, receive, send):
            if scope["type"] == "http":
                headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
                self.requests.append(headers)
                if headers.get("x-api-key") != LANGSMITH_KEY or headers.get("x-tenant-id") != TENANT:
                    await send({"type": "http.response.start", "status": 401, "headers": []})
                    return await send({"type": "http.response.body", "body": b"unauthorized"})
            await app(scope, receive, send)
        self.server = uvicorn.Server(uvicorn.Config(gate, host="127.0.0.1", port=0, log_level="error"))
        threading.Thread(target=lambda: asyncio.run(self.server.serve()), daemon=True).start()
        self.port = wait_for(lambda: self.server.started and self.server.servers[0].sockets[0].getsockname()[1])

    def stop(self):
        self.server.should_exit = True


@unittest.skipUnless(base.HAVE_MCP, "mcp not installed")
class LangSmithUpstream(unittest.TestCase):
    agent, events, close = base.McpGateway.agent, base.McpGateway.events, base.McpGateway.close

    def setUp(self):
        self.kit = KitStandIn()
        self.addCleanup(self.kit.stop)
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=POLICY, gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get", "export_run"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/mcp": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume", "observe"]})
        self.closed = False
        self.addCleanup(self.close)
        for name, value in (("bearer", SECRET), ("langsmith.key", LANGSMITH_KEY)):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(value)
        cfg = os.path.join(self.dir, "mcp-gateway.yaml")
        with open(cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "signer": "unused",
                       "upstreams": [{"name": "langsmith",
                                      "url": f"http://127.0.0.1:{self.kit.port}/v1/managed-tools/kits/support/mcp",
                                      "headers": {"X-Api-Key": "langsmith.key"},
                                      "settings": {"X-Tenant-Id": TENANT}}]}, f)
        self.port = serve(self, base.mcp_gateway.serve(base.mcp_gateway.load_config(cfg), InProcess(self.s, base.MCP)))
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}

    def test_an_allowed_call_reaches_the_kit_with_the_key_and_is_signed_and_completed(self):
        self.assertEqual(sorted(t.name for t in self.agent(lambda c: c.list_tools()).tools),
                         ["langsmith__create_ticket", "langsmith__delete_ticket"])
        out = self.agent(lambda c: c.call_tool("langsmith__create_ticket", {"title": "printer"}))
        self.assertEqual((out.is_error, out.content[0].text), (False, "created printer"))
        self.assertEqual(self.kit.ran, [("create_ticket", "printer")])
        self.assertTrue(self.kit.requests)
        self.assertTrue(all(r.get("x-api-key") == LANGSMITH_KEY and r.get("x-tenant-id") == TENANT
                            for r in self.kit.requests), self.kit.requests)
        self.assertFalse(any("authorization" in r and SECRET in r["authorization"] for r in self.kit.requests))
        evs = [e for e in self.events() if e["type"] in ("policy.decision", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"], e["data"].get("tool")) for e in evs],
                         [("policy.decision", "gateway", "T2", "mcp:langsmith/create_ticket"),
                          ("tool.result", "gateway", "T2", None)])

    def test_a_denied_call_never_reaches_the_kit(self):
        out = self.agent(lambda c: c.call_tool("langsmith__delete_ticket", {"ticket_id": "T-1"}))
        self.assertTrue(out.is_error)
        self.assertIn("R-NO-DELETE", out.content[0].text)
        self.assertEqual(self.kit.ran, [])

    def test_the_key_is_in_no_record_no_bundle_and_nothing_the_agent_sees(self):
        seen = [self.agent(lambda c: c.list_tools()).model_dump_json(),
                self.agent(lambda c: c.call_tool("langsmith__create_ticket", {"title": "printer"})).model_dump_json(),
                self.agent(lambda c: c.call_tool("langsmith__delete_ticket", {"ticket_id": "T-1"})).model_dump_json()]
        self.assertFalse(any(LANGSMITH_KEY in s for s in seen))
        self.s.checkpoint()
        st = self.s.log.storage
        bundle, trust = os.path.join(self.dir, "run.tkb"), os.path.join(self.dir, "trust.json")
        from tracekit.bundle_v2 import export
        export(st, "default", self.run["run_id"], st.checkpoint_latest()[1], bundle,
               tenant_salt=self.s.log.tenant_salt("default"))
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0}, f)
        rep, code = verify_v2.verify(bundle, trust)
        self.assertEqual(code, verify_v2.EXIT_OK)
        with zipfile.ZipFile(bundle) as z:
            self.assertFalse([n for n in z.namelist() if LANGSMITH_KEY.encode() in z.read(n)])
        for root, _, files in os.walk(self.dir):   # the signer's whole store
            for name in files:
                if name != "langsmith.key":
                    with open(os.path.join(root, name), "rb") as f:
                        self.assertNotIn(LANGSMITH_KEY.encode(), f.read(), name)


if __name__ == "__main__":
    unittest.main()
