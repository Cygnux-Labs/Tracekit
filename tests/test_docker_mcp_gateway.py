"""Docker's MCP Gateway behind the MCP gateway (docs/integrations/docker-mcp-gateway.md): the config's `command` starts
a stand-in for `docker mcp gateway run --servers=duckduckgo` (an MCP server on stdio, Docker's default transport), and
each tool call is decided, held for a person, run and completed through an in-process v2 signer, tier T2."""
import json
import os
import signal
import sys
import threading
import time
import unittest

import test_mcp_gateway as base
from adapter_contract import tmpdir
from factories import wait_for
from test_executor import InProcess
from test_gateway import AGENT, SECRET, serve
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS

# Docker's gateway serves its servers' tools unprefixed; this one also notes each call it runs, with its command line
# and the setting it got, next to itself
DOCKER = '''
import json, os, sys
from mcp.server.mcpserver import MCPServer

s = MCPServer("docker")


@s.tool()
def search(query: str) -> str:
    """Search the web."""
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ran.jsonl"), "a") as f:
        f.write(json.dumps({"argv": sys.argv[1:], "query": query, "context": os.environ.get("DOCKER_CONTEXT")}) + "\\n")
    return "results for " + query


with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "pid"), "w") as f:
    f.write(str(os.getpid()))
s.run()
'''
POLICY = Engine({"deny": [{"id": "R-INTERNAL", "tool": "^mcp:duckduckgo/search$", "pattern": "internal-only"}],
                 "ask": [{"id": "R-PAYROLL", "tool": "^mcp:duckduckgo/search$", "pattern": "payroll",
                          "approval": {"executor": "t2"}}]})


@unittest.skipUnless(base.HAVE_MCP, "mcp not installed")
class DockerUpstream(unittest.TestCase):
    agent, events, close = base.McpGateway.agent, base.McpGateway.events, base.McpGateway.close

    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=POLICY, gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/mcp": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume", "observe"]})
        self.closed = False
        self.addCleanup(self.close)
        for name, value in (("bearer", SECRET), ("docker.py", DOCKER)):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(value)
        cfg = os.path.join(self.dir, "mcp-gateway.yaml")
        with open(cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "signer": "unused",
                       "upstreams": [{"name": "duckduckgo",
                                      "command": [sys.executable, os.path.join(self.dir, "docker.py"),
                                                  "mcp", "gateway", "run", "--servers=duckduckgo"],
                                      "settings": {"DOCKER_CONTEXT": "desktop-linux"}}]}, f)
        self.port = serve(self, base.mcp_gateway.serve(base.mcp_gateway.load_config(cfg), InProcess(self.s, base.MCP)))
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}

    def ran(self):
        try:
            with open(os.path.join(self.dir, "ran.jsonl")) as f:
                return [json.loads(line) for line in f]
        except FileNotFoundError:
            return []

    def test_a_call_through_docker_is_decided_run_and_completed_t2(self):
        self.assertEqual([t.name for t in self.agent(lambda c: c.list_tools()).tools], ["duckduckgo__search"])
        out = self.agent(lambda c: c.call_tool("duckduckgo__search", {"query": "docker"}))
        self.assertEqual((out.is_error, out.content[0].text), (False, "results for docker"))
        self.assertEqual(self.ran(), [{"argv": ["mcp", "gateway", "run", "--servers=duckduckgo"], "query": "docker",
                                       "context": "desktop-linux"}])
        evs = [e for e in self.events() if e["type"] in ("policy.decision", "tool.result")]
        self.assertEqual([(e["type"], e["source"], e["tier"], e["data"].get("tool")) for e in evs],
                         [("policy.decision", "gateway", "T2", "mcp:duckduckgo/search"),
                          ("tool.result", "gateway", "T2", None)])

    def test_docker_exits_and_the_next_call_starts_it_again(self):
        self.assertFalse(self.agent(lambda c: c.call_tool("duckduckgo__search", {"query": "one"})).is_error)
        with open(os.path.join(self.dir, "pid")) as f:
            os.kill(int(f.read()), signal.SIGTERM)   # Docker Desktop restarting, an OOM kill
        time.sleep(1)
        out = self.agent(lambda c: c.call_tool("duckduckgo__search", {"query": "two"}))
        self.assertEqual((out.is_error, out.content[0].text), (False, "results for two"))
        self.assertEqual([r["query"] for r in self.ran()], ["one", "two"])

    def test_a_denied_call_never_reaches_docker(self):
        out = self.agent(lambda c: c.call_tool("duckduckgo__search", {"query": "internal-only roadmap"}))
        self.assertTrue(out.is_error)
        self.assertIn("R-INTERNAL", out.content[0].text)
        self.assertEqual(self.ran(), [])

    def test_an_asked_call_waits_for_a_person_and_docker_runs_the_approved_arguments(self):
        got = {}
        t = threading.Thread(target=lambda: got.update(out=self.agent(
            lambda c: c.call_tool("duckduckgo__search", {"query": "payroll 2026"}))))
        t.start()
        aids = wait_for(lambda: [a["approval_id"] for a in self.s.call(AGENT, "approval_list", {
            "run_id": self.run["run_id"], "state": "requested"})["approvals"]])
        self.assertEqual(self.ran(), [])   # held: Docker hasn't seen the call
        self.s.call(AGENT, "approval_decide", {"request_id": "d1", "approval_id": aids[0], "decision": "approve"})
        t.join(20)
        self.assertEqual(got["out"].content[0].text, "results for payroll 2026")
        self.assertEqual([r["query"] for r in self.ran()], ["payroll 2026"])
        kinds = [(e["type"], e["source"]) for e in self.events()]
        for k in [("approval.request", "gateway"), ("approval.consumed", "signer"), ("tool.result", "gateway")]:
            self.assertIn(k, kinds)


if __name__ == "__main__":
    unittest.main()
