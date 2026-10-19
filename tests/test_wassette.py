"""Wassette behind the MCP gateway (docs/integrations/wassette.md): the docs' policy, over the server pack, holds each
component load and permission grant for a person and lets the other tools run. Through the real gateway and an
in-process v2 signer, with an upstream offering Wassette's tools as Wassette names them and their arguments
(crates/mcp-server/src/tools.rs in microsoft/wassette)."""
import asyncio
import json
import os
import shutil
import threading
import time
import unittest

from adapter_contract import tmpdir
from test_docs import FENCE, ROOT, read
from test_executor import InProcess
from test_gateway import AGENT, SECRET, serve
from test_mcp_gateway import HAVE_MCP, MCP
from test_signer_service import records
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS

if HAVE_MCP:
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.mcpserver import MCPServer

    from tracekit import mcp_gateway

RAN = []
HELD = {"load-component": {"path": "oci://ghcr.io/microsoft/fetch-rs:latest"},
        "grant-storage-permission": {"component_id": "fetch_rs",
                                     "details": {"uri": "fs:///srv/data", "access": ["read", "write"]}},
        "grant-network-permission": {"component_id": "fetch_rs", "details": {"host": "api.github.com"}},
        "grant-environment-variable-permission": {"component_id": "fetch_rs", "details": {"key": "GITHUB_TOKEN"}}}
RUN = {"fetch": {"url": "https://api.github.com/zen"}, "get-policy": {"component_id": "fetch_rs"},
       "list-components": {}, "revoke-network-permission": {"component_id": "fetch_rs",
                                                             "details": {"host": "api.github.com"}},
       "unload-component": {"id": "fetch_rs"}}


def policy(d):
    """The signer policy the docs give, next to a copy of the shipped packs as `packs/`."""
    [block] = [b for lang, b in FENCE.findall(read(os.path.join(ROOT, "docs", "integrations", "wassette.md")))
               if lang == "yaml" and "WASSETTE-GRANT" in b]
    shutil.copytree(os.path.join(ROOT, "tracekit", "policy2", "packs"), os.path.join(d, "packs"))
    with open(os.path.join(d, "policy.yaml"), "w", encoding="utf-8") as f:
        f.write(block)
    return svc.load_policy(os.path.join(d, "policy.yaml"))


def ran(name, **args):
    RAN.append((name, args))
    return json.dumps({"status": "ok"})


def wassette():
    s = MCPServer("wassette")

    def permission(name):
        def tool(component_id: str, details: dict) -> str:
            return ran(name, component_id=component_id, details=details)
        return tool

    for name in ("grant-storage-permission", "grant-network-permission", "grant-environment-variable-permission",
                 "revoke-network-permission"):
        s.tool(name=name)(permission(name))

    @s.tool(name="load-component")
    def load(path: str) -> str:
        return ran("load-component", path=path)

    @s.tool(name="unload-component")
    def unload(id: str) -> str:
        return ran("unload-component", id=id)

    @s.tool(name="get-policy")
    def get_policy(component_id: str) -> str:
        return ran("get-policy", component_id=component_id)

    @s.tool(name="list-components")
    def list_components() -> str:
        return ran("list-components")

    @s.tool()
    def fetch(url: str) -> str:   # fetch-rs's one export
        return ran("fetch", url=url)
    return s


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class WassetteBehindTheGateway(unittest.TestCase):
    def setUp(self):
        RAN.clear()
        self.dir = tmpdir(self)
        self.s = svc.SignerService(os.path.join(self.dir, "signer"), policy=policy(self.dir),
                                   gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/mcp": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume", "observe"]})
        self.addCleanup(self.s.close)
        with open(os.path.join(self.dir, "bearer"), "w") as f:
            f.write(SECRET)
        cfg = os.path.join(self.dir, "mcp-gateway.yaml")
        with open(cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "signer": "unused", "approval_wait_s": 30,
                       "upstreams": [{"name": "wassette", "url": "http://127.0.0.1:9/mcp"}]}, f)
        self.port = serve(self, mcp_gateway.serve(mcp_gateway.load_config(cfg), InProcess(self.s, MCP),
                                                  {"wassette": wassette()}))
        out = self.s.call(AGENT, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}

    def call(self, name, args, answer=None):
        """The agent's tools/call of wassette__<name>; with `answer`, a person answers its approval so."""
        def person():
            while True:
                for a in self.s.call(AGENT, "approval_list", {"run_id": self.run["run_id"],
                                                              "state": "requested"})["approvals"]:
                    self.s.call(AGENT, "approval_decide", {"request_id": a["approval_id"],
                                                           "approval_id": a["approval_id"], "decision": answer})
                    return
                time.sleep(0.01)
        if answer:
            threading.Thread(target=person, daemon=True).start()

        async def go():
            headers = {"authorization": "Bearer " + SECRET,
                       "x-tracekit-run": f"{self.run['run_id']}.{self.run['run_token']}"}
            async with Client(streamable_http_client(f"http://127.0.0.1:{self.port}/mcp",
                                                     http_client=httpx2.AsyncClient(headers=headers))) as c:
                return await c.call_tool("wassette__" + name, args)
        return asyncio.run(go())

    def decisions(self):
        self.s.close()
        return {e["data"]["tool"]: e for r in records(os.path.join(self.dir, "signer")) for e in [r["event"]]
                if e["type"] == "policy.decision" and e["run_id"] == self.run["run_id"]}

    def test_each_load_and_grant_waits_for_a_person_and_runs_only_once_approved(self):
        for name, args in HELD.items():
            with self.subTest(name):
                RAN.clear()
                out = self.call(name, args, "reject")
                self.assertTrue(out.is_error)
                self.assertIn("WASSETTE-GRANT", out.content[0].text)
                self.assertEqual(RAN, [])   # rejected: Wassette never sees the call
                self.assertFalse(self.call(name, args, "approve").is_error)
                self.assertEqual(RAN, [(name, args)])   # exactly the approved arguments
        evs = self.decisions()
        for name in HELD:
            e = evs["mcp:wassette/" + name]
            self.assertEqual((e["source"], e["tier"], e["data"]["decision"]), ("gateway", "T2", "ask"))
            self.assertIn("WASSETTE-GRANT", e["data"]["rule_ids"])

    def test_the_other_tools_run_without_a_person(self):
        for name, args in RUN.items():
            with self.subTest(name):
                self.assertFalse(self.call(name, args).is_error)
        self.assertEqual(RAN, list(RUN.items()))
        evs = self.decisions()
        self.assertEqual({n: evs["mcp:wassette/" + n]["data"]["decision"] for n in RUN}, dict.fromkeys(RUN, "flag"))

    def test_the_rule_holds_claude_codes_name_for_the_tool_too(self):
        d = self.s.policy.decide("mcp__wassette__grant-network-permission", HELD["grant-network-permission"])
        self.assertEqual(d["verdict"], "ask")
        self.assertIn("WASSETTE-GRANT", d["rule_ids"])


if __name__ == "__main__":
    unittest.main()
