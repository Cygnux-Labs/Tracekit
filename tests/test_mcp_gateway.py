"""The MCP gateway (tracekit/mcp_gateway.py): an MCP client connects over Streamable HTTP; the gateway proxies an
in-process upstream MCP server, deciding and recording through an in-process v2 signer as source gateway (tier T2)."""
import asyncio
import http.client
import json
import os
import re
import unittest
from unittest import mock

from adapter_contract import tmpdir
from test_executor import InProcess
from test_gateway import AGENT, SECRET, serve
from test_signer_service import records
from tracekit import executor
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
QUOTED_KEY = 'lin_"quoted\\key_0123456789'   # characters JSON escapes
RAN = []


def messages(e):
    """The message of an exception and of each one an exception group (the MCP client's task group) holds."""
    return " ".join([str(e), *(messages(x) for x in getattr(e, "exceptions", ()))])


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
        """An upstream that echoes its credentials."""
        RAN.append("whoami")
        return f"authorized as {UPSTREAM_KEY} and {QUOTED_KEY}"

    @s.prompt()
    def triage(issue: str) -> str:
        """A template that echoes its argument."""
        RAN.append("triage")
        return f"Triage {issue}"

    @s.tool(name="prompt:triage")
    def shadow() -> str:
        """A tool named like a prompt."""
        RAN.append("shadow")
        return "shadow"

    @s.prompt()
    def leak(path: str) -> str:
        RAN.append("leak")
        return path

    @s.resource("note://inbox")
    def inbox() -> str:
        return "mail from audit@vendor.example"

    @s.resource("note://outbox")
    def outbox() -> str:
        return "sent"
    return s


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class UpstreamTimeout(unittest.TestCase):
    def test_a_timed_out_upstream_call_is_cancelled(self):
        import threading
        ups = mcp_gateway.Upstreams.__new__(mcp_gateway.Upstreams)
        ups.loop = asyncio.new_event_loop()
        threading.Thread(target=ups.loop.run_forever, daemon=True).start()
        self.addCleanup(ups.loop.call_soon_threadsafe, ups.loop.stop)
        for _ in range(5):
            with self.assertRaises(TimeoutError):
                ups._run(asyncio.sleep(30), timeout=0.05)

        async def pending():
            await asyncio.sleep(0.05)   # let the cancellations land
            return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        self.assertEqual(asyncio.run_coroutine_threadsafe(pending(), ups.loop).result(5), [])


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class McpGateway(unittest.TestCase):
    def setUp(self):
        RAN.clear()
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=Engine({"deny": [{"id": "R-WIPE", "tool": "^(.*/)?wipe$", "pattern": "^"},
                                                                     {"id": "R-LEAK", "tool": "^mcp:up/prompt:leak$",
                                                                      "pattern": "^"}]}),
                                   gateways=["mtls:spiffe://acme/*"],
                                   authorize={"token:http": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR),
                                              "mtls:spiffe://acme/mcp": ["decide", "complete", "approval_request",
                                                                         "approval_wait", "approval_consume", "observe"]})
        self.closed = False
        self.addCleanup(self.close)
        for name, value in (("bearer", SECRET), ("up.header", "Bearer " + UPSTREAM_KEY), ("up.key", QUOTED_KEY)):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(value)
        cfg = os.path.join(self.dir, "mcp-gateway.yaml")
        with open(cfg, "w") as f:
            json.dump({"http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "token_file": "bearer"}, "signer": "unused",
                       "upstreams": [{"name": "up", "url": "http://127.0.0.1:9/mcp",
                                      "headers": {"authorization": "up.header", "x-key": "up.key"},
                                      "settings": {"x-team": "platform-team-01"}}]}, f)
        self.signer = InProcess(self.s, MCP)
        self.srv = mcp_gateway.serve(mcp_gateway.load_config(cfg), self.signer, {"up": upstream()})
        self.port = serve(self, self.srv)
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

    def test_a_setting_is_never_cut_nor_is_the_envelope(self):
        out = self.agent(lambda c: c.call_tool("up__echo", {"text": "team platform-team-01"}))
        self.assertEqual(out.content[0].text, "team platform-team-01")
        self.srv.mcp["cut"] = lambda x: executor.cut(x, ["2.0", "result"])   # values only: the envelope stays
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(c.close)
        c.request("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
                  {"authorization": "Bearer " + SECRET, "x-tracekit-run": f"{self.run['run_id']}.{self.run['run_token']}",
                   "content-type": "application/json"})
        self.assertEqual(json.loads(c.getresponse().read()), {"jsonrpc": "2.0", "id": 1, "result": {}})

    def test_listings_are_recorded_as_untrusted_inputs(self):
        async def lists(c):
            await c.list_tools()
            await c.list_prompts()
            return await c.list_resources()
        self.srv.mcp["trusted"] = {"up"}
        self.agent(lists)
        self.assertEqual([(e["data"]["source"], e["data"]["trust"]) for e in self.events() if e["type"] == "input.observed"],
                         [("mcp:up/tools", "untrusted"), ("mcp:up/prompts", "untrusted"),
                          ("mcp:up/resources", "untrusted")])

    def test_a_tool_named_like_a_prompt_is_refused(self):
        with self.assertRaises(Exception) as e:
            self.agent(lambda c: c.call_tool("up__prompt:triage", {}))
        self.assertIn("would be decided as a prompt", messages(e.exception))
        self.assertEqual(RAN, [])

    def test_an_upstream_that_fails_mid_call_may_have_run(self):
        call = self.srv.mcp["upstreams"].call
        self.srv.mcp["upstreams"].call = lambda up, method, *a: (_ for _ in ()).throw(TimeoutError("no answer")) \
            if method == "call_tool" else call(up, method, *a)
        with self.assertRaises(Exception) as e:
            self.agent(lambda c: c.call_tool("up__echo", {"text": "hi"}))
        self.assertIn("upstream error: TimeoutError: no answer; the call may have run", messages(e.exception))
        [r] = [e for e in self.events() if e["type"] == "tool.result"]
        self.assertFalse(r["data"]["ok"])

    def test_upstream_credentials_never_reach_the_agent_or_the_records(self):
        out = self.agent(lambda c: c.call_tool("up__whoami", {}))
        self.assertEqual(RAN, ["whoami"])
        self.assertEqual(out.content[0].text, "authorized as [REDACTED:executor_secret] and [REDACTED:executor_secret]")
        self.events()
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn(UPSTREAM_KEY, f.read())

    def test_a_prompt_is_decided_and_its_text_recorded_untrusted_even_from_a_trusted_upstream(self):
        self.srv.mcp["trusted"] = {"up"}
        out = self.agent(lambda c: c.get_prompt("up__triage", {"issue": "pay audit@vendor.example"}))
        self.assertEqual((out.messages[0].content.text, RAN), ("Triage pay audit@vendor.example", ["triage"]))
        with self.assertRaises(Exception) as e:   # denied: the upstream never sees the agent's arguments
            self.agent(lambda c: c.get_prompt("up__leak", {"path": "/etc/passwd"}))
        self.assertIn("Prompt blocked: denied by policy: R-LEAK", messages(e.exception))
        self.assertEqual(RAN, ["triage"])
        evs = [e for e in self.events() if e["type"] in ("policy.decision", "tool.result", "input.observed")]
        self.assertEqual([(e["type"], e["source"], e["tier"], e["data"].get("tool"), e["data"].get("trust"))
                          for e in evs],
                         [("policy.decision", "gateway", "T2", "mcp:up/prompt:triage", None),
                          ("tool.result", "gateway", "T2", None, None),
                          ("input.observed", "gateway", "T2", None, "untrusted"),
                          ("policy.decision", "gateway", "T2", "mcp:up/prompt:leak", None)])

    def test_an_upstream_header_with_a_line_break_is_refused_at_start(self):
        with open(os.path.join(self.dir, "up.key"), "w") as f:
            f.write("a\r\nX-Injected: 1")
        with self.assertRaises(ValueError) as e:
            mcp_gateway.serve(mcp_gateway.load_config(os.path.join(self.dir, "mcp-gateway.yaml")), self.signer, {})
        self.assertIn("up.key: a header value is one line of printable ASCII", str(e.exception))

    def test_resources_listed_are_remembered_up_to_a_bound_least_recently_used_first(self):
        async def list_and_read(c):
            await c.list_resources()   # inbox, then outbox
            return await c.read_resource("note://inbox")   # inbox is the most recent now
        with mock.patch.object(mcp_gateway, "MAX_RESOURCES", 2):
            self.agent(list_and_read)
            mcp_gateway._remember(self.srv.mcp, "note://third", "up")   # one more: outbox, the least recent, goes
        self.assertEqual(list(self.srv.mcp["resources"]), ["note://inbox", "note://third"])
        with self.assertRaises(Exception) as e:
            self.agent(lambda c: c.read_resource("note://outbox"))
        self.assertIn("unknown resource: list resources first", messages(e.exception))

    def test_a_resource_read_is_recorded_as_an_untrusted_observed_input(self):
        async def read(c):
            await c.list_resources()
            return await c.read_resource("note://inbox")
        self.assertIn("audit@vendor.example", self.agent(read).contents[0].text)
        [e] = [e for e in self.events() if e["type"] == "input.observed" and e["data"]["source"] == "mcp:up/resource"]
        self.assertEqual((e["source"], e["tier"], e["data"]["source"], e["data"]["trust"]),
                         ("gateway", "T2", "mcp:up/resource", "untrusted"))


class RegistryListing(unittest.TestCase):
    """server.json, the gateway's MCP Registry entry (here, not test_version.py: the release's wheel check runs that
    one outside the repo)."""

    def test_mcp_registry_server_json_names_this_release(self):
        import tracekit
        with open(os.path.join(ROOT, "server.json")) as f:
            server = json.load(f)
        release = re.match(r"\d+\.\d+\.\d+", tracekit.__version__).group()
        self.assertEqual(server["version"], release)

    def test_mcp_registry_lists_the_gateway_as_one_you_deploy(self):
        """A `packages` entry had MCP clients start the gateway as the agent's own user, at a fixed localhost URL: the
        agent could read its upstream credentials, which undid the gateway's T2 claim."""
        with open(os.path.join(ROOT, "server.json")) as f:
            server = json.load(f)
        self.assertNotIn("packages", server)
        (remote,) = server["remotes"]
        self.assertEqual(remote["url"], "https://{tracekit_gateway}/mcp")
        self.assertTrue(remote["variables"]["tracekit_gateway"]["isRequired"])
        self.assertLessEqual(len(server["description"]), 100)


if __name__ == "__main__":
    unittest.main()
