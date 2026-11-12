"""The MCP gateway (tracekit/mcp_gateway.py): an MCP client connects over Streamable HTTP; the gateway proxies an
in-process upstream MCP server, deciding and recording through an in-process v2 signer as source gateway (tier T2)."""
import asyncio
import concurrent.futures
import contextlib
import http.client
import json
import os
import re
import sys
import threading
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
    from mcp import Client, StdioServerParameters, types as mcp_types
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.lowlevel import Server as LowServer
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


def paged_upstream():
    """A two-page upstream: tools, resources and prompts each span two cursor pages."""
    tool_p1 = mcp_types.Tool(name="tool_p1", description="page 1 tool",
                              inputSchema={"type": "object", "properties": {}})
    tool_p2 = mcp_types.Tool(name="tool_p2", description="page 2 tool",
                              inputSchema={"type": "object", "properties": {}})
    res_p1 = mcp_types.Resource(uri="note://res-p1", name="res-p1", mimeType="text/plain")
    res_p2 = mcp_types.Resource(uri="note://res-p2", name="res-p2", mimeType="text/plain")
    prompt_p1 = mcp_types.Prompt(name="prompt_p1", description="page 1 prompt")
    prompt_p2 = mcp_types.Prompt(name="prompt_p2", description="page 2 prompt")

    async def on_list_tools(ctx, params):
        cursor = params.cursor if params else None
        if cursor is None:
            return mcp_types.ListToolsResult(tools=[tool_p1], next_cursor="2")
        return mcp_types.ListToolsResult(tools=[tool_p2])

    async def on_call_tool(ctx, params):
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=f"ran:{params.name}")])

    async def on_list_resources(ctx, params):
        cursor = params.cursor if params else None
        if cursor is None:
            return mcp_types.ListResourcesResult(resources=[res_p1], next_cursor="2")
        return mcp_types.ListResourcesResult(resources=[res_p2])

    async def on_read_resource(ctx, params):
        return mcp_types.ReadResourceResult(
            contents=[mcp_types.TextResourceContents(
                uri=str(params.uri), text=f"content:{params.uri}", mimeType="text/plain")])

    async def on_list_prompts(ctx, params):
        cursor = params.cursor if params else None
        if cursor is None:
            return mcp_types.ListPromptsResult(prompts=[prompt_p1], next_cursor="2")
        return mcp_types.ListPromptsResult(prompts=[prompt_p2])

    return LowServer("paged-up",
                     on_list_tools=on_list_tools,
                     on_call_tool=on_call_tool,
                     on_list_resources=on_list_resources,
                     on_read_resource=on_read_resource,
                     on_list_prompts=on_list_prompts)


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
class OpenFailure(unittest.TestCase):
    """#770: an upstream that can't be opened names the cause inside mcp's task group, and _open's own late
    branches (the couldn't-be-opened message, the opened-just-as-the-wait-ran-out return) are covered directly."""

    def test_a_group_of_one_unwraps_nested_too_and_a_group_of_two_stays(self):
        class Group(Exception):
            def __init__(self, subs):
                super().__init__("unhandled errors in a TaskGroup")
                self.exceptions = tuple(subs)

        cause = ValueError("the real cause")
        self.assertIs(mcp_gateway._cause(Group([cause])), cause)
        self.assertIs(mcp_gateway._cause(Group([Group([cause])])), cause)
        two = Group([cause, KeyError("another")])
        self.assertIs(mcp_gateway._cause(two), two)
        self.assertIs(mcp_gateway._cause(cause), cause)

    def test_a_refused_url_names_the_connect_error(self):
        target = streamable_http_client("http://127.0.0.1:9/mcp", http_client=httpx2.AsyncClient())
        with self.assertRaises(mcp_gateway.Unreachable) as e:
            mcp_gateway.Upstreams({"bad": target})
        self.assertTrue(str(e.exception).endswith(
            "upstream 'bad' couldn't be opened: ConnectError: All connection attempts failed"),
            str(e.exception))
        self.assertNotIn("TaskGroup", str(e.exception))

    def test_a_stdio_upstream_that_exits_names_the_inside_error(self):
        target = StdioServerParameters(command=sys.executable, args=["-c", "pass"])
        with self.assertRaises(mcp_gateway.Unreachable) as e:
            mcp_gateway.Upstreams({"bad": target})
        self.assertIn("upstream 'bad' couldn't be opened: ", str(e.exception))
        self.assertIn("MCPError: Connection closed", str(e.exception))
        self.assertNotIn("TaskGroup", str(e.exception))

    def test_an_upstream_that_opens_just_as_the_wait_runs_out_is_kept(self):
        class LateResult(concurrent.futures.Future):
            """The session is there when result() returns; the wait still reports that it ran out."""
            def result(self, timeout=None):
                super().result(timeout)
                raise TimeoutError("the wait ran out")

        with mock.patch.object(concurrent.futures, "Future", LateResult), \
                mock.patch.object(mcp_gateway, "UPSTREAM_TIMEOUT_S", 30):
            ups = mcp_gateway.Upstreams({"up": upstream()})
        self.addCleanup(ups.close)
        tools = ups.call("up", "list_tools")
        self.assertIn("echo", [t.name for t in tools.tools])


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

    def _swap_upstream(self, srv):
        old = self.srv.mcp["upstreams"]
        old.close()
        ups = mcp_gateway.Upstreams({"up": srv})
        self.srv.mcp["upstreams"] = ups
        self.addCleanup(ups.close)

    def test_all_three_lists_show_every_page(self):
        """Every tool, resource and prompt from every cursor page reaches the agent."""
        self._swap_upstream(paged_upstream())
        async def lists(c):
            tools = await c.list_tools()
            resources = await c.list_resources()
            prompts = await c.list_prompts()
            return tools, resources, prompts
        tools, resources, prompts = self.agent(lists)
        self.assertSetEqual({t.name for t in tools.tools}, {"up__tool_p1", "up__tool_p2"})
        self.assertSetEqual({str(r.uri) for r in resources.resources}, {"note://res-p1", "note://res-p2"})
        self.assertSetEqual({p.name for p in prompts.prompts}, {"up__prompt_p1", "up__prompt_p2"})

    def test_last_page_tool_is_callable(self):
        """A tool from the second page can be called through the gateway."""
        self._swap_upstream(paged_upstream())
        out = self.agent(lambda c: c.call_tool("up__tool_p2", {}))
        self.assertFalse(out.is_error)
        self.assertIn("ran:tool_p2", out.content[0].text)

    def test_last_page_resource_is_readable(self):
        """A resource URI from the second page is remembered and can be read."""
        self._swap_upstream(paged_upstream())
        async def list_and_read(c):
            await c.list_resources()
            return await c.read_resource("note://res-p2")
        result = self.agent(list_and_read)
        self.assertIn("note://res-p2", result.contents[0].text)

    def test_each_list_gives_one_observed_per_upstream(self):
        """Listing across multiple pages produces one input.observed per upstream per list."""
        self._swap_upstream(paged_upstream())
        async def lists(c):
            await c.list_tools()
            await c.list_resources()
            await c.list_prompts()
        self.agent(lists)
        observed = [(e["data"]["source"], e["data"]["trust"])
                    for e in self.events() if e["type"] == "input.observed"]
        self.assertEqual(observed, [("mcp:up/tools", "untrusted"),
                                     ("mcp:up/resources", "untrusted"),
                                     ("mcp:up/prompts", "untrusted")])

    def test_repeated_cursor_is_an_error(self):
        """A cursor returned twice raises an error naming the upstream and what it did (it named the 100-page cap,
        which the listing never reached)."""
        async def on_list_tools(ctx, params):
            return mcp_types.ListToolsResult(tools=[], next_cursor="same-forever")
        self._swap_upstream(LowServer("bad", on_list_tools=on_list_tools))
        with self.assertRaises(Exception) as e:
            self.agent(lambda c: c.list_tools())
        self.assertIn("upstream 'up': tools/list page 2 returned a cursor an earlier page had returned, so the listing "
                      "would never end; fix the upstream's cursor", messages(e.exception))
        self.assertNotIn("100 pages", messages(e.exception))

    def test_a_listing_past_its_shared_budget_names_the_upstream(self):
        """One listing has UPSTREAM_TIMEOUT_S for every upstream and page; past it the agent read "upstream error:
        TimeoutError: ; the gateway connects to an upstream that went away again on the next call"."""
        async def on_list_tools(ctx, params):
            await asyncio.sleep(1)
            return mcp_types.ListToolsResult(tools=[])
        self._swap_upstream(LowServer("slow", on_list_tools=on_list_tools))
        with mock.patch.object(mcp_gateway, "UPSTREAM_TIMEOUT_S", 0.3), self.assertRaises(Exception) as e:
            self.agent(lambda c: c.list_tools())
        self.assertIn("upstream 'up': tools/list timed out (one listing has 0.3 s for every upstream and page)",
                      messages(e.exception))

    def test_a_timeout_the_upstream_call_raises_is_not_the_listings(self):
        """Only the listing's own time running out names its budget. A TimeoutError raised inside the upstream call (a
        socket's, anyio's fail_after) or by the reconnect's wait read "tools/list timed out (one listing has 600 s for
        every upstream and page)"; it keeps the upstream error and its advice."""
        ups = self.srv.mcp["upstreams"]
        advice = "; the gateway connects to an upstream that went away again on the next call"

        def listing_error(*patches):
            with contextlib.ExitStack() as stack, self.assertRaises(Exception) as e:
                for p in patches:
                    stack.enter_context(p)
                self.agent(lambda c: c.list_tools())
            self.assertNotIn("one listing has", messages(e.exception))
            return messages(e.exception)
        self.assertIn("upstream error: TimeoutError: read timed out" + advice, listing_error(
            mock.patch.object(ups.clients["up"], "list_tools", new_callable=mock.AsyncMock,
                              side_effect=TimeoutError("read timed out"))))
        self.assertIn("upstream error: upstream 'up' gave no session in 600 s; nothing was sent to it",
                      listing_error(   # the reconnect's wait for a session
                          mock.patch.object(mcp_gateway, "_closed", return_value=True),
                          mock.patch.object(ups, "_open", side_effect=mcp_gateway.Unreachable(
                              "upstream 'up' gave no session in 600 s"))))

    def test_a_call_to_an_upstream_that_cant_be_opened_was_not_sent(self):
        """A tools/call whose upstream went away and can't be opened again says nothing was sent, not that it may
        have run, and completes as an error."""
        ups = self.srv.mcp["upstreams"]
        with mock.patch.object(mcp_gateway, "_closed", return_value=True), \
                mock.patch.object(ups, "_open", side_effect=mcp_gateway.Unreachable(
                    "upstream 'up' couldn't be opened: ConnectionRefusedError: refused")), \
                self.assertRaises(Exception) as e:
            self.agent(lambda c: c.call_tool("up__echo", {"text": "hi"}))
        self.assertIn("upstream error: upstream 'up' couldn't be opened: ConnectionRefusedError: refused; nothing was "
                      "sent to it", messages(e.exception))
        self.assertNotIn("may have run", messages(e.exception))
        self.assertEqual(RAN, [])
        [r] = [e for e in self.events() if e["type"] == "tool.result"]
        self.assertFalse(r["data"]["ok"])

    def test_a_call_that_ends_as_its_wait_runs_out_gives_its_own_answer(self):
        """An upstream answering between the wait running out and the check gives that answer, not the wait's empty
        TimeoutError; a TimeoutError the call raised itself is raised as it was."""
        ups = self.srv.mcp["upstreams"]

        class Late(concurrent.futures.Future):   # the wait runs out, and the answer is there at once
            def result(self, timeout=None):
                if timeout is not None:
                    raise concurrent.futures.TimeoutError()
                return super().result()

        def run(outcome):
            def submit(coro, loop):
                coro.close()
                fut = Late()
                if isinstance(outcome, BaseException):
                    fut.set_exception(outcome)
                else:
                    fut.set_result(outcome)
                return fut

            async def nothing():
                pass
            with mock.patch.object(mcp_gateway.asyncio, "run_coroutine_threadsafe", submit):
                return ups._run(nothing(), timeout=1)
        self.assertEqual("listed", run("listed"))
        with self.assertRaisesRegex(TimeoutError, "read timed out"):
            run(TimeoutError("read timed out"))

        class Ending(Late):   # not done when checked, and already finishing when cancelled
            def done(self):
                return False

            def cancel(self):
                return False
        Late = Ending
        self.assertEqual("listed", run("listed"))

    def test_a_reconnect_that_gets_no_session_names_the_upstream(self):
        """The reconnect's wait for a session names the upstream, and gives up the attempt so the next call opens a
        new one."""
        ups = self.srv.mcp["upstreams"]

        class Never:   # an upstream whose session never opens
            def __init__(self, target):
                pass

            async def __aenter__(self):
                await asyncio.Event().wait()

            async def __aexit__(self, *exc):
                return False
        held = ups._held["up"]
        try:
            with mock.patch("mcp.Client", Never), mock.patch.object(mcp_gateway, "UPSTREAM_TIMEOUT_S", 0.2), \
                    self.assertRaisesRegex(mcp_gateway.Unreachable, r"^upstream 'up' gave no session in 0.2 s$"):
                ups._open("up")
            attempt = ups._held["up"]
            with contextlib.suppress(concurrent.futures.CancelledError, concurrent.futures.TimeoutError):
                attempt.result(5)
            self.assertTrue(attempt.cancelled())
        finally:
            ups._held["up"] = held   # the open session this test left alone

    def _serve_expecting_failure(self, cfg, client, targets):
        """serve() failing after its bind, with the server it built kept (serve raises before returning it):
        returns the exception. The failed Upstreams' loop threads (their reprs name run_forever) are joined,
        since close() only schedules loop.stop; the server's socket must be closed."""
        kept = []
        real = mcp_gateway.transport.HttpServer

        def keeping(*a, **kw):
            srv = real(*a, **kw)
            kept.append(srv)
            return srv

        before = {t for t in threading.enumerate() if "(run_forever)" in repr(t)}
        with mock.patch.object(mcp_gateway.transport, "HttpServer", keeping):
            with self.assertRaises(Exception) as e:
                mcp_gateway.serve(cfg, client, targets)
        new = [t for t in threading.enumerate() if "(run_forever)" in repr(t) and t not in before]
        for t in new:
            t.join(5)
        self.assertTrue(all(not t.is_alive() for t in new))   # the opened upstream was closed, its loop stopped
        [srv] = kept
        self.assertEqual(srv.socket.fileno(), -1)
        return e.exception

    def test_serve_closes_its_socket_and_upstreams_when_a_later_upstream_cant_open(self):
        """#770: serve() binds its socket before it opens the upstreams; when a later one can't be opened, the
        socket and the upstream that did open are closed, not left behind for an embedding caller."""
        cfg = mcp_gateway.load_config(os.path.join(self.dir, "mcp-gateway.yaml"))
        bad = streamable_http_client("http://127.0.0.1:9/mcp", http_client=httpx2.AsyncClient())
        e = self._serve_expecting_failure(cfg, self.signer, {"good": upstream(), "bad": bad})
        self.assertIsInstance(e, mcp_gateway.Unreachable)

    def test_serve_closes_its_socket_and_upstreams_when_the_signer_url_cant_be_parsed(self):
        """#770: the same cleanup when the signer Client is what raises, with an upstream already open."""
        cfg = mcp_gateway.load_config(os.path.join(self.dir, "mcp-gateway.yaml"))
        cfg["signer"] = "http://[::1"
        e = self._serve_expecting_failure(cfg, None, {"good": upstream()})
        self.assertIsInstance(e, ValueError)

    def test_page_bound_error_forgets_page1_resources(self):
        """Hitting the page cap on resources/list returns an error and remembers nothing."""
        self._swap_upstream(paged_upstream())
        with mock.patch.object(mcp_gateway, "MAX_LIST_PAGES", 1):
            with self.assertRaises(Exception) as e:
                self.agent(lambda c: c.list_resources())
        self.assertIn("upstream 'up': resources/list exceeded 1 pages; "
                      "the gateway lists at most 1 pages per upstream; "
                      "give the upstream larger pages or fix its cursor",
                      messages(e.exception))
        self.assertNotIn("note://res-p1", self.srv.mcp["resources"])

    def test_upstream_error_on_page2_forgets_page1_resources(self):
        """An upstream that raises on its second page returns an error and remembers nothing."""
        async def on_list_resources(ctx, params):
            cursor = params.cursor if params else None
            if cursor is None:
                return mcp_types.ListResourcesResult(
                    resources=[mcp_types.Resource(uri="note://r1", name="r1",
                                                  mimeType="text/plain")],
                    next_cursor="2")
            raise RuntimeError("upstream failed on page 2")
        self._swap_upstream(LowServer("bad", on_list_resources=on_list_resources))
        with self.assertRaises(Exception) as e:
            self.agent(lambda c: c.list_resources())
        # the gateway's own error; what follows it depends on the mcp version (newer servers report a generic
        # "Internal server error" instead of the upstream's RuntimeError)
        self.assertIn("upstream error:", messages(e.exception))
        self.assertNotIn("note://r1", self.srv.mcp["resources"])


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
