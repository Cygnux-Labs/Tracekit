"""The adapter contract (tests/adapter_contract.py) for the MCP client adapter (tracekit/integrations/mcp.py), with an
in-process MCP server on the mcp package's in-memory transport (no network).

`call_tool` holds an `ask` while it waits for the approval, so the driver runs each call on a thread of its own and
returns once the approval is requested, as tests/test_contract_claude_code.py does.
"""
import asyncio
import threading
import time
import unittest
from unittest import mock

import pydantic

import adapter_contract as ac
from tracekit.sdk.client import Client

try:
    import mcp
    import mcp.types
    from mcp import Client as MCPClient
    from mcp import MCPError
    from mcp.server.mcpserver import MCPServer

    from tracekit.integrations.mcp import TracekitSession
except ImportError:   # optional: the dev extra installs it
    HAVE_MCP = False
else:
    HAVE_MCP = True
    SERVER = MCPServer("contract/mcp")   # recorded as mcp:contract_mcp/<tool>
    for f in ac.TOOLS:
        SERVER.tool()(f)

    @SERVER.tool()
    def broken() -> str:
        """Fails the request itself."""
        ac.RAN.append("broken")
        raise MCPError(-32603, "boom")


class Driver:
    SKIP = {"retry": "MCP has no tool call id: every call_tool is a call of its own",
            "saved_state": "call_tool holds the call while it waits for the approval: there is no saved state to "
                           "resume in a new process, replay or edit",
            "modes": "call_tool is async only, with no streaming path",
            "l1": "an MCP client keeps no agent state to commit"}

    def __init__(self, case, signer_path, **kw):
        self.signer, self.kw = Client(signer_path), kw
        case.addCleanup(self.signer.close)
        r = self.signer.register_run({"agent": {"name": "contract"}})
        self._run = {"run_id": r["run_id"], "run_token": r["run_token"]}

    def run(self):
        return self._run

    async def _call(self, tool, args):
        async with MCPClient(SERVER) as c:
            try:
                return await TracekitSession(c.session, self.signer, self._run, **self.kw).call_tool(tool, args)
            except Exception as e:   # raised here, not wrapped in the client's task group on the way out
                raised = e
        raise raised

    def call(self, tool, args, tcid="call-1", mode="sync"):
        ac.RAN.clear()
        self.out = {}

        def go():
            try:
                self.out["result"] = asyncio.run(self._call(tool, args))
            except Exception as e:
                self.out["raised"] = f"{type(e).__name__}: {e}"
        self.waiting = threading.Thread(target=go)
        self.waiting.start()
        while self.waiting.is_alive():
            aid = next((a["approval_id"] for a in self.signer.approval_list({"run_id": self._run["run_id"]})["approvals"]
                        if a["state"] == "requested"), None)
            if aid:
                return {"ran": [], "seen": None, "is_error": False, "continued": False, "raised": None,
                        "approval_id": aid}
            time.sleep(0.02)
        return self.finish()

    def resume(self, hint=ac.HINT, replay=False):
        self.waiting.join(60)
        return self.finish()

    def finish(self):
        r = self.out.get("result")
        return {"ran": list(ac.RAN), "seen": r and r.content[0].text, "is_error": bool(r and r.is_error),
                "continued": r is not None, "raised": self.out.get("raised"), "approval_id": None}


class MCPContract(ac.Contract):
    def test_tool_exception_reaches_the_framework_and_completes_as_error(self):
        """An MCP server reports a tool's exception as an isError result; an error of the request itself raises."""
        out = self.d.call("fail", {"why": "boom"})
        self.assertEqual((out["ran"], out["is_error"], out["raised"]), (["fail"], True, None))
        out = self.d.call("broken", {})
        self.assertEqual((out["ran"], out["raised"]), (["broken"], "MCPError: boom"))
        self.assertEqual([r["ok"] for r in self.assert_bound(2)], [False, False])

    def test_ask_is_refused_when_the_caller_cannot_wait_or_nobody_decides_in_time(self):
        self.d.kw["approval_wait_s"] = 0
        self.refused(self.d.call("pay", ac.PAY), "cannot wait")
        self.d.kw["approval_wait_s"] = 0.2
        aid = self.paused()
        self.refused(self.d.resume(), "no one approved the call within 0.2 s, so it did not run and its approval was "
                                      "withdrawn")
        self.assertEqual(self.client.approval_get({"approval_id": aid})["state"], "expired")


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class TestOnFakeSigner(MCPContract, ac.OnFake, unittest.TestCase):
    driver = Driver


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class TestOnRealSigner(MCPContract, ac.OnReal, unittest.TestCase):
    driver = Driver

    def test_recorded_as_an_mcp_tool(self):
        self.d.call("echo", {"text": "hi"})
        [e] = [e["data"] for e in self.events(self.d.run()) if e["type"] == "policy.decision"]
        self.assertEqual(e["tool"], "mcp:contract_mcp/echo")
        [gap] = [e["data"] for e in self.events(self.d.run()) if e["type"] == "capture.gap"]
        self.assertIn("class hint 'mcp'", gap["reason"])   # the contract policy has no tools map


class _Mcp1Session:
    """An mcp 1.x ClientSession: it doesn't keep the server's name."""

    def __init__(self):
        self.calls = 0

    async def call_tool(self, name, arguments=None):
        from mcp.types import CallToolResult, TextContent
        self.calls += 1
        return CallToolResult(content=[TextContent(type="text", text="done")], is_error=False)

    async def get_prompt(self, name, arguments=None):
        from mcp.types import GetPromptResult, PromptMessage, TextContent
        self.calls += 1
        if name == "boom":
            raise MCPError(-32603, "boom")
        return GetPromptResult(messages=[PromptMessage(role="user", content=TextContent(type="text", text="hi"))])

    async def read_resource(self, uri, *a, **kw):
        from mcp.types import ReadResourceResult, TextResourceContents
        self.calls += 1
        return ReadResourceResult(contents=[TextResourceContents(uri=uri, text=f"body of {uri}")])


class _StubSession(_Mcp1Session):
    server_info = type("Info", (), {"name": "stub"})()


class _Signer:
    """A signer that fails the way it is told: `decide`, `complete` and `observe` raise `errors[method]` when set."""

    def __init__(self, decision="allow", **errors):
        self.decision, self.errors, self.tools, self.completed = decision, errors, [], []
        self.observed, self.requests = [], []

    def __getattr__(self, method):
        def call(req):
            self.requests.append((method, req))
            self.tools += [req["tool"]] if method == "decide" else []
            self.completed += [req] if method == "complete" else []
            self.observed += [req] if method == "observe" else []
            if method in self.errors:
                raise self.errors[method]
            return {"decide": {"decision": self.decision, "decision_id": "dec-1", "rule_ids": ["r1"]},
                    "approval_consume": {"ok": True, "rule_ids": []}}.get(method, {"run_seq": 0})
        return call


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class SignerFailures(unittest.TestCase):
    RUN = {"run_id": "r1", "run_token": "t"}

    def call(self, signer, **run):
        session = _StubSession()
        out = asyncio.run(TracekitSession(session, signer, {**self.RUN, **run}).call_tool("x", {}))
        return out, session.calls

    def test_unreachable_signer_refuses_unless_the_run_fails_open(self):
        from tracekit.sdk.client import SignerUnavailable
        out, calls = self.call(_Signer(decide=SignerUnavailable("down")))
        self.assertEqual((out.is_error, calls), (True, 0))   # fail_modes default: closed
        out, calls = self.call(_Signer(decide=SignerUnavailable("down")), fail_modes={"default": "open"})
        self.assertEqual((out.is_error, calls), (False, 1))

    def test_a_refusal_never_lets_the_call_run(self):
        from tracekit.signer.rpc_schema import RPCError
        out, calls = self.call(_Signer(decide=RPCError("run_closed", "closed")), fail_modes={"default": "open"})
        self.assertEqual((out.is_error, calls), (True, 0))
        self.assertIn("run_closed", out.content[0].text)

    def test_a_failed_complete_warns_and_keeps_the_result(self):
        from tracekit.signer.rpc_schema import RPCError
        with self.assertWarns(UserWarning):
            out, calls = self.call(_Signer(complete=RPCError("unavailable", "storage down")))
        self.assertEqual((out.is_error, out.content[0].text, calls), (False, "done", 1))

    def test_mcp_1_results_say_is_error_as_isError(self):
        """mcp 1.x's CallToolResult has only `isError` and ignores `is_error=`: a refusal sets isError, and a server's
        isError result completes as an error."""
        from tracekit.signer.rpc_schema import RPCError

        class Result(pydantic.BaseModel):   # mcp 1.x's shape: camelCase fields, unknown arguments ignored
            content: list
            isError: bool = False

        class Failing(_Mcp1Session):
            async def call_tool(self, name, arguments=None):
                self.calls += 1
                return Result(content=[], isError=True)
        sent = []

        class Seen(_Signer):
            def __getattr__(self, method):
                call = super().__getattr__(method)
                return lambda req: sent.append((method, req)) or call(req)
        with mock.patch("tracekit.integrations.mcp.CallToolResult", Result):
            out = asyncio.run(TracekitSession(_Mcp1Session(), _Signer(decide=RPCError("run_closed", "closed")),
                                              self.RUN, server="s").call_tool("x", {}))
            self.assertIs(out.isError, True)
            asyncio.run(TracekitSession(Failing(), Seen(), self.RUN, server="s").call_tool("x", {}))
        self.assertEqual([r["status"] for m, r in sent if m == "complete"], ["error"])

    def test_an_mcp_1_session_is_named_by_the_caller_else_unknown(self):
        signer = _Signer()
        asyncio.run(TracekitSession(_Mcp1Session(), signer, self.RUN, server="git hub").call_tool("x", {}))
        with self.assertWarns(UserWarning) as cm:
            asyncio.run(TracekitSession(_Mcp1Session(), signer, self.RUN).call_tool("x", {}))
        self.assertEqual(signer.tools, ["mcp:git_hub/x", "mcp:unknown/x"])
        self.assertIn("server=", str(cm.warning))

    def test_get_prompt_is_decided_and_completed_as_a_prompt_call(self):
        session, signer = _StubSession(), _Signer()
        out = asyncio.run(TracekitSession(session, signer, self.RUN).get_prompt("triage", {"issue": "1"}))
        self.assertEqual((out.messages[0].content.text, session.calls, signer.tools),
                         ("hi", 1, ["mcp:stub/prompt:triage"]))
        self.assertEqual([r["status"] for r in signer.completed], ["ok"])

        session = _StubSession()
        with self.assertRaises(RuntimeError) as cm:
            asyncio.run(TracekitSession(session, _Signer(decision="deny"), self.RUN).get_prompt("triage", {}))
        self.assertIn("Tool call blocked by policy: ", str(cm.exception))
        self.assertEqual(session.calls, 0)

        signer = _Signer()
        with self.assertRaises(MCPError):
            asyncio.run(TracekitSession(_StubSession(), signer, self.RUN).get_prompt("boom", {}))
        self.assertEqual([(r["status"], r["error"]) for r in signer.completed], [("error", "MCPError: boom")])

        from tracekit import autowire
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        with mock.patch("mcp.ClientSession", _StubSession), \
                mock.patch.object(_StubSession, "call_tool", _StubSession.call_tool), \
                mock.patch.object(_StubSession, "get_prompt", _StubSession.get_prompt), \
                mock.patch.object(_StubSession, "read_resource", _StubSession.read_resource):
            autowire._mcp(run)
            out = asyncio.run(_StubSession().get_prompt("triage", {"issue": "1"}))
        self.assertEqual((out.messages[0].content.text, signer.tools), ("hi", ["mcp:stub/prompt:triage"]))

    def test_read_resource_is_recorded_as_an_untrusted_observed_input(self):
        session, signer = _StubSession(), _Signer()
        out = asyncio.run(TracekitSession(session, signer, self.RUN).read_resource("note://inbox"))
        self.assertEqual((out.contents[0].text, session.calls), ("body of note://inbox", 1))
        self.assertEqual([(r["source"], r["trust"], r["value"]["contents"][0]["text"]) for r in signer.observed],
                         [("mcp:stub/resource", "untrusted", "body of note://inbox")])

        from tracekit import autowire
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        with mock.patch("mcp.ClientSession", _StubSession), \
                mock.patch.object(_StubSession, "call_tool", _StubSession.call_tool), \
                mock.patch.object(_StubSession, "get_prompt", _StubSession.get_prompt), \
                mock.patch.object(_StubSession, "read_resource", _StubSession.read_resource):
            autowire._mcp(run)
            out = asyncio.run(_StubSession().read_resource("note://inbox"))
        self.assertEqual((out.contents[0].text, [(r["source"], r["trust"]) for r in signer.observed]),
                         ("body of note://inbox", [("mcp:stub/resource", "untrusted")]))

    def test_an_unrecorded_resource_is_withheld_when_the_run_fails_closed(self):
        """The default fail mode is closed, and a signer refusal is withheld even when the run fails open."""
        from tracekit.sdk.client import SignerUnavailable
        from tracekit.signer.rpc_schema import RPCError
        session = _StubSession()
        with self.assertRaises(SignerUnavailable):
            asyncio.run(TracekitSession(session, _Signer(observe=SignerUnavailable("down")),
                                        self.RUN).read_resource("note://inbox"))
        self.assertEqual(session.calls, 1)   # fetched from the server, not returned
        with self.assertRaises(RPCError):
            asyncio.run(TracekitSession(_StubSession(), _Signer(observe=RPCError("unavailable", "storage down")),
                                        self.RUN).read_resource("note://inbox"))
        with self.assertRaises(RPCError):
            asyncio.run(TracekitSession(_StubSession(), _Signer(observe=RPCError("unavailable", "storage down")),
                                        {**self.RUN, "fail_modes": {"mcp": "open"}}).read_resource("note://inbox"))

    def test_an_unrecorded_resource_is_returned_when_the_run_fails_open(self):
        from tracekit.sdk.client import SignerUnavailable
        session = _StubSession()
        with self.assertWarns(UserWarning) as cm:
            gate = TracekitSession(session, _Signer(observe=SignerUnavailable("down")),
                                   {**self.RUN, "fail_modes": {"mcp": "open"}})
            out = asyncio.run(gate.read_resource("note://inbox"))
        self.assertEqual((out.contents[0].text, session.calls), ("body of note://inbox", 1))
        self.assertIn("not recorded", str(cm.warning))

    def test_a_resource_over_half_a_frame_is_recorded_as_its_digest(self):
        from mcp.types import ReadResourceResult, TextResourceContents
        from tracekit.format.canon import event_hash

        class Big(_StubSession):
            async def read_resource(self, uri, *a, **kw):
                return ReadResourceResult(contents=[TextResourceContents(uri=uri, text="x" * (1 << 20))])
        signer = _Signer()
        out = asyncio.run(TracekitSession(Big(), signer, self.RUN).read_resource("note://inbox"))
        self.assertEqual(len(out.contents[0].text), 1 << 20)
        self.assertEqual([r["value"] for r in signer.observed],
                         [event_hash(out.model_dump(mode="json", by_alias=True, exclude_none=True))])


class _ListingSession(_StubSession):
    """List methods return one page, the one `params.cursor` names (the first when the caller asks for none)."""

    def __init__(self):
        super().__init__()
        self.cursors, self.results = [], []

    def _page(self, kw):
        cursor = getattr(kw.get("params"), "cursor", None)
        self.cursors.append(cursor)
        self.calls += 1
        return cursor

    async def list_tools(self, *a, **kw):
        from mcp.types import ListToolsResult, Tool
        if self._page(kw) == "boom":
            raise MCPError(-32603, "boom")
        out = ListToolsResult(tools=[Tool(name="echo", description="do this", inputSchema={"type": "object"})])
        self.results.append(out)
        return out

    async def list_resources(self, *a, **kw):
        from mcp.types import ListResourcesResult, Resource
        cursor = self._page(kw) or "page-1"
        out = ListResourcesResult(resources=[Resource(name="box", uri=f"mem://{cursor}", description="inbox")])
        self.results.append(out)
        return out

    async def list_prompts(self, *a, **kw):
        from mcp.types import ListPromptsResult, Prompt
        self._page(kw)
        out = ListPromptsResult(prompts=[Prompt(name="triage", description="sort issues")])
        self.results.append(out)
        return out


@unittest.skipUnless(HAVE_MCP, "mcp not installed")
class ListsAreObserved(unittest.TestCase):
    RUN = SignerFailures.RUN

    def test_each_list_is_one_untrusted_observe_of_the_page_asked_for(self):
        from mcp.types import PaginatedRequestParams
        session, signer = _ListingSession(), _Signer()
        gate = TracekitSession(session, signer, self.RUN, server="git hub")
        tools = asyncio.run(gate.list_tools())
        resources = asyncio.run(gate.list_resources(params=PaginatedRequestParams(cursor="page-2")))
        prompts = asyncio.run(gate.list_prompts())
        self.assertIs(tools, session.results[0])
        self.assertIs(resources, session.results[1])
        self.assertIs(prompts, session.results[2])
        self.assertEqual(session.cursors, [None, "page-2", None])
        observed = [r for m, r in signer.requests if m == "observe"]
        self.assertEqual([(r["source"], r["trust"]) for r in observed],
                         [("mcp:git_hub/tools", "untrusted"), ("mcp:git_hub/resources", "untrusted"),
                          ("mcp:git_hub/prompts", "untrusted")])
        self.assertEqual([r["client_seq"] for r in observed], [0, 1, 2])
        self.assertEqual(observed[0]["value"], tools.model_dump(mode="json", by_alias=True, exclude_none=True))
        self.assertEqual(observed[1]["value"]["resources"][0]["uri"], "mem://page-2")
        self.assertEqual(observed[1]["value"], resources.model_dump(mode="json", by_alias=True, exclude_none=True))
        self.assertEqual(observed[2]["value"]["prompts"][0]["description"], "sort issues")

    def test_an_unrecorded_list_is_withheld_when_the_run_fails_closed(self):
        """The default fail mode is closed, and a signer refusal is withheld even when the run fails open."""
        from tracekit.sdk.client import SignerUnavailable
        from tracekit.signer.rpc_schema import RPCError
        session = _ListingSession()
        with self.assertRaises(SignerUnavailable):
            asyncio.run(TracekitSession(session, _Signer(observe=SignerUnavailable("down")), self.RUN).list_tools())
        self.assertEqual(session.results[0].tools[0].name, "echo")   # fetched from the server, not returned
        with self.assertRaises(RPCError):
            asyncio.run(TracekitSession(_ListingSession(), _Signer(observe=RPCError("unavailable", "down")),
                                        {**self.RUN, "fail_modes": {"mcp": "open"}}).list_prompts())

    def test_an_unrecorded_list_is_returned_when_the_run_fails_open(self):
        from tracekit.sdk.client import SignerUnavailable
        session = _ListingSession()
        with self.assertWarns(UserWarning) as cm:
            out = asyncio.run(TracekitSession(session, _Signer(observe=SignerUnavailable("down")),
                                              {**self.RUN, "fail_modes": {"mcp": "open"}}).list_resources())
        self.assertIs(out, session.results[0])
        self.assertEqual(out.resources[0].uri, "mem://page-1")
        self.assertIn("not recorded", str(cm.warning))

    def test_a_list_the_session_fails_to_return_is_not_observed(self):
        from mcp.types import PaginatedRequestParams
        signer = _Signer()
        with self.assertRaises(MCPError):
            asyncio.run(TracekitSession(_ListingSession(), signer, self.RUN).list_tools(
                params=PaginatedRequestParams(cursor="boom")))
        self.assertEqual(signer.requests, [])

    def test_an_unnamed_session_records_unknown_and_warns(self):
        session, signer = _ListingSession(), _Signer()
        session.server_info = None
        with self.assertWarns(UserWarning) as cm:
            asyncio.run(TracekitSession(session, signer, self.RUN).list_resources())
        self.assertEqual(signer.requests[0][1]["source"], "mcp:unknown/resources")
        self.assertIn("server=", str(cm.warning))

    def test_instrument_observes_a_sessions_lists(self):
        from tracekit import autowire
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        with mock.patch("mcp.ClientSession", _ListingSession), \
                mock.patch.object(_ListingSession, "call_tool", _ListingSession.call_tool), \
                mock.patch.object(_ListingSession, "get_prompt", _ListingSession.get_prompt), \
                mock.patch.object(_ListingSession, "read_resource", _ListingSession.read_resource), \
                mock.patch.object(_ListingSession, "list_tools", _ListingSession.list_tools), \
                mock.patch.object(_ListingSession, "list_resources", _ListingSession.list_resources), \
                mock.patch.object(_ListingSession, "list_prompts", _ListingSession.list_prompts):
            autowire._mcp(run)
            out = asyncio.run(_ListingSession().list_resources(params=None))
        self.assertEqual(out.resources[0].uri, "mem://page-1")
        [req] = [r for m, r in signer.requests if m == "observe"]
        self.assertEqual((req["source"], req["trust"]), ("mcp:stub/resources", "untrusted"))
        self.assertEqual(req["value"]["resources"][0]["description"], "inbox")


@unittest.skipUnless(HAVE_MCP and hasattr(mcp.types, "InputRequiredResult"), "mcp 2.3+ with InputRequiredResult required")
class InputRequiredRounds(unittest.TestCase):
    RUN = SignerFailures.RUN

    def setUp(self):
        from mcp.client.session import ClientSession
        self.orig_methods = {
            m: getattr(ClientSession, m)
            for m in ("call_tool", "get_prompt", "read_resource", "list_tools", "list_resources", "list_prompts")
            if hasattr(ClientSession, m)
        }
        self.addCleanup(self._restore)

    def _restore(self):
        from mcp.client.session import ClientSession
        for m, fn in self.orig_methods.items():
            setattr(ClientSession, m, fn)

    def _make_server(self):
        from mcp.server.lowlevel import Server
        import mcp.types as t

        seen_args = []

        async def on_list_tools(ctx, params):
            return t.ListToolsResult(tools=[
                t.Tool(name="ask_input", description="tool needing input", inputSchema={"type": "object"}),
                t.Tool(name="ask_input_no_state", description="tool needing input without state", inputSchema={"type": "object"}),
                t.Tool(name="fail_round", description="tool that fails in round 2", inputSchema={"type": "object"}),
            ])

        async def on_call_tool(ctx, params):
            seen_args.append(dict(params.arguments or {}))
            if params.name == "ask_input":
                if params.request_state is None:
                    return t.InputRequiredResult(
                        request_state="state-tool-1",
                        input_requests={"req-1": t.ElicitRequest(
                            params=t.ElicitRequestFormParams(
                                message="enter data",
                                requested_schema={"type": "object", "properties": {}},
                            )
                        )},
                    )
                return t.CallToolResult(content=[t.TextContent(type="text", text="tool ok")], is_error=False)
            if params.name == "ask_input_no_state":
                return t.InputRequiredResult(
                    request_state=None,
                    input_requests={"req-no-state": t.ElicitRequest(
                        params=t.ElicitRequestFormParams(
                            message="enter data",
                            requested_schema={"type": "object", "properties": {}},
                        )
                    )},
                )
            if params.name == "fail_round":
                if params.request_state is None:
                    return t.InputRequiredResult(
                        request_state="state-fail-1",
                        input_requests={"req-f": t.ElicitRequest(
                            params=t.ElicitRequestFormParams(
                                message="enter data",
                                requested_schema={"type": "object", "properties": {}},
                            )
                        )},
                    )
                raise RuntimeError("boom in round 2")
            raise MCPError(-32601, f"unknown tool: {params.name}")

        async def on_list_prompts(ctx, params):
            return t.ListPromptsResult(prompts=[
                t.Prompt(name="ask_prompt", description="prompt needing input"),
            ])

        async def on_get_prompt(ctx, params):
            if params.name == "ask_prompt":
                if params.request_state is None:
                    return t.InputRequiredResult(
                        request_state="state-prompt-1",
                        input_requests={"req-p": t.ElicitRequest(
                            params=t.ElicitRequestFormParams(
                                message="enter prompt data",
                                requested_schema={"type": "object", "properties": {}},
                            )
                        )},
                    )
                return t.GetPromptResult(
                    description="done prompt",
                    messages=[t.PromptMessage(role="user", content=t.TextContent(type="text", text="prompt ok"))],
                )
            raise MCPError(-32601, f"unknown prompt: {params.name}")

        srv = Server("contract_server", on_list_tools=on_list_tools, on_call_tool=on_call_tool,
                     on_list_prompts=on_list_prompts, on_get_prompt=on_get_prompt)
        return srv, seen_args

    def test_tool_call_input_required_round_decided_and_completed_once(self):
        from tracekit import autowire
        import mcp.types as t
        server, _ = self._make_server()
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def elicit(ctx, params):
            return t.ElicitResult(action="accept", content=None)

        async def run_call():
            async with MCPClient(server, elicitation_callback=elicit) as c:
                return await c.call_tool("ask_input", {"k": "v"})

        out = asyncio.run(run_call())
        self.assertEqual(out.content[0].text, "tool ok")
        self.assertFalse(out.is_error)

        decides = [r for m, r in signer.requests if m == "decide"]
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(decides), 1)
        self.assertEqual(len(completes), 1)
        self.assertEqual(completes[0]["status"], "ok")

        observed = [r for m, r in signer.requests if m == "observe" and r["source"].endswith("/input_required")]
        self.assertEqual(len(observed), 1)
        self.assertEqual((observed[0]["source"], observed[0]["trust"]),
                         ("mcp:contract_server/input_required", "untrusted"))
        self.assertIn("req-1", observed[0]["value"])

    def test_get_prompt_input_required_round_decided_and_completed_once(self):
        from tracekit import autowire
        import mcp.types as t
        server, _ = self._make_server()
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def elicit(ctx, params):
            return t.ElicitResult(action="accept", content=None)

        async def run_prompt():
            async with MCPClient(server, elicitation_callback=elicit) as c:
                return await c.get_prompt("ask_prompt", {"k": "v"})

        out = asyncio.run(run_prompt())
        self.assertEqual(out.messages[0].content.text, "prompt ok")

        decides = [r for m, r in signer.requests if m == "decide"]
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(decides), 1)
        self.assertEqual(len(completes), 1)
        self.assertEqual(completes[0]["status"], "ok")

        observed = [r for m, r in signer.requests if m == "observe"]
        self.assertEqual(len(observed), 1)
        self.assertEqual((observed[0]["source"], observed[0]["trust"]),
                         ("mcp:contract_server/input_required", "untrusted"))
        self.assertIn("req-p", observed[0]["value"])

    def test_resumed_round_sends_signer_agreed_arguments(self):
        from tracekit import autowire
        import mcp.types as t
        server, seen_args = self._make_server()

        class T2Signer(_Signer):
            def __getattr__(self, method):
                call = super().__getattr__(method)
                if method == "approval_consume":
                    return lambda req: {"ok": True, "rule_ids": [], "args": {"k": "t2-rewritten"}}
                return call

        signer = T2Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def elicit(ctx, params):
            return t.ElicitResult(action="accept", content=None)

        async def run_call():
            async with MCPClient(server, elicitation_callback=elicit) as c:
                return await c.call_tool("ask_input", {"k": "caller-original"})

        out = asyncio.run(run_call())
        self.assertEqual(out.content[0].text, "tool ok")
        self.assertEqual(seen_args, [{"k": "t2-rewritten"}, {"k": "t2-rewritten"}])
        self.assertEqual(len([r for m, r in signer.requests if m == "decide"]), 1)
        self.assertEqual(len([r for m, r in signer.requests if m == "complete"]), 1)

    def test_result_without_request_state_completes_call(self):
        from tracekit import autowire
        server, _ = self._make_server()
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def run_call():
            async with MCPClient(server) as c:
                return await c.session.call_tool("ask_input_no_state", {"k": "v"}, allow_input_required=True)

        out = asyncio.run(run_call())
        self.assertEqual(out.result_type, "input_required")
        decides = [r for m, r in signer.requests if m == "decide"]
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(decides), 1)
        self.assertEqual(len(completes), 1)
        self.assertEqual(completes[0]["status"], "ok")

    def test_round_whose_observe_fails_completes_kept_call_as_error(self):
        from tracekit import autowire
        from tracekit.sdk.client import SignerUnavailable
        server, _ = self._make_server()
        signer = _Signer(observe=SignerUnavailable("down"))
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def run_call():
            async with MCPClient(server) as c:
                return await c.session.call_tool("ask_input", {"k": "v"}, allow_input_required=True)

        def find_exc(e, cls):
            if isinstance(e, cls):
                return True
            if hasattr(e, "exceptions"):
                return any(find_exc(sub, cls) for sub in e.exceptions)
            return False

        with self.assertRaises(Exception) as cm:
            asyncio.run(run_call())
        self.assertTrue(find_exc(cm.exception, SignerUnavailable))

        decides = [r for m, r in signer.requests if m == "decide"]
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(decides), 1)
        self.assertEqual(len(completes), 1)
        self.assertEqual(completes[0]["status"], "error")
        self.assertIn("SignerUnavailable: down", completes[0]["error"])

    def test_made_up_request_state_is_decided_anew(self):
        from tracekit import autowire
        server, _ = self._make_server()
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def run_calls():
            async with MCPClient(server) as c:
                # 1. Get real state from ask_input
                out1 = await c.session.call_tool("ask_input", {"k": "v"}, allow_input_required=True)
                real_state = out1.request_state
                # 2. Send different state with same arguments -> decides anew
                await c.session.call_tool("ask_input", {"k": "v"}, request_state="different-state",
                                          allow_input_required=True)
                # 3. Send real state with different arguments -> decides anew
                await c.session.call_tool("ask_input", {"k": "other"}, request_state=real_state,
                                          allow_input_required=True)

        asyncio.run(run_calls())
        decides = [r for m, r in signer.requests if m == "decide"]
        self.assertEqual(len(decides), 3)

    def test_round_that_raises_completes_kept_call_as_error(self):
        from tracekit import autowire
        import mcp.types as t
        server, _ = self._make_server()
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def elicit(ctx, params):
            return t.ElicitResult(action="accept", content=None)

        async def run_failing():
            async with MCPClient(server, elicitation_callback=elicit) as c:
                await c.call_tool("fail_round", {"k": "v"})

        with self.assertRaises(Exception):
            asyncio.run(run_failing())

        decides = [r for m, r in signer.requests if m == "decide"]
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(decides), 1)
        self.assertEqual(len(completes), 1)
        self.assertEqual(completes[0]["status"], "error")
        self.assertIn("MCPError", completes[0]["error"])

    def test_resumed_round_refused_by_signer_completes_as_error(self):
        from tracekit import autowire
        import mcp.types as t
        server, seen_args = self._make_server()

        consume_calls = 0

        class QuarantinedSigner(_Signer):
            def __getattr__(self, method):
                call = super().__getattr__(method)
                if method == "approval_consume":
                    def consume(req):
                        nonlocal consume_calls
                        consume_calls += 1
                        if consume_calls > 1:
                            return {"ok": False, "rule_ids": ["TK-QUARANTINE"], "reason": "run quarantined"}
                        return {"ok": True, "rule_ids": []}
                    return consume
                return call

        signer = QuarantinedSigner()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def elicit(ctx, params):
            return t.ElicitResult(action="accept", content=None)

        async def run_call():
            async with MCPClient(server, elicitation_callback=elicit) as c:
                return await c.call_tool("ask_input", {"k": "v"})

        out = asyncio.run(run_call())
        self.assertEqual(len(seen_args), 1)
        decides = [r for m, r in signer.requests if m == "decide"]
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(decides), 1)
        self.assertEqual(len(completes), 1)
        self.assertEqual(completes[0]["status"], "error")
        self.assertIn("TK-QUARANTINE", completes[0]["error"])
        self.assertTrue(out.is_error)
        self.assertIn("TK-QUARANTINE", out.content[0].text)

    def test_request_state_is_used_once(self):
        from tracekit import autowire
        server, _ = self._make_server()
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def run_calls():
            async with MCPClient(server) as c:
                out1 = await c.session.call_tool("ask_input", {"k": "v"}, allow_input_required=True)
                real_state = out1.request_state
                await c.session.call_tool("ask_input", {"k": "v"}, request_state=real_state,
                                          allow_input_required=True)
                d1 = len([r for m, r in signer.requests if m == "decide"])
                await c.session.call_tool("ask_input", {"k": "v"}, request_state=real_state,
                                          allow_input_required=True)
                d2 = len([r for m, r in signer.requests if m == "decide"])
                return d1, d2

        d1, d2 = asyncio.run(run_calls())
        self.assertEqual(d1, 1)
        self.assertEqual(d2, 2)

    def test_server_that_reuses_request_state_decides_both_calls(self):
        """The first call, left after its first round, is never completed; the second completes."""
        from mcp.server.lowlevel import Server
        import mcp.types as t
        from tracekit import autowire

        async def on_list_tools(ctx, params):
            return t.ListToolsResult(tools=[
                t.Tool(name="constant_state_tool", description="returns fixed state", inputSchema={"type": "object"}),
            ])

        async def on_call_tool(ctx, params):
            if params.request_state is None:
                return t.InputRequiredResult(
                    request_state="fixed-state-123",
                    input_requests={"req": t.ElicitRequest(
                        params=t.ElicitRequestFormParams(
                            message="input",
                            requested_schema={"type": "object", "properties": {}},
                        )
                    )},
                )
            return t.CallToolResult(content=[t.TextContent(type="text", text="done")], is_error=False)

        server = Server("constant_state_server", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def run_test():
            async with MCPClient(server) as c:
                out1 = await c.session.call_tool("constant_state_tool", {"k": "v"}, allow_input_required=True)
                out2 = await c.session.call_tool("constant_state_tool", {"k": "v"}, allow_input_required=True)
                out3 = await c.session.call_tool("constant_state_tool", {"k": "v"}, request_state="fixed-state-123",
                                                  allow_input_required=True)
                return out1, out2, out3

        asyncio.run(run_test())
        decides = [r for m, r in signer.requests if m == "decide"]
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(decides), 2)
        self.assertEqual([(r["tool_call_id"], r["status"]) for r in completes], [(decides[1]["tool_call_id"], "ok")])

    def test_round_whose_observe_fails_warns_when_fail_open(self):
        from tracekit import autowire
        from tracekit.sdk.client import SignerUnavailable
        server, _ = self._make_server()
        signer = _Signer(observe=SignerUnavailable("down"))
        run = mock.Mock(client=signer, registered={**self.RUN, "fail_modes": {"mcp": "open"}})
        autowire._mcp(run)

        async def run_call():
            async with MCPClient(server) as c:
                return await c.session.call_tool("ask_input", {"k": "v"}, allow_input_required=True)

        with self.assertWarns(UserWarning) as cm:
            out = asyncio.run(run_call())

        self.assertEqual(out.result_type, "input_required")
        self.assertIn("MCP input_required not recorded: down", str(cm.warning))
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(len(completes), 0)

    def test_round_without_input_requests_skips_observe(self):
        from mcp.server.lowlevel import Server
        import mcp.types as t
        from tracekit import autowire

        async def on_list_tools(ctx, params):
            return t.ListToolsResult(tools=[
                t.Tool(name="state_only", description="state only", inputSchema={"type": "object"}),
            ])

        async def on_call_tool(ctx, params):
            if params.request_state is None:
                return t.InputRequiredResult(request_state="s1", input_requests=None)
            return t.CallToolResult(content=[t.TextContent(type="text", text="done")], is_error=False)

        server = Server("state_only_server", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
        signer = _Signer()
        run = mock.Mock(client=signer, registered=self.RUN)
        autowire._mcp(run)

        async def run_call():
            async with MCPClient(server) as c:
                return await c.session.call_tool("state_only", {"k": "v"}, allow_input_required=True)

        out = asyncio.run(run_call())
        self.assertEqual(out.result_type, "input_required")
        observed = [r for m, r in signer.requests if m == "observe"]
        self.assertEqual(len(observed), 0)

    def _state_reusing_server(self):
        """A server that answers every first round with the same request_state (a stateless server, or one whose state
        only encodes progress), and finishes on the next."""
        from mcp.server.lowlevel import Server
        import mcp.types as t

        async def on_list_tools(ctx, params):
            return t.ListToolsResult(tools=[t.Tool(name="ask", inputSchema={"type": "object"})])

        async def on_call_tool(ctx, params):
            if params.request_state is None:
                return t.InputRequiredResult(request_state="S", input_requests={"q": t.ElicitRequest(
                    params=t.ElicitRequestFormParams(message="who?",
                                                 requested_schema={"type": "object", "properties": {}}))})
            await asyncio.sleep(0.05)   # the other call's rounds run meanwhile
            return t.CallToolResult(content=[t.TextContent(type="text", text="done")])
        return Server("srv", on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    def _wired(self):
        """instrument()'s MCP wiring on a signer whose decisions have ids of their own and send results whole."""
        from tracekit import autowire
        ids = iter(range(1, 100))

        class Signer(_Signer):
            def __getattr__(self, method):
                call = super().__getattr__(method)
                if method == "decide":
                    return lambda req: dict(call(req), decision_id=f"dec-{next(ids)}", send_result=True)
                return call
        signer = Signer()
        autowire._mcp(mock.Mock(client=signer, registered=self.RUN))
        return signer

    @staticmethod
    async def _elicit(ctx, params):
        import mcp.types as t
        return t.ElicitResult(action="accept", content={})

    def test_concurrent_calls_on_a_server_that_reuses_request_state_never_share_a_decision(self):
        """#718: B's first round, kept under the same (tool, arguments, state) as A's, completed B "ok" at round 1, and
        B's second round was decided a third time."""
        server, signer = self._state_reusing_server(), self._wired()

        async def both():
            async with MCPClient(server, elicitation_callback=self._elicit) as c:
                return await asyncio.gather(c.call_tool("ask", {"k": "v"}), c.call_tool("ask", {"k": "v"}))
        self.assertEqual([o.content[0].text for o in asyncio.run(both())], ["done", "done"])
        decided = {r["tool_call_id"]: r for m, r in signer.requests if m == "decide"}
        self.assertEqual(len(decided), 2)
        completes = [r for m, r in signer.requests if m == "complete"]
        self.assertEqual(sorted(r["tool_call_id"] for r in completes), sorted(decided))
        for r in completes:
            self.assertEqual((r["status"], r["result"]["content"][0]["text"]), ("ok", "done"))
            self.assertEqual(r["decision_id"], f"dec-{list(decided).index(r['tool_call_id']) + 1}")

    def test_a_call_left_between_rounds_is_never_completed(self):
        """#718: call A is left after its first round, by its caller or by mcp.Client when the elicitation callback
        raises; call B, same tool, arguments and state, ran its last round under A's id and decision. Then A was
        completed "ok" with its input request when B began, though its caller got an exception. A stays decided and
        is never completed (the signer's decided_not_completed gap at run close); B completes under its own decision."""
        import mcp.types as t
        for elicitation_fails in (False, True):
            with self.subTest(elicitation_fails=elicitation_fails):
                self._restore()   # _wired() wraps ClientSession's methods again
                server, signer = self._state_reusing_server(), self._wired()
                fails = [RuntimeError("the person closed the dialog")] if elicitation_fails else []

                async def elicit(ctx, params):
                    if fails:
                        raise fails.pop()
                    return t.ElicitResult(action="accept", content={})

                async def left_then_new():
                    async with MCPClient(server, elicitation_callback=elicit) as c:
                        if elicitation_fails:
                            with self.assertRaises(Exception):   # an ExceptionGroup holding the callback's error
                                await c.call_tool("ask", {"k": "v"})                                   # A
                        else:
                            await c.session.call_tool("ask", {"k": "v"}, allow_input_required=True)   # A: round 1
                        return await c.call_tool("ask", {"k": "v"})                                     # B, to its end
                self.assertEqual(asyncio.run(left_then_new()).content[0].text, "done")
                _, b = [r["tool_call_id"] for m, r in signer.requests if m == "decide"]
                self.assertEqual([(r["tool_call_id"], r["decision_id"], r["status"], r["result"]["content"][0]["text"])
                                  for m, r in signer.requests if m == "complete"], [(b, "dec-2", "ok", "done")])


@unittest.skipUnless(HAVE_MCP and hasattr(mcp.types, "InputRequiredResult"), "mcp 2.3+ with InputRequiredResult required")
class BigLists(unittest.TestCase):
    """#685: a tools/list over the signer's 1 MiB frame (300 tools with 40-field schemas, about 1.4 MB of JSON), on the
    real signer, under instrument(). It was sent whole in `observe`, so the signer refused it (quota_exceeded) whatever
    the fail mode, and a call_tool failed after the tool ran: mcp lists the tools again to check its result."""

    def setUp(self):
        from mcp.client.session import ClientSession
        from tracekit import autowire
        from tracekit.policy2.engine import Engine
        from tracekit.signer.service import SignerService
        for name in ("call_tool", "get_prompt", "read_resource", "list_tools", "list_resources",
                     "list_prompts"):   # autowire patches them
            patcher = mock.patch.object(ClientSession, name, getattr(ClientSession, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.service = SignerService(ac.tmpdir(self), policy=Engine({}))
        self.addCleanup(self.service.close)
        client = Client(ac._serve(self, self.service.handle_frame))
        self.addCleanup(client.close)
        self.run = client.register_run({"agent": {"name": "big"}})
        autowire._mcp(mock.Mock(client=client, registered=self.run))

    @staticmethod
    def server():
        from mcp.server.lowlevel import Server
        import mcp.types as t
        props = {f"field_{i}": {"type": "string", "description": "a field " * 8} for i in range(40)}

        async def on_list_tools(ctx, params):
            return t.ListToolsResult(tools=[t.Tool(name=f"tool_{i}", description="does a thing " * 10,
                                                   inputSchema={"type": "object", "properties": props})
                                            for i in range(300)])

        async def on_call_tool(ctx, params):
            return t.CallToolResult(content=[t.TextContent(type="text", text="ran " + params.name)])
        return Server("big", on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    def events(self, typ):
        return [r["event"]["data"] for r in self.service.log.storage.iter_run("default", self.run["run_id"])
                if r["event"]["type"] == typ]

    def test_a_list_over_half_a_frame_is_recorded_as_its_digest(self):
        async def listed():
            async with MCPClient(self.server()) as c:
                return await c.list_tools()
        out = asyncio.run(listed())
        self.assertEqual(len(out.tools), 300)
        self.assertGreater(len(out.model_dump_json()), 1 << 20)
        [seen] = self.events("input.observed")
        self.assertEqual((seen["source"], seen["trust"]), ("mcp:big/tools", "untrusted"))
        self.assertLess(seen["output"]["size"], 100)   # the digest, not the page

    def test_the_list_mcp_makes_inside_call_tool_is_not_recorded(self):
        async def called():
            async with MCPClient(self.server()) as c:   # no list first: mcp lists to check the result
                return await c.call_tool("tool_7", {})
        out = asyncio.run(called())
        self.assertEqual((out.is_error, out.content[0].text), (False, "ran tool_7"))
        self.assertEqual(self.events("input.observed"), [])
        self.assertEqual([r["ok"] for r in self.events("tool.result")], [True])

    def test_input_requests_over_half_a_frame_are_recorded_as_their_digest(self):
        """A round's input requests are recorded as a list is: sent whole, the signer refused requests over its frame
        (quota_exceeded) and the call failed."""
        from mcp.server.lowlevel import Server
        import mcp.types as t

        async def on_list_tools(ctx, params):
            return t.ListToolsResult(tools=[t.Tool(name="ask", inputSchema={"type": "object"})])

        async def on_call_tool(ctx, params):
            return t.InputRequiredResult(request_state="S", input_requests={"q": t.ElicitRequest(
                params=t.ElicitRequestFormParams(message="who? " * 300_000,   # 1.5 MB
                                                 requested_schema={"type": "object", "properties": {}}))})

        async def asked():
            async with MCPClient(Server("big", on_list_tools=on_list_tools, on_call_tool=on_call_tool)) as c:
                return await c.session.call_tool("ask", {}, allow_input_required=True)
        self.assertEqual(asyncio.run(asked()).result_type, "input_required")
        [seen] = self.events("input.observed")
        self.assertEqual((seen["source"], seen["trust"]), ("mcp:big/input_required", "untrusted"))
        self.assertLess(seen["output"]["size"], 100)   # the digest, not the requests
