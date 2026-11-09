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


class _StubSession(_Mcp1Session):
    server_info = type("Info", (), {"name": "stub"})()


class _Signer:
    """A signer that fails the way it is told: `decide` and `complete` raise `errors[method]` when set."""

    def __init__(self, decision="allow", **errors):
        self.decision, self.errors, self.tools, self.completed, self.requests = decision, errors, [], [], []

    def __getattr__(self, method):
        def call(req):
            self.requests.append((method, req))
            self.tools += [req["tool"]] if method == "decide" else []
            self.completed += [req] if method == "complete" else []
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
                mock.patch.object(_StubSession, "get_prompt", _StubSession.get_prompt):
            autowire._mcp(run)
            out = asyncio.run(_StubSession().get_prompt("triage", {"issue": "1"}))
        self.assertEqual((out.messages[0].content.text, signer.tools), ("hi", ["mcp:stub/prompt:triage"]))


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

    def test_a_failed_observe_warns_and_returns_the_list(self):
        from mcp.types import PaginatedRequestParams

        from tracekit.signer.rpc_schema import RPCError
        session, signer = _ListingSession(), _Signer(observe=RPCError("unavailable", "down"))
        with self.assertWarns(UserWarning) as cm:
            out = asyncio.run(TracekitSession(session, signer, self.RUN).list_tools())
        self.assertIs(out, session.results[0])
        self.assertIn("not recorded", str(cm.warning))
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
                mock.patch.object(_ListingSession, "list_tools", _ListingSession.list_tools), \
                mock.patch.object(_ListingSession, "list_resources", _ListingSession.list_resources), \
                mock.patch.object(_ListingSession, "list_prompts", _ListingSession.list_prompts):
            autowire._mcp(run)
            out = asyncio.run(_ListingSession().list_resources(params=None))
        self.assertEqual(out.resources[0].uri, "mem://page-1")
        [req] = [r for m, r in signer.requests if m == "observe"]
        self.assertEqual((req["source"], req["trust"]), ("mcp:stub/resources", "untrusted"))
        self.assertEqual(req["value"]["resources"][0]["description"], "inbox")
