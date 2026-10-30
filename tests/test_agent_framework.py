"""Microsoft Agent Framework's function middleware (tracekit.integrations.agent_framework) on a real Agent with a
scripted chat client and a mock run: only an allow or an approved ask runs the function, the model reads the reason
for anything else and the run goes on, and nothing Tracekit fails at raises into the agent."""
import asyncio
import importlib.metadata
import importlib.util
import threading
import time
import unittest
import warnings
from unittest import mock

import adapter_contract as ac
import test_said as ts

HAVE = importlib.util.find_spec("agent_framework") is not None
if HAVE:
    from agent_framework import (Agent, AgentSession, BaseChatClient, ChatMiddlewareLayer, ChatResponse,
                                 ChatResponseUpdate, Content, FunctionInvocationLayer, FunctionMiddleware, Message,
                                 MiddlewareTermination, ResponseStream, WorkflowBuilder, tool)
    from pydantic import BaseModel

    from tracekit import autowire
    from tracekit.integrations.agent_framework import Tracekit
    from tracekit.integrations.gate import WAIT_MS

    class Scripted(FunctionInvocationLayer, BaseChatClient):
        """A chat client whose model is `script(messages)`, the contents of its next response: no network, no key."""

        def __init__(self, script, **kw):
            super().__init__(**kw)
            self.script = script

        def _inner_get_response(self, *, messages, stream, options, **kwargs):
            contents = self.script(messages)
            if stream:
                async def updates():
                    yield ChatResponseUpdate(role="assistant", contents=contents)
                return ResponseStream(updates(), finalizer=ChatResponse.from_updates)

            async def response():
                return ChatResponse(messages=[Message(role="assistant", contents=contents)])
            return response()

    class Layered(FunctionInvocationLayer, ChatMiddlewareLayer, BaseChatClient):
        """Scripted, with the chat middleware layer inside the function loop, as a real client has it
        (OpenAIChatCompletionClient: FunctionInvocationLayer, ChatMiddlewareLayer, ChatTelemetryLayer, the raw
        client)."""

        def __init__(self, script, **kw):
            super().__init__(**kw)
            self.script = script

        _inner_get_response = Scripted._inner_get_response

from tracekit.format.canon import event_hash
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import AsyncRunHandle, Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService

FIRST = {"args_source": "coerced", "attempt": 0}   # how a call's first decide and consume are sent
MCP1 = importlib.util.find_spec("mcp") is not None and importlib.metadata.version("mcp").startswith("1.")


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return ts.vault(r, on=False)


def model(*calls):
    """A model that sends each (call id, function, arguments) in its own turn, then answers with the last result it
    read."""
    def script(messages):
        back = [c for m in messages for c in m.contents if c.type == "function_result"]
        if len(back) < len(calls):
            call_id, name, args = calls[len(back)]
            return [Content.from_function_call(call_id, name, arguments=args)]
        return [Content.from_text(back[-1].result)]
    return script


def agent(r, fn, args=None, **kw):
    """An agent whose model calls `close_account` once as call-1 (with `args`, default {"account": "ACC-9"})."""
    return Agent(client=Scripted(model(("call-1", "close_account", {"account": "ACC-9"} if args is None else args))),
                 tools=[fn], middleware=[Tracekit(r)], **kw)


def go(a, *args, **kw):
    return asyncio.run(a.run(*args or ("close it",), **kw))


@unittest.skipUnless(HAVE, "agent_framework not installed")
class Hook(unittest.TestCase):
    def setUp(self):
        self.ran = []

    def tool(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        return close_account

    def test_only_an_allow_or_an_approved_ask_runs(self):
        for name, r, runs in (("allow", run(), True), ("deny", run("deny", ["D1"]), False),
                              ("ask approved", run("ask", ["A1"]), True),
                              ("ask rejected", run("ask", ["A1"], state="rejected"), False),
                              ("consume refused", run(consume=False), False)):
            with self.subTest(name):
                self.ran.clear()
                out = go(agent(r, self.tool())).text
                self.assertEqual(self.ran, ["ACC-9"] if runs else [])
                if runs:
                    self.assertEqual(out, "closed ACC-9")
                    r.complete.assert_called_once_with("call-1", "ok", attempt=0, result=mock.ANY)
                else:
                    self.assertIn("Tracekit policy", out)
                    if name == "consume refused":   # allowed, then refused: completed as not run
                        r.complete.assert_called_once_with("call-1", "error", attempt=0, error=mock.ANY)
                    else:
                        r.complete.assert_not_called()

    def test_the_signer_decides_the_models_call_id_and_arguments(self):
        r = run()
        go(agent(r, self.tool(), '{"account": "ACC-9"}'))
        r.decide.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"}, **FIRST)
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint=None, **FIRST)

    def test_no_arguments_or_an_empty_string_are_no_arguments(self):
        def close_account(account: str = "ACC-0") -> str:
            """Close an account."""
            return f"closed {account}"
        for args in ("", None):
            with self.subTest(args=args):
                r = run()
                a = Agent(client=Scripted(model(("call-1", "close_account", args))), tools=[close_account],
                          middleware=[Tracekit(r)])
                self.assertEqual(go(a).text, "closed ACC-0")
                self.assertEqual(r.decide.call_args.args, ("call-1", "close_account", {}))

    def test_an_approved_ask_waits_for_a_person_and_consumes_its_approval(self):
        r = run("ask", ["A1"])
        go(agent(r, self.tool()))
        r.call.assert_any_call("approval_wait", approval_id="apr-1", timeout_ms=WAIT_MS)
        self.assertEqual(WAIT_MS, 300000)
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint="apr-1", **FIRST)

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIn("not approved: requested", go(agent(r, self.tool())).text)
        self.assertEqual(r.call.call_args_list[-1], mock.call("approval_abandon", approval_id="apr-1",
                                                              reason="no answer within the middleware's wait"))
        self.assertEqual(self.ran, [])

    def test_the_refusal_names_the_rules_but_not_the_unknown_tool_flag(self):
        out = go(agent(run("deny", ["TK-D001", "TK-UNKNOWN-TOOL"]), self.tool())).text
        self.assertEqual(out, "Tool call blocked by Tracekit policy: TK-D001")

    def test_nothing_tracekit_fails_at_raises_into_the_agent(self):
        for exc in (RPCError("run_closed", "r"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                self.assertIn("Tracekit could not decide it", go(agent(r, self.tool())).text)
                self.assertEqual(self.ran, [])
        r = run()
        r.approval_consume.return_value = {}   # a bad answer
        self.assertIn("Tracekit could not decide it", go(agent(r, self.tool())).text)
        self.assertEqual(self.ran, [])
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(go(agent(r, self.tool())).text, "closed ACC-9")

    def test_an_outage_follows_the_runs_fail_mode(self):
        out = go(agent(run("deny", unavailable=True, reason="signer unavailable: down"), self.tool())).text
        self.assertEqual(out, "Tool call refused by Tracekit: signer unavailable: down")
        self.assertEqual(self.ran, [])
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(go(agent(r, self.tool())).text, "closed ACC-9")
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_a_function_error_is_recorded_and_reaches_the_framework(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            if len(self.ran) == 1:
                raise ValueError("account is locked")
            return f"closed {account}"
        r = run()
        a = Agent(client=Scripted(model(("call-1", "close_account", {"account": "ACC-9"}),
                                        ("call-2", "close_account", {"account": "ACC-9"}))),
                  tools=[close_account], middleware=[Tracekit(r)])
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            res = go(a)
        first = next(c for m in res.messages for c in m.contents if c.type == "function_result")
        self.assertEqual(first.result, "Error: Function failed.")   # Agent Framework's own error result
        self.assertEqual(res.text, "closed ACC-9")
        self.assertEqual([c.args[:2] for c in r.complete.call_args_list], [("call-1", "error"), ("call-2", "ok")])
        self.assertEqual(r.complete.call_args_list[0].kwargs["error"], "ValueError: account is locked")

    def test_a_call_sent_again_under_the_same_id_is_its_next_attempt(self):
        r = run()
        a = Agent(client=Scripted(model(("call-1", "close_account", {"account": "ACC-9"}),
                                        ("call-1", "close_account", {"account": "ACC-9"}))),
                  tools=[self.tool()], middleware=[Tracekit(r)])
        go(a)
        self.assertEqual(self.ran, ["ACC-9", "ACC-9"])
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        self.assertEqual([c.kwargs["attempt"] for c in r.complete.call_args_list], [0, 1])

    def test_a_result_goes_to_the_signer_as_the_json_the_model_reads(self):
        class Page(BaseModel):
            title: str
            pay_to: str

        def close_account(account: str) -> Page:
            """Close an account."""
            return Page(title="Invoice 7", pay_to="mallory-acct-7731")
        r = run(send_result=True)
        go(agent(r, close_account))
        self.assertEqual(r.complete.call_args.kwargs["result"], {"title": "Invoice 7", "pay_to": "mallory-acct-7731"})
        r = run(send_result=True)
        go(agent(r, self.tool()))
        self.assertEqual(r.complete.call_args.kwargs["result"], "closed ACC-9")

        def close_account(account: str) -> str:
            """Close an account."""
            return '{"a": 1, "a": 2}'   # not JSON to the gateway's strict parse: recorded as the text, not {"a": 2}
        r = run(send_result=True)
        go(agent(r, close_account))
        self.assertEqual(r.complete.call_args.kwargs["result"], '{"a": 1, "a": 2}')

    def test_arguments_a_later_middleware_changes_are_recorded_as_changed(self):
        class Rewrite(FunctionMiddleware):
            async def process(self, context, call_next):
                context.arguments = {"account": "ACC-1"}
                await call_next()
        for order in ("after", "before"):
            with self.subTest(f"rewritten {order} Tracekit"):
                self.ran.clear()
                r = run()
                mw = [Tracekit(r), Rewrite()] if order == "after" else [Rewrite(), Tracekit(r)]
                go(Agent(client=Scripted(model(("call-1", "close_account", {"account": "ACC-9"}))),
                         tools=[self.tool()], middleware=mw))
                self.assertEqual(self.ran, ["ACC-1"])
                if order == "after":   # it ran with arguments the signer never decided
                    self.assertEqual(r.complete.call_args.args[1], "error")
                    self.assertIn("changed after the decision", r.complete.call_args.kwargs["error"])
                else:   # decided as they run
                    self.assertEqual(r.decide.call_args.args[2], {"account": "ACC-1"})
                    self.assertEqual(r.complete.call_args.args[1], "ok")

    def test_approved_arguments_other_than_the_calls_dont_run(self):
        r = run()
        r.approval_consume.return_value = {"ok": True, "rule_ids": [], "args": {"account": "ACC-1"}}
        self.assertIn("arguments the signer approved", go(agent(r, self.tool())).text)
        self.assertEqual(self.ran, [])

    def test_a_later_middleware_ending_the_loop_completes_the_call_with_its_result(self):
        class Handoff(FunctionMiddleware):   # as agent_framework_orchestrations' handoff middleware does
            async def process(self, context, call_next):
                context.result = [Content.from_text('{"handoff_to": "billing"}')]
                raise MiddlewareTermination(result=context.result)
        r = run()
        go(Agent(client=Scripted(model(("call-1", "close_account", {"account": "ACC-9"}))), tools=[self.tool()],
                 middleware=[Tracekit(r), Handoff()]))
        self.assertEqual(self.ran, [])
        r.complete.assert_called_once_with("call-1", "ok", attempt=0, result=mock.ANY)

    def test_a_call_a_later_middleware_ends_or_holds_unrun_or_rewrites_is_an_error(self):
        class Block(FunctionMiddleware):   # ends the loop with no result
            async def process(self, context, call_next):
                raise MiddlewareTermination("Validation failed")

        class Hold(FunctionMiddleware):   # Agent Framework's own approval request instead of the call
            async def process(self, context, call_next):
                call = Content.from_function_call(context.metadata["call_id"], "close_account", arguments={})
                context.result = Content.from_function_approval_request(id="req-1", function_call=call)

        class RewriteAndEnd(FunctionMiddleware):
            async def process(self, context, call_next):
                context.arguments = {"account": "ACC-1"}
                await call_next()
                raise MiddlewareTermination(result=context.result)
        for later, why in ((Block, "ended the loop"), (Hold, "not run"), (RewriteAndEnd, "changed after the decision")):
            with self.subTest(later.__name__):
                self.ran.clear()
                r = run()
                go(Agent(client=Scripted(model(("call-1", "close_account", {"account": "ACC-9"}))),
                         tools=[self.tool()], middleware=[Tracekit(r), later()]))
                self.assertEqual(self.ran, ["ACC-1"] if later is RewriteAndEnd else [])
                self.assertEqual(r.complete.call_args.args, ("call-1", "error"))
                self.assertIn(why, r.complete.call_args.kwargs["error"])

    def test_the_call_runs_marked_as_decided_for_a_wired_mcp_session(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(autowire.DECIDED_UPSTREAM.get())
            return "closed"
        go(agent(run(), close_account))
        self.assertEqual(self.ran, [True])
        self.assertFalse(autowire.DECIDED_UPSTREAM.get())

    def test_a_run_cancelled_during_an_ask_withdraws_the_approval(self):
        waiting, answered = threading.Event(), threading.Event()
        r = run("ask", ["A1"])

        def call(method, **f):
            if method == "approval_wait":
                waiting.set()
                answered.wait(5)
                return {"state": "approved"}
            return {"approval_request": {"approval_id": "apr-1"}, "approval_abandon": {}, "model_event": {}}[method]
        r.call.side_effect = call

        async def cancel():
            task = asyncio.ensure_future(agent(r, self.tool()).run("close it"))
            self.assertTrue(await asyncio.to_thread(waiting.wait, 5))   # in the ask, however slow the runner
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            answered.set()   # a person approves after the agent run was cancelled
        asyncio.run(cancel())   # returns once the approval_wait thread has (asyncio.run waits for its executor)
        self.assertIn("approval_abandon", [c.args[0] for c in r.call.call_args_list])
        r.approval_consume.assert_not_called()
        self.assertEqual(self.ran, [])


@unittest.skipUnless(HAVE, "agent_framework not installed")
class Paths(unittest.TestCase):
    """Every way Agent Framework runs a function the model chose goes through the middleware."""

    def setUp(self):
        self.ran = []

    def tool(self, name="close_account"):
        def fn(account: str) -> str:
            """Close an account."""
            self.ran.append((name, account))
            return f"closed {account}"
        fn.__name__ = name
        return fn

    def test_an_async_function(self):
        async def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        for r, runs in ((run(), True), (run("deny", ["D1"]), False)):
            self.ran.clear()
            go(agent(r, close_account))
            self.assertEqual(self.ran, ["ACC-9"] if runs else [])

    def test_a_streamed_run(self):
        async def stream(a):
            s = a.run("close it", stream=True)
            async for _ in s:
                pass
            return await s.get_final_response()
        for r, runs in ((run(), True), (run("deny", ["D1"]), False)):
            self.ran.clear()
            out = asyncio.run(stream(agent(r, self.tool()))).text
            self.assertEqual((bool(self.ran), "Tracekit policy" in out), (runs, not runs))

    def test_middleware_given_to_one_run_or_to_the_chat_client(self):
        for where in ("run", "client"):
            with self.subTest(where):
                self.ran.clear()
                r = run("deny", ["D1"])
                client = Scripted(model(("call-1", "close_account", {"account": "ACC-9"})),
                                  **({"middleware": [Tracekit(r)]} if where == "client" else {}))
                a = Agent(client=client, tools=[self.tool()])
                out = go(a, **({"middleware": [Tracekit(r)]} if where == "run" else {})).text
                self.assertEqual((self.ran, out), ([], "Tool call blocked by Tracekit policy: D1"))

    def test_an_agent_as_a_tool_is_decided_and_its_own_calls_need_its_own_middleware(self):
        for inner in (False, True):
            with self.subTest(sub_agent_has_tracekit=inner):
                self.ran.clear()
                parent_run, sub_run = run(), run("deny", ["D1"])
                sub = Agent(client=Scripted(model(("sub-1", "close_account", {"account": "ACC-9"}))), name="helper",
                            tools=[self.tool()], middleware=[Tracekit(sub_run)] if inner else None)
                parent = Agent(client=Scripted(model(("p-1", "helper", {"task": "close ACC-9"}))),
                               tools=[sub.as_tool()], middleware=[Tracekit(parent_run)])
                go(parent)
                parent_run.decide.assert_called_once_with("p-1", "helper", {"task": "close ACC-9"}, **FIRST)
                self.assertEqual(self.ran, [] if inner else [("close_account", "ACC-9")])
        sub_run = mock.Mock()
        sub = Agent(client=Scripted(model(("sub-1", "close_account", {"account": "ACC-9"}))), name="helper",
                    tools=[self.tool()], middleware=[Tracekit(sub_run)])
        parent = Agent(client=Scripted(model(("p-1", "helper", {"task": "close ACC-9"}))), tools=[sub.as_tool()],
                       middleware=[Tracekit(run("deny", ["D1"]))])
        self.assertEqual(go(parent).text, "Tool call blocked by Tracekit policy: D1")
        sub_run.decide.assert_not_called()   # a refused delegate never starts

    def test_its_own_approval_comes_first_then_tracekit_decides_the_approved_call(self):
        for approved in (True, False):
            with self.subTest(approved=approved):
                self.ran.clear()
                r, session = run(), AgentSession()
                a = agent(r, tool(self.tool(), approval_mode="always_require"))
                paused = go(a, session=session)
                r.decide.assert_not_called()   # Agent Framework holds it for its own approver first
                answer = paused.user_input_requests[0].to_function_approval_response(approved=approved)
                go(a, Message(role="user", contents=[answer]), session=session)
                self.assertEqual(self.ran, [("close_account", "ACC-9")] if approved else [])
                if approved:   # then the signer decides it, under the model's call id
                    r.decide.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"}, **FIRST)
                else:
                    r.decide.assert_not_called()

    def test_an_agent_in_a_workflow(self):
        r = run("deny", ["D1"])
        a = agent(r, self.tool(), name="closer")
        asyncio.run(WorkflowBuilder(start_executor=a).build().run("close it"))
        r.decide.assert_called_once()
        self.assertEqual(self.ran, [])

    @unittest.skipUnless(MCP1, "Agent Framework 1.22's MCP tools need mcp 1.x")
    def test_an_mcp_tool_is_decided_once(self):
        from mcp import ClientSession
        from mcp.server.fastmcp import FastMCP
        from mcp.shared.memory import create_connected_server_and_client_session

        from agent_framework import MCPStdioTool
        server = FastMCP("files")

        @server.tool()
        def list_files(path: str) -> str:
            """List the files."""
            self.ran.append(path)
            return "README.md"
        self.addCleanup(setattr, ClientSession, "call_tool", ClientSession.call_tool)
        self.addCleanup(setattr, ClientSession, "initialize", ClientSession.initialize)

        async def main(r):
            async with create_connected_server_and_client_session(server._mcp_server) as session:
                async with MCPStdioTool(name="files", command="unused", session=session) as files:
                    a = Agent(client=Scripted(model(("m-1", "list_files", {"path": "src"}))), tools=[files],
                              middleware=[Tracekit(r)])
                    return (await a.run("list them")).text
        with mock.patch("tracekit.integrations.mcp.TracekitSession") as gate:
            autowire._mcp(mock.Mock())   # what instrument() wires: every ClientSession decides its calls
            for r, runs in ((run(), True), (run("deny", ["D1"]), False)):
                self.ran.clear()
                out = asyncio.run(main(r))
                r.decide.assert_called_once_with("m-1", "list_files", {"path": "src"}, **FIRST)
                self.assertEqual(self.ran, ["src"] if runs else [])
                if runs:
                    self.assertIn("README.md", out)
            gate.assert_not_called()   # decided by the middleware, not again by the wired session


@unittest.skipUnless(HAVE, "agent_framework not installed")
class Said(unittest.TestCase):
    """`tk.chat` records each response: reasoning (protected_data sealed), text and function calls under the call ids
    the function middleware decides them by, streamed or not; the response itself only with the vault; a failure to
    record changes nothing for the agent."""

    def answer(self, r, stream=False):
        def script(messages):
            if not any(c.type == "function_result" for m in messages for c in m.contents):
                return [Content.from_text_reasoning(text="the user wants ACC-9 closed", protected_data="PD"),
                        Content.from_text("Closing ACC-9."),
                        Content.from_function_call("call-1", "close_account", arguments={"account": "ACC-9"})]
            return [Content.from_text("done")]

        def close_account(account: str) -> str:
            """Close an account."""
            return f"closed {account}"
        tk = Tracekit(r)
        a = Agent(client=Layered(script=script), tools=[close_account], middleware=[tk, tk.chat])
        if not stream:
            return go(a).messages[-1].text

        async def streamed():
            s = a.run("close it", stream=True)
            async for _ in s:
                pass
            return await s.get_final_response()
        return asyncio.run(streamed()).messages[-1].text

    def test_the_reasoning_before_a_call_is_linked_to_it(self):
        for stream in (False, True):
            with self.subTest(stream=stream):
                r = ts.vault(run())
                self.assertEqual(self.answer(r, stream), "done")
                first = ts.recorded(r)[0]
                self.assertEqual([t["id"] for t in first["tool_uses"]], ["call-1"])
                self.assertEqual(r.decide.call_args.args[0], "call-1")
                self.assertEqual(ts.segments(first), [("reasoning", "summary", "the user wants ACC-9 closed", []),
                                                      ("text", "full", "Closing ACC-9.", ["call-1"])])
                self.assertEqual(first["body"]["output"][0]["encrypted_content"], "PD")

    def test_without_the_vault_only_the_commitment(self):
        r = run()
        self.answer(r)
        self.assertTrue(ts.recorded(r) and all("body" not in f and f["content_digest"] for f in ts.recorded(r)))

    def test_a_failure_to_record_changes_nothing_for_the_agent(self):
        r = ts.failing(run())
        with self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
            self.assertEqual(self.answer(r), "done")


@unittest.skipUnless(HAVE, "agent_framework not installed")
class Setup(unittest.TestCase):
    def test_a_run_handle_is_required(self):
        with self.assertRaisesRegex(TypeError, "instrument\\(\\) returns None"):
            Tracekit(None)

    def test_an_async_run_handle_works(self):
        sync = run()
        self.assertIs(Tracekit(AsyncRunHandle(sync)).run, sync)


@unittest.skipUnless(HAVE, "agent_framework not installed")
class RealSigner(unittest.TestCase):
    def signer(self, policy):
        s = SignerService(ac.tmpdir(self), policy=Engine(policy))
        self.addCleanup(s.close)
        return s, Client(ac._serve(self, lambda identity, frame: s.handle_frame(identity, frame)))

    def test_validated_arguments_go_as_coerced_so_the_models_own_dont_mismatch(self):
        s, client = self.signer({})

        def refund(amount: float, n: int) -> str:
            """Refund."""
            return "refunded"
        asked = {"amount": 10, "n": "5", "extra": "x"}   # Agent Framework runs it with {"amount": 10.0, "n": 5}
        with client.run(agent="reconcile") as r:   # the model's tool use as the LLM gateway or autotrace records it
            r.call("model_event", provider="p", model="m", phase="response", tool_results_sent=[],
                   tool_uses=[{"id": "c-1", "name": "refund", "executed_by": "client", "args_source": "parsed",
                               "args_digest": event_hash({"tool": "refund", "args": asked})}])
            go(Agent(client=Scripted(model(("c-1", "refund", asked))), tools=[refund], middleware=[Tracekit(r)]))
            rid = r.run_id
        s.sweep(time.monotonic() + 61)   # past the grace window: run.final, reconciled
        events = [e["event"] for e in s.log.storage.iter_run("default", rid)]
        self.assertEqual(next(e for e in events if e["type"] == "policy.decision")["args_source"], "coerced")
        self.assertEqual(events[-1]["type"], "run.final")
        self.assertEqual([e["type"] for e in events if e["type"].startswith("reconcile.")], [])

    def test_a_payee_from_an_untrusted_tools_object_is_traced_to_it(self):
        """Values an untrusted tool's returned object carries reach the provenance index."""
        s, client = self.signer({"untrusted": ["WebFetch"]})

        class Page(BaseModel):
            title: str
            pay_to: str

        def WebFetch(url: str) -> Page:   # noqa: N802 - the policy names the tool
            """Fetch a page."""
            return Page(title="Invoice 7", pay_to="mallory-acct-7731")

        def pay(to: str) -> str:
            """Pay someone."""
            return "paid"
        script = model(("w-1", "WebFetch", {"url": "https://docs.example.org/i"}),
                       ("w-2", "pay", {"to": "mallory-acct-7731"}))
        with client.run(agent="provenance") as r:
            go(Agent(client=Scripted(script), tools=[WebFetch, pay], middleware=[Tracekit(r)]), "pay the invoice")
            rid = r.run_id
        d = next(e["event"]["data"] for e in s.log.storage.iter_run("default", rid)
                 if e["event"]["type"] == "policy.decision" and e["event"].get("tool_call_id") == "w-2")
        self.assertEqual([p["source"]["tool"] for p in d["provenance"]], ["WebFetch"])


@unittest.skipUnless(HAVE, "agent_framework not installed")
class VersionCheck(unittest.TestCase):
    """The version check the integration shares with the other hand-wired ones: a framework outside the version
    Tracekit is tested with warns once when the integration is built, one inside the range does not warn."""

    def test_it_warns_for_a_version_outside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.agent_framework import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="0.0.1"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        msgs = [str(x.message) for x in w if "is wired but untested" in str(x.message)]
        self.assertEqual(1, len(msgs))
        self.assertIn("Agent Framework 0.0.1 is wired but untested; Tracekit is tested with "
                      "agent-framework-core>=1.22,<1.23", msgs[0])

    def test_it_does_not_warn_for_a_version_inside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.agent_framework import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="1.22.0"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        self.assertEqual([], [str(x.message) for x in w if "is wired but untested" in str(x.message)])


if __name__ == "__main__":
    unittest.main()
