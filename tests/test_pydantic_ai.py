"""Pydantic AI's tool-execute hook (tracekit.integrations.pydantic_ai) on a real Agent with a FunctionModel and a mock
run: only an allow or an approved ask runs the tool, the model reads the reason for anything else and the run goes on,
and nothing Tracekit fails at raises into the agent."""
import asyncio
import importlib.util
import threading
import unittest
import warnings
from unittest import mock

import adapter_contract as ac
import test_gateway
import test_said as ts

HAVE = importlib.util.find_spec("pydantic_ai") is not None
OPENAI = HAVE and importlib.util.find_spec("openai") is not None
if HAVE:
    from pydantic import BaseModel
    from pydantic_ai import (Agent, DeferredToolRequests, DeferredToolResults, ModelRetry, RunContext, ToolOutput,
                             ToolReturn)
    from pydantic_ai.capabilities import AbstractCapability
    from pydantic_ai.exceptions import ApprovalRequired, UnexpectedModelBehavior
    from pydantic_ai.messages import (ModelResponse, RetryPromptPart, TextPart, ThinkingPart, ToolCallPart,
                                      ToolReturnPart)
    from pydantic_ai.models.function import DeltaToolCall, FunctionModel

    from tracekit import autowire
    from tracekit.integrations.pydantic_ai import Tracekit
if OPENAI:
    from openai import AsyncOpenAI
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

from tracekit.policy2.engine import Engine
from tracekit.sdk.client import AsyncRunHandle, Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return ts.vault(r, on=False)


def agent(r, tool, args=None):
    """An agent whose model calls `tool` once (with `args`, default {"account": "ACC-9"}) and then answers with what
    the tool returned, or with the retry prompt it was given."""
    def model(messages, info):
        parts = [p for m in messages for p in m.parts]
        back = [p for p in parts if isinstance(p, (ToolReturnPart, RetryPromptPart))]
        if not back or isinstance(back[-1], RetryPromptPart) and len(back) < 2:
            return ModelResponse(parts=[ToolCallPart("close_account", {"account": "ACC-9"} if args is None else args,
                                                     f"call-{len(back) + 1}")])
        return ModelResponse(parts=[TextPart(str(back[-1].content))])
    return Agent(FunctionModel(model), tools=[tool], capabilities=[Tracekit(r)])


@unittest.skipUnless(HAVE, "pydantic_ai not installed")
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
                out = agent(r, self.tool()).run_sync("close it").output
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

    def test_the_signer_decides_the_models_own_arguments(self):
        r = run()
        agent(r, self.tool(), '{"account": "ACC-9"}').run_sync("close it")
        r.decide.assert_called_once_with("call-1", "close_account", '{"account": "ACC-9"}', attempt=0)
        r.approval_consume.assert_called_once_with("call-1", "close_account", '{"account": "ACC-9"}',
                                                   approval_id_hint=None, attempt=0)

    def test_approved_arguments_match_the_models_json_text_parsed(self):
        r = run()
        r.approval_consume.return_value = {"ok": True, "rule_ids": [], "args": {"account": "ACC-9"}}
        self.assertEqual(agent(r, self.tool(), '{"account": "ACC-9"}').run_sync("close it").output, "closed ACC-9")
        self.assertEqual(self.ran, ["ACC-9"])

    def test_an_approved_ask_consumes_its_approval(self):
        r = run("ask", ["A1"])
        agent(r, self.tool()).run_sync("close it")
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint="apr-1", attempt=0)

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIn("not approved: requested", agent(r, self.tool()).run_sync("close it").output)
        self.assertEqual([c.args[0] for c in r.call.call_args_list if c.args[0] != "model_event"][-1],
                         "approval_abandon")

    def test_the_refusal_names_the_rules_but_not_the_unknown_tool_flag(self):
        out = agent(run("deny", ["TK-D001", "TK-UNKNOWN-TOOL"]), self.tool()).run_sync("close it").output
        self.assertEqual(out, "Tool call blocked by Tracekit policy: TK-D001")

    def test_nothing_tracekit_fails_at_raises_into_the_agent(self):
        for exc in (RPCError("run_closed", "r"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                self.assertIn("Tracekit could not decide it", agent(r, self.tool()).run_sync("close it").output)
                self.assertEqual(self.ran, [])
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(agent(r, self.tool()).run_sync("close it").output, "closed ACC-9")

    def test_an_outage_follows_the_runs_fail_mode(self):
        out = agent(run("deny", unavailable=True, reason="signer unavailable: down"), self.tool()).run_sync("x").output
        self.assertEqual(out, "Tool call refused by Tracekit: signer unavailable: down")
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(agent(r, self.tool()).run_sync("x").output, "closed ACC-9")
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_a_tool_error_is_recorded_and_a_retry_is_a_new_decision(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            if len(self.ran) == 1:
                raise ModelRetry("account is locked, try again")
            return f"closed {account}"
        r = run()
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            self.assertEqual(agent(r, close_account).run_sync("close it").output, "closed ACC-9")
        self.assertEqual([c.args[0] for c in r.decide.call_args_list], ["call-1", "call-2"])
        self.assertEqual([c.args[:2] for c in r.complete.call_args_list], [("call-1", "error"), ("call-2", "ok")])
        self.assertIn("account is locked", r.complete.call_args_list[0].kwargs["error"])

    def test_a_refused_call_reads_as_denied_in_the_history(self):
        r = agent(run("deny", ["D1"]), self.tool()).run_sync("close it")
        part = next(p for m in r.all_messages() for p in m.parts if isinstance(p, ToolReturnPart))
        self.assertEqual((part.outcome, part.content), ("denied", "Tool call blocked by Tracekit policy: D1"))

    def test_an_empty_argument_string_is_no_arguments(self):
        def close_account(account: str = "ACC-0") -> str:
            """Close an account."""
            return f"closed {account}"
        r = run()
        agent(r, close_account, "").run_sync("close it")
        self.assertEqual(r.decide.call_args.args, ("call-1", "close_account", {}))

    def test_an_untrusted_tools_result_goes_to_the_signer_as_the_model_reads_it(self):
        class Page(BaseModel):
            title: str
            pay_to: str

        def close_account(account: str) -> Page:
            """Close an account."""
            return Page(title="Invoice 7", pay_to="mallory-acct-7731")
        r = run(send_result=True)
        agent(r, close_account).run_sync("close it")
        self.assertEqual(r.complete.call_args.kwargs["result"], {"title": "Invoice 7", "pay_to": "mallory-acct-7731"})

    def test_a_tool_return_is_recorded_as_its_return_value(self):
        """Its return_value is the tool result the model reads; its content goes as a message of its own."""
        def close_account(account: str) -> ToolReturn:
            """Close an account."""
            return ToolReturn(return_value={"closed": account}, content="the account had a balance")
        r = run(send_result=True)
        agent(r, close_account).run_sync("close it")
        self.assertEqual(r.complete.call_args.kwargs["result"], {"closed": "ACC-9"})

    def test_arguments_another_capability_changes_are_recorded_as_changed(self):
        class Before(AbstractCapability):
            async def before_tool_execute(self, ctx, *, call, tool_def, args):
                return {"account": "ACC-1"}
        class Wrap(AbstractCapability):
            async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
                return await handler({"account": "ACC-1"})
        for rewrite, order in ((Before, "first"), (Before, "last"), (Wrap, "first"), (Wrap, "last")):
            with self.subTest(f"{rewrite.__name__}, Tracekit listed {order}"):
                self.ran.clear()
                r = run()
                caps = [Tracekit(r), rewrite()] if order == "first" else [rewrite(), Tracekit(r)]
                def model(messages, info):
                    if any(isinstance(p, ToolReturnPart) for m in messages for p in m.parts):
                        return ModelResponse(parts=[TextPart("done")])
                    return ModelResponse(parts=[ToolCallPart("close_account", {"account": "ACC-9"}, "call-1")])
                Agent(FunctionModel(model), tools=[self.tool()], capabilities=caps).run_sync("close it")
                self.assertEqual(self.ran, ["ACC-1"])
                self.assertEqual(r.complete.call_args.args[1], "error")
                self.assertIn("changed after the decision", r.complete.call_args.kwargs["error"])

    def test_approved_arguments_other_than_the_calls_dont_run(self):
        r = run()
        r.approval_consume.return_value = {"ok": True, "rule_ids": [], "args": {"account": "ACC-1"}}
        self.assertIn("arguments the signer approved", agent(r, self.tool()).run_sync("close it").output)
        self.assertEqual(self.ran, [])

    def test_a_deferred_call_resumed_is_decided_as_its_next_attempt(self):
        def model(messages, info):
            back = [p for m in messages for p in m.parts if isinstance(p, ToolReturnPart)]
            if back:
                return ModelResponse(parts=[TextPart(str(back[-1].content))])
            return ModelResponse(parts=[ToolCallPart("close_account", {"account": "ACC-9"}, "call-1")])
        r = run()
        a = Agent(FunctionModel(model), output_type=[str, DeferredToolRequests], capabilities=[Tracekit(r)])

        @a.tool
        def close_account(ctx: RunContext, account: str) -> str:
            """Close an account."""
            if not ctx.tool_call_approved:
                raise ApprovalRequired
            self.ran.append(account)
            return f"closed {account}"
        first = a.run_sync("close it")
        self.assertIsInstance(first.output, DeferredToolRequests)
        r.complete.assert_not_called()   # deferred, not run: a resumed call is the next attempt, not a failure
        out = a.run_sync(message_history=first.all_messages(),
                         deferred_tool_results=DeferredToolResults(approvals={"call-1": True})).output
        self.assertEqual((out, self.ran), ("closed ACC-9", ["ACC-9"]))
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        r.complete.assert_called_once_with("call-1", "ok", attempt=1, result=mock.ANY)

    def test_a_run_cancelled_during_an_ask_withdraws_the_approval(self):
        answered = threading.Event()
        r = run("ask", ["A1"])

        def call(method, **f):
            if method == "approval_wait":
                answered.wait(5)   # a person approves after the agent run was cancelled
                return {"state": "approved"}
            return {"approval_request": {"approval_id": "apr-1"}, "approval_abandon": {}, "model_event": {}}[method]
        r.call.side_effect = call

        async def go():
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(agent(r, self.tool()).run("close it"), 0.3)
        threading.Timer(0.6, answered.set).start()
        asyncio.run(go())   # returns once the approval_wait thread has (asyncio.run waits for its executor)
        self.assertIn("approval_abandon", [c.args[0] for c in r.call.call_args_list])
        r.approval_consume.assert_not_called()
        self.assertEqual(self.ran, [])


@unittest.skipUnless(HAVE, "pydantic_ai not installed")
class Output(unittest.TestCase):
    """An output function runs the model's arguments too: it is decided like a tool call."""

    def setUp(self):
        self.ran = []

    def bash(self):
        def Bash(command: str) -> str:
            """Run a command; its output is the answer."""
            self.ran.append(command)
            return f"ran {command}"
        return Bash

    def test_an_output_function_is_decided_before_it_runs(self):
        def model(messages, info):
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"command": "sudo rm -rf /"}, "o-1")])
        r = run("deny", ["TK-D001"])
        with self.assertRaises(UnexpectedModelBehavior):   # refused every time the model asks: no answer, nothing run
            Agent(FunctionModel(model), output_type=ToolOutput(self.bash()), capabilities=[Tracekit(r)]).run_sync("x")
        self.assertEqual(self.ran, [])
        self.assertEqual(r.decide.call_args_list[0].args, ("o-1", "final_result", {"command": "sudo rm -rf /"}))
        r = run()
        out = Agent(FunctionModel(model), output_type=ToolOutput(self.bash()), capabilities=[Tracekit(r)]).run_sync("x")
        self.assertEqual((out.output, self.ran), ("ran sudo rm -rf /", ["sudo rm -rf /"]))
        r.complete.assert_called_once_with("o-1", "ok", attempt=0)   # the model reads "Final result processed."

    def test_streaming_runs_an_output_function_once_on_the_decided_final_output(self):
        async def stream(messages, info):
            name = info.output_tools[0].name
            yield {0: DeltaToolCall(name=name, json_args='{"command": "ec', tool_call_id="o-1")}
            yield {0: DeltaToolCall(json_args='ho hi"}')}
        r = run()
        a = Agent(FunctionModel(stream_function=stream), output_type=ToolOutput(self.bash()), capabilities=[Tracekit(r)])

        async def go():
            async with a.run_stream("x") as res:
                return [o async for o in res.stream_output(debounce_by=None)]
        asyncio.run(go())
        self.assertEqual(self.ran, ["echo hi"])   # never the partial "ec"
        r.decide.assert_called_once()


@unittest.skipUnless(HAVE, "pydantic_ai not installed")
class Setup(unittest.TestCase):
    def test_a_run_handle_is_required(self):
        with self.assertRaisesRegex(TypeError, "instrument\\(\\) returns None"):
            Tracekit(None)

    def test_an_async_run_handle_works(self):
        sync = run()
        self.assertIs(Tracekit(AsyncRunHandle(sync)).run, sync)

    def test_instrument_gives_every_agent_built_after_it_the_capability_once(self):
        init = Agent.__init__
        self.addCleanup(setattr, Agent, "__init__", init)
        r = run()
        autowire._pydantic_ai(r)
        model = FunctionModel(lambda m, i: ModelResponse(parts=[TextPart("hi")]))
        given = Tracekit(run())
        for caps, want in ((None, 1), ([given], 1)):
            a = Agent(model, capabilities=caps)
            mine = [c for c in a._root_capability.capabilities if isinstance(c, Tracekit)]
            self.assertEqual(len(mine), want)
        self.assertIs(mine[0], given)

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "mcp not installed")
    def test_a_call_the_capability_decided_is_not_decided_again_by_the_wired_mcp_session(self):
        from mcp import ClientSession
        original = mock.AsyncMock(return_value="result")
        self.addCleanup(setattr, ClientSession, "call_tool", ClientSession.call_tool)
        self.addCleanup(setattr, ClientSession, "initialize", ClientSession.initialize)
        ClientSession.call_tool = original
        process = mock.Mock()
        with mock.patch("tracekit.integrations.mcp.TracekitSession") as gate:
            gate.return_value.call_tool = mock.AsyncMock(return_value="gated")
            autowire._mcp(process)
            session = object.__new__(ClientSession)
            token = autowire.DECIDED_UPSTREAM.set(True)
            try:
                self.assertEqual(asyncio.run(ClientSession.call_tool(session, "read_file", {"path": "x"})), "result")
            finally:
                autowire.DECIDED_UPSTREAM.reset(token)
            gate.assert_not_called()
            asyncio.run(ClientSession.call_tool(session, "read_file", {"path": "x"}))
            gate.assert_called_once()   # outside the capability, the wired session decides as before


@unittest.skipUnless(HAVE, "pydantic_ai not installed")
class Said(unittest.TestCase):
    """Each model response is recorded: its thinking, text and the calls of the agent's function tools, under the ids
    they are decided by; the response itself only with the vault; a failure to record changes nothing for the agent."""

    def agent(self, r, output_type=str):
        def close_account(account: str) -> str:
            """Close an account."""
            return f"closed {account}"

        def model(messages, info):
            if not any(isinstance(p, ToolReturnPart) for m in messages for p in m.parts):
                return ModelResponse(parts=[ThinkingPart("the user asked to close it", signature="sig-1"),
                                            TextPart("Closing ACC-9."),
                                            ToolCallPart("close_account", {"account": "ACC-9"}, "call-1")])
            return ModelResponse(parts=[TextPart("done")])
        return Agent(FunctionModel(model), tools=[close_account], capabilities=[Tracekit(r)])

    def test_the_reasoning_before_a_call_is_linked_to_it(self):
        r = ts.vault(run())
        self.assertEqual(self.agent(r).run_sync("close it").output, "done")
        first, last = ts.recorded(r)
        self.assertEqual([t["id"] for t in first["tool_uses"]], ["call-1"])   # the id the call was decided under
        self.assertEqual(r.decide.call_args.args[0], "call-1")
        self.assertEqual(ts.segments(first), [("reasoning", "summary", "the user asked to close it", []),
                                              ("text", "full", "Closing ACC-9.", ["call-1"])])
        self.assertEqual(first["body"]["output"][0]["encrypted_content"], "sig-1")
        self.assertEqual(ts.segments(last), [("text", "full", "done", [])])

    def test_without_the_vault_only_the_commitment(self):
        r = run()
        self.agent(r).run_sync("close it")
        self.assertTrue(all("body" not in f and f["content_digest"] for f in ts.recorded(r)))

    def test_an_output_call_is_recorded_as_its_responses_only_when_it_is_decided(self):
        """The signer reconciles decided calls with recorded responses: an output function's call (decided) is
        recorded, under the response's exchange id, just before its decision; a data-only output's (never decided)
        is not, so neither reads as reconcile.fabricated or hook_missing."""
        def model(messages, info):
            return ModelResponse(parts=[TextPart("Running it."),
                                        ToolCallPart(info.output_tools[0].name, {"command": "ls"}, "o-1")])
        def Bash(command: str) -> str:
            """Run a command; its output is the answer."""
            return f"ran {command}"
        r = ts.vault(run())
        Agent(FunctionModel(model), output_type=ToolOutput(Bash), capabilities=[Tracekit(r)]).run_sync("x")
        first, call = ts.recorded(r)
        self.assertNotIn("tool_uses", first)
        self.assertEqual(([t["id"] for t in call["tool_uses"]], call["exchange_id"]), (["o-1"], first["exchange_id"]))
        names = [c[0] for c in r.mock_calls]
        self.assertLess(r.mock_calls.index(mock.call.call("model_event", **call)), names.index("decide"))

        class Answer(BaseModel):
            answer: str
        r = ts.vault(run())
        Agent(FunctionModel(lambda m, info: ModelResponse(parts=[ToolCallPart(
            info.output_tools[0].name, {"answer": "42"}, "o-2")])), output_type=Answer,
            capabilities=[Tracekit(r)]).run_sync("x")
        self.assertEqual(ts.recorded(r), [])   # nothing said but a data-only output: no call to record
        r.decide.assert_not_called()

    def test_a_tool_that_needs_approval_is_recorded_as_its_responses_call_once_approved_and_decided(self):
        def model(messages, info):
            back = [p for m in messages for p in m.parts if isinstance(p, ToolReturnPart)]
            if back:
                return ModelResponse(parts=[TextPart(str(back[-1].content))])
            return ModelResponse(parts=[ToolCallPart("close_account", {"account": "ACC-9"}, "call-1")])
        r = ts.vault(run())
        a = Agent(FunctionModel(model), output_type=[str, DeferredToolRequests], capabilities=[Tracekit(r)])

        @a.tool_plain(requires_approval=True)
        def close_account(account: str) -> str:
            """Close an account."""
            return f"closed {account}"
        first = a.run_sync("close it")
        self.assertEqual((ts.recorded(r), r.decide.call_count), ([], 0))   # waiting for a person: no call recorded
        a.run_sync(message_history=first.all_messages(),
                   deferred_tool_results=DeferredToolResults(approvals={"call-1": True}))
        call = ts.recorded(r)[0]
        self.assertEqual([t["id"] for t in call["tool_uses"]], ["call-1"])
        self.assertEqual(r.decide.call_args.args[0], "call-1")

    def test_a_failure_to_record_changes_nothing_for_the_agent(self):
        r = ts.failing(run())
        with self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
            self.assertEqual(self.agent(r).run_sync("close it").output, "done")


@unittest.skipUnless(HAVE, "pydantic_ai not installed")
class Provenance(unittest.TestCase):
    """On a real signer: values an untrusted tool's model result carries reach the provenance index."""

    def test_a_payee_from_an_untrusted_tools_model_result_is_traced_to_it(self):
        s = SignerService(ac.tmpdir(self), policy=Engine({"untrusted": ["WebFetch"]}))
        self.addCleanup(s.close)
        client = Client(ac._serve(self, lambda identity, frame: s.handle_frame(identity, frame)))

        class Page(BaseModel):
            title: str
            pay_to: str

        def WebFetch(url: str) -> Page:
            """Fetch a page."""
            return Page(title="Invoice 7", pay_to="mallory-acct-7731")

        def pay(to: str) -> str:
            """Pay someone."""
            return "paid"

        def model(messages, info):
            back = [p for m in messages for p in m.parts if isinstance(p, ToolReturnPart)]
            if not back:
                return ModelResponse(parts=[ToolCallPart("WebFetch", {"url": "https://docs.example.org/i"}, "w-1")])
            if len(back) == 1:
                return ModelResponse(parts=[ToolCallPart("pay", {"to": "mallory-acct-7731"}, "w-2")])
            return ModelResponse(parts=[TextPart("done")])
        with client.run(agent="provenance") as r:
            Agent(FunctionModel(model), tools=[WebFetch, pay], capabilities=[Tracekit(r)]).run_sync("pay the invoice")
            rid = r.run_id
        d = next(e["event"]["data"] for e in s.log.storage.iter_run("default", rid)
                 if e["event"]["type"] == "policy.decision" and e["event"].get("tool_call_id") == "w-2")
        self.assertEqual([p["source"]["tool"] for p in d["provenance"]], ["WebFetch"])


@unittest.skipUnless(OPENAI, "pydantic_ai or openai not installed")
class VerifiedToolResults(test_gateway.Gateway):
    """Through the LLM gateway, with verify_tool_results: refuse and Pydantic AI's OpenAI chat model: what the
    capability records is what the model is sent, so an honest run's requests are not refused (they were: 403)."""
    verify = "refuse"

    def setUp(self):
        super().setUp()
        self.gw.gateway.max_body = 1 << 20   # the requests carry the tools' definitions
        self.client = Client(ac._serve(self, lambda identity, frame: self.s.handle_frame(test_gateway.AGENT, frame)))

    def model(self, r):
        c = AsyncOpenAI(base_url=f"http://127.0.0.1:{self.port}/v1", api_key=test_gateway.SECRET, max_retries=0,
                        default_headers={"X-Tracekit-Run": f"{r.run_id}.{r.run_token}"})
        return OpenAIChatModel("gpt-x", provider=OpenAIProvider(openai_client=c))

    def replies(self, *turns):
        """The provider's answer to each request: [(tool, call id, arguments)] to call, or the final text."""
        self.up.reply = [("json", {"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-x",
                                   "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                                   "choices": [{"index": 0, "finish_reason": "stop", "message": {
                                       "role": "assistant", "content": t}} if isinstance(t, str) else {
                                       "index": 0, "finish_reason": "tool_calls", "message": {
                                           "role": "assistant", "content": None, "tool_calls": [
                                               {"id": i, "type": "function", "function": {"name": n, "arguments": a}}
                                               for n, i, a in t]}}]}) for t in turns]

    def mismatches(self, run_id):
        return [e["tool_call_id"] for e in self.events({"run_id": run_id}) if e["type"] == "reconcile.result_mismatch"]

    def test_tools_returning_none_an_empty_list_or_a_tool_return(self):
        def send_email() -> None:
            """Send an email."""

        def search() -> list:
            """Search."""
            return []

        def lookup() -> ToolReturn:
            """Look up."""
            return ToolReturn(return_value={"v": 1}, content="more context for the model")
        self.replies([("send_email", "call_none", "{}"), ("search", "call_empty", "{}"), ("lookup", "call_tr", "{}")],
                     "done")
        with self.client.run(agent="pai") as r:
            out = Agent(self.model(r), tools=[send_email, search, lookup], capabilities=[Tracekit(r)]).run_sync("go")
        self.assertEqual(out.output, "done")
        self.assertEqual(self.mismatches(r.run_id), [])

    def test_an_output_functions_call_sent_again_in_a_later_run(self):
        def finish(text: str) -> str:
            """Finish."""
            return text.upper()
        self.replies([("final_result", "call_out", '{"text": "hi"}')], "follow-up answer")
        with self.client.run(agent="pai") as r:
            first = Agent(self.model(r), output_type=ToolOutput(finish, name="final_result"),
                          capabilities=[Tracekit(r)]).run_sync("go")
            out = Agent(self.model(r), capabilities=[Tracekit(r)]).run_sync("again",
                                                                              message_history=first.all_messages())
        self.assertEqual((first.output, out.output), ("HI", "follow-up answer"))
        self.assertEqual(self.mismatches(r.run_id), [])


if __name__ == "__main__":
    unittest.main()
