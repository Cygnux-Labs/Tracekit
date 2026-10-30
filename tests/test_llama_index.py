"""LlamaIndex's call_tool step gated by tracekit.integrations.llama_index on real agents (FunctionAgent, ReActAgent,
CodeActAgent, an AgentWorkflow with a handoff) with a scripted MockFunctionCallingLLM and a mock run: only an allow or
an approved ask runs the tool, the model reads the reason for anything else and the run goes on, and nothing Tracekit
fails at raises into the workflow."""
import asyncio
import importlib.util
import threading
import unittest
import warnings
from unittest import mock

import adapter_contract as ac
import test_said as ts

HAVE = importlib.util.find_spec("llama_index") is not None
if HAVE:
    from pydantic import BaseModel
    from llama_index.core.agent.workflow import (AgentWorkflow, CodeActAgent, FunctionAgent, ReActAgent, ToolCall,
                                                 ToolCallResult)
    from llama_index.core.base.llms.types import TextBlock, ThinkingBlock, ToolCallBlock
    from llama_index.core.llms import ChatMessage
    from llama_index.core.llms.mock import MockFunctionCallingLLM
    from llama_index.core.tools import FunctionTool
    from llama_index.core.workflow import (Context, Event, HumanResponseEvent, InputRequiredEvent, StopEvent,
                                           WorkflowTimeoutError, step)

    from tracekit import autowire
    from tracekit.integrations.llama_index import Tracekit

from tracekit import gateway
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import AsyncRunHandle, Client
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import SignerService

CLOSE = ("close_account", {"account": "ACC-9"}, "call-1")
HANDOFF = ("handoff", {"to_agent": "billing", "reason": "billing closes accounts"}, "h-1")


def run(decision="allow", rule_ids=(), consume=True, state="approved", **more):
    r = mock.Mock()
    r.decide.return_value = {"decision": decision, "rule_ids": list(rule_ids), "decision_id": "dec-1", **more}
    r.call.side_effect = lambda m, **f: {"approval_request": {"approval_id": "apr-1"},
                                         "approval_wait": {"state": state}, "approval_abandon": {}}[m]
    r.approval_consume.return_value = {"ok": consume, "rule_ids": list(rule_ids)}
    return ts.vault(r, on=False)


def model(*turns):
    """A scripted function-calling model: each turn is the tool calls ((tool, args, id) each) of one response, made
    once the earlier turns have their results; then it answers with the text of every result."""
    def respond(messages, **kw):
        got = {m.additional_kwargs.get("tool_call_id"): m.content for m in messages if m.role == "tool"}
        for turn in turns:
            if any(i not in got for _, _, i in turn):
                return ChatMessage(role="assistant", blocks=[ToolCallBlock(tool_call_id=i, tool_name=t, tool_kwargs=a)
                                                             for t, a, i in turn])
        return ChatMessage(role="assistant", content=" | ".join(str(got[i]) for turn in turns for _, _, i in turn))
    return MockFunctionCallingLLM(response_generator=respond)


def gated(r, *tools, turns=([CLOSE],), **agent):
    return Tracekit(r).gate(FunctionAgent(tools=list(tools), llm=model(*turns), **agent))


def ask(workflow, events=None, answer=None):
    """The workflow's answer to "close it"; what it streams goes to `events`, and `answer` answers an
    InputRequiredEvent."""
    async def go():
        h = workflow.run(user_msg="close it")
        async for e in h.stream_events():
            if events is not None:
                events.append(e)
            if isinstance(e, InputRequiredEvent):
                h.ctx.send_event(HumanResponseEvent(response=answer))
        return str(await h)
    return asyncio.run(go())


class Tools(unittest.TestCase):
    def setUp(self):
        self.ran = []

    def tool(self):
        def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        return close_account


@unittest.skipUnless(HAVE, "llama_index not installed")
class Hook(Tools):
    def test_only_an_allow_or_an_approved_ask_runs(self):
        for name, r, runs in (("allow", run(), True), ("deny", run("deny", ["D1"]), False),
                              ("ask approved", run("ask", ["A1"]), True),
                              ("ask rejected", run("ask", ["A1"], state="rejected"), False),
                              ("consume refused", run(consume=False), False)):
            with self.subTest(name):
                self.ran.clear()
                out = ask(gated(r, self.tool()))
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

    def test_the_signer_decides_the_call_id_and_the_models_arguments(self):
        r = run()
        ask(gated(r, self.tool()))
        r.decide.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"}, attempt=0)
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint=None, attempt=0)

    def test_sync_and_async_tools_are_gated(self):
        async def close_account(account: str) -> str:
            """Close an account."""
            self.ran.append(account)
            return f"closed {account}"
        for tool in (self.tool(), close_account):
            with self.subTest(tool=tool):
                self.ran.clear()
                self.assertIn("Tracekit policy", ask(gated(run("deny", ["D1"]), tool)))
                self.assertEqual(self.ran, [])
                self.assertEqual(ask(gated(run(), tool)), "closed ACC-9")

    def test_each_parallel_call_is_decided_on_its_own(self):
        r = run()
        r.decide.side_effect = lambda call_id, *a, **k: {"decision": "deny" if call_id == "call-2" else "allow",
                                                        "rule_ids": ["D1"], "decision_id": "dec-" + call_id}
        out = ask(gated(r, self.tool(), turns=([CLOSE, ("close_account", {"account": "ACC-7"}, "call-2")],)))
        self.assertEqual(out, "closed ACC-9 | Tool call blocked by Tracekit policy: D1")
        self.assertEqual(self.ran, ["ACC-9"])
        self.assertEqual(sorted(c.args[0] for c in r.decide.call_args_list), ["call-1", "call-2"])

    def test_a_call_named_by_its_tool_or_by_nothing_is_decided_under_an_id_of_its_own(self):
        r = run()
        events = []
        ask(gated(r, self.tool(), turns=([("close_account", {"account": "A"}, "close_account"),
                                          ("close_account", {"account": "B"}, "")],)), events)
        ids = [c.args[0] for c in r.decide.call_args_list]
        self.assertEqual((len(set(ids)), [len(i) for i in ids], sorted(self.ran)), (2, [36, 36], ["A", "B"]))
        self.assertEqual(sorted(c.args[0] for c in r.complete.call_args_list), sorted(ids))
        self.assertEqual(sorted(e.tool_id for e in events if isinstance(e, ToolCallResult)), ["", "close_account"])

    def test_an_approved_ask_consumes_its_approval(self):
        r = run("ask", ["A1"])
        ask(gated(r, self.tool()))
        r.approval_consume.assert_called_once_with("call-1", "close_account", {"account": "ACC-9"},
                                                   approval_id_hint="apr-1", attempt=0)

    def test_an_unanswered_approval_is_withdrawn(self):
        r = run("ask", ["A1"], state="requested")
        self.assertIn("not approved: requested", ask(gated(r, self.tool())))
        self.assertEqual([c.args[0] for c in r.call.call_args_list if c.args[0] != "model_event"][-1],
                         "approval_abandon")

    def test_the_refusal_names_the_rules_but_not_the_unknown_tool_flag(self):
        self.assertEqual(ask(gated(run("deny", ["TK-D001", "TK-UNKNOWN-TOOL"]), self.tool())),
                         "Tool call blocked by Tracekit policy: TK-D001")

    def test_a_refused_call_is_an_error_tool_result_in_the_stream(self):
        events = []
        ask(gated(run("deny", ["D1"]), self.tool()), events)
        call, result = [e for e in events if isinstance(e, (ToolCall, ToolCallResult))]
        self.assertEqual((type(call), call.tool_id), (ToolCall, "call-1"))
        out = result.tool_output
        self.assertEqual((result.tool_id, out.is_error, result.return_direct, out.content),
                         ("call-1", True, False, "Tool call blocked by Tracekit policy: D1"))

    def test_nothing_tracekit_fails_at_raises_into_the_workflow(self):
        for exc in (RPCError("run_closed", "r"), KeyError("bug")):
            with self.subTest(exc=exc):
                r = run()
                r.decide.side_effect = exc
                self.assertIn("Tracekit could not decide it", ask(gated(r, self.tool())))
                self.assertEqual(self.ran, [])
        r = run()
        r.complete.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not recorded"):
            self.assertEqual(ask(gated(r, self.tool())), "closed ACC-9")

        def close_account(account: str) -> dict:
            """Close an account."""
            return {"closed": account}
        r = run(send_result=True)
        r.observe.side_effect = RuntimeError("bug")
        with self.assertWarnsRegex(UserWarning, "was not observed"):
            self.assertEqual(ask(gated(r, close_account)), "{'closed': 'ACC-9'}")

    def test_an_outage_follows_the_runs_fail_mode(self):
        out = ask(gated(run("deny", unavailable=True, reason="signer unavailable: down"), self.tool()))
        self.assertEqual(out, "Tool call refused by Tracekit: signer unavailable: down")
        r = run("allow", unavailable=True, reason="signer unavailable: down")
        self.assertEqual(ask(gated(r, self.tool())), "closed ACC-9")
        r.approval_consume.assert_not_called()
        r.complete.assert_not_called()

    def test_a_tool_error_is_recorded_and_reaches_the_model_as_llamaindex_gives_it(self):
        def close_account(account: str) -> str:
            """Close an account."""
            raise ValueError("account is locked")
        r = run()
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            self.assertEqual(ask(gated(r, close_account)), "account is locked")
        r.complete.assert_called_once_with("call-1", "error", attempt=0, error="ValueError: account is locked")

    def test_a_tool_the_agent_doesnt_have_is_decided_and_recorded_as_an_error(self):
        r = run()
        self.assertIn("Tool close_account not found", ask(gated(r)))
        r.decide.assert_called_once()
        self.assertEqual(r.complete.call_args.args[1], "error")

    def test_an_empty_argument_string_is_no_arguments(self):
        def close_account(account: str = "ACC-0") -> str:
            """Close an account."""
            return f"closed {account}"
        r = run()
        ask(gated(r, close_account, turns=([("close_account", "", "call-1")],)))
        self.assertEqual(r.decide.call_args.args, ("call-1", "close_account", {}))

    def test_a_result_is_recorded_as_the_model_reads_it_and_an_untrusted_structure_is_observed(self):
        class Page(BaseModel):
            title: str
            pay_to: str

        def close_account(account: str) -> Page:
            """Close an account."""
            return Page(title="Invoice 7", pay_to="mallory-acct-7731")
        events = []
        r = run(send_result=True)
        ask(gated(r, close_account), events)
        [read] = [e.tool_output.content for e in events if isinstance(e, ToolCallResult)]
        self.assertEqual(r.complete.call_args.kwargs["result"], read)
        r.observe.assert_called_once_with({"title": "Invoice 7", "pay_to": "mallory-acct-7731"},
                                          "llama_index:close_account:call-1")
        for name, r, tool in (("a text result", run(send_result=True), self.tool()),
                              ("a trusted tool", run(), close_account)):
            with self.subTest(name):   # nothing the text doesn't carry, or nothing provenance reads
                ask(gated(r, tool))
                r.observe.assert_not_called()

    def test_approved_arguments_other_than_the_calls_dont_run(self):
        r = run()
        r.approval_consume.return_value = {"ok": True, "rule_ids": [], "args": {"account": "ACC-1"}}
        self.assertIn("arguments the signer approved", ask(gated(r, self.tool())))
        self.assertEqual(self.ran, [])

    def test_arguments_the_agents_own_call_tool_changes_are_recorded_as_changed(self):
        class InPlace(FunctionAgent):
            @step
            async def call_tool(self, ctx: Context, ev: ToolCall) -> ToolCallResult:
                ev.tool_kwargs["account"] = "ACC-1"
                return await super().call_tool(ctx, ev)

        class Anew(FunctionAgent):
            @step
            async def call_tool(self, ctx: Context, ev: ToolCall) -> ToolCallResult:
                return await super().call_tool(ctx, ev.model_copy(update={"tool_kwargs": {"account": "ACC-1"}}))
        for cls in (InPlace, Anew):
            with self.subTest(cls.__name__):
                self.ran.clear()
                r = run()
                ask(Tracekit(r).gate(cls(tools=[self.tool()], llm=model([CLOSE]))))
                self.assertEqual(self.ran, ["ACC-1"])
                r.complete.assert_called_once_with("call-1", "error", attempt=0,
                                                   error="the call's arguments changed after the decision")

    def test_a_tool_that_waits_for_an_event_is_decided_again_when_it_runs_again(self):
        async def close_account(ctx: Context, account: str) -> str:
            """Close an account once a person says so."""
            self.ran.append(account)
            answer = await ctx.wait_for_event(HumanResponseEvent, waiter_event=InputRequiredEvent(prefix="sure?"))
            return f"closed {account}: {answer.response}"
        r = run()
        self.assertEqual(ask(gated(r, close_account), answer="yes"), "closed ACC-9: yes")
        self.assertEqual(self.ran, ["ACC-9", "ACC-9"])   # LlamaIndex runs the step again from its start
        self.assertEqual([c.kwargs["attempt"] for c in r.decide.call_args_list], [0, 1])
        r.complete.assert_called_once_with("call-1", "ok", attempt=1, result=mock.ANY)

    def test_a_workflow_cancelled_during_an_ask_withdraws_the_approval(self):
        answered = threading.Event()
        r = run("ask", ["A1"])

        def call(method, **f):
            if method == "approval_wait":
                answered.wait(5)   # a person approves after the workflow timed out
                return {"state": "approved"}
            return {"approval_request": {"approval_id": "apr-1"}, "approval_abandon": {}, "model_event": {}}[method]
        r.call.side_effect = call
        threading.Timer(0.6, answered.set).start()
        with self.assertRaises(WorkflowTimeoutError):
            ask(gated(r, self.tool(), timeout=0.3))   # returns once the approval_wait thread has
        r.call.assert_any_call("approval_abandon", approval_id="apr-1",
                               reason="the workflow was cancelled while it waited")
        r.approval_consume.assert_not_called()
        self.assertEqual(self.ran, [])

    def test_a_call_the_gate_decided_is_not_decided_again_by_the_wired_mcp_session(self):
        seen = []

        def close_account(account: str) -> str:
            """Close an account."""
            seen.append(autowire.DECIDED_UPSTREAM.get())
            return "closed"
        ask(gated(run(), close_account))
        self.assertEqual((seen, autowire.DECIDED_UPSTREAM.get()), ([True], False))


@unittest.skipUnless(HAVE, "llama_index not installed")
class Agents(Tools):
    """Every agent's tool calls go through the call_tool step of what runs it."""

    def test_react_decides_the_action_under_the_id_llamaindex_gives_it(self):
        def react(messages, **kw):
            seen = [m.content for m in messages if m.role != "system" and m.content.startswith("Observation:")]
            if seen:
                return ChatMessage(role="assistant", content="Thought: done.\nAnswer: " + seen[-1].split(": ", 1)[1])
            return ChatMessage(role="assistant", content='Thought: close it.\nAction: close_account\n'
                                                         'Action Input: {"account": "ACC-9"}')
        r = run("deny", ["D1"])
        agent = Tracekit(r).gate(ReActAgent(tools=[self.tool()], llm=MockFunctionCallingLLM(response_generator=react)))
        self.assertEqual(ask(agent), "Tool call blocked by Tracekit policy: D1")
        call_id, tool, args = r.decide.call_args.args
        self.assertEqual((len(call_id), tool, args, self.ran), (36, "close_account", {"account": "ACC-9"}, []))

    def test_codeact_decides_the_code_before_it_runs(self):
        ran = []

        def execute(code: str) -> dict:
            ran.append(code)
            return {"output": "hi"}

        def respond(messages, **kw):
            if any("Result of executing" in (m.content or "") for m in messages):
                return ChatMessage(role="assistant", content="done")
            return ChatMessage(role="assistant", content="<execute>\nprint('hi')\n</execute>")
        r = run("deny", ["D1"])
        llm = MockFunctionCallingLLM(response_generator=respond)
        agent = Tracekit(r).gate(CodeActAgent(code_execute_fn=execute, llm=llm))
        ask(agent)
        self.assertEqual((r.decide.call_args.args[1:], ran), (("execute", {"code": "print('hi')"}), []))

    def workflow(self, r):
        triage = FunctionAgent(name="triage", description="Routes requests.", can_handoff_to=["billing"],
                               llm=model([HANDOFF]))
        billing = FunctionAgent(name="billing", description="Closes accounts.", tools=[self.tool()],
                                llm=model([CLOSE]))
        return Tracekit(r).gate(AgentWorkflow(agents=[triage, billing], root_agent="triage"))

    def test_an_agent_workflow_gates_the_handoff_and_every_agents_tools(self):
        r = run()
        self.assertEqual(ask(self.workflow(r)), "closed ACC-9")
        self.assertEqual([c.args for c in r.decide.call_args_list], [HANDOFF[2:] + HANDOFF[:2], CLOSE[2:] + CLOSE[:2]])
        self.assertEqual(self.ran, ["ACC-9"])

    def test_a_refused_handoff_hands_nothing_off(self):
        r = run()
        r.decide.side_effect = lambda call_id, tool, *a, **k: {"decision": "deny" if tool == "handoff" else "allow",
                                                              "rule_ids": ["D1"], "decision_id": "dec-1"}
        self.assertEqual(ask(self.workflow(r)), "Tool call blocked by Tracekit policy: D1")
        self.assertEqual((r.decide.call_count, self.ran), (1, []))

    def test_a_return_direct_tool_ends_the_run_only_when_it_ran(self):
        tool = FunctionTool.from_defaults(self.tool(), return_direct=True)
        ended = ask(gated(run(), tool, turns=([CLOSE], [("close_account", {"account": "ACC-7"}, "call-2")])))
        self.assertEqual((ended, self.ran), ("closed ACC-9", ["ACC-9"]))
        self.ran.clear()
        refused = ask(gated(run("deny", ["D1"]), tool))
        self.assertEqual((refused, self.ran), ("Tool call blocked by Tracekit policy: D1", []))

    def test_an_agent_a_tool_runs_is_gated_when_it_is_gated_too(self):
        r = run()
        tk = Tracekit(r)
        expert = tk.gate(FunctionAgent(tools=[self.tool()], llm=model([CLOSE])))

        async def ask_expert(question: str) -> str:
            """Ask the expert."""
            return str(await expert.run(user_msg=question))
        outer = tk.gate(FunctionAgent(tools=[ask_expert], llm=model([("ask_expert", {"question": "close"}, "q-1")])))
        self.assertEqual(ask(outer), "closed ACC-9")
        self.assertEqual(sorted(c.args[0] for c in r.decide.call_args_list), ["call-1", "q-1"])


@unittest.skipUnless(HAVE, "llama_index not installed")
class Said(Tools):
    """Each AgentOutput is recorded before its calls run: thinking, text and tool calls, under the ids they are decided
    by; the message itself only with the vault; a failure to record changes nothing for the agent."""

    def answer(self, r):
        def respond(messages, **kw):
            if not any(m.role == "tool" for m in messages):
                return ChatMessage(role="assistant", blocks=[
                    ThinkingBlock(content="the user wants ACC-9 closed"), TextBlock(text="Closing ACC-9."),
                    ToolCallBlock(tool_call_id="call-1", tool_name="close_account", tool_kwargs={"account": "ACC-9"})])
            return ChatMessage(role="assistant", content="done")
        agent = FunctionAgent(tools=[self.tool()], llm=MockFunctionCallingLLM(response_generator=respond))
        return ask(Tracekit(r).gate(agent))

    def test_the_reasoning_before_a_call_is_linked_to_it(self):
        r = ts.vault(run())
        self.assertEqual(self.answer(r), "done")
        first = ts.recorded(r)[0]
        self.assertEqual([t["id"] for t in first["tool_uses"]], ["call-1"])
        self.assertEqual(r.decide.call_args.args[0], "call-1")
        self.assertEqual(ts.segments(first), [("reasoning", "summary", "the user wants ACC-9 closed", []),
                                              ("text", "full", "Closing ACC-9.", ["call-1"])])
        self.assertEqual(ts.segments(ts.recorded(r)[-1]), [("text", "full", "done", [])])

    def test_without_the_vault_only_the_commitment(self):
        r = run()
        self.answer(r)
        self.assertTrue(all("body" not in f and f["content_digest"] for f in ts.recorded(r)))

    def test_a_failure_to_record_changes_nothing_for_the_agent(self):
        r = ts.failing(run())
        with self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
            self.assertEqual(self.answer(r), "done")
        self.assertEqual(self.ran, ["ACC-9"])


@unittest.skipUnless(HAVE, "llama_index not installed")
class Setup(unittest.TestCase):
    def test_a_run_handle_is_required(self):
        with self.assertRaisesRegex(TypeError, "instrument\\(\\) returns None"):
            Tracekit(None)

    def test_an_async_run_handle_works(self):
        sync = run()
        self.assertIs(Tracekit(AsyncRunHandle(sync)).run, sync)

    def test_only_an_agent_or_a_workflow_is_gated_and_only_once(self):
        tk = Tracekit(run())
        with self.assertRaisesRegex(TypeError, "agent or AgentWorkflow"):
            tk.gate(lambda: None)
        agent = tk.gate(FunctionAgent(llm=model()))
        with self.assertRaisesRegex(ValueError, "gated already"):
            Tracekit(run()).gate(agent)

    def test_an_object_that_takes_tool_calls_in_another_step_is_not_gated(self):
        class Elsewhere(FunctionAgent):
            @step
            async def run_tool(self, ctx: Context, ev: ToolCall) -> ToolCallResult:
                return await FunctionAgent.call_tool(self, ctx, ev)
        with self.assertRaisesRegex(TypeError, r"takes tool calls in the steps \['call_tool', 'run_tool'\]"):
            Tracekit(run()).gate(Elsewhere(llm=model()))

    def test_a_gated_workflow_keeps_its_class_and_steps(self):
        class Ping(Event):
            pass

        class Flow(AgentWorkflow):
            pass

        @step(workflow=Flow, skip_graph_checks=["reachability"])
        async def extra(ev: Ping) -> StopEvent:
            return StopEvent()
        agent = FunctionAgent(llm=model())
        flow = Tracekit(run()).gate(Flow(agents=[agent]))
        self.assertIsInstance(flow, Flow)
        self.assertEqual(type(flow).__name__, "Flow")
        self.assertIn("extra", flow._get_steps())


@unittest.skipUnless(HAVE, "llama_index not installed")
class RealSigner(unittest.TestCase):
    """On a real signer, in this process."""

    def signer(self, **config):
        s = SignerService(ac.tmpdir(self), policy=Engine({"untrusted": ["WebFetch"]}), **config)
        self.addCleanup(s.close)
        self.callers = []
        return s, Client(ac._serve(self, lambda identity, frame: (self.callers.append(identity),
                                                                  s.handle_frame(identity, frame))[1]))

    def records(self, s, rid, kind):
        return [e["event"] for e in s.log.storage.iter_run("default", rid) if e["event"]["type"] == kind]

    def test_a_payee_from_an_untrusted_tools_result_is_traced_to_it(self):
        s, client = self.signer()

        class Page(BaseModel):
            title: str
            pay_to: str

        def WebFetch(url: str) -> Page:   # noqa: N802 - the policy names the tool
            """Fetch a page."""
            return Page(title="Invoice 7", pay_to="mallory-acct-7731")

        def pay(to: str) -> str:
            """Pay someone."""
            return "paid"
        turns = ([("WebFetch", {"url": "https://docs.example.org/i"}, "w-1")],
                 [("pay", {"to": "mallory-acct-7731"}, "w-2")])
        with client.run(agent="provenance") as r:
            ask(Tracekit(r).gate(FunctionAgent(tools=[WebFetch, pay], llm=model(*turns))))
            rid = r.run_id
        d = next(e["data"] for e in self.records(s, rid, "policy.decision") if e.get("tool_call_id") == "w-2")
        source = d["provenance"][0]["source"]["run_seq"]
        [seen] = [e for e in self.records(s, rid, "input.observed") if e["run_seq"] == source]
        self.assertEqual((len(d["provenance"]), seen["data"]["source"]), (1, "llama_index:WebFetch:w-1"))

    def test_a_result_the_model_read_as_text_matches_what_the_gateway_saw_sent(self):
        s, client = self.signer(gateways=["mtls:spiffe://acme/*"], verify_tool_results="record",
                                authorize={"mtls:spiffe://acme/gateway": ["model_event"]})

        class Page(BaseModel):
            title: str

        def lookup(account: str) -> dict:
            """Look an account up."""
            return {"account": account, "open": False}

        def WebFetch(url: str) -> Page:   # noqa: N802 - the policy names the tool
            """Fetch a page."""
            return Page(title="Invoice 7")
        events = []
        turns = ([("lookup", {"account": "ACC-9"}, "l-1"), ("WebFetch", {"url": "https://docs.example.org/i"}, "w-1")],)
        with client.run(agent="gateway") as r:
            ask(Tracekit(r).gate(FunctionAgent(tools=[lookup, WebFetch], llm=model(*turns))), events)
            sent = [{"id": e.tool_id, "forms": gateway.result_forms(e.tool_output.content)}
                    for e in events if isinstance(e, ToolCallResult)]   # the tool messages the next request sends
            s.call(CallerIdentity("mtls", "spiffe://acme/gateway", True), "model_event", {
                "request_id": "gw-1", "run_id": r.run_id, "run_token": r.run_token,
                "caller": "{0.scheme}:{0.subject}".format(self.callers[0]),
                "stream": "gw", "client_seq": 0, "provider": "openai", "model": "m", "phase": "request",
                "tool_results": sent})
            rid = r.run_id
        self.assertEqual(len(sent), 2)
        self.assertEqual(self.records(s, rid, "reconcile.result_mismatch"), [])

    def test_two_calls_of_one_tool_named_by_it_both_run(self):
        """Ollama's and Google's integrations give each call its tool's name as its id."""
        s, client = self.signer()
        ran = []

        def close_account(account: str) -> str:
            """Close an account."""
            ran.append(account)
            return "closed " + account
        turns = ([("close_account", {"account": "A"}, "close_account"),
                  ("close_account", {"account": "B"}, "close_account")],)
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")   # every outcome recorded
            with client.run(agent="ollama") as r:
                ask(Tracekit(r).gate(FunctionAgent(tools=[close_account], llm=model(*turns))))
                rid = r.run_id
        self.assertEqual(sorted(ran), ["A", "B"])
        self.assertEqual(len({e["tool_call_id"] for e in self.records(s, rid, "tool.result")}), 2)


@unittest.skipUnless(HAVE, "llama_index not installed")
class VersionCheck(unittest.TestCase):
    """The version check the integration shares with the other hand-wired ones: a framework outside the version
    Tracekit is tested with warns once when the integration is built, one inside the range does not warn."""

    def test_it_warns_for_a_version_outside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.llama_index import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="0.0.1"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        msgs = [str(x.message) for x in w if "is wired but untested" in str(x.message)]
        self.assertEqual(1, len(msgs))
        self.assertIn("LlamaIndex 0.0.1 is wired but untested; Tracekit is tested with "
                      "llama-index-core>=0.14.25,<0.15", msgs[0])

    def test_it_does_not_warn_for_a_version_inside_the_tested_range(self):
        from tracekit.integrations import version_check
        from tracekit.integrations.llama_index import Tracekit
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="0.14.25"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Tracekit(mock.Mock())
        self.assertEqual([], [str(x.message) for x in w if "is wired but untested" in str(x.message)])


if __name__ == "__main__":
    unittest.main()
