"""tracekit.integrations.langchain beyond the adapter contract (tests/test_contract_langchain.py): the result
commitment, `ask` without a checkpointer, an interrupt raised inside a tool, an `ask` under each ToolNode error
handling, several asks in one ToolNode, and the async gate's signer calls off the event loop."""
import asyncio
import itertools
import json
import time
import types
import unittest
from unittest import mock

import adapter_contract as ac
import test_said as ts
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.testing import FakeSigner

try:
    from langchain.agents import create_agent
    from langchain.agents.middleware import wrap_tool_call
    from langchain.agents.structured_output import ToolStrategy
    from langchain_core.language_models import BaseChatModel
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_core.runnables import RunnableLambda
    from langchain_core.tools import tool
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode, tools_condition
    from langgraph.types import Command, interrupt

    from test_contract_langchain import TOOLS, StubModel
    from tracekit import autowire
    from tracekit.format.canon import event_hash
    from tracekit.integrations.langchain import TracekitMiddleware, tracekit_tool_node
except ImportError:   # optional: the dev extra installs them
    HAVE_LC = False
else:
    HAVE_LC = True

    @tool
    def confirm(question: str) -> str:
        """Ask the user, pausing the run."""
        return interrupt(question)

    @tool("pay")
    def counted_pay(to: str, cents: int) -> str:
        """Send money."""
        PAID.append(cents)
        return f"paid {cents}"

THREAD = {"configurable": {"thread_id": "t"}}
PAID = []   # the cents of each counted_pay that ran


def prompt(name, **args):
    return {"messages": [HumanMessage(json.dumps({"name": name, "args": args, "id": "call-1"}))]}


def tool_message(out):
    return next(m for m in out["messages"] if isinstance(m, ToolMessage))


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class Middleware(unittest.TestCase):
    def setUp(self):
        self.signer = FakeSigner(lambda tool, args: ("ask", ["R-PAY"]) if tool == "pay" else ("allow", []))
        r = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
        self.run = {"run_id": r["run_id"], "run_token": r["run_token"]}

    def agent(self, checkpointer=None):
        return create_agent(StubModel(), [*TOOLS, confirm], checkpointer=checkpointer,
                            middleware=[TracekitMiddleware(self.signer, self.run["run_id"], self.run["run_token"])])

    def recorded(self, typ):
        return [e["data"] for e in self.signer.read({**self.run, "limit": 1000})["events"] if e["type"] == typ]

    def test_result_is_recorded_as_a_commitment(self):
        sent = []
        complete = self.signer.complete
        self.signer.complete = lambda req: sent.append(req) or complete(req)
        self.agent().invoke(prompt("echo", text="hi"))
        self.assertEqual([r["result"] for r in sent], [event_hash("hi")])

    def test_ask_without_a_checkpointer_is_denied(self):
        out = self.agent().invoke(prompt("pay", to="a", cents=1))
        self.assertIn("no checkpointer", tool_message(out).content)
        self.assertEqual(self.recorded("approval.request"), [])

    def test_interrupt_inside_a_tool_is_not_recorded_as_an_outcome(self):
        a = self.agent(InMemorySaver())
        a.invoke(prompt("confirm", question="sure?"), THREAD)
        self.assertEqual(self.recorded("tool.result"), [])
        out = a.invoke(Command(resume="yes"), THREAD)
        self.assertEqual(tool_message(out).content, "yes")
        self.assertEqual([r["status"] for r in self.recorded("tool.result")], ["ok"])

    def test_args_changed_after_the_decision_complete_as_error(self):
        @wrap_tool_call
        def rewrite(request, handler):
            request.tool_call["args"]["text"] = "other"
            return handler(request)
        a = create_agent(StubModel(), TOOLS, middleware=[
            TracekitMiddleware(self.signer, self.run["run_id"], self.run["run_token"]), rewrite])
        a.invoke(prompt("echo", text="hi"))
        [r] = self.recorded("tool.result")
        self.assertEqual(r["status"], "error")

    def test_a_blocking_signer_call_does_not_stall_the_event_loop(self):   # issue #680
        """The async gate's signer calls run in a worker thread: while `decide` sleeps 0.3s, other tasks on the
        loop (here a 10ms tick) keep running - no inter-tick gap approaches the sleep."""
        decide = self.signer.decide
        self.signer.decide = lambda req: time.sleep(0.3) or decide(req)

        async def one_run_then_tick():
            a_task = asyncio.create_task(self.agent().ainvoke(prompt("echo", text="hi")))
            gaps, last = [], time.monotonic()
            while not a_task.done():
                await asyncio.sleep(0.01)
                now = time.monotonic()
                gaps.append(now - last)
                last = now
            out = await a_task
            self.assertEqual(tool_message(out).content, "hi")
            return max(gaps)
        slowest = asyncio.run(one_run_then_tick())
        self.assertEqual([d["tool_call_id"] for d in self.recorded("policy.decision")], ["call-1"])
        self.assertEqual([r["status"] for r in self.recorded("tool.result")], ["ok"])
        self.assertLess(slowest, 0.2, f"the event loop stalled {slowest:.3f}s for the signer")


if HAVE_LC:
    class ThinkingModel(BaseChatModel):
        """Thinks (a signed summary, and an open model's reasoning_content), says what it will do and calls echo; then
        answers, in the agent's structured output when it has one."""

        def _generate(self, messages, stop=None, run_manager=None, **kw):
            if isinstance(messages[-1], HumanMessage):
                msg = AIMessage([{"type": "thinking", "thinking": "the user wants an echo", "signature": "sig-1"},
                                 {"type": "text", "text": "Echoing."}],
                                additional_kwargs={"reasoning_content": "raw chain of thought"},
                                tool_calls=[{"id": "call-1", "name": "echo", "args": {"text": "hi"}}],
                                response_metadata={"model_name": "m-1", "model_provider": "anthropic"})
            elif self.structured:
                msg = AIMessage("", tool_calls=[{"id": "call-2", "name": "Echo", "args": {"text": "hi"}}])
            else:
                msg = AIMessage("done")
            return ChatResult(generations=[ChatGeneration(message=msg)])

        structured: bool = False

        def bind_tools(self, tools, **kw):
            return self

        @property
        def _llm_type(self):
            return "stub"


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class Said(unittest.TestCase):
    """create_agent's model responses are recorded: reasoning and text before each call, and each call, under its id,
    once it reaches the gate; the response itself only with the vault; a failure to record changes nothing for the
    agent."""

    def setUp(self):
        self.signer = FakeSigner()
        r = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
        self.run = {"run_id": r["run_id"], "run_token": r["run_token"]}
        self.sent = []
        model_event = self.signer.model_event
        self.signer.model_event = lambda req: self.sent.append(req) or model_event(req)

    def invoke(self, **kw):
        a = create_agent(ThinkingModel(structured="response_format" in kw), TOOLS, middleware=[
            TracekitMiddleware(self.signer, self.run["run_id"], self.run["run_token"])], **kw)
        return a.invoke({"messages": [HumanMessage("echo hi")]})

    def test_the_reasoning_before_a_call_is_linked_to_it(self):
        status = self.signer.status
        self.signer.status = lambda req: {**status(req), **ts.VAULT}
        self.invoke()
        first, call, last = self.sent
        self.assertNotIn("tool_uses", first)
        self.assertEqual(([t["id"] for t in call["tool_uses"]], call["exchange_id"]), (["call-1"], first["exchange_id"]))
        decided = [e["data"]["tool_call_id"] for e in self.signer.read({**self.run, "limit": 100})["events"]
                   if e["type"] == "policy.decision"]
        self.assertEqual(decided, ["call-1"])
        self.assertEqual((first["model"], first["provider"]), ("m-1", "anthropic"))
        self.assertEqual(ts.segments(first), [("reasoning", "full", "raw chain of thought", []),
                                              ("reasoning", "summary", "the user wants an echo", []),
                                              ("text", "full", "Echoing.", [])])
        self.assertEqual(first["body"]["output"][1]["encrypted_content"], "sig-1")
        self.assertEqual(ts.segments(last), [("text", "full", "done", [])])

    def test_without_the_vault_only_the_commitment_and_no_structured_output_call(self):
        out = self.invoke(response_format=ToolStrategy(dict(title="Echo", type="object",
                                                            properties={"text": {"type": "string"}})))
        self.assertEqual(out["structured_response"], {"text": "hi"})
        self.assertEqual(len(self.sent), 2)   # the response and its echo call: the structured answer said nothing else
        self.assertTrue(all("body" not in r and r["content_digest"] for r in self.sent))
        self.assertEqual([t["name"] for r in self.sent for t in r.get("tool_uses", ())], ["echo"])   # not Echo

    def test_a_call_another_middleware_stops_before_the_gate_is_not_recorded(self):
        """A person's reject, a call limit: the call never ran and no hook saw it; recorded, the signer would read it
        as one that ran with no decision (reconcile.hook_missing)."""
        from langchain.agents.middleware import HumanInTheLoopMiddleware, ToolCallLimitMiddleware
        mw = lambda: TracekitMiddleware(self.signer, self.run["run_id"], self.run["run_token"])
        a = create_agent(StubModel(), TOOLS, checkpointer=InMemorySaver(),
                         middleware=[HumanInTheLoopMiddleware({"echo": True}), mw()])
        a.invoke(prompt("echo", text="hi"), THREAD)
        a.invoke(Command(resume={"decisions": [{"type": "reject", "message": "no"}]}), THREAD)
        calls = [{"name": "echo", "args": {"text": str(i)}, "id": f"c{i}"} for i in range(3)]
        create_agent(StubModel(), TOOLS, middleware=[ToolCallLimitMiddleware(run_limit=1), mw()]).invoke(
            {"messages": [HumanMessage(json.dumps(calls))]})
        self.assertEqual([t["id"] for r in self.sent for t in r.get("tool_uses", ())], ["c0"])   # the one that ran
        decided = [e["data"]["tool_call_id"] for e in self.signer.read({**self.run, "limit": 100})["events"]
                   if e["type"] == "policy.decision"]
        self.assertEqual(decided, ["c0"])

    def test_a_failure_to_record_changes_nothing_for_the_agent(self):
        self.signer.model_event = mock.Mock(side_effect=SignerUnavailable("down"))
        with self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
            out = self.invoke()
        self.assertEqual(out["messages"][-1].content, "done")


def handle_tool_error(state):
    """The fallback of LangGraph's customer-support tutorial: `ToolNode(tools).with_fallbacks([RunnableLambda(
    handle_tool_error)], exception_key="error")`."""
    return {"messages": [ToolMessage(f"Error: {state.get('error')!r}\n please fix your mistakes.", tool_call_id=c["id"])
                         for c in state["messages"][-1].tool_calls]}


def tool_graph(node):
    g = StateGraph(MessagesState)
    g.add_node("model", lambda state: {"messages": [StubModel().invoke(state["messages"])]})
    g.add_node("tools", node)
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    return g.compile(checkpointer=InMemorySaver())


ERROR_HANDLING = {"default": {}, "True": {"handle_tool_errors": True}, "a string": {"handle_tool_errors": "failed"},
                  "a callable": {"handle_tool_errors": lambda e: f"Error: {e!r}"},
                  "a tuple": {"handle_tool_errors": (ValueError,)}, "a type": {"handle_tool_errors": ValueError},
                  "str, a type that isn't an exception": {"handle_tool_errors": str}}


class GatedNodes(unittest.TestCase):
    """Gated ToolNodes, built by hand and as instrument() wires them."""

    def setUp(self):
        for name in ("__init__", "_func", "_afunc", "with_fallbacks"):   # instrument() patches ToolNode for the process
            patcher = mock.patch.object(ToolNode, name, getattr(ToolNode, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.wired = ToolNode.__init__

    def nodes(self, tools=None, **kw):
        """(how, a function building the gated node of `tools`, else TOOLS): by hand, and a plain ToolNode as
        instrument() wires it, each on a signer of its own"""
        tools = tools or TOOLS
        for how in ("by hand", "instrument()"):
            ac.RAN.clear()
            ToolNode.__init__ = self.wired
            self.signer = FakeSigner(ac._rule)
            self.run = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
            if how == "by hand":
                yield how, lambda: tracekit_tool_node(tools, self.signer, self.run, **kw)
            else:
                autowire._langgraph(types.SimpleNamespace(client=self.signer, registered=self.run, **{
                    k: self.run[k] for k in ("run_id", "run_token")}))
                yield how, lambda: ToolNode(tools, **kw)


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class ErrorHandling(GatedNodes):
    """An `ask` pauses the graph whatever the ToolNode's handle_tool_errors and inside with_fallbacks, wired by hand
    or by instrument(); the tool's own errors are handled as configured."""

    def pause_and_approve(self, graph, mode="sync"):
        run = graph.invoke if mode == "sync" else lambda v, c: asyncio.run(graph.ainvoke(v, c))
        out = run(prompt("pay", to="a", cents=1), THREAD)
        self.assertIn("__interrupt__", out, [m.content for m in out["messages"]])
        self.assertEqual(ac.RAN, [])
        aid = out["__interrupt__"][0].value["tracekit"]["approval_id"]
        self.signer.approval_decide({"request_id": "ok-" + aid, "approval_id": aid, "decision": "approve"})
        out = run(Command(resume={"approval_id": aid}), THREAD)
        self.assertEqual((tool_message(out).content, ac.RAN), ("paid 1", ["pay"]))

    def test_an_ask_pauses_under_every_handle_tool_errors(self):
        for setting, kw in ERROR_HANDLING.items():
            for mode in ("sync", "async"):
                for how, node in self.nodes(**kw):
                    with self.subTest(setting=setting, wired=how, mode=mode):
                        self.pause_and_approve(tool_graph(node()), mode)

    def test_an_ask_pauses_through_with_fallbacks(self):   # the tutorial's create_tool_node_with_fallback
        for mode in ("sync", "async"):
            for how, node in self.nodes():
                with self.subTest(wired=how, mode=mode):
                    fallback = node().with_fallbacks([RunnableLambda(handle_tool_error)], exception_key="error")
                    self.pause_and_approve(tool_graph(fallback), mode)

    def test_the_tools_own_errors_are_handled_as_configured(self):
        for how, node in self.nodes(handle_tool_errors=True):
            with self.subTest(wired=how):
                out = tool_graph(node()).invoke(prompt("fail", why="boom"), THREAD)
                self.assertIn("ValueError('boom')", tool_message(out).content)
        for how, node in self.nodes(handle_tool_errors=str):   # a callable that is a type: ToolNode calls it
            with self.subTest(wired=how, handler=str):
                self.assertEqual(tool_message(tool_graph(node()).invoke(prompt("fail", why="boom"), THREAD)).content,
                                 "boom")
        for how, node in self.nodes():
            with self.subTest(wired=how, fallbacks=True):
                fallback = node().with_fallbacks([RunnableLambda(handle_tool_error)], exception_key="error")
                out = tool_graph(fallback).invoke(prompt("fail", why="boom"), THREAD)
                self.assertIn("please fix your mistakes", tool_message(out).content)


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class ManyAsks(GatedNodes):
    """#687: a message whose calls ask, beside one allowed and one denied call, in one ToolNode. LangGraph gives the node
    one resume value, by the order its calls reach interrupt(), and runs the node again from its start on each resume:
    the call a person approved ran only when it got there first (7 of 16 under ainvoke, 4 of 16 under invoke), and with
    three or more asks a call that ran was refused on the next pass, or the allowed call ran twice. Each ask is
    approved, rejected or left waiting, answered in a different order each time, then the run resumes once."""

    def outcomes(self, node, mode, answers, order):
        """{tool call id: (times it ran before the resume, whether the pause listed its approval, times it ran in all,
        what the model read: its result or the rule that refused it, the results the signer recorded, the rules of its
        recorded refusal)}, and whether the resume paused again"""
        graph = tool_graph(node)
        go = graph.invoke if mode == "sync" else lambda v, c: asyncio.run(graph.ainvoke(v, c))
        calls = [{"name": "pay", "args": {"to": "a", "cents": i}, "id": f"pay-{i}"} for i in range(len(answers))]
        calls += [{"name": "echo", "args": {"text": "hi"}, "id": "echo"},
                  {"name": "wipe", "args": {"path": "/"}, "id": "wipe"}]

        def ran():
            return {c["id"]: PAID.count(c["args"]["cents"]) if c["name"] == "pay" else ac.RAN.count(c["name"])
                    for c in calls}
        asked = go({"messages": [HumanMessage(json.dumps(calls))]}, THREAD)["__interrupt__"][0].value["tracekit"]
        before, listed = ran(), {a["tool_call_id"] for a in asked.get("approvals", ())}
        approvals = {r["tool_call_id"]: r["approval_id"] for r in self.recorded("approval.request")}
        for i in order:
            if answers[i] != "wait":
                self.signer.approval_decide({"request_id": f"{i}", "decision": answers[i],
                                             "approval_id": approvals[f"pay-{i}"]})
        out = go(Command(resume={"approval_id": asked["approval_id"]}), THREAD)
        blocked = "Tool call blocked by policy: "
        seen = {m.tool_call_id: m.content[len(blocked):].split(" ")[0] if m.content.startswith(blocked) else m.content
                for m in out["messages"] if isinstance(m, ToolMessage)}
        results = [r["tool_call_id"] for r in self.recorded("tool.result")]
        refused = {r["tool_call_id"]: r["rule_ids"] for r in self.recorded("approval.refused")}
        after = ran()
        return {c["id"]: (before[c["id"]], c["id"] in listed, after[c["id"]], seen.get(c["id"]),
                          results.count(c["id"]), refused.get(c["id"])) for c in calls}, "__interrupt__" in out

    def recorded(self, typ):
        return [e["data"] for e in self.signer.read({"run_id": self.run["run_id"], "run_token": self.run["run_token"],
                                                     "limit": 1000})["events"] if e["type"] == typ]

    def test_each_call_runs_once_or_is_refused_and_is_recorded_as_it_did(self):
        want = {"approve": lambda i: (0, True, 1, f"paid {i}", 1, None),
                "reject": lambda i: (0, True, 0, "TK-APPROVAL-REJECTED", 0, ["TK-APPROVAL-REJECTED"]),
                "wait": lambda i: (0, True, 0, "TK-APPROVAL-REQUESTED", 0, ["TK-APPROVAL-REQUESTED"])}
        cases = [*itertools.product(want, repeat=2), *itertools.product(want, repeat=3),
                 *itertools.product(("approve", "wait"), repeat=5)]
        for k, answers in enumerate(cases):
            orders = list(itertools.permutations(range(len(answers))))
            for mode in ("sync", "async"):
                for how, node in self.nodes(tools=[TOOLS[0], counted_pay, TOOLS[2]]):
                    with self.subTest(answers=answers, mode=mode, wired=how):
                        PAID.clear()
                        self.assertEqual(self.outcomes(node(), mode, answers, orders[k % len(orders)]),
                                         ({**{f"pay-{i}": want[a](i) for i, a in enumerate(answers)},
                                           "echo": (0, False, 1, "hi", 1, None),
                                           "wipe": (0, False, 0, "R-WIPE", 0, None)}, False))


class Jittery:
    """The client, with the pause a busy process may take between a call's client_seq and its send."""

    def __init__(self, client):
        self.client = client

    def __getattr__(self, name):
        def call(req):
            if "tool_call_id" in req:   # a model event, or the vault's status, names no call
                time.sleep(int(req["tool_call_id"][1:]) % 3 / 1000)
            return getattr(self.client, name)(req)
        return call


class Down:
    """A signer that cannot be reached."""

    def __getattr__(self, name):
        def call(req):
            raise SignerUnavailable("no signer answering")
        return call


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class Failures(ac.OnReal, unittest.TestCase):
    def setUp(self):
        ac.RAN.clear()
        self.client = Client(self.serve_signer())
        self.addCleanup(self.client.close)
        r = self.client.register_run({"agent": {"name": "test"}})
        self.run = {"run_id": r["run_id"], "run_token": r["run_token"]}

    def agent(self, signer, **kw):
        return create_agent(StubModel(), TOOLS, middleware=[TracekitMiddleware(signer, **self.run, **kw)])

    def test_parallel_sync_calls_reach_the_signer_in_order(self):
        calls = [{"name": "echo", "args": {"text": str(i)}, "id": f"c{i}"} for i in range(48)]
        for _ in range(2):   # within the signer's event burst
            out = self.agent(Jittery(self.client)).invoke({"messages": [HumanMessage(json.dumps(calls))]})
            self.assertEqual(out["messages"][-1].content, "done")
        types = [e["type"] for e in self.events(self.run)]
        self.assertEqual((types.count("policy.decision"), types.count("tool.result")), (96, 96))
        self.assertNotIn("capture.gap", types)

    def test_signer_unreachable_follows_the_fail_mode(self):
        out = self.agent(Down(), fail_modes={"default": "closed"}).invoke(prompt("echo", text="hi"))
        self.assertIn("signer unavailable", tool_message(out).content)
        self.assertEqual(ac.RAN, [])
        out = self.agent(Down(), fail_modes={"default": "open"}).invoke(prompt("echo", text="hi"))
        self.assertEqual((tool_message(out).content, ac.RAN), ("hi", ["echo"]))

    def test_signer_unreachable_follows_the_fail_mode_of_the_tools_class(self):
        @tool
        def terminal(commands: str) -> str:   # LangChain's ShellTool name: class shell in the default policy
            """Run commands."""
            ac.RAN.append("terminal")
            return "ran"
        agent = create_agent(StubModel(), [*TOOLS, terminal], middleware=[TracekitMiddleware(
            Down(), **self.run, fail_modes={"default": "closed", "shell": "open"})])
        self.assertEqual(tool_message(agent.invoke(prompt("terminal", commands="ls"))).content, "ran")
        self.assertIn("signer unavailable", tool_message(agent.invoke(prompt("echo", text="hi"))).content)
        self.assertEqual(ac.RAN, ["terminal"])

    def test_an_outage_reads_the_default_policy_once(self):
        """The fail mode's class comes from the shipped default policy, compiled once, not on every refused call."""
        from tracekit.integrations.claude_code import _tool_class
        from tracekit.signer import service
        _tool_class.cache_clear()
        with mock.patch.object(service, "load_policy", wraps=service.load_policy) as load:
            agent = self.agent(Down(), fail_modes={"default": "closed"})
            for _ in range(3):
                self.assertIn("signer unavailable", tool_message(agent.invoke(prompt("echo", text="hi"))).content)
        self.assertEqual(load.call_count, 1)

    def test_closed_run_refuses_the_call(self):
        self.client.close_run(dict(self.run))
        out = self.agent(self.client).invoke(prompt("echo", text="hi"))
        self.assertIn("run_closed", tool_message(out).content)
        self.assertEqual(ac.RAN, [])

    def test_a_failed_complete_leaves_the_result_unchanged(self):
        signer = mock.Mock(wraps=self.client)
        signer.complete.side_effect = SignerUnavailable("gone")
        with self.assertWarns(UserWarning):
            out = self.agent(signer).invoke(prompt("echo", text="hi"))
        self.assertEqual((tool_message(out).content, out["messages"][-1].content), ("hi", "done"))
        with self.assertWarns(UserWarning), self.assertRaises(ValueError):
            self.agent(signer).invoke(prompt("fail", why="boom"))


if __name__ == "__main__":
    unittest.main()
