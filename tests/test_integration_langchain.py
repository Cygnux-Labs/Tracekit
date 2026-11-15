"""tracekit.integrations.langchain beyond the adapter contract (tests/test_contract_langchain.py): the result
commitment, `ask` without a checkpointer, an interrupt raised inside a tool, an `ask` under each ToolNode error
handling, the held pass of a ToolNode with several calls of one message (#687), and the async gate's signer calls off
the event loop."""
import asyncio
import collections
import itertools
import json
import random
import threading
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
    from langgraph.types import Command, RetryPolicy, interrupt

    from test_contract_langchain import TOOLS, StubModel
    from test_signer_service import ME, OTHER, PAY_ASKS
    from tracekit import autowire
    from tracekit.format.canon import event_hash
    from tracekit.integrations.executor_tools import CALL_ID, EXECUTOR
    from tracekit.integrations.langchain import TracekitMiddleware, tracekit_tool_node
    from tracekit.signer import service as svc
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

    @tool("pay")
    def confirmed_pay(to: str, cents: int) -> str:
        """Send money once the person confirms: the tool's own pause."""
        answer = interrupt(f"pay {cents}?")
        PAID.append((cents, answer))
        return f"paid {cents} after {answer}"

    @tool("pay")
    def held_open_pay(to: str, cents: int) -> str:
        """Send money; a first run stays open while a second may start."""
        PAID.append(cents)
        held_open()
        return f"paid {cents}"

    @tool("pay")
    def asking_held_open_pay(to: str, cents: int) -> str:
        """Send money once the person confirms; a first run stays open while a second may start."""
        answer = interrupt(f"pay {cents}?")
        PAID.append(cents)
        held_open()
        return f"paid {cents} after {answer}"

THREAD = {"configurable": {"thread_id": "t"}}
PAID = []   # the cents of each counted_pay that ran; (cents, the answer it got) for confirmed_pay
SECOND = threading.Event()   # a pay's second run started (held_open)


def held_open():
    """A pay's first run waits (1 s at most) for a second run of it, so two passes that both run it overlap."""
    if len(PAID) > 1:
        SECOND.set()
    else:
        SECOND.wait(1)


def at_once(*fns):
    """The outputs of `fns`, run at once in threads of their own (what one raised, in its place)."""
    outs = [None] * len(fns)

    def run(i):
        try:
            outs[i] = fns[i]()
        except Exception as e:
            outs[i] = e
    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(fns))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return outs


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


def tool_graph(node, saver=None, **kw):
    """model <-> `node` (`kw`: add_node's, a retry_policy), on `saver` (else an InMemorySaver of its own)."""
    g = StateGraph(MessagesState)
    g.add_node("model", lambda state: {"messages": [StubModel().invoke(state["messages"])]})
    g.add_node("tools", node, **kw)
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    return g.compile(checkpointer=InMemorySaver() if saver is None else saver)


def runner(graph, mode):
    """graph.invoke, or graph.ainvoke run to its end"""
    return graph.invoke if mode == "sync" else lambda v, c: asyncio.run(graph.ainvoke(v, c))


def message(calls):
    return {"messages": [HumanMessage(json.dumps(calls))]}


def read(out):
    """{tool call id: what the model read}"""
    return {m.tool_call_id: m.content for m in out["messages"] if isinstance(m, ToolMessage)}


ERROR_HANDLING = {"default": {}, "True": {"handle_tool_errors": True}, "a string": {"handle_tool_errors": "failed"},
                  "a callable": {"handle_tool_errors": lambda e: f"Error: {e!r}"},
                  "a tuple": {"handle_tool_errors": (ValueError,)}, "a type": {"handle_tool_errors": ValueError},
                  "str, a type that isn't an exception": {"handle_tool_errors": str}}


class GatedNodes(unittest.TestCase):
    """Gated ToolNodes, built by hand and as instrument() wires them."""

    def setUp(self):
        for name in ("__init__", "_func", "_afunc", "_arun_one", "with_fallbacks"):   # instrument() patches ToolNode
            patcher = mock.patch.object(ToolNode, name, getattr(ToolNode, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.wired = ToolNode.__init__

    def nodes(self, tools=None, rule=ac._rule, **kw):
        """(how, a function building the gated node of `tools`, else TOOLS): by hand, and a plain ToolNode as
        instrument() wires it, each on a signer of its own whose policy is `rule`"""
        tools = tools or TOOLS
        for how in ("by hand", "instrument()"):
            ac.RAN.clear()
            PAID.clear()
            ToolNode.__init__ = self.wired
            self.signer = FakeSigner(rule)
            self.run = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
            if how == "by hand":
                yield how, lambda: tracekit_tool_node(tools, self.signer, self.run, **kw)
            else:
                autowire._langgraph(types.SimpleNamespace(client=self.signer, registered=self.run, **{
                    k: self.run[k] for k in ("run_id", "run_token")}))
                yield how, lambda: ToolNode(tools, **kw)

    def recorded(self, typ, approval_id=None):
        return [e["data"] for e in self.signer.read({"run_id": self.run["run_id"], "run_token": self.run["run_token"],
                                                     "limit": 1000})["events"]
                if e["type"] == typ and approval_id in (None, e["data"].get("approval_id"))]

    def approve(self, aid, decision="approve"):
        self.signer.approval_decide({"request_id": f"{decision}-{aid}", "decision": decision, "approval_id": aid})


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


class Driven(GatedNodes):
    def drive(self, go, first, approve=(), most=8):
        """(the last output, each pause in order: "tracekit" or the tool's own question): `first` sent, then each pause
        answered, by its interrupt id, until the run ends: a person approves the listed approvals of the calls in
        `approve` (any other is left waiting), and answers a tool's own question "yes: <question>"."""
        out, pauses = go(first, THREAD), []
        while "__interrupt__" in out and len(pauses) < most:
            answers = {}
            for i in out["__interrupt__"]:   # create_agent's calls are tasks of their own: they pause together
                shown = i.value.get("tracekit") if isinstance(i.value, dict) else None
                pauses.append("tracekit" if shown else i.value)
                for a in shown.get("approvals", [shown]) if shown else ():
                    if a["tool_call_id"] in approve and not self.recorded("approval", a["approval_id"]):
                        self.approve(a["approval_id"])
                answers[i.id] = {"approval_id": shown["approval_id"]} if shown else f"yes: {i.value}"
            out = go(Command(resume=answers), THREAD)
        return out, pauses

    def graphs(self, tools, rule=ac._rule):
        """(how, the graph): create_agent, and the gated ToolNodes (GatedNodes.nodes), each on a signer of its own"""
        ToolNode.__init__ = self.wired
        ac.RAN.clear()
        PAID.clear()
        self.signer = FakeSigner(rule)
        self.run = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
        yield "create_agent", create_agent(StubModel(), tools, checkpointer=InMemorySaver(), middleware=[
            TracekitMiddleware(self.signer, self.run["run_id"], self.run["run_token"])])
        for how, node in self.nodes(tools=tools, rule=rule):
            yield how, tool_graph(node())


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class ManyAsks(Driven):
    """#687: a message whose calls ask, beside one allowed and one denied call, in one ToolNode. LangGraph gives the node
    one resume value, by the order its calls reach interrupt(), and runs the node again from its start on each resume:
    on main the call a person approved ran only when it got there first, and with three or more asks a call that ran
    was refused on the next pass, or the allowed call ran twice. Each ask is approved, rejected or left waiting,
    answered in a different order each time, then the run resumes once."""

    def outcomes(self, node, mode, answers, order):
        """{tool call id: (times it ran before the resume, whether the pause listed its approval, times it ran in all,
        what the model read: its result or the rule that refused it, the results the signer recorded, the rules of its
        recorded refusal)}, and whether the resume paused again"""
        go = runner(tool_graph(node), mode)
        calls = [{"name": "pay", "args": {"to": "a", "cents": i}, "id": f"pay-{i}"} for i in range(len(answers))]
        calls += [{"name": "echo", "args": {"text": "hi"}, "id": "echo"},
                  {"name": "wipe", "args": {"path": "/"}, "id": "wipe"}]

        def ran():
            return {c["id"]: PAID.count(c["args"]["cents"]) if c["name"] == "pay" else ac.RAN.count(c["name"])
                    for c in calls}
        asked = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
        before, listed = ran(), {a["tool_call_id"] for a in asked.get("approvals", ())}
        approvals = {r["tool_call_id"]: r["approval_id"] for r in self.recorded("approval.request")}
        for i in order:
            if answers[i] != "wait":
                self.approve(approvals[f"pay-{i}"], answers[i])
        out = go(Command(resume={"approval_id": asked["approval_id"]}), THREAD)
        blocked = "Tool call blocked by policy: "
        seen = {k: v[len(blocked):].split(" ")[0] if v.startswith(blocked) else v for k, v in read(out).items()}
        results = [r["tool_call_id"] for r in self.recorded("tool.result")]
        refused = {r["tool_call_id"]: r["rule_ids"] for r in self.recorded("approval.refused")}
        after = ran()
        return {c["id"]: (before[c["id"]], c["id"] in listed, after[c["id"]], seen.get(c["id"]),
                          results.count(c["id"]), refused.get(c["id"])) for c in calls}, "__interrupt__" in out

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
                        self.assertEqual(self.outcomes(node(), mode, answers, orders[k % len(orders)]),
                                         ({**{f"pay-{i}": want[a](i) for i, a in enumerate(answers)},
                                           "echo": (0, False, 1, "hi", 1, None),
                                           "wipe": (0, False, 0, "R-WIPE", 0, None)}, False))

    def test_the_approved_one_of_two_asks_runs_every_time(self):   # parallel_ask_invoke.py, parallel_ask_ainvoke.py
        """The #687 probes, 16 trials each, the signer's answers jittered: two asks, the shown one approved, one resume
        by its id. On main the approved call ran only when its gate reached interrupt() first (in 8 of 16 trials under
        invoke and 2 of 16 under ainvoke, measured), and the run paused again every time."""
        calls = [{"name": "pay", "args": {"to": "a", "cents": i}, "id": f"c{i}"} for i in (1, 2)]
        for mode in ("sync", "async"):
            for trial in range(16):
                for how, node in self.nodes(tools=[counted_pay]):
                    with self.subTest(mode=mode, trial=trial, wired=how):
                        jitter, request = random.Random(trial), self.signer.approval_request
                        self.signer.approval_request = lambda req: time.sleep(jitter.random() / 50) or request(req)
                        go = runner(tool_graph(node()), mode)
                        shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                        self.approve(shown["approval_id"])
                        out = go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)
                        self.assertEqual((shown["tool_call_id"], PAID, "__interrupt__" in out), ("c1", [1], False))
                        self.assertTrue(read(out)["c2"].startswith("Tool call blocked by policy: TK-APPROVAL-REQUESTED"))

    def test_every_listed_ask_approved_runs_each_call_once_after_one_resume(self):
        """allowed_sibling_runs.py, many_asks_one_at_a_time.py: an allowed call beside 1 and 3 asks, every approval the
        pause lists approved. On main each resume answered one ask and the run paused again, and the allowed call ran
        again on each resume."""
        for n in (1, 3):
            calls = [{"name": "echo", "args": {"text": "hi"}, "id": "e"}] + [
                {"name": "pay", "args": {"to": "a", "cents": i}, "id": f"c{i}"} for i in range(n)]
            for mode in ("sync", "async"):
                for how, node in self.nodes(tools=[TOOLS[0], counted_pay]):
                    with self.subTest(asks=n, mode=mode, wired=how):
                        go, resumes = runner(tool_graph(node()), mode), 0
                        out = go(message(calls), THREAD)
                        while "__interrupt__" in out and resumes < 5:
                            shown = out["__interrupt__"][0].value["tracekit"]
                            for a in shown.get("approvals", [shown]):
                                if not self.recorded("approval", a["approval_id"]):
                                    self.approve(a["approval_id"])
                            out = go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)
                            resumes += 1
                        self.assertEqual((resumes, sorted(PAID), ac.RAN), (1, list(range(n)), ["echo"]))
                        self.assertEqual(read(out), {"e": "hi", **{f"c{i}": f"paid {i}" for i in range(n)}})
                        self.assertEqual(sorted(r["tool_call_id"] for r in self.recorded("tool.result")),
                                         sorted(c["id"] for c in calls))

    def test_approved_after_its_refusal_the_models_retry_runs(self):   # approve_then_retry.py
        """Two asks, the shown one approved: the other is refused, naming its approval. A person then grants it and the
        model retries the call (a new call id): the retry pauses once and runs on the resume. On main the resume ran
        whichever call reached interrupt() first and the run paused again, so no call was refused."""
        calls = [{"name": "pay", "args": {"to": "a", "cents": i}, "id": f"c{i}"} for i in (1, 2)]
        for mode in ("sync", "async"):
            for how, node in self.nodes(tools=[counted_pay]):
                with self.subTest(mode=mode, wired=how):
                    go = runner(tool_graph(node()), mode)
                    shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                    self.approve(shown["approval_id"])
                    refused = read(go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)).get("c2", "")
                    self.assertEqual(PAID, [1])
                    self.assertTrue(refused.startswith("Tool call blocked by policy: TK-APPROVAL-REQUESTED (approval "),
                                    refused)
                    self.approve(refused.split("(approval ")[1].split(")")[0])
                    out = go(message([dict(calls[1], id="c3")]), THREAD)
                    self.assertIn("__interrupt__", out)
                    out = go(Command(resume={"approval_id": out["__interrupt__"][0].value["tracekit"]["approval_id"]}),
                             THREAD)
                    self.assertEqual((read(out)["c3"], PAID), ("paid 2", [1, 2]))


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class ToolPauses(Driven):
    """A tool that pauses the run itself (interrupt()), beside or under an `ask`. LangGraph pairs resume values with a
    node's interrupt() calls by their order, and runs the node again from its start on each resume. On main the tool's
    approved call was refused once the person answered it (TK-APPROVAL-CONSUMED), and a call that ran before the tool's
    pause ran again, or was asked for a second approval."""

    def test_a_tool_asked_under_an_approval_gets_the_persons_own_answer(self):
        for mode in ("sync", "async"):
            for how, graph in self.graphs([confirmed_pay]):
                with self.subTest(mode=mode, built=how):
                    PAID.clear()
                    out, pauses = self.drive(runner(graph, mode), message(
                        [{"name": "pay", "args": {"to": "a", "cents": 1}, "id": "pay-1"}]), approve={"pay-1"})
                    self.assertEqual((pauses, read(out)), (["tracekit", "pay 1?"], {"pay-1": "paid 1 after yes: pay 1?"}))
                    self.assertEqual({t: [r["tool_call_id"] for r in self.recorded(t)] for t in ("approval.request",
                                                                                                 "tool.result")},
                                     {"approval.request": ["pay-1"], "tool.result": ["pay-1"]})
                    self.assertEqual(PAID, [(1, "yes: pay 1?")])   # it ran once, with the person's answer

    def test_a_tool_that_asks_beside_other_calls_gets_the_answer_and_each_call_runs_once(self):
        """tool_interrupt_eight_shapes.py, probe_tool_interrupt2.py: a pay that asks, and then asks the person itself,
        beside an allowed call, and beside another ask left waiting."""
        shapes = {"beside an allowed call": [{"name": "echo", "args": {"text": "hi"}, "id": "e"}],
                  "beside another ask": [{"name": "pay", "args": {"to": "a", "cents": 2}, "id": "pay-2"},
                                         {"name": "echo", "args": {"text": "hi"}, "id": "e"}]}
        for shape, others in shapes.items():
            calls = [{"name": "pay", "args": {"to": "a", "cents": 1}, "id": "pay-1"}, *others]
            for mode in ("sync", "async"):
                for how, graph in self.graphs([confirmed_pay, TOOLS[0]]):
                    with self.subTest(shape=shape, mode=mode, built=how):
                        out, pauses = self.drive(runner(graph, mode), message(calls), approve={"pay-1"})
                        self.assertEqual((PAID, ac.RAN), ([(1, "yes: pay 1?")], ["echo"]))
                        self.assertEqual((pauses.count("pay 1?"), set(pauses)), (1, {"tracekit", "pay 1?"}))
                        seen = {k: v.split(" (")[0] for k, v in read(out).items()}
                        self.assertEqual(seen, {"pay-1": "paid 1 after yes: pay 1?", "e": "hi", **(
                            {"pay-2": "Tool call blocked by policy: TK-APPROVAL-REQUESTED"} if len(others) > 1 else {})})
                        self.assertEqual(sorted(r["tool_call_id"] for r in self.recorded("tool.result")), ["e", "pay-1"])
                        self.assertEqual(sorted(r["tool_call_id"] for r in self.recorded("approval.request")),
                                         sorted(c["id"] for c in calls if c["name"] == "pay"))

    def test_a_tool_that_pauses_beside_asks_gets_the_answer_and_no_call_runs_or_asks_twice(self):
        calls = [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "pay-0"},
                 {"name": "pay", "args": {"to": "a", "cents": 1}, "id": "pay-1"},
                 {"name": "confirm", "args": {"question": "sure?"}, "id": "confirm"},
                 {"name": "echo", "args": {"text": "hi"}, "id": "echo"}]
        for mode in ("sync", "async"):
            for how, graph in self.graphs([counted_pay, confirm, TOOLS[0]]):
                with self.subTest(mode=mode, built=how):
                    PAID.clear()
                    ac.RAN.clear()
                    out, pauses = self.drive(runner(graph, mode), message(calls), approve={"pay-0"})
                    self.assertEqual((set(pauses), pauses.count("sure?")), ({"tracekit", "sure?"}, 1))
                    self.assertEqual({k: v.split(" (")[0] for k, v in read(out).items()},
                                     {"pay-0": "paid 0", "pay-1": "Tool call blocked by policy: TK-APPROVAL-REQUESTED",
                                      "confirm": "yes: sure?", "echo": "hi"})
                    self.assertEqual({t: sorted(r["tool_call_id"] for r in self.recorded(t))
                                      for t in ("approval.request", "tool.result")},
                                     {"approval.request": ["pay-0", "pay-1"], "tool.result": ["confirm", "echo", "pay-0"]})
                    self.assertEqual((PAID, ac.RAN), ([0], ["echo"]))   # each ran once

    def test_an_executors_call_stays_the_executors_and_an_approved_call_runs_once(self):
        """probe_executor_and_mixed.py, probe_executor_ask.py: [refund (a tool executor's, whose policy asks), pay-0 and
        pay-1 (asks), confirm (pauses itself)], pay-0 approved and pay-1 left waiting. The pass neither decides nor
        lists the executor's call. On main pay-0 was asked for a second approval, refused on the last resume
        (TK-APPROVAL-CONSUMED), and the model never read its result."""
        @tool
        def refund(cents: int) -> str:
            """An executor's action: the executor decides it."""
            ac.RAN.append(("refund", CALL_ID.get()))
            return "refunded"
        refund.metadata = {EXECUTOR: True}
        calls = [{"name": "refund", "args": {"cents": 1}, "id": "x1"},
                 {"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"},
                 {"name": "pay", "args": {"to": "a", "cents": 1}, "id": "p1"},
                 {"name": "confirm", "args": {"question": "sure?"}, "id": "q"}]
        for mode in ("sync", "async"):
            for how, node in self.nodes(tools=[refund, counted_pay, confirm],
                                        rule=lambda t, a: ("ask", ["R-REFUND"]) if t == "refund" else ac._rule(t, a)):
                with self.subTest(mode=mode, wired=how):
                    out, pauses = self.drive(runner(tool_graph(node()), mode), message(calls), approve={"p0"})
                    self.assertEqual((pauses, PAID, set(ac.RAN)), (["tracekit", "sure?"], [0], {("refund", "x1")}))
                    self.assertEqual({k: v.split(" (")[0] for k, v in read(out).items()},
                                     {"x1": "refunded", "p0": "paid 0", "q": "yes: sure?",
                                      "p1": "Tool call blocked by policy: TK-APPROVAL-REQUESTED"})
                    self.assertEqual(sorted(r["tool_call_id"] for r in self.recorded("approval.request")), ["p0", "p1"])
                    self.assertNotIn("x1", [d["tool_call_id"] for d in self.recorded("policy.decision")])

    def test_a_retry_runs_again_only_the_call_that_raised(self):   # probe_retry.py
        """A RetryPolicy retry runs the node again from its start: the call that raised runs again as a new attempt,
        and the allowed call beside it is given back. On main it ran again too."""
        failed = []

        @tool
        def flaky(x: int) -> str:
            """Fails the first time."""
            ac.RAN.append("flaky")
            if not failed:
                failed.append(1)
                raise ConnectionError("transient")
            return "ok"
        calls = [{"name": "flaky", "args": {"x": 1}, "id": "f"}, {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
        retry = RetryPolicy(max_attempts=3, initial_interval=0.01, retry_on=ConnectionError)
        for mode in ("sync", "async"):
            for how, node in self.nodes(tools=[flaky, TOOLS[0]]):
                with self.subTest(mode=mode, wired=how):
                    failed.clear()
                    out = runner(tool_graph(node(), retry_policy=retry), mode)(message(calls), THREAD)
                    self.assertEqual((read(out), collections.Counter(ac.RAN)),
                                     ({"f": "ok", "e": "hi"}, {"flaky": 2, "echo": 1}))
                    self.assertEqual(sorted((r["tool_call_id"], r["attempt"], r["status"])
                                            for r in self.recorded("tool.result")),
                                     [("e", 0, "ok"), ("f", 0, "error"), ("f", 1, "ok")])

    def test_a_slow_sibling_ends_before_a_tools_own_pause_is_passed_on(self):   # probe_async_race.py
        """A slow call (allowed, or approved) beside a tool that pauses the run itself runs once and is recorded once.
        On main it ran again on the resume, and under ainvoke its first run was cut off before it was recorded."""
        @tool
        def slow_echo(text: str) -> str:
            """Echo, slowly."""
            time.sleep(0.2)
            ac.RAN.append("slow_echo")
            return text

        @tool("pay")
        def slow_pay(to: str, cents: int) -> str:
            """Send money, slowly."""
            time.sleep(0.2)
            ac.RAN.append(f"pay{cents}")
            return f"paid {cents}"
        q = {"name": "confirm", "args": {"question": "sure?"}, "id": "q"}
        slow = {"allowed": ([slow_echo, confirm], {"name": "slow_echo", "args": {"text": "hi"}, "id": "e"}, "hi"),
                "approved": ([slow_pay, confirm], {"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"},
                             "paid 0")}
        for label, (tools, call, result) in slow.items():
            for mode in ("sync", "async"):
                for how, node in self.nodes(tools=tools):
                    with self.subTest(sibling=label, mode=mode, wired=how):
                        out, pauses = self.drive(runner(tool_graph(node()), mode), message([call, q]),
                                                 approve={call["id"]})
                        self.assertEqual((read(out), ac.RAN), ({call["id"]: result, "q": "yes: sure?"},
                                                               ["slow_echo" if label == "allowed" else "pay0"]))
                        self.assertEqual(sorted(r["tool_call_id"] for r in self.recorded("tool.result")),
                                         sorted([call["id"], "q"]))
                        self.assertEqual(len(self.recorded("approval.request")), int(label == "approved"))

    def test_a_call_id_twice_in_one_message_runs_neither_call(self):   # probe851.py dup, probe851_dupslow.py
        """Two pays under one call id, beside echo. What the signer keeps of a call is by id: at e7158780b5 the second
        pay took up the first's consumed plan, so one approval paid twice and one result was recorded. Both are
        refused now, undecided, each in a message of its own; echo runs."""
        @tool("pay")
        def slow_pay(to: str, cents: int) -> str:
            """Send money, slowly."""
            PAID.append(cents)
            time.sleep(0.2)
            return f"paid {cents}"
        pay, echo = ({"name": "pay", "args": {"to": "mallory", "cents": 500}, "id": "c1"},
                     {"name": "echo", "args": {"text": "hi"}, "id": "e"})
        refused = "Tool call blocked by policy: the message has 2 calls with id 'c1', so none of them runs"
        for mode in ("sync", "async"):
            for how, node in self.nodes(tools=[slow_pay, TOOLS[0]]):
                with self.subTest(mode=mode, wired=how):
                    out, pauses = self.drive(runner(tool_graph(node()), mode), message([pay, pay, echo]),
                                             approve={"c1"})
                    self.assertEqual((PAID, ac.RAN, pauses), ([], ["echo"], []))
                    self.assertEqual([m.content for m in out["messages"]
                                      if isinstance(m, ToolMessage) and m.tool_call_id == "c1"], [refused] * 2)
                    self.assertEqual([d["tool_call_id"] for d in self.recorded("policy.decision")], ["e"])

    def test_an_approved_call_cut_off_mid_run_never_runs_again_on_its_approval(self):   # probe851.py cancel, crash
        """The resume's ainvoke cancelled by asyncio.wait_for while the approved pay ran, or a BaseException out of the
        tool, then the run resumed again in the same process. At e7158780b5 its plan still said it could run, and it
        paid twice on one consume. The signer judges it again now: its approval was used (TK-APPROVAL-CONSUMED)."""
        class Cut(BaseException):
            """The process dying mid-tool."""
        cut = []

        @tool("pay")
        async def hanging_pay(to: str, cents: int) -> str:
            """Send money, then wait for a slow confirmation."""
            PAID.append(cents)
            await asyncio.sleep(5)
            return f"paid {cents}"

        @tool("pay")
        def dying_pay(to: str, cents: int) -> str:
            """Send money; its first run dies before it ends."""
            PAID.append(cents)
            if not cut:
                cut.append(1)
                raise Cut()
            return f"paid {cents}"
        calls = [{"name": "pay", "args": {"to": "bob", "cents": 120}, "id": "p0"},
                 {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
        for how_cut, pay in (("asyncio.wait_for", hanging_pay), ("BaseException", dying_pay)):
            for how, node in self.nodes(tools=[pay, TOOLS[0]]):
                with self.subTest(cut=how_cut, wired=how):
                    cut.clear()
                    graph = tool_graph(node())
                    go = runner(graph, "async" if how_cut == "asyncio.wait_for" else "sync")
                    shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                    self.approve(shown["approval_id"])
                    resume = Command(resume={"approval_id": shown["approval_id"]})
                    if how_cut == "asyncio.wait_for":
                        with self.assertRaises(asyncio.TimeoutError):
                            asyncio.run(asyncio.wait_for(graph.ainvoke(resume, THREAD), 0.5))
                    else:
                        with self.assertRaises(Cut):
                            graph.invoke(resume, THREAD)
                    self.assertEqual(PAID, [120])
                    out = go(resume, THREAD)
                    self.assertEqual(PAID, [120])   # never again on the one approval
                    self.assertTrue(read(out)["p0"].startswith("Tool call blocked by policy: TK-APPROVAL-CONSUMED"),
                                    read(out)["p0"])
                    self.assertEqual(read(out)["e"], "hi")

    def test_a_signer_of_the_apps_own_without_call_state_still_approves(self):
        """A SignerAPI of the app's own that predates call_state: a resumed node decides its calls again, as 1.6 did.
        At e7158780b5 a single call's resume raised AttributeError, so no approved call of it ran."""
        class Older:
            def __init__(self, signer):
                self.signer = signer

            def __getattr__(self, name):
                if name == "call_state":
                    raise AttributeError(name)
                return getattr(self.signer, name)
        pay = {"name": "pay", "args": {"to": "a", "cents": 1}, "id": "p"}
        for calls in ([pay], [pay, {"name": "echo", "args": {"text": "hi"}, "id": "e"}]):
            for mode in ("sync", "async"):
                with self.subTest(calls=len(calls), mode=mode):
                    ac.RAN.clear()
                    self.signer = FakeSigner(ac._rule)
                    self.run = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
                    node = tracekit_tool_node(TOOLS, Older(self.signer), self.run)
                    out, pauses = self.drive(runner(tool_graph(node), mode), message(calls), approve={"p"})
                    self.assertEqual((pauses, read(out)["p"], ac.RAN.count("pay")), (["tracekit"], "paid 1", 1))

    def test_a_signer_without_call_claim_never_lets_a_paused_call_go_on(self):   # probe851_pausedrace_noclaim.py
        """A SignerAPI of the app's own without call_claim can't say that no other pass went on with an approved call
        after its tool's own pause: the call is refused once the person answers it, as in 1.6, and never runs twice."""
        class NoClaim:
            def __init__(self, signer):
                self.signer = signer

            def __getattr__(self, name):
                if name == "call_claim":
                    raise AttributeError(name)
                return getattr(self.signer, name)
        pay = {"name": "pay", "args": {"to": "a", "cents": 1}, "id": "pay-1"}
        for calls in ([pay], [pay, {"name": "echo", "args": {"text": "hi"}, "id": "e"}]):
            for mode in ("sync", "async"):
                with self.subTest(calls=len(calls), mode=mode):
                    PAID.clear()
                    self.signer = FakeSigner(ac._rule)
                    self.run = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
                    node = tracekit_tool_node([confirmed_pay, TOOLS[0]], NoClaim(self.signer), self.run)
                    out, pauses = self.drive(runner(tool_graph(node), mode), message(calls), approve={"pay-1"})
                    self.assertEqual((pauses, PAID, read(out)["pay-1"]), (
                        ["tracekit", "pay 1?"], [], "Tool call blocked by policy: the signer has no call_claim"))

    def test_a_pass_cut_off_while_it_claims_a_call_gives_the_true_reason(self):   # probe851_claim.py claimcut
        """An approved pay whose tool asked the person itself; the answer's pass is cut off while it claims the call
        (ainvoke cancelled during call_claim; a BaseException out of call_claim after the signer said yes), then the
        run resumes again in the same process. At 1ad4d100e5 the plan stayed running, and the model read that another
        resume of the thread ran it. The signer judges it again now: its approval was used."""
        class Cut(BaseException):
            """The pass dying while it claims."""
        calls = [{"name": "pay", "args": {"to": "a", "cents": 1}, "id": "pay-1"},
                 {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
        for mode in ("sync", "async"):
            for how, node in self.nodes(tools=[confirmed_pay, TOOLS[0]]):
                with self.subTest(mode=mode, wired=how):
                    graph = tool_graph(node())
                    go = runner(graph, mode)
                    shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                    self.approve(shown["approval_id"])
                    out = go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)
                    self.assertEqual(out["__interrupt__"][0].value, "pay 1?")
                    claim, cut, claiming, release = self.signer.call_claim, [], threading.Event(), threading.Event()

                    def cut_claim(req):
                        if cut:
                            return claim(req)
                        cut.append(1)
                        out = claim(req)   # the signer says yes, then the pass is cut off
                        if mode == "sync":
                            raise Cut()
                        claiming.set()
                        release.wait(5)   # its ainvoke is cancelled meanwhile
                        return out

                    async def cancelled():
                        task = asyncio.ensure_future(graph.ainvoke(Command(resume="yes"), THREAD))
                        await asyncio.to_thread(claiming.wait, 5)
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                        release.set()
                    self.signer.call_claim = cut_claim
                    if mode == "async":
                        asyncio.run(cancelled())
                    else:
                        with self.assertRaises(Cut):
                            graph.invoke(Command(resume="yes"), THREAD)
                    out = go(Command(resume="yes"), THREAD)
                    self.assertEqual(PAID, [])
                    self.assertTrue(read(out)["pay-1"].startswith("Tool call blocked by policy: TK-APPROVAL-CONSUMED"),
                                    read(out)["pay-1"])

    def test_a_cancelled_claim_leaves_a_call_another_pass_runs_alone(self):
        """Three async resumes of one thread in one process: A runs an allowed call; B is cancelled while it tries to
        claim that call; then C resumes while A still runs it. At 93a34eebb0 B's cancellation marked A's running plan
        cut, so C ran the call a second time. A pass cuts only a plan it took itself now: C is refused."""
        calls = [{"name": "pay", "args": {"to": "a", "cents": 1}, "id": "pay-1"},
                 {"name": "slow", "args": {"text": "hi"}, "id": "s"}]
        claim, held = TracekitMiddleware._claim, {}

        @tool
        async def slow(text: str) -> str:
            """Echo; its first run lasts until C's pass ends."""
            ac.RAN.append("slow")
            if len(ac.RAN) == 1:
                held["started"].set()
                await asyncio.wait_for(held["c_done"].wait(), 5)
            return text

        def claiming_slowly(gate_self, request, p, *rest):
            if request.tool_call["id"] == "s":
                held["claims"] += 1
                if held["claims"] == 2:   # B's, which is cancelled meanwhile
                    held["claiming"].set()
                    held["let_b_go"].wait(5)
            return claim(gate_self, request, p, *rest)

        async def three(graph, resume):
            held.update(started=asyncio.Event(), c_done=asyncio.Event())
            a = asyncio.ensure_future(graph.ainvoke(resume, THREAD))
            await held["started"].wait()
            b = asyncio.ensure_future(graph.ainvoke(resume, THREAD))
            await asyncio.to_thread(held["claiming"].wait, 5)
            b.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await b
            held["let_b_go"].set()
            c = await graph.ainvoke(resume, THREAD)
            held["c_done"].set()
            return c, await a
        for how, node in self.nodes(tools=[counted_pay, slow]):
            with self.subTest(wired=how):
                held.update(claims=0, claiming=threading.Event(), let_b_go=threading.Event())
                graph = tool_graph(node())
                shown = graph.invoke(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                self.approve(shown["approval_id"])
                with mock.patch.object(TracekitMiddleware, "_claim", claiming_slowly):
                    c, a = asyncio.run(three(graph, Command(resume={"approval_id": shown["approval_id"]})))
                self.assertEqual((ac.RAN, read(a)["s"]), (["slow"], "hi"))
                self.assertEqual(read(c)["s"], "Tool call blocked by policy: it runs in another pass of its node: the "
                                               "thread was resumed twice at once")

    def test_a_wrapper_outside_the_gate_cannot_change_a_decided_call(self):   # probe851_wrap.py
        """instrument() puts the gate inside a ToolNode's own wrap_tool_call, which sees each call after the pass
        decided it: a wrapper that changes an approved pay's amount (5 to 99999) has the call refused, not run."""
        def outer(request, handler):
            if request.tool_call["name"] == "pay":
                request = request.override(tool_call={**request.tool_call,
                                                      "args": {**request.tool_call["args"], "cents": 99999}})
            return handler(request)
        calls = [{"name": "pay", "args": {"to": "a", "cents": 5}, "id": "p"},
                 {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
        for mode in ("sync", "async"):
            for how, node in self.nodes(tools=[counted_pay, TOOLS[0]], wrap_tool_call=outer):
                if how == "by hand":   # tracekit_tool_node takes no wrapper of the app's
                    continue
                with self.subTest(mode=mode):
                    out, _ = self.drive(runner(tool_graph(node()), mode), message(calls), approve={"p"})
                    self.assertEqual((PAID, read(out)), ([], {
                        "p": "Tool call blocked by policy: the call's arguments changed after the decision", "e": "hi"}))

    def test_two_resumes_at_once_after_a_tools_own_pause_pay_once(self):   # probe851_pausedrace.py same
        """An approved pay asked the person itself; the answer is resumed twice at once in one process (a double
        submit). At 8e5f8383 both passes ran it on its one consume (the second complete refused with a warning only).
        The first pass to take the call runs it now; the other is refused."""
        pay, echo = ({"name": "pay", "args": {"to": "b", "cents": 120}, "id": "p0"},
                     {"name": "echo", "args": {"text": "hi"}, "id": "e"})
        for calls in ([pay, echo], [pay]):
            for mode in ("sync", "async"):
                for how, node in self.nodes(tools=[asking_held_open_pay, TOOLS[0]]):
                    with self.subTest(calls=len(calls), mode=mode, wired=how):
                        SECOND.clear()
                        go = runner(tool_graph(node()), mode)
                        shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                        self.approve(shown["approval_id"])
                        out = go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)
                        self.assertEqual(out["__interrupt__"][0].value, "pay 120?")
                        outs = at_once(*[lambda: go(Command(resume="yes"), THREAD)] * 2)
                        self.assertEqual(PAID, [120])
                        self.assertEqual(sorted(read(o)["p0"] for o in outs), [
                            "Tool call blocked by policy: it runs in another pass of its node: the thread was resumed "
                            "twice at once", "paid 120 after yes"])
                        self.assertEqual([r["tool_call_id"] for r in self.recorded("tool.result")].count("p0"), 1)

    def test_a_resume_that_starts_while_another_is_about_to_run_the_call_pays_once(self):   # probe851_race_slow.py
        """Resume B of one thread starts once resume A consumed the approved pay, before A's tool starts. At
        8e5f8383 B found the pay consumed and ran it too (12 of 12, sync and async). One pass runs it now."""
        calls = [{"name": "pay", "args": {"to": "b", "cents": 120}, "id": "p0"},
                 {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
        gate = TracekitMiddleware._gate
        for mode in ("sync", "async"):
            for how, node in self.nodes(tools=[held_open_pay, TOOLS[0]]):
                with self.subTest(mode=mode, wired=how):
                    SECOND.clear()
                    go = runner(tool_graph(node()), mode)
                    shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                    self.approve(shown["approval_id"])
                    consumed, delayed, consume = threading.Event(), [], self.signer.approval_consume

                    def consuming(req):
                        out = consume(req)
                        if req["tool_call_id"] == "p0" and out["ok"]:
                            consumed.set()
                        return out

                    def slow_gate(gate_self, request):   # A's pay: a scheduling delay before its tool starts
                        if request.tool_call["id"] == "p0" and not delayed:
                            delayed.append(1)
                            time.sleep(0.3)
                        return gate(gate_self, request)
                    self.signer.approval_consume = consuming
                    resume = Command(resume={"approval_id": shown["approval_id"]})
                    with mock.patch.object(TracekitMiddleware, "_gate", slow_gate):
                        outs = at_once(lambda: go(resume, THREAD), lambda: consumed.wait(5) and go(resume, THREAD))
                    self.assertEqual(PAID, [120])
                    self.assertEqual(sorted(read(o)["p0"] for o in outs), [
                        "Tool call blocked by policy: it runs in another pass of its node: the thread was resumed "
                        "twice at once", "paid 120"])
                    self.assertEqual([r["tool_call_id"] for r in self.recorded("tool.result")].count("p0"), 1)


class Agent:
    """A SignerService called in this process as identity `who`."""

    def __init__(self, s, who):
        self.s, self.who = s, who

    def __getattr__(self, method):
        return lambda req: self.s.call(self.who, method, req)


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class AnotherProcess(unittest.TestCase):
    """A run paused in one process and resumed in another, on the real signer (probe_cross_process.py,
    fresh_gate_after_tool_pause.py): a new gate and graph on the same checkpointer, so the gate keeps nothing of the
    first; what the signer recorded (call_state) says what each call did."""

    def setUp(self):
        ac.RAN.clear()

        @tool("pay")
        def pay(to: str, cents: int) -> str:
            """Send money."""
            ac.RAN.append(f"pay{cents}")
            return f"paid {cents}"

        @tool("pay")
        def asking_pay(to: str, cents: int) -> str:
            """Send money after the person confirms (its own pause)."""
            a = interrupt(f"pay {cents}?")
            ac.RAN.append(f"pay{cents}:{a}")
            return f"paid {cents} after {a}"

        @tool
        def echo(text: str) -> str:
            """Echo."""
            ac.RAN.append("echo")
            return text

        @tool
        def asking(question: str) -> str:
            """Ask the person."""
            a = interrupt(question)
            ac.RAN.append(f"confirm:{a}")
            return a
        self.pay, self.asking_pay, self.echo, self.asking = pay, asking_pay, echo, asking

    def signer(self):
        """(the signer, it as the agent's identity, a run of it)"""
        s = svc.SignerService(ac.tmpdir(self), policy=PAY_ASKS, grace_s=0, fsck_every_s=0)
        self.addCleanup(s.close)
        agent = Agent(s, ME)
        return s, agent, agent.register_run({"request_id": "reg", "agent": {"name": "p"}})

    @staticmethod
    def approve(s, aid):
        s.call(OTHER, "approval_decide", {"request_id": aid, "decision": "approve", "approval_id": aid})

    def scenario(self, tools, calls, mode, switch):
        """(what the model read, each pause, the run's records once closed): each pay approved by another identity,
        each tool's question answered "yes", a new gate and graph before the nth resume when `switch(n)`"""
        ac.RAN.clear()
        s, agent, run = self.signer()
        saver = InMemorySaver()
        go = runner(tool_graph(tracekit_tool_node(tools, agent, run), saver), mode)
        out, pauses = go(message(calls), THREAD), []
        while "__interrupt__" in out and len(pauses) < 8:
            if switch(len(pauses)):   # another process: a new gate, the same saved state
                go = runner(tool_graph(tracekit_tool_node(tools, agent, run), saver), mode)
            v = out["__interrupt__"][0].value
            if isinstance(v, dict) and "tracekit" in v:
                pauses.append("tracekit")
                for a in v["tracekit"].get("approvals", [v["tracekit"]]):
                    if s.log.approvals[a["approval_id"]]["state"] == "requested":
                        self.approve(s, a["approval_id"])
                out = go(Command(resume={"approval_id": v["tracekit"]["approval_id"]}), THREAD)
            else:
                pauses.append(v)
                out = go(Command(resume="yes"), THREAD)
        agent.close_run({"request_id": "close", "run_id": run["run_id"], "run_token": run["run_token"]})
        s.sweep(time.monotonic() + 5)
        return read(out), pauses, [r["event"] for r in s.log.storage.iter_run("default", run["run_id"])]

    def check(self, events, calls, ran):
        """Each call ran once, was recorded once, and no approval was refused or left open."""
        self.assertEqual(sorted(ac.RAN), sorted(ran))
        self.assertEqual(sorted((e["tool_call_id"], e["data"]["ok"]) for e in events if e["type"] == "tool.result"),
                         sorted((c["id"], True) for c in calls))
        kinds = [e["type"] for e in events]
        self.assertEqual((kinds.count("approval.consumed"), kinds.count("approval.refused")),
                         (sum(c["name"] == "pay" for c in calls), 0))
        self.assertEqual([e["data"]["kind"] for e in events if e["type"] == "capture.gap"], [])

    def test_resumed_in_another_process_each_call_runs_once(self):
        """X1-X3 of probe_cross_process.py, the second process answering a tool's own question, and X2 all in one
        process. On main X1 was refused (TK-APPROVAL-CONSUMED) once the person answered, and X2 ran echo again and
        refused pay-0."""
        pay0 = {"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"}
        echo = {"name": "echo", "args": {"text": "hi"}, "id": "e"}
        q = {"name": "asking", "args": {"question": "sure?"}, "id": "q"}
        standin = "ran; its result is recorded at run_seq "
        for mode in ("sync", "async"):
            with self.subTest("X1: one ask, its tool pauses", mode=mode):
                calls = [{"name": "pay", "args": {"to": "a", "cents": 1}, "id": "p1"}]
                seen, pauses, events = self.scenario([self.asking_pay], calls, mode, lambda n: n == 1)
                self.assertEqual((seen, pauses), ({"p1": "paid 1 after yes"}, ["tracekit", "pay 1?"]))
                self.check(events, calls, ["pay1:yes"])
            with self.subTest("X2: an ask, echo and a tool that pauses", mode=mode):
                seen, pauses, events = self.scenario([self.pay, self.echo, self.asking], [pay0, echo, q], mode,
                                                     lambda n: n == 1)
                self.assertEqual((seen["q"], pauses), ("yes", ["tracekit", "sure?"]))
                seq = {e["tool_call_id"]: e["run_seq"] for e in events if e["type"] == "tool.result"}
                self.assertIn(seen["p0"], ("paid 0", f"{standin}{seq['p0']}"))
                self.assertIn(seen["e"], ("hi", f"{standin}{seq['e']}"))
                self.check(events, [pay0, echo, q], ["pay0", "echo", "confirm:yes"])
            with self.subTest("X3: an ask whose tool pauses, beside echo", mode=mode):
                calls = [{"name": "pay", "args": {"to": "a", "cents": 2}, "id": "p2"}, echo]
                seen, pauses, events = self.scenario([self.asking_pay, self.echo], calls, mode, lambda n: n == 1)
                self.assertEqual((seen["p2"], pauses), ("paid 2 after yes", ["tracekit", "pay 2?"]))
                seq = {e["tool_call_id"]: e["run_seq"] for e in events if e["type"] == "tool.result"}
                self.assertIn(seen["e"], ("hi", f"{standin}{seq['e']}"))
                self.check(events, calls, ["pay2:yes", "echo"])
            with self.subTest("X2, all in one process", mode=mode):
                seen, pauses, events = self.scenario([self.pay, self.echo, self.asking], [pay0, echo, q], mode,
                                                     lambda n: False)
                self.assertEqual((seen, pauses), ({"p0": "paid 0", "e": "hi", "q": "yes"}, ["tracekit", "sure?"]))
                self.check(events, [pay0, echo, q], ["pay0", "echo", "confirm:yes"])

    def test_a_new_gate_at_every_resume(self):   # fresh_gate_after_tool_pause.py
        """A new gate for every resume, as a server that resumes each request in a process of its own. On main the
        approved pay was refused once its tool's question was answered (TK-APPROVAL-CONSUMED), and echo ran again."""
        for mode in ("sync", "async"):
            with self.subTest("one ask, its tool pauses", mode=mode):
                calls = [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"}]
                seen, _, events = self.scenario([self.asking_pay], calls, mode, lambda n: True)
                self.assertEqual(seen, {"p0": "paid 0 after yes"})
                self.check(events, calls, ["pay0:yes"])
            with self.subTest("pay-0 approved, a tool that pauses, echo", mode=mode):
                calls = [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"},
                         {"name": "asking", "args": {"question": "sure?"}, "id": "q"},
                         {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
                seen, _, events = self.scenario([self.pay, self.asking, self.echo], calls, mode, lambda n: True)
                self.assertEqual(seen["q"], "yes")
                self.check(events, calls, ["pay0", "confirm:yes", "echo"])

    def test_two_processes_resuming_one_thread_at_once_pay_once(self):   # probe851_pausedrace.py new
        """An approved pay asked the person itself; two processes (a new gate each, the same checkpointer) resume the
        answer at once. Both read from the signer that the pay was consumed and went on paused; at 8e5f8383 both ran
        it. The signer lets one pass go on per pause now (call_claim): the other is refused."""
        pay, echo = ({"name": "pay", "args": {"to": "b", "cents": 120}, "id": "p0"},
                     {"name": "echo", "args": {"text": "hi"}, "id": "e"})
        for calls in ([pay, echo], [pay]):
            for mode in ("sync", "async"):
                with self.subTest(calls=len(calls), mode=mode):
                    PAID.clear()
                    SECOND.clear()
                    (s, agent, run), saver = self.signer(), InMemorySaver()
                    graph = lambda: runner(tool_graph(tracekit_tool_node([asking_held_open_pay, self.echo], agent, run),
                                                      saver), mode)
                    go = graph()
                    shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                    self.approve(s, shown["approval_id"])
                    self.assertEqual(go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)[
                        "__interrupt__"][0].value, "pay 120?")
                    outs = at_once(*[lambda: graph()(Command(resume="yes"), THREAD)] * 2)
                    self.assertEqual(PAID, [120])
                    self.assertEqual(sorted(read(o)["p0"] for o in outs), [
                        "Tool call blocked by policy: p0 already went on after that pause: its thread was resumed "
                        "twice at once", "paid 120 after yes"])
                    events = [r["event"] for r in s.log.storage.iter_run("default", run["run_id"])]
                    self.assertEqual(([e["type"] for e in events].count("approval.consumed"),
                                      [e.get("tool_call_id") for e in events if e["type"] == "tool.result"].count("p0")),
                                     (1, 1))

    def test_after_a_signer_restart_a_paused_call_is_approved_again(self):   # probe851_claim.py crashrestart
        """An approved pay that asked the person itself: its continuation dies mid-pay (the process crashed after the
        signer let it go on) and the signer restarts, or the signer restarts while the person answers; then another
        process resumes. The signer keeps its claims in memory: at 1ad4d100e5 the pay was claimed again after the
        restart and ran twice, with one result recorded. A call whose approval was used before the signer process
        started is refused now: a person approves it again."""
        class Crash(BaseException):
            """The process dying mid-pay."""
        died, restarted = [], "Tool call blocked by policy: the signer restarted since this call's approval was used; " \
                               "ask again"

        @tool("pay")
        def dying_pay(to: str, cents: int) -> str:
            """Send money once the person confirms; its first run dies after paying."""
            answer = interrupt(f"pay {cents}?")
            PAID.append(cents)
            if not died:
                died.append(1)
                raise Crash()
            return f"paid {cents} after {answer}"
        calls = [{"name": "pay", "args": {"to": "b", "cents": 120}, "id": "p0"}]
        for crash in (True, False):
            with self.subTest(crash=crash):
                PAID.clear()
                died[:] = [] if crash else [1]
                d = ac.tmpdir(self)
                s = svc.SignerService(d, policy=PAY_ASKS, grace_s=0, fsck_every_s=0)
                agent, saver = Agent(s, ME), InMemorySaver()
                run = agent.register_run({"request_id": "reg", "agent": {"name": "p"}})

                def go(value):   # each a process of its own: a new gate on the same checkpointer
                    return tool_graph(tracekit_tool_node([dying_pay], agent, run), saver).invoke(value, THREAD)
                shown = go(message(calls))["__interrupt__"][0].value["tracekit"]
                self.approve(s, shown["approval_id"])
                self.assertEqual(go(Command(resume={"approval_id": shown["approval_id"]}))["__interrupt__"][0].value,
                                 "pay 120?")
                if crash:
                    with self.assertRaises(Crash):
                        go(Command(resume="yes"))
                s.close()
                agent.s = svc.SignerService(d, policy=PAY_ASKS, grace_s=0, fsck_every_s=0)
                self.addCleanup(agent.s.close)
                self.assertEqual((PAID, read(go(Command(resume="yes")))["p0"]), ([120] if crash else [], restarted))

    def test_two_resumes_that_consume_at_once_never_pay_twice(self):
        """Two resumes of one thread that reach approval_consume at once, in one process or two: the signer consumes
        the approval once. One pass runs the pay, or, in one process, the second consume's refusal can leave both
        refused (fail closed: the approval is used, and the run ends with a decided_not_completed gap)."""
        calls = [{"name": "pay", "args": {"to": "b", "cents": 120}, "id": "p0"},
                 {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
        for gates in ("one", "two"):
            for mode in ("sync", "async"):
                with self.subTest(gates=gates, mode=mode):
                    PAID.clear()
                    SECOND.clear()
                    (s, agent, run), saver = self.signer(), InMemorySaver()
                    graph = lambda: runner(tool_graph(tracekit_tool_node([held_open_pay, self.echo], agent, run),
                                                      saver), mode)
                    go = graph()
                    shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                    self.approve(s, shown["approval_id"])
                    resume = Command(resume={"approval_id": shown["approval_id"]})
                    at_once(*[(lambda: go(resume, THREAD)) if gates == "one" else
                              (lambda: graph()(resume, THREAD))] * 2)
                    events = [r["event"] for r in s.log.storage.iter_run("default", run["run_id"])]
                    self.assertLessEqual(len(PAID), 1)
                    self.assertEqual(([e["type"] for e in events].count("approval.consumed"),
                                      [e.get("tool_call_id") for e in events if e["type"] == "tool.result"].count("p0")),
                                     (1, len(PAID)))

    def test_a_paused_call_whose_saved_args_changed_does_not_go_on(self):
        """[a pay that asks the person itself, echo]: approved and consumed, its tool paused; then the saved checkpoint's
        amount is changed (2 to 99999) and another process resumes. The signer says these aren't the decided
        arguments (call_state's same_args), so the call isn't taken up as paused: approval_consume refuses it."""
        calls = [{"name": "pay", "args": {"to": "a", "cents": 2}, "id": "p2"},
                 {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
        for mode in ("sync", "async"):
            with self.subTest(mode=mode):
                ac.RAN.clear()
                (s, agent, run), saver = self.signer(), InMemorySaver()
                go = runner(tool_graph(tracekit_tool_node([self.asking_pay, self.echo], agent, run), saver), mode)
                shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                self.approve(s, shown["approval_id"])
                out = go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)
                self.assertEqual(out["__interrupt__"][0].value, "pay 2?")   # consumed: its tool asks the person
                t = saver.get_tuple(THREAD)
                t.checkpoint["channel_values"]["messages"][-1].tool_calls[0]["args"]["cents"] = 99999
                saver.put(t.parent_config, t.checkpoint, t.metadata,
                          {"messages": t.checkpoint["channel_versions"]["messages"]})
                go = runner(tool_graph(tracekit_tool_node([self.asking_pay, self.echo], agent, run), saver), mode)
                out = go(Command(resume="yes"), THREAD)
                self.assertNotIn("pay99999:yes", ac.RAN)
                self.assertTrue(read(out)["p2"].startswith("Tool call blocked by policy: TK-APPROVAL-MISMATCH"),
                                read(out)["p2"])

    def test_a_call_whose_recorded_result_failed_runs_again_as_a_new_attempt(self):
        """[pay-0 (asks), flaky]: approved; on the resume flaky raises and the run fails. Another process runs the node
        again: pay-0 ran (the stand-in), and flaky, whose recorded result failed, runs again as attempt 1."""
        failed = []

        @tool
        def flaky(x: int) -> str:
            """Fails the first time."""
            ac.RAN.append("flaky")
            if not failed:
                failed.append(1)
                raise ConnectionError("transient")
            return "ok"
        calls = [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"},
                 {"name": "flaky", "args": {"x": 1}, "id": "f"}]
        for mode in ("sync", "async"):
            with self.subTest(mode=mode):
                ac.RAN.clear()
                failed.clear()
                (s, agent, run), saver = self.signer(), InMemorySaver()
                go = runner(tool_graph(tracekit_tool_node([self.pay, flaky], agent, run), saver), mode)
                shown = go(message(calls), THREAD)["__interrupt__"][0].value["tracekit"]
                self.approve(s, shown["approval_id"])
                with self.assertRaises(ConnectionError):
                    go(Command(resume={"approval_id": shown["approval_id"]}), THREAD)
                go = runner(tool_graph(tracekit_tool_node([self.pay, flaky], agent, run), saver), mode)
                out = go(None, THREAD)
                self.assertEqual((read(out)["f"], sorted(ac.RAN)), ("ok", ["flaky", "flaky", "pay0"]))
                self.assertTrue(read(out)["p0"].startswith("ran; its result is recorded at run_seq "), read(out)["p0"])
                self.assertEqual(sorted((e.get("attempt", 0), e["data"]["ok"]) for e in s.log.storage.iter_run(
                    "default", run["run_id"]) for e in [e["event"]] if e["type"] == "tool.result"
                    and e["tool_call_id"] == "f"), [(0, False), (1, True)])


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
