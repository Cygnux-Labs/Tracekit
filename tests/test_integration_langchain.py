"""tracekit.integrations.langchain beyond the adapter contract (tests/test_contract_langchain.py): the result
commitment, `ask` without a checkpointer, an interrupt raised inside a tool, and an `ask` under each ToolNode error
handling."""
import asyncio
import json
import time
import types
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.testing import FakeSigner

try:
    from langchain.agents import create_agent
    from langchain.agents.middleware import wrap_tool_call
    from langchain_core.messages import HumanMessage, ToolMessage
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

THREAD = {"configurable": {"thread_id": "t"}}


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
                  "a tuple": {"handle_tool_errors": (ValueError,)}, "a type": {"handle_tool_errors": ValueError}}


@unittest.skipUnless(HAVE_LC, "langchain>=1 / langgraph-checkpoint-sqlite not installed")
class ErrorHandling(unittest.TestCase):
    """An `ask` pauses the graph whatever the ToolNode's handle_tool_errors and inside with_fallbacks, wired by hand
    or by instrument(); the tool's own errors are handled as configured."""

    def setUp(self):
        for name in ("__init__", "with_fallbacks"):   # instrument() patches ToolNode for the process
            patcher = mock.patch.object(ToolNode, name, getattr(ToolNode, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.wired = ToolNode.__init__

    def nodes(self, **kw):
        """(how, a function building the gated node): by hand, and a plain ToolNode as instrument() wires it, each on a
        signer of its own"""
        for how in ("by hand", "instrument()"):
            ac.RAN.clear()
            ToolNode.__init__ = self.wired
            self.signer = FakeSigner(ac._rule)
            self.run = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
            if how == "by hand":
                yield how, lambda: tracekit_tool_node(TOOLS, self.signer, self.run, **kw)
            else:
                autowire._langgraph(types.SimpleNamespace(client=self.signer, registered=self.run, **{
                    k: self.run[k] for k in ("run_id", "run_token")}))
                yield how, lambda: ToolNode(TOOLS, **kw)

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
        for how, node in self.nodes():
            with self.subTest(wired=how, fallbacks=True):
                fallback = node().with_fallbacks([RunnableLambda(handle_tool_error)], exception_key="error")
                out = tool_graph(fallback).invoke(prompt("fail", why="boom"), THREAD)
                self.assertIn("please fix your mistakes", tool_message(out).content)


class Jittery:
    """The client, with the pause a busy process may take between a call's client_seq and its send."""

    def __init__(self, client):
        self.client = client

    def __getattr__(self, name):
        def call(req):
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
