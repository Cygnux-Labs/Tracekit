import asyncio
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import install  # noqa: E402
from tracekit.adapters import traced  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        install.init_dev(self.home, [], start=True)

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        if self.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = self.old
        shutil.rmtree(self.d, ignore_errors=True)

    def events(self):
        return [r["event"] for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r and not r.get("elided")]


class Generic(Base):
    def test_sync_and_async_functions_are_recorded_and_denied_calls_never_run(self):
        ran = []
        with Tracer(agent="gen", cwd=self.d) as t:
            @traced(t, name="Bash")  # the default rules match the tool name, so name it as the rules expect
            def shell(command):
                ran.append(command)
                return "ok"

            @traced(t, name="fetch")
            async def fetch(url):
                return {"status": 200}

            self.assertEqual(shell("ls"), "ok")
            self.assertEqual(asyncio.run(fetch("https://x.invalid")), {"status": 200})
            with self.assertRaises(PermissionError):
                shell(command="sudo rm -rf /")
        self.assertEqual(ran, ["ls"])  # the denied call's body never executed
        types = [e["type"] for e in self.events()]
        self.assertEqual(types.count("tool.call"), 3)
        self.assertIn("deny", [e["data"]["decision"] for e in self.events() if e["type"] == "policy.decision"])
        self.assertEqual(sum(1 for e in self.events() if e["type"] == "tool.result"), 2)


import importlib.util  # noqa: E402

HAVE_LC = importlib.util.find_spec("langchain_core") is not None


@unittest.skipUnless(HAVE_LC, "langchain-core not installed")
class LangChain(Base):
    def test_tool_runs_through_callbacks_and_deny_blocks_the_body(self):
        from langchain_core.tools import tool
        from tracekit.adapters.langchain import TracekitCallbackHandler
        ran = []

        @tool
        def Bash(command: str) -> str:
            """Run a shell command."""
            ran.append(command)
            return "done"

        @tool
        def boom(x: str) -> str:
            """Always fails."""
            raise ValueError("kaput")

        with Tracer(agent="lc", cwd=self.d) as t:
            cfg = {"callbacks": [TracekitCallbackHandler(t)]}
            self.assertEqual(Bash.invoke({"command": "ls -la"}, config=cfg), "done")
            with self.assertRaises(PermissionError):
                Bash.invoke({"command": "sudo id"}, config=cfg)
            with self.assertRaises(ValueError):
                boom.invoke({"x": "1"}, config=cfg)
        self.assertEqual(ran, ["ls -la"])
        results = [e["data"]["ok"] for e in self.events() if e["type"] == "tool.result"]
        self.assertEqual(results, [True, False])

    def test_langgraph_prebuilt_tool_node(self):
        try:
            from langgraph.prebuilt import ToolNode
        except ImportError:
            self.skipTest("langgraph not installed")
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from tracekit.adapters.langchain import TracekitCallbackHandler

        @tool
        def Bash(command: str) -> str:
            """Run a shell command."""
            return "out:" + command

        from langgraph.graph import END, START, MessagesState, StateGraph
        g = StateGraph(MessagesState)
        g.add_node("tools", ToolNode([Bash]))
        g.add_edge(START, "tools")
        g.add_edge("tools", END)
        graph = g.compile()
        msg = AIMessage(content="", tool_calls=[{"name": "Bash", "args": {"command": "echo hi"}, "id": "c1"}])
        with Tracer(agent="lg", cwd=self.d) as t:
            out = graph.invoke({"messages": [msg]}, config={"callbacks": [TracekitCallbackHandler(t)]})
        self.assertIn("out:echo hi", out["messages"][-1].content)
        self.assertEqual(sum(1 for e in self.events() if e["type"] == "tool.call"), 1)

    def test_langgraph_node_tracing(self):
        try:
            from langgraph.graph import END, START, StateGraph
        except ImportError:
            self.skipTest("langgraph not installed")
        from typing import TypedDict
        from langchain_core.runnables import RunnableLambda
        from tracekit.adapters.langchain import TracekitCallbackHandler

        class S(TypedDict):
            n: int

        inner = RunnableLambda(lambda x: x + 1)  # a runnable inside a node: must not become its own step
        g = StateGraph(S)
        g.add_node("plan", lambda s: {"n": inner.invoke(s["n"])})
        g.add_node("act", lambda s: {"n": s["n"] * 10})
        g.add_edge(START, "plan")
        g.add_edge("plan", "act")
        g.add_edge("act", END)
        graph = g.compile()
        with Tracer(agent="lg", cwd=self.d) as t:
            out = graph.invoke({"n": 1}, config={"callbacks": [TracekitCallbackHandler(t, nodes=True)]})
        self.assertEqual(out["n"], 20)
        calls = [e["data"] for e in self.events() if e["type"] == "tool.call"]
        self.assertEqual([c["name"] for c in calls], ["node:plan", "node:act"])
        self.assertTrue(all("step" in c["input"] for c in calls))
        self.assertEqual([e["data"]["ok"] for e in self.events() if e["type"] == "tool.result"], [True, True])
        before = len(self.events())
        with Tracer(agent="lg2", cwd=self.d) as t:  # off by default: no node steps
            graph.invoke({"n": 1}, config={"callbacks": [TracekitCallbackHandler(t)]})
        self.assertFalse([e for e in self.events()[before:] if e["type"] == "tool.call"])

if __name__ == "__main__":
    unittest.main()
