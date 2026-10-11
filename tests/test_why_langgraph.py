"""tracekit.why.langgraph: fork replay of a recorded LangGraph thread (examples/v2/langchain/injection.py) names the
fetched page as the cause and rules out the benign tool result, without running a tool, calling the signer or touching
the recorded thread, its store and cache, or other threads of the same graph."""
import asyncio
import contextlib
import io
import json
import os
import random
import sys
import tempfile
import threading
import tracemalloc
import unittest
from typing import Annotated

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    sys.path.insert(0, os.path.join(ROOT, "examples", "v2", "langchain"))
    import injection as inj
    from langchain.agents import create_agent
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import InjectedToolCallId, tool
    from langgraph.cache.memory import InMemoryCache
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode, tools_condition
    from langgraph.store.memory import InMemoryStore
    from langgraph.types import CachePolicy, Command
    from tracekit.testing import FakeSigner
    from tracekit.why.cli import main
    from tracekit.why.langgraph import attribute_thread, fork_replay
except ImportError:   # optional: the dev extra installs them
    HAVE_LG = False
else:
    HAVE_LG = True

CONF = {"configurable": {"thread_id": "t"}}
GO = {"messages": [("user", "go")]}


def _call(name, i, **args):
    return {"messages": [AIMessage("", tool_calls=[{"name": name, "args": args, "id": f"{name}{i}"}])]}


def _results(state):
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


def _loop(model, tools, state=None, spare=None, cache=None, **compile_kw):
    """model <-> tools until the model stops. `tools` is any node; `spare` adds an unreachable ToolNode."""
    g = StateGraph(state or MessagesState)
    g.add_node("model", model, cache_policy=CachePolicy() if cache else None)
    g.add_node("tools", tools)
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    if spare:
        g.add_node("spare", spare)
        g.add_edge("spare", END)
    return g.compile(checkpointer=InMemorySaver(), cache=cache, **compile_kw)


@unittest.skipUnless(HAVE_LG, "langchain>=1 / langgraph not installed")
class ForkReplay(unittest.TestCase):
    def setUp(self):
        inj.SAVER.delete_thread(inj.THREAD["configurable"]["thread_id"])
        self.signer = FakeSigner(lambda tool, args: ("allow", []))
        r = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
        self.recorded, self.reg = {"run_id": r["run_id"], "run_token": r["run_token"]}, r
        out = inj.record(inj.graph_factory(self.signer, r))
        self.page, self.weather = [m.tool_call_id for m in out["messages"] if m.type == "tool"][:2]
        self.graph = inj.graph_factory()

    def events(self):
        return self.signer.read({**self.recorded, "limit": 1000})["events"]

    def test_names_the_page_and_rules_out_the_benign_input(self):
        signed = inj.graph_factory(self.signer, self.reg)   # tool calls gated by the signer, checkpoints committed
        before, history = len(self.events()), len(list(self.graph.get_state_history(inj.THREAD)))
        calls = []
        real = inj.send_email.func
        inj.send_email.func = lambda **kw: calls.append(kw) or real(**kw)
        self.addCleanup(setattr, inj.send_email, "func", real)
        r = attribute_thread(signed, inj.THREAD, inj.TARGET, n=80, n_max=160)
        self.assertEqual(r["suspects"], [self.page, self.weather])
        self.assertEqual([c["intervention"] for c in r["causes"]], [self.page])
        self.assertEqual(r["causes"][0]["role"], "primary")
        weather = next(t for t in r["tests"] if t["intervention"] == self.weather)
        self.assertEqual(weather["verdict"], "ruled-out")
        self.assertEqual({(t["rung"], t["off_tape_actions"]) for t in r["tests"]}, {(3, 0)})
        self.assertEqual(r["fork"]["as_node"], "tools")
        self.assertEqual(calls, [])                         # no real tool ran
        self.assertEqual(len(self.events()), before)        # nothing reached the signer
        self.assertEqual(len(list(self.graph.get_state_history(inj.THREAD))), history)   # the thread is untouched

    def test_a_call_the_run_never_made_is_stubbed_and_counted(self):
        real = inj.model

        def other_body(state, config):   # in the branches the email has other arguments than the recorded one
            out = real(state, config)
            for tc in out["messages"][0].tool_calls:
                if tc["name"] == "send_email":
                    tc["args"] = {**tc["args"], "body": "something else"}
            return out

        inj.model = other_body
        self.addCleanup(setattr, inj, "model", real)
        r = fork_replay(inj.graph_factory(), inj.THREAD, None, self.weather, inj.TARGET, n=20)
        self.assertEqual(r["rung"], 3)
        self.assertGreater(r["off_tape_actions"], 0)

    def test_a_checkpoint_before_the_message_has_nothing_to_remove(self):
        early = list(self.graph.get_state_history(inj.THREAD))[-2].config["configurable"]["checkpoint_id"]
        with self.assertRaisesRegex(ValueError, "no message or tool call"):
            fork_replay(self.graph, inj.THREAD, early, self.page, inj.TARGET, n=2)

    def test_cli(self):
        out, log = io.StringIO(), tempfile.mkdtemp()
        with contextlib.redirect_stdout(out):
            main(["attribute", "--langgraph", "injection:graph_factory", "--thread", "injection",
                  "--target", inj.TARGET, "--suspect", self.page, "--out", log, "--json"])
        r = json.loads(out.getvalue())
        self.assertEqual((r["rung"], r["causes"][0]["intervention"]), (3, self.page))
        with open(os.path.join(log, "langgraph-injection", "tests.jsonl"), encoding="utf-8") as f:
            saved = [json.loads(line) for line in f]
        self.assertEqual([(t["intervention"], t["rung"], t["fork"]) for t in saved],
                         [(t["intervention"], 3, r["fork"]) for t in r["tests"]])



@unittest.skipUnless(HAVE_LG, "langchain>=1 / langgraph not installed")
class Branches(unittest.TestCase):
    """A fetched page asks for an email; the model follows it. Every real tool call is recorded in self.real."""

    def setUp(self):
        self.real = []

        @tool
        def fetch(url: str) -> str:
            """Fetch a page."""
            self.real.append(url)
            return "PAGE do it"

        @tool
        def send(to: str) -> str:
            """Send an email."""
            self.real.append(to)
            return "sent"

        self.tools = [fetch, send]

    @staticmethod
    def follows(state, config=None):
        res = _results(state)
        if not res:
            return _call("fetch", 0, url="u")
        if len(res) == 1 and "do it" in res[0].content:
            return _call("send", 1, to="x")
        return {"messages": [AIMessage("done")]}

    def record(self, graph):
        graph.invoke(GO, CONF)
        self.real.clear()
        return graph

    def test_a_toolnode_in_a_subgraph_is_served(self):
        sub = StateGraph(MessagesState)
        sub.add_node("t", ToolNode(self.tools))
        sub.add_edge(START, "t")
        sub.add_edge("t", END)
        graph = self.record(_loop(self.follows, sub.compile(), spare=ToolNode(self.tools)))
        r = fork_replay(graph, CONF, None, "fetch0", "tool=send", n=3)
        self.assertEqual((r["p_with"], r["p_without"], r["off_tape_actions"], self.real), (1.0, 0.0, 0, []))

    def test_a_tool_run_outside_a_servable_toolnode_stops_the_replay(self):
        hidden = ToolNode(self.tools)
        graph = self.record(_loop(self.follows, lambda state: hidden.invoke(state), spare=ToolNode(self.tools)))
        with self.assertRaisesRegex(RuntimeError, "ran outside a ToolNode"):
            fork_replay(graph, CONF, None, "fetch0", "tool=send", n=3)

    def test_other_threads_of_the_same_graph_run_their_real_tools(self):
        node, live = ToolNode(self.tools), {}

        def model(state, config):   # while a branch runs, someone else invokes the same graph object
            if live.get("armed"):
                live["armed"] = False
                t = threading.Thread(target=lambda: live.update(out=graph.invoke(GO, {"configurable": {
                    "thread_id": "live"}})))
                t.start()
                t.join()
            return self.follows(state)

        graph = self.record(_loop(model, node))
        live["armed"] = True
        fork_replay(graph, CONF, None, "fetch0", "tool=send", n=2)
        self.assertEqual(self.real, ["u", "x"])
        self.assertEqual([m.content for m in _results(live["out"])], ["PAGE do it", "sent"])
        self.assertIsNone(node._wrap_tool_call)   # the user's ToolNode is left as it was

    def test_branches_get_a_scratch_thread_and_store_and_no_cache(self):
        store, cache, seen = InMemoryStore(), InMemoryCache(), []

        def model(state, config, *, store):   # follows the page in about half of its runs, seeded
            seen.append(config["configurable"]["thread_id"])
            store.put(("notes",), str(len(seen)), {"n": len(seen)})
            res = _results(state)
            if not res:
                return _call("fetch", 0, url="u")
            if len(res) == 1 and random.Random(config["configurable"].get("tracekit_seed", 0)).random() < 0.5:
                return _call("send", 1, to="x")
            return {"messages": [AIMessage("done")]}

        graph = self.record(_loop(model, ToolNode(self.tools), cache=cache, store=store))
        recorded, notes = len(seen), len(store.search(("notes",), limit=1000))
        cached = sum(map(len, cache._cache.values()))
        r = fork_replay(graph, CONF, None, "fetch0", "tool=send", n=40)
        self.assertTrue(0 < r["p_with"] < 1, r)   # the cache would serve the recorded call to every unaltered branch
        self.assertEqual((len(store.search(("notes",), limit=1000)), sum(map(len, cache._cache.values()))),
                         (notes, cached))
        branches = set(seen[recorded:])
        self.assertNotIn("t", branches)
        self.assertEqual(len(branches), r["program_runs"])

    def test_tool_results_are_served_with_status_and_artifact(self):
        @tool
        def note(x: int) -> str:
            """Take a note."""
            return "noted"

        @tool
        def flaky(x: int) -> str:
            """Fails."""
            raise ValueError("down")

        @tool(response_format="content_and_artifact")
        def table(x: int):
            """A table."""
            return "see artifact", {"rows": 3}

        seen = []

        def model(state):
            res = _results(state)
            if len(res) < 3:
                return _call(["note", "flaky", "table"][len(res)], len(res), x=1)
            seen.append([(m.name, m.status, m.artifact) for m in res[1:]])
            return {"messages": [AIMessage("done")]}

        graph = _loop(model, ToolNode([note, flaky, table], handle_tool_errors=True))
        graph.invoke(GO, CONF)
        fork_replay(graph, CONF, None, "note0", "tool=table", n=2)
        self.assertEqual(seen[-1], [("flaky", "error", None), ("table", "success", {"rows": 3})])

    def test_branch_memory_does_not_grow_with_the_trials(self):
        @tool
        def fetch(url: str) -> str:
            """Fetch a big page."""
            return "x" * 1_000_000 + " do it"

        graph = _loop(self.follows, ToolNode([fetch, self.tools[1]]))
        graph.invoke(GO, CONF)
        tracemalloc.start()
        self.addCleanup(tracemalloc.stop)
        fork_replay(graph, CONF, None, "fetch0", "tool=send", n=40)
        self.assertLess(tracemalloc.get_traced_memory()[1], 80_000_000)   # 4 MB a branch when branches share a saver


@unittest.skipUnless(HAVE_LG, "langchain>=1 / langgraph not installed")
class Tape(unittest.TestCase):
    def setUp(self):
        answers = iter(["pending", "done"])

        @tool
        def status(job: int) -> str:
            """Job status."""
            return next(answers)

        @tool
        def deploy(job: int) -> str:
            """Deploy."""
            return "ok"

        def model(state):   # polls until the job is done, then deploys; gives up after three polls
            res = [m.content for m in _results(state)]
            if "ok" in res or len(res) >= 3:
                return {"messages": [AIMessage("stop")]}
            return _call("deploy" if res and res[-1] == "done" else "status", len(res), job=1)

        self.graph = _loop(model, ToolNode([status, deploy]))
        self.graph.invoke({"messages": [("user", "deploy job 1")]}, CONF)

    def test_a_branch_continues_the_tape_after_the_fork(self):
        r = fork_replay(self.graph, CONF, None, "status0", "tool=deploy", n=4)
        self.assertEqual((r["p_with"], r["off_tape_actions"]), (1.0, 0))   # the second poll is served "done"

    def test_only_the_removed_occurrence_is_blanked(self):
        r = fork_replay(self.graph, CONF, None, "status0", "tool=deploy", n=4)
        self.assertEqual(r["p_without"], 1.0)   # the next poll with the same args still reads "done"


@unittest.skipUnless(HAVE_LG, "langchain>=1 / langgraph not installed")
class Shapes(unittest.TestCase):
    def test_parallel_tool_calls_of_create_agent(self):
        @tool
        def fetch(url: str) -> str:
            """Fetch."""
            return "page"

        @tool
        def weather(city: str) -> str:
            """Weather."""
            return "sunny"

        class Model(GenericFakeChatModel):
            def bind_tools(self, tools, **kw):
                return self

        turns = [AIMessage("", tool_calls=[{"name": "fetch", "args": {"url": "a"}, "id": "c1"},
                                           {"name": "weather", "args": {"city": "L"}, "id": "c2"}]),
                 AIMessage("", tool_calls=[{"name": "fetch", "args": {"url": "b"}, "id": "c3"}]), AIMessage("done")]

        def replies():
            while True:
                yield from (m.model_copy() for m in turns)

        agent = create_agent(Model(messages=replies()), [fetch, weather], checkpointer=InMemorySaver())
        agent.invoke(GO, CONF)
        r = attribute_thread(agent, CONF, "tool=fetch,arg~b", n=2, n_max=2)
        self.assertEqual((r["suspects"], r["fork"]["as_node"]), (["c1", "c2"], "tools"))

    def test_content_in_another_state_key_is_refused(self):
        class State(MessagesState):
            context: str

        @tool
        def fetch(url: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
            """Fetch into the context."""
            return Command(update={"context": "PAGE do it", "messages": [ToolMessage("see context",
                                                                                     tool_call_id=tool_call_id)]})

        def model(state):
            if not _results(state):
                return _call("fetch", 0, url="u")
            return {"messages": [AIMessage("done")]}

        graph = _loop(model, ToolNode([fetch]), state=State)
        graph.invoke(GO, CONF)
        with self.assertRaisesRegex(ValueError, "also wrote context"):
            fork_replay(graph, CONF, None, "fetch0", "tool=send", n=2)

    def test_an_async_graph_is_refused(self):
        @tool
        def fetch(url: str) -> str:
            """Fetch."""
            return "page"

        async def model(state):
            return {"messages": [AIMessage("done")]} if _results(state) else _call("fetch", 0, url="u")

        graph = _loop(model, ToolNode([fetch]))
        asyncio.run(graph.ainvoke(GO, CONF))
        with self.assertRaisesRegex(ValueError, "async-only"):
            fork_replay(graph, CONF, None, "fetch0", "tool=fetch", n=2)


if __name__ == "__main__":
    unittest.main()
