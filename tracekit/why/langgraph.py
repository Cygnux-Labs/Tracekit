"""Counterfactual replay of a LangGraph thread by forking one of its checkpoints (rung 3).

LangGraph keeps every checkpoint of a thread. To test whether a message caused an action, take the checkpoint at which
the message entered the state and fork it twice per trial: once as recorded, once with the message removed
(`update_state(..., as_node=<the node that added it>)`), then run only what comes after (`invoke(None, fork)`). The
prefix is the recorded run itself, not a re-execution of it.

Each branch runs on its own copy of the graph: a fresh in-memory checkpointer holding only the fork point under a
scratch thread id, an empty scratch store if the graph has one, no node cache, and copies of every ToolNode (in
subgraphs added as nodes too, and inside `.with_fallbacks()`) that serve each call from the thread's own tool results
(same tool, same canonical args, in order) or a stub. No real tool runs, and the user's graph, thread, store, cache and
ToolNodes are never touched. A branch with a new tool result that did not come from that serving stops with an error,
unless the call is one `routing` names: a routing schema a node of the app answers itself (as in LangGraph's
customer-support tutorial). Model nodes run again; a node
that wants paired seeds reads `config["configurable"]["tracekit_seed"]`. With `log`, each test is appended to
`<log>/langgraph-<thread>/tests.jsonl`, the why log's tests file.
"""
from __future__ import annotations

import contextlib
import copy
import gc
import json
import os
import re
import uuid
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from langchain_core.messages import AIMessage, RemoveMessage, ToolMessage
from langchain_core.runnables.fallbacks import RunnableWithFallbacks
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.prebuilt import ToolNode
from langgraph.pregel import Pregel
from langgraph.store.memory import InMemoryStore

from .core import canonical
from .graph import parse_target
from .replay import MIN_EFFECT, attribute, counterfactual

# A removed tool result is replaced, not deleted: model APIs reject a tool call left without its result.
REMOVED = "(content removed by tracekit why)"
STUB = "(tracekit why: this call is not in the recorded run, so nothing was run)"


class _Thread:
    """The part of a why Run that counterfactual() reads; events carry their values inline."""

    def __init__(self, run_id: str, events: Sequence[Dict[str, Any]] = (), path: Optional[str] = None):
        self.run_id, self.events, self.path, self.stamp = run_id, list(events), path, {}

    def add_test(self, r: Dict[str, Any]) -> None:
        r.update(self.stamp, method=r["method"].replace("paired re-execution, tool results from tape",
                                                        "paired LangGraph checkpoint forks, tool results from the thread"))
        if self.path:
            os.makedirs(self.path, exist_ok=True)
            with open(os.path.join(self.path, "tests.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(r, sort_keys=True, default=str) + "\n")

    def of_type(self, t: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["type"] == t]

    @staticmethod
    def value(v: Any) -> Any:
        return v


def _is(m: Any, spec: str) -> bool:
    return m.id == spec or getattr(m, "tool_call_id", None) == spec


def _key(tc: Dict[str, Any]) -> tuple:
    return tc["name"], canonical(tc["args"])


def _actions(messages: Sequence[Any], results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tool-call events; a call missing from `results` was not served from the thread, so it counts as off tape."""
    return [{"type": "action", "tool": tc["name"], "agent": m.name or "", "args_ref": tc["args"],
             "result_ref": results.get(tc["id"], (None,))[0], "mode": results.get(tc["id"], (None, "unserved"))[1],
             "message": m.id}
            for m in messages if isinstance(m, AIMessage) for tc in m.tool_calls]


def _tool_node(b: Any) -> Optional[ToolNode]:
    """The ToolNode a node runs: the node itself, or the one `.with_fallbacks()` wraps."""
    b = b.runnable if isinstance(b, RunnableWithFallbacks) else b
    return b if isinstance(b, ToolNode) else None


def _nodes(graph: Any, path: str = "") -> Iterator[Tuple[str, Any]]:
    """Every node of the graph and of the subgraphs added to it as nodes, by path."""
    for name, n in graph.nodes.items():
        yield path + name, n
        if isinstance(n.bound, Pregel):
            yield from _nodes(n.bound, f"{path}{name}/")


def _check(graph: Any) -> None:
    """Refuse what a branch cannot run without touching real tools or the user's state."""
    # lean: a sync replay; spots async checkpointers by class name; add an ainvoke path when async graphs need it
    if type(graph.checkpointer).__name__.startswith("Async"):
        raise ValueError("the graph's checkpointer is async; fork replay runs synchronously; give the factory the "
                         "matching sync checkpointer over the same database")
    tool_nodes = 0
    for path, n in _nodes(graph):
        # not getattr: RunnableWithFallbacks hands an attribute lookup to its runnable's type hints
        if getattr(n.bound, "__dict__", {}).get("func", True) is None:
            raise ValueError(f"node {path!r} is async-only; fork replay runs graphs synchronously; give it a sync "
                             "function too (RunnableLambda(func, afunc))")
        if isinstance(n.bound, Pregel) and isinstance(n.bound.checkpointer, BaseCheckpointSaver):
            raise ValueError(f"subgraph {path!r} has its own checkpointer, which branches would write to; compile it "
                             "with checkpointer=None or True so it uses the parent's")
        sub = n.subgraphs[0] if n.subgraphs else None
        if sub is not None and sub is not n.bound and any(_tool_node(m.bound) for _, m in _nodes(sub)):
            raise ValueError(f"node {path!r} runs a subgraph with a ToolNode from its own code, where fork replay "
                             "cannot serve its tool calls; add the subgraph as a node instead")
        tool_nodes += _tool_node(n.bound) is not None
    if not tool_nodes:
        raise ValueError("the graph has no ToolNode, so its tool calls cannot be served from the recorded run; "
                         "fork replay refuses rather than run real tools; put the graph's tools in a ToolNode")


def _copy(graph: Any, serve: Any, **update: Any) -> Any:
    """A copy of the graph whose ToolNodes (in subgraph nodes too) call `serve` instead of their tools; the user's
    graph, nodes and ToolNodes are left as they are."""
    nodes = {}
    for name, n in graph.nodes.items():
        b, t = n.bound, _tool_node(n.bound)
        if t is not None:
            t = copy.copy(t)
            t.func, t.afunc = t._func, t._afunc   # the copy's own methods, not the original's
            t._wrap_tool_call, t._awrap_tool_call = serve, None
            n = n.copy({"bound": t if isinstance(b, ToolNode) else b.model_copy(update={"runnable": t})})
        elif isinstance(b, Pregel):
            b = _copy(b, serve, store=None, cache=None)   # store and cache come from the branch graph
            n = n.copy({"bound": b, "subgraphs": [b]})
        nodes[name] = n
    return graph.copy(update={"nodes": nodes, **update})


class _Step:
    """One checkpoint of the walked thread, kept small: which messages it holds and what its step wrote."""

    def __init__(self, s: Any, parent: Any, tool_steps: set):
        msgs = s.values.get("messages", ())
        self.config, self.next = s.config, s.next
        self.ids = {m.id for m in msgs} | {m.tool_call_id for m in msgs if isinstance(m, ToolMessage)}
        before = parent.values if parent is not None else {}
        self.other = sorted(k for k in set(s.values) | set(before)
                            if k != "messages" and s.values.get(k) != before.get(k))
        old = {m.id for m in before.get("messages", ())}
        # the tool results a ToolNode step added (another node may add a ToolMessage of its own: a routing call's)
        self.tool_results = {m.tool_call_id for m in msgs if isinstance(m, ToolMessage) and m.id not in old} if (
            parent is not None and set(parent.next) & tool_steps) else set()


class _Fork:
    """A System for counterfactual(): each run() is one branch of the thread, forked where the suspects entered."""

    def __init__(self, graph: Any, thread_config: Dict[str, Any], checkpoint_id: Optional[str],
                 log: Optional[str] = None, routing: Sequence[str] = ()):
        _check(graph)
        self.routing = set(routing)
        # nodes whose steps add served tool results: ToolNodes, and subgraphs with one
        tool_steps = {name for name, n in graph.nodes.items() if _tool_node(n.bound) is not None or (
            isinstance(n.bound, Pregel) and any(_tool_node(m.bound) for _, m in _nodes(n.bound)))}
        conf = dict(thread_config["configurable"], **({"checkpoint_id": checkpoint_id} if checkpoint_id else {}))
        steps, s = [], graph.get_state({"configurable": conf})
        self.recorded = s.values.get("messages") if s is not None and s.config else None
        while s is not None and s.config:   # the checkpoints of this branch of the thread, latest first
            parent = graph.get_state(s.parent_config) if s.parent_config else None
            steps.append(_Step(s, parent, tool_steps))
            s = parent
        self.steps = steps[::-1]
        if not self.recorded:
            raise ValueError(f"thread {conf['thread_id']!r} has no recorded messages in this checkpointer")
        wrote = sorted({k for st in self.steps if st.tool_results for k in st.other})
        if wrote:
            raise ValueError(f"a tool step of this thread also wrote {', '.join(wrote)} (a tool returning a Command): "
                             "fork replay serves a tool call with its recorded ToolMessage only, so those writes would "
                             "be lost; it supports tools that return messages")
        self.graph, self.thread_id = graph, conf["thread_id"]
        self.thread = _Thread(f"langgraph:{self.thread_id}", path=log and os.path.join(
            log, "langgraph-" + re.sub(r"[^\w.-]", "_", str(self.thread_id))))
        self.calls = {tc["id"]: tc for m in self.recorded if isinstance(m, AIMessage) for tc in m.tool_calls}
        self.tape: Dict[tuple, List[ToolMessage]] = {}   # (tool, canonical args) -> its recorded results, in order
        for m in self.recorded:
            if isinstance(m, ToolMessage) and m.tool_call_id in self.calls:
                self.tape.setdefault(_key(self.calls[m.tool_call_id]), []).append(m)

    def fork_at(self, suspects: Sequence[str]) -> "_Fork":
        """Fork where the first of the suspects entered the state."""
        entered = {}
        for sp in suspects:
            entered[sp] = next((i for i, st in enumerate(self.steps) if sp in st.ids), None)
            if entered[sp] is None:
                raise ValueError(f"no message or tool call {sp!r} in thread {self.thread_id!r}")
        i = min(entered.values())
        first = min(entered, key=entered.get)
        if i == 0 or len(set(self.steps[i - 1].next)) != 1:
            raise ValueError(f"cannot tell which node added {first!r}: it is in the first checkpoint or came from a "
                             "step that ran several different nodes at once; fork replay needs the message to come "
                             "from one node's step; pick another suspect, or run those nodes one after the other")
        if self.steps[i].other:
            raise ValueError(f"the step that added {first!r} also wrote {', '.join(self.steps[i].other)}; fork replay "
                             "removes messages only, so that content would stay in the branch; keep what a node adds "
                             "to the state in messages, or test another suspect")
        # a later suspect's tool result is blanked when a branch reaches that same recorded call again: the same
        # occurrence of (tool, args) on the tape, not every later call with those args
        self.blank: Dict[str, tuple] = {}
        for sp in suspects:
            if entered[sp] == i:
                continue
            m = next((m for m in self.recorded if isinstance(m, ToolMessage) and _is(m, sp)
                      and m.tool_call_id in self.calls), None)
            if m is None:
                raise ValueError(f"{sp} entered after the fork point and is not a tool result, so it cannot be removed "
                                 "in the same branch; test it on its own")
            k = _key(self.calls[m.tool_call_id])
            self.blank[sp] = (k, next(j for j, r in enumerate(self.tape[k]) if r is m))
        self.node = self.steps[i - 1].next[0]
        self.at = self.graph.get_state(self.steps[i].config)
        self.fork = self.graph.checkpointer.get_tuple(self.steps[i].config)
        self.thread.stamp = {"rung": 3, "scope": "langgraph",
                             "fork": {"checkpoint_id": self.steps[i].config["configurable"]["checkpoint_id"],
                                      "as_node": self.node}}
        # a branch continues the tape where the fork point left it, not from the thread's first result
        self.consumed: Dict[tuple, int] = {}
        for m in self.at.values["messages"]:
            if isinstance(m, ToolMessage) and m.tool_call_id in self.calls:
                k = _key(self.calls[m.tool_call_id])
                self.consumed[k] = self.consumed.get(k, 0) + 1
        return self

    def suspects_before(self, target: str) -> List[str]:
        """The ToolNode results recorded before the first tool call that matches `target`: what the model had read."""
        pred = parse_target(target)
        results = {m.tool_call_id: (m.content, "tape") for m in self.recorded if isinstance(m, ToolMessage)}
        hit = next((a for a in _actions(self.recorded, results) if pred(a, self.thread)), None)
        if hit is None:
            raise ValueError(f"target {target!r} did not happen in this thread")
        out, served = [], {tcid for st in self.steps for tcid in st.tool_results}
        for m in self.recorded:
            if m.id == hit["message"]:
                return out
            if isinstance(m, ToolMessage) and m.tool_call_id in served:
                out.append(m.tool_call_id)
        return out

    def run(self, *, seed: int = 0, interventions: Sequence[str] = (), **_: Any) -> _Thread:
        at = self.at.values["messages"]
        edits = [ToolMessage(REMOVED, id=m.id, tool_call_id=m.tool_call_id, name=m.name)
                 if isinstance(m, ToolMessage) else RemoveMessage(id=m.id)
                 for m in at if any(_is(m, sp) for sp in interventions)]
        blank = {self.blank[sp] for sp in interventions if sp in self.blank}
        served: Dict[str, tuple] = {}
        used = {k: c - 1 for k, c in self.consumed.items()}
        applied = [bool(edits)]

        def serve(request, execute):   # never calls execute: the real tool does not run
            tc = request.tool_call
            k = _key(tc)
            j = used[k] = used.get(k, -1) + 1
            recs = self.tape.get(k, ())
            if (k, j) in blank:
                applied[0] = True
                served[tc["id"]] = (REMOVED, "tape")
                return ToolMessage(REMOVED, tool_call_id=tc["id"], name=tc["name"])
            if j >= len(recs):
                served[tc["id"]] = (STUB, "stub")
                return ToolMessage(STUB, tool_call_id=tc["id"], name=tc["name"])
            r = recs[j]
            served[tc["id"]] = (r.content, "tape")
            return ToolMessage(r.content, artifact=r.artifact, status=r.status, tool_call_id=tc["id"], name=tc["name"])

        scratch = InMemorySaver()   # one per branch, dropped with it
        fork_config = scratch.put({"configurable": {"thread_id": f"tracekit-why-{uuid.uuid4().hex}",
                                                    "checkpoint_ns": ""}},
                                  self.fork.checkpoint, self.fork.metadata, self.fork.checkpoint["channel_versions"])
        branch = _copy(self.graph, serve, checkpointer=scratch, cache=None,
                       store=InMemoryStore() if self.graph.store is not None else None)
        cfg = branch.update_state(fork_config, {"messages": edits}, as_node=self.node)
        out = branch.invoke(None, {"configurable": dict(cfg["configurable"], tracekit_seed=seed)})
        before = {m.id for m in at}
        new = [m for m in out["messages"] if m.id not in before]
        names = {tc["id"]: tc["name"] for m in out["messages"] if isinstance(m, AIMessage) for tc in m.tool_calls}
        ran = [m.tool_call_id for m in new if isinstance(m, ToolMessage) and m.tool_call_id not in served
               and names.get(m.tool_call_id, m.name) not in self.routing]
        if ran:
            raise RuntimeError(f"tool call {', '.join(ran)} ran outside a ToolNode fork replay can serve (a real tool "
                               "may have run); fork replay serves ToolNodes that are nodes of the graph or of its "
                               "subgraph nodes; a call a node of the app answers itself (a routing schema) goes in "
                               "routing= (--routing); stopping")
        events = _actions(new, served)
        del branch, scratch, out, cfg   # each branch holds a copy of the thread's state: free it before the next one
        gc.collect()   # its graph copy is cyclic; without a collection, branches pile up until the collector runs
        return _Thread(self.thread.run_id, events + ([{"type": "decision", "ablated": True}] if applied[0] else []))


@contextlib.contextmanager
def _trials_heap() -> Iterator[None]:
    """Each branch's gc.collect() scans only what the trials allocate: the objects the process held before are frozen
    (out of the collector's sight) for the trials and unfrozen after, so a branch's collection costs the same in a
    large host process as in a small one. A host that froze objects itself keeps its freeze (and full collections)."""
    if gc.get_freeze_count():
        yield
        return
    gc.freeze()
    try:
        yield
    finally:
        gc.unfreeze()


def fork_replay(graph: Any, thread_config: Dict[str, Any], checkpoint_id: Optional[str], intervention: str,
                target: str, *, n: int = 30, n_max: Optional[int] = None,
                min_effect: float = MIN_EFFECT, log: Optional[str] = None, routing: Sequence[str] = ()) -> Dict[str, Any]:
    """Does removing the message `intervention` (a message id or tool_call_id) change how often `target` happens in
    the rest of the thread? `checkpoint_id` picks the recorded checkpoint to start from (None: the thread's latest).
    Same verdicts and intervals as tracekit.why's counterfactual. `log`: the why log folder the test is appended to.
    `routing`: names of calls a node of the app answers itself (routing schemas), not a ToolNode."""
    fork = _Fork(graph, thread_config, checkpoint_id, log, routing).fork_at([intervention])
    with _trials_heap():
        return counterfactual(fork.thread, intervention, target, n=n, n_max=n_max, system=fork, use_tape=False,
                              min_effect=min_effect)


def attribute_thread(graph: Any, thread_config: Dict[str, Any], target: str, suspects: Optional[Sequence[str]] = None,
                     *, checkpoint_id: Optional[str] = None, n: int = 10, n_max: int = 40,
                     min_effect: float = MIN_EFFECT, size_roles: bool = True,
                     log: Optional[str] = None, routing: Sequence[str] = ()) -> Dict[str, Any]:
    """tracekit.why's attribute() over fork replay. Default suspects: every ToolNode result before the first tool call
    that matches `target`. Every test forks where the earliest suspect entered, so all share one unaltered arm.
    `routing`: as for fork_replay."""
    fork = _Fork(graph, thread_config, checkpoint_id, log, routing)
    suspects = fork.suspects_before(target) if suspects is None else list(suspects)
    if not suspects:
        raise ValueError("no suspects: no tool result came before the action; pass suspects explicitly")
    fork.fork_at(suspects)
    with _trials_heap():
        r = attribute(fork.thread, target, suspects, n=n, n_max=n_max, system=fork, min_effect=min_effect,
                      size_roles=size_roles)
    r.update(rung=3, fork=fork.thread.stamp["fork"])
    return r
