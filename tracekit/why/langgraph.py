"""Counterfactual replay of a LangGraph thread by forking one of its checkpoints (rung 3).

LangGraph keeps every checkpoint of a thread. To test whether a message caused an action, take the checkpoint at which
the message entered the state and fork it twice per trial: once as recorded, once with the message removed
(`update_state(..., as_node=<the node that added it>)`), then run only what comes after (`invoke(None, fork)`). The
prefix is the recorded run itself, not a re-execution of it.

Branches run on a copy of the graph whose checkpointer holds only the fork point, so nothing lands in the user's
thread. Tool calls never reach a real tool: every ToolNode call is served from the thread's own tool results (same
tool, same canonical args, in order) or a stub. Model nodes run again; a node that wants paired seeds reads
`config["configurable"]["tracekit_seed"]`.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from langchain_core.messages import AIMessage, RemoveMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.prebuilt import ToolNode

from .core import canonical
from .graph import parse_target
from .replay import MIN_EFFECT, attribute, counterfactual

# A removed tool result is replaced, not deleted: model APIs reject a tool call left without its result.
REMOVED = "(content removed by tracekit why)"
STUB = "(tracekit why: this call is not in the recorded run, so nothing was run)"


class _Thread:
    """The part of a why Run that counterfactual() reads; events carry their values inline."""

    def __init__(self, run_id: str, events: Sequence[Dict[str, Any]] = ()):
        self.run_id, self.events = run_id, list(events)

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
    return [{"type": "action", "tool": tc["name"], "agent": m.name or "", "args_ref": tc["args"],
             "result_ref": results.get(tc["id"], (None,))[0], "mode": results.get(tc["id"], (None, "tape"))[1],
             "message": m.id}
            for m in messages if isinstance(m, AIMessage) for tc in m.tool_calls]


class _Fork:
    """A System for counterfactual(): each run() is one branch of the thread, forked where the suspects entered."""

    def __init__(self, graph: Any, thread_config: Dict[str, Any], checkpoint_id: Optional[str]):
        conf = dict(thread_config["configurable"], **({"checkpoint_id": checkpoint_id} if checkpoint_id else {}))
        snaps, s = [], graph.get_state({"configurable": conf})
        while s is not None and s.config:   # the checkpoints of this branch of the thread, latest first
            snaps.append(s)
            s = graph.get_state(s.parent_config) if s.parent_config else None
        self.snaps = snaps[::-1]
        if not self.snaps or not self.snaps[-1].values.get("messages"):
            raise ValueError(f"thread {conf['thread_id']!r} has no recorded messages in this checkpointer")
        self.graph, self.thread_id = graph, conf["thread_id"]
        self.thread = _Thread(f"langgraph:{self.thread_id}")
        self.recorded = self.snaps[-1].values["messages"]
        self.calls = {tc["id"]: tc for m in self.recorded if isinstance(m, AIMessage) for tc in m.tool_calls}
        self.tape: Dict[tuple, List[Any]] = {}   # (tool, canonical args) -> its recorded results, in order
        for m in self.recorded:
            if isinstance(m, ToolMessage) and m.tool_call_id in self.calls:
                self.tape.setdefault(_key(self.calls[m.tool_call_id]), []).append(m.content)
        self.tools = [n.bound for n in graph.nodes.values() if isinstance(n.bound, ToolNode)]
        if not self.tools:
            raise ValueError("the graph has no ToolNode, so its tool calls cannot be served from the recorded run; "
                             "fork replay refuses rather than run real tools; put the graph's tools in a ToolNode")

    def fork_at(self, suspects: Sequence[str]) -> "_Fork":
        """Fork where the first of the suspects entered the state, on a scratch copy of that checkpoint."""
        entered = {}
        for sp in suspects:
            entered[sp] = next((i for i, x in enumerate(self.snaps)
                                if any(_is(m, sp) for m in x.values.get("messages", ()))), None)
            if entered[sp] is None:
                raise ValueError(f"no message or tool call {sp!r} in thread {self.thread_id!r}")
        # a removed tool result is also blanked when a branch makes its call again
        self.blank = {sp: _key(self.calls[m.tool_call_id]) for sp in suspects for m in self.recorded
                      if isinstance(m, ToolMessage) and _is(m, sp) and m.tool_call_id in self.calls}
        i = min(entered.values())
        if i == 0 or len(self.snaps[i - 1].next) != 1:
            raise ValueError(f"cannot tell which node added {min(entered, key=entered.get)!r}: "
                             "fork replay needs the message to come from one node's step")
        late = [sp for sp in suspects if entered[sp] > i and sp not in self.blank]
        if late:
            raise ValueError(f"{', '.join(late)} entered after the fork point and is not a tool result, so it cannot "
                             "be removed in the same branch; test it on its own")
        self.at, self.node = self.snaps[i], self.snaps[i - 1].next[0]
        scratch = InMemorySaver()
        t = self.graph.checkpointer.get_tuple(self.at.config)
        self.fork_config = scratch.put({"configurable": {"thread_id": self.thread_id, "checkpoint_ns": ""}},
                                       t.checkpoint, t.metadata, t.checkpoint["channel_versions"])
        self.branches = self.graph.copy(update={"checkpointer": scratch})
        return self

    def suspects_before(self, target: str) -> List[str]:
        """The tool results recorded before the first tool call that matches `target`: what the model had read."""
        pred = parse_target(target)
        results = {m.tool_call_id: (m.content, "tape") for m in self.recorded if isinstance(m, ToolMessage)}
        hit = next((a for a in _actions(self.recorded, results) if pred(a, self.thread)), None)
        if hit is None:
            raise ValueError(f"target {target!r} did not happen in this thread")
        out = []
        for m in self.recorded:
            if m.id == hit["message"]:
                return out
            if isinstance(m, ToolMessage):
                out.append(m.tool_call_id)
        return out

    def run(self, *, seed: int = 0, interventions: Sequence[str] = (), **_: Any) -> _Thread:
        at = self.at.values["messages"]
        edits = [ToolMessage(REMOVED, id=m.id, tool_call_id=m.tool_call_id, name=m.name)
                 if isinstance(m, ToolMessage) else RemoveMessage(id=m.id)
                 for m in at if any(_is(m, sp) for sp in interventions)]
        blank = {self.blank[sp] for sp in interventions if sp in self.blank}
        served: Dict[str, tuple] = {}
        used: Dict[tuple, int] = {}
        applied = [bool(edits)]

        def serve(request, execute):   # never calls execute: the real tool does not run
            tc = request.tool_call
            k = _key(tc)
            j = used[k] = used.get(k, -1) + 1
            if k in blank:
                applied[0] = True
                served[tc["id"]] = (REMOVED, "tape")
            else:
                recs = self.tape.get(k, ())
                served[tc["id"]] = (recs[j], "tape") if j < len(recs) else (STUB, "stub")
            return ToolMessage(served[tc["id"]][0], tool_call_id=tc["id"], name=tc["name"])

        async def aserve(request, execute):
            return serve(request, execute)

        # lean: swaps ToolNode's private wrapper for the branch, so one replay at a time per graph; use a public
        # ToolNode hook if LangGraph adds one
        saved = [(tn._wrap_tool_call, tn._awrap_tool_call) for tn in self.tools]
        try:
            for tn in self.tools:
                tn._wrap_tool_call, tn._awrap_tool_call = serve, aserve
            cfg = self.branches.update_state(self.fork_config, {"messages": edits}, as_node=self.node)
            out = self.branches.invoke(None, {"configurable": dict(cfg["configurable"], tracekit_seed=seed)})
        finally:
            for tn, (w, aw) in zip(self.tools, saved):
                tn._wrap_tool_call, tn._awrap_tool_call = w, aw
        before = {m.id for m in at}
        events = _actions([m for m in out["messages"] if m.id not in before], served)
        return _Thread(self.thread.run_id, events + ([{"type": "decision", "ablated": True}] if applied[0] else []))


def _rung3(r: Dict[str, Any], fork: _Fork) -> Dict[str, Any]:
    r.update(rung=3, scope="langgraph", fork={"checkpoint_id": fork.at.config["configurable"]["checkpoint_id"],
                                              "as_node": fork.node},
             method=r["method"].replace("paired re-execution, tool results from tape",
                                        "paired LangGraph checkpoint forks, tool results from the thread"))
    return r


def fork_replay(graph: Any, thread_config: Dict[str, Any], checkpoint_id: Optional[str], intervention: str,
                target: str, *, n: int = 30, n_max: Optional[int] = None,
                min_effect: float = MIN_EFFECT) -> Dict[str, Any]:
    """Does removing the message `intervention` (a message id or tool_call_id) change how often `target` happens in
    the rest of the thread? `checkpoint_id` picks the recorded checkpoint to start from (None: the thread's latest).
    Same verdicts and intervals as tracekit.why's counterfactual."""
    fork = _Fork(graph, thread_config, checkpoint_id).fork_at([intervention])
    return _rung3(counterfactual(fork.thread, intervention, target, n=n, n_max=n_max, system=fork, use_tape=False,
                                 save=False, min_effect=min_effect), fork)


def attribute_thread(graph: Any, thread_config: Dict[str, Any], target: str, suspects: Optional[Sequence[str]] = None,
                     *, checkpoint_id: Optional[str] = None, n: int = 10, n_max: int = 40,
                     min_effect: float = MIN_EFFECT, size_roles: bool = True) -> Dict[str, Any]:
    """tracekit.why's attribute() over fork replay. Default suspects: every tool result before the first tool call
    that matches `target`. Every test forks where the earliest suspect entered, so all share one unaltered arm."""
    fork = _Fork(graph, thread_config, checkpoint_id)
    suspects = fork.suspects_before(target) if suspects is None else list(suspects)
    if not suspects:
        raise ValueError("no suspects: no tool result came before the action; pass suspects explicitly")
    fork.fork_at(suspects)
    r = attribute(fork.thread, target, suspects, n=n, n_max=n_max, system=fork, min_effect=min_effect, save=False,
                  size_roles=size_roles)
    for t in r["tests"]:
        _rung3(t, fork)
    r.update(rung=3, fork=r["group"]["fork"])
    return r
