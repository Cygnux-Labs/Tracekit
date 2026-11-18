"""What moved a call, graded by how it is known, and the chain back to the run's goal (docs/why.md#influence).

    exact     the signer's provenance: an argument's value came only from that record (the run's provenance index)
    measured  a replay without the source changed whether the call happened (a run test, verdict causal)
    seen      the source was in the context of the model call that asked for the call: `recorded` by the agent's
              runtime, `gateway` (the LLM gateway's record of the request sent it: tool_results_sent) or
              `reconstructed` (an import's "everything the run observed before the model call")
    hint      text overlap: the call's argument text is in the source (why's own value search, or shingle overlap).
              Never an influence: hidden unless asked for, never used for a finding

The goal is the run's task (an input of kind task, else the person's trusted prompts). A consequential call (stopped,
sensitive, or with provenance) gets a chain walked back from it: a call to the model call that asked for it, a message
to the model call that wrote it, a model call to the source in its context that carries an exact or measured
influence on the call (else the goal, when it was in that context, else another agent's message: the run's own hop),
observed content to the call it repeats.

It serves no step of the task (drift) when a replay without the goal kept it (run tests removing the task, or each of
the person's prompts, verdict ruled out: the call didn't need the task); it `serves` the task when such a replay changed
it, or when the chain reaches the goal or a model call on it had the goal in its context. An argument set by untrusted
content from outside the run's agents (exact) or a replay tying the call to untrusted content (measured) is named
(`untrusted`), never called drift on its own: a task that asks the agent to act on what it reads ("pay the bill in
bill.txt") gets those too (E28: 31 of 97 clean AgentDojo runs). An exact value from another agent's message is not
named: the signer's index is per run, so it can't say where that agent got the value.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from .analysis import _committed, _ended, _short, arg_provenance, is_sensitive
from .core import Run
from .graph import Graph

MAX_CHAIN = 12      # steps of a chain kept; a longer one starts with "…"
SHOWN = 8           # seen edges and hints listed per call (untrusted first, then the latest); `seen`, `hinted`: all


def goals(run: Run, g: Graph) -> List[str]:
    """The run's goal: its task inputs, else the trusted prompts the person typed."""
    task = [n for n, x in g.nodes.items() if x["type"] == "input" and x.get("kind") == "task"]
    return task or [n for n, x in g.nodes.items() if x["type"] == "input" and x.get("trust") == "trusted"
                    and x["event"].get("source", "").endswith("UserPromptSubmit")]


def consequential(run: Run, ev: Dict[str, Any]) -> bool:
    return bool(_ended(ev) or is_sensitive(run, ev) or ev.get("provenance"))


def _seen_basis(dec: Dict[str, Any], ref: Optional[str]) -> str:
    entry = next((c for c in dec.get("context", ()) if c.get("ref") == ref), {})
    if entry.get("seen") == "gateway":
        return "gateway"
    return "reconstructed" if dec.get("context_mode") == "reconstructed" else "recorded"


def graded(g: Graph, nid: str) -> Dict[str, Any]:
    """{"edges": the exact, measured and seen edges into call `nid`, "ruled": the sources a replay tested and ruled
    out}."""
    ev = g.nodes[nid]["event"]
    out: List[Dict[str, Any]] = []
    for p in ev.get("provenance") or []:
        src = "ev:" + p["from_event"] if p.get("from_event") else None
        if src in g.nodes:
            out.append({"src": src, "grade": "exact", "basis": "provenance", "field": p.get("field"),
                        "kind": p.get("kind"), "record": p.get("record")})
    ruled = []
    for e in g.in_edges(nid, ("tested",)):
        if e.get("verdict") == "causal":
            out.append({"src": e["src"], "grade": "measured", "basis": "replay", "effect": e.get("effect"),
                        "ci": e.get("ci"), "n": e.get("n"), "target": e.get("target")})
        elif e.get("verdict") == "ruled-out":
            ruled.append(e["src"])
    dec = "ev:" + ev["decision"] if ev.get("decision") else None
    if dec in g.nodes:
        dev = g.nodes[dec]["event"]
        for e in g.in_edges(dec, ("observed",)):
            if e["kind"].startswith("context"):
                basis = _seen_basis(dev, e.get("ref"))
                out.append({"src": e["src"], "grade": "seen", "basis": basis, "via": dec,
                            **({"cites": dev["tracekit"]} if basis == "gateway" and dev.get("tracekit") else {})})
    _describe(g, out)
    return {"edges": out, "ruled": ruled}


def hints(run: Run, g: Graph, nid: str, not_from: Set[str], texts=None) -> List[Dict[str, Any]]:
    """Text overlap into call `nid` from sources with no exact or measured edge (`not_from`): why's search for each
    argument value in what came before, and the graph's overlap edges when it was built with them."""
    out: List[Dict[str, Any]] = []
    for row in arg_provenance(run, g, g.nodes[nid]["event"], texts):
        out += [{"src": s["node"], "grade": "hint", "basis": "value", "value": row["value"]} for s in row["sources"]
                if s["node"] not in not_from and s["node"] != nid and s["node"] in g.nodes]
    out += [{"src": e["src"], "grade": "hint", "basis": "overlap", "score": e.get("score")}
            for e in g.in_edges(nid, ("inferred",)) if e["src"] not in not_from]
    _describe(g, out)
    return out


def _describe(g: Graph, edges: List[Dict[str, Any]]) -> None:
    for e in edges:
        n = g.nodes[e["src"]]
        # an exact source is untrusted by what provenance is: values only untrusted content brought into the run
        e.update(label=n["label"], type=n["type"], agent=n["agent"], seq=n["seq"],
                 trust="untrusted" if e["grade"] == "exact" else n.get("trust", "trusted"))


def untrusted(edges: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The edge that ties a call to untrusted content, or None: content from outside the run's agents (observed content
    or a tool's result, not another agent's message) set one of its arguments (exact), or a replay showed untrusted
    content caused it (measured)."""
    return next((e for e in edges if e["grade"] == "exact" and e["type"] in ("input", "action")
                 or e["grade"] == "measured" and e["trust"] == "untrusted"), None)


def drifted(got: Dict[str, Any], goal: List[str]) -> bool:
    """Whether a call serves no step of the task, from its graded() edges: a replay without each part of the goal kept
    it (with several prompts, a test of one alone proves nothing) and none without it changed it."""
    gs = set(goal)
    return bool(gs) and gs <= set(got["ruled"]) and not any(e["grade"] == "measured" and e["src"] in gs
                                                            for e in got["edges"])


def _context(g: Graph, dec: str) -> List[str]:
    return [e["src"] for e in g.in_edges(dec, ("observed",)) if e["kind"].startswith("context")]


def chain(g: Graph, nid: str, keys: Set[str], goal: Set[str]) -> Tuple[List[str], bool]:
    """(node ids from where the chain starts to call `nid`, whether it was cut at MAX_CHAIN steps): see the module
    docstring. `keys`: the sources of the call's exact and measured edges."""
    carries = set(g.descendants(keys)) if keys else set()   # a key source and everything its content reached
    steps, x = [nid], nid
    while True:
        n = g.nodes[x]
        nxt: Optional[str] = None
        if n["type"] in ("action", "message"):
            d = n["event"].get("decision")
            nxt = "ev:" + d if d and "ev:" + d in g.nodes else None
        elif n["type"] == "decision":
            ctx = [s for s in _context(g, x) if s not in steps]
            # what carries a key source's content, else the goal, else another agent's message: the run's own hop
            pick = [s for s in ctx if s in carries] or [s for s in ctx if s in goal] or \
                [s for s in ctx if g.nodes[s]["type"] == "message"]
            nxt = max(pick, key=lambda s: g.nodes[s]["seq"]) if pick else None
        elif n["type"] == "input" and x not in goal:
            nxt = next((e["src"] for e in g.in_edges(x, ("observed",)) if e["kind"] == "same-content"), None)
        if nxt is None or nxt in steps:
            return steps[::-1], False
        if len(steps) == MAX_CHAIN:
            return steps[::-1], True
        steps.append(nxt)
        x = nxt


def call_influence(run: Run, g: Graph, nid: str, goal: Optional[List[str]] = None, texts=None) -> Dict[str, Any]:
    """Graded edges, hints, chain, goal and what the call serves, for call node `nid`."""
    goal = goals(run, g) if goal is None else goal
    gs = set(goal)
    ev = g.nodes[nid]["event"]
    got = graded(g, nid)
    edges = got["edges"]
    steps, cut = chain(g, nid, {e["src"] for e in edges if e["grade"] in ("exact", "measured")}, gs)
    goal_seen = steps[0] in gs or any(g.nodes[s]["type"] == "decision" and gs & set(_context(g, s)) for s in steps)
    needs = any(e["grade"] == "measured" and e["src"] in gs for e in edges)   # a replay without the task changed it
    serves = "drift" if drifted(got, goal) else "task" if goal_seen or needs else "unknown"
    step = next((s for s in steps if g.nodes[s]["type"] == "decision"), None) if serves == "task" else None
    seen = [e for e in edges if e["grade"] == "seen"]
    hinted = hints(run, g, nid, {e["src"] for e in edges if e["grade"] != "seen"}, texts)
    out = {"node": nid, "tool": ev["tool"], "agent": ev["agent"], "seq": ev["seq"], "ended": _ended(ev),
           "goal": [_goal_text(run, g, s) for s in goal], "seen": len(seen), "hinted": len(hinted),
           "edges": [e for e in edges if e["grade"] != "seen"] + _first(seen), "hints": _first(hinted),
           "ruled_out": [g.nodes[s]["label"] for s in got["ruled"]], "chain": [_step(g, s, nid, edges) for s in steps],
           "truncated": cut, "serves": serves, "untrusted": untrusted(edges),
           "step": _step(g, step, nid, edges)["text"] if step else None,
           **({"tracekit": ev["tracekit"]} if ev.get("tracekit") else {})}
    out["words"] = words(out)
    return out


def _first(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(edges, key=lambda e: (e["trust"] != "untrusted", -e["seq"]))[:SHOWN]


def _goal_text(run: Run, g: Graph, nid: str) -> Optional[str]:
    v = run.value(g.nodes[nid]["event"].get("ref"))
    return None if v is None or _committed(v) else _short(v, 120)


def _best(edges: List[Dict[str, Any]], src: str) -> Optional[Dict[str, Any]]:
    """The strongest exact or measured edge from `src`: what a chain step says about its influence on the call."""
    return next((e for grade in ("exact", "measured") for e in edges if e["src"] == src and e["grade"] == grade), None)


def _step(g: Graph, s: str, nid: str, edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    n, ev = g.nodes[s], g.nodes[s]["event"]
    t = n["type"]
    if s == nid:
        text = "this call"
    elif t == "input":
        text = "the task" if n.get("kind") == "task" else f"read {n['label']}"
    elif t == "decision":
        ctx = _context(g, s)
        bad = sum(g.nodes[c].get("trust") == "untrusted" for c in ctx)
        text = f"{n['agent']} decided ({n['label']}; {len(ctx)} in context" + (f", {bad} untrusted)" if bad else ")")
    elif t == "message":
        text = f"message {ev['agent']} → {ev['to']}"
    else:
        text = f"called {n['label']}"
    e = _best(edges, s) if s != nid else None
    trust = "untrusted" if e and e["grade"] == "exact" else n.get("trust", "trusted")
    return {"node": s, "type": t, "text": text, "trust": trust,
            "grade": e["grade"] if e else None, "how": _how(e) if e else None}


def _how(e: Dict[str, Any]) -> str:
    if e["grade"] == "exact":
        return f"exact: `{e['field']}`"
    if e["grade"] == "measured":
        return "measured: effect " + (f"{e['effect']:+.2f}" if isinstance(e.get("effect"), (int, float)) else "?")
    return e["grade"]


def words(inf: Dict[str, Any]) -> str:
    """The answer in words, first: where the call came from, or that nothing links it."""
    head = f"{inf['tool']} ({inf['agent']}" + (f", {inf['ended']}" if inf["ended"] else "") + ")"
    goal = next((t for t in inf["goal"] if t), None)

    def say(st):
        text = f"task '{goal}'" if st["text"] == "the task" and goal else st["text"]
        notes = [x for x in ("untrusted" if st["trust"] == "untrusted" else "", st["how"] or "") if x]
        return text + (f" ({'; '.join(notes)})" if notes else "")
    path = ("… → " if inf["truncated"] else "") + " → ".join(say(s) for s in inf["chain"])
    if not inf["edges"]:
        return f"{head}: no influence found. Nothing exact, measured or seen links it to what the agents read."
    u = inf["untrusted"]
    note = "" if not u or inf["serves"] == "drift" else " " + (
        f"Its `{u['field']}` came only from {u['label']} (untrusted; exact)" if u["grade"] == "exact" else
        f"A replay without {u['label']} (untrusted) changed it ({_how(u)})") + \
        ": test it without the task to see whether it serves the task."
    if inf["serves"] == "drift":
        return f"{head} serves no step of the task: a replay without the task kept it. Chain: {path}."
    if inf["serves"] == "unknown":
        return f"{head}: no chain to the task recorded. {path[0].upper() + path[1:]}.{note}"
    return f"{head} came from: {path}.{note}"


def influences(run: Run, g: Graph, texts=None, risky: bool = False) -> List[Dict[str, Any]]:
    """call_influence() of every consequential call of the run, in log order; `risky`: the calls stopped or flagged,
    with an exact or measured edge (a replay tested them), or that serve no step of the task, whatever their tool."""
    goal = goals(run, g)

    def shown(nid: str, ev: Dict[str, Any]) -> bool:
        got = graded(g, nid)
        return bool(_ended(ev)) or any(e["grade"] != "seen" for e in got["edges"]) or drifted(got, goal)
    return [call_influence(run, g, nid, goal, texts) for nid, n in sorted(g.nodes.items(), key=lambda kv: kv[1]["seq"])
            if n["type"] == "action" and (shown(nid, n["event"]) if risky else consequential(run, n["event"]))]
