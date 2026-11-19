"""What moved a call, graded by how it is known, and the chain back to the run's goal (docs/why.md#influence).

    exact     the signer's provenance: this untrusted record holds an argument's value, and nothing the signer indexed
              as trusted does (the run's provenance index); only on a run imported from its signed records, the call's
              citation matching its record. A why log's own `provenance` field is `claimed`: shown as the log's word,
              never used for a finding, the chain or the order of the answers
    measured  a replay without the source changed whether the call happened (a run test, verdict causal, whose target
              matches only this call in the run: graph._attach_tests)
    seen      the source was in the context of the model call that asked for the call: `recorded` by the agent's
              runtime, `gateway` (the LLM gateway's record of the request sent it: tool_results_sent) or
              `reconstructed` (an import's "everything the run observed before the model call")
    hint      text overlap: the call's argument text is in the source (why's own value search, or shingle overlap).
              Never an influence: hidden unless asked for, never used for a finding

The goal is the run's own task, as the signer recorded it where it did: an input of source `task`, trusted and of kind
task (in an import, one its signed records back), else the trusted prompts the person typed. A call gets a chain walked
back from it: a call to the model call that asked for it, a message to the model call that wrote it, a model call to
the source in its context that is (or carries) an exact or measured source of the call, else the goal when it was in
that context, else another agent's message (the run's own hop), observed content to the call it repeats.

Only a replay says whether a call serves the task: it serves no step of it (drift) when the strongest replay without
each part of the goal kept it, and `serves` the task when one without it changed it. Otherwise it is `unknown`, and the
words name the untrusted content its model call had in context. An argument from untrusted content outside the run's
agents (exact) or a replay tying the call to untrusted content (measured) is named (`untrusted`), never called drift on
its own: a task that asks the agent to act on what it reads ("pay the bill in bill.txt") gets those too (E28: 31 of 97
clean AgentDojo runs). An exact value from another agent's message is not named: the signer's index is per run, so it
can't say where that agent got the value.
"""
from __future__ import annotations

import heapq
from typing import Any, Dict, List, Optional, Set, Tuple

from .analysis import _committed, _ended, _short, _texts, arg_provenance, is_sensitive, trusted_holders
from .core import Run
from .graph import Graph

MAX_CHAIN = 12      # steps of a chain kept; a longer one starts with "…"
SHOWN = 8           # seen edges and hints listed per call (untrusted first, then the latest); `seen`, `hinted`: all
NAMED = 5           # untrusted sources in context the words name; the rest are counted


def _imported(run: Run) -> bool:
    return (run.start.get("meta") or {}).get("source") == "tracekit"


def _backed(run: Run, ev: Dict[str, Any]) -> bool:
    """Whether a signed record backs event `ev`: the run was imported from its records (import_v2) and the event cites
    one that matched it."""
    return _imported(run) and bool(ev.get("tracekit") or ev.get("tracekit_task")) and not ev.get("tracekit_mismatch")


def goals(run: Run, g: Graph) -> List[str]:
    """The run's goal: its own task (source task, trusted, kind task; in an import, backed by its signed records), else
    the trusted prompts the person typed (in an import, backed too). An input's kind or source alone, which the log
    writes, makes nothing a goal."""
    def mine(x: Dict[str, Any]) -> bool:
        return x["type"] == "input" and x.get("trust") == "trusted" and (not _imported(run) or _backed(run, x["event"]))
    task = [n for n, x in g.nodes.items() if mine(x) and x.get("kind") == "task" and x["event"].get("source") == "task"]
    return task or [n for n, x in g.nodes.items() if mine(x) and x["event"].get("source", "").endswith("UserPromptSubmit")]


def consequential(run: Run, ev: Dict[str, Any]) -> bool:
    return bool(_ended(ev) or is_sensitive(run, ev) or ev.get("provenance"))


def graded(g: Graph, nid: str, seen: bool = True) -> Dict[str, Any]:
    """{"edges": the exact (or claimed), measured and (with `seen`) seen edges into call `nid`, "ruled": the sources a
    replay tested and ruled out}. A finding reads no seen edge: it asks for none."""
    ev = g.nodes[nid]["event"]
    out: List[Dict[str, Any]] = []
    grade = "exact" if _backed(g.run, ev) else "claimed"
    for p in ev.get("provenance") or []:
        src = "ev:" + p["from_event"] if p.get("from_event") else None
        if src in g.nodes:
            out.append({"src": src, "grade": grade, "basis": "provenance", "field": p.get("field"),
                        "kind": p.get("kind"), "record": p.get("record")})
    ruled = []
    for e in g.in_edges(nid, ("tested",)):
        if e.get("verdict") == "causal":
            out.append({"src": e["src"], "grade": "measured", "basis": "replay", "effect": e.get("effect"),
                        "ci": e.get("ci"), "n": e.get("n"), "target": e.get("target")})
        elif e.get("verdict") == "ruled-out":
            ruled.append(e["src"])
    _describe(g, out)
    dec = _decision(g, ev)
    return {"edges": out + (_seen(g, dec) if seen and dec else []), "ruled": ruled}


def _decision(g: Graph, ev: Dict[str, Any]) -> Optional[str]:
    dec = "ev:" + ev["decision"] if ev.get("decision") else None
    return dec if dec in g.nodes else None


def _seen(g: Graph, dec: str, edges: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """The seen edges of model call `dec`'s context, in order (of its context `edges` given, else of all)."""
    dev, out = g.nodes[dec]["event"], []
    via_gateway = {c["ref"] for c in dev.get("context", ()) if c.get("seen") == "gateway"}
    rest = "reconstructed" if dev.get("context_mode") == "reconstructed" else "recorded"
    for e in _context(g, dec)[0] if edges is None else edges:
        basis = "gateway" if e.get("ref") in via_gateway else rest
        out.append({"src": e["src"], "grade": "seen", "basis": basis, "via": dec,
                    **({"cites": dev["tracekit"]} if basis == "gateway" and dev.get("tracekit") else {})})
    _describe(g, out)
    return out


def hints(g: Graph, nid: str, prov: List[Dict[str, Any]], not_from: Set[str]) -> List[Dict[str, Any]]:
    """Text overlap into call `nid` from sources with no exact or measured edge (`not_from`): why's search for each
    argument value in what came before (`prov`: arg_provenance of the call), and the graph's overlap edges when it was
    built with them."""
    out: List[Dict[str, Any]] = []
    for row in prov:
        out += [{"src": s["node"], "grade": "hint", "basis": "value", "value": row["value"]} for s in row["sources"]
                if s["node"] not in not_from and s["node"] != nid and s["node"] in g.nodes]
    out += [{"src": e["src"], "grade": "hint", "basis": "overlap", "score": e.get("score")}
            for e in g.in_edges(nid, ("inferred",)) if e["src"] not in not_from]
    _describe(g, out)
    return out


def _describe(g: Graph, edges: List[Dict[str, Any]]) -> None:
    for e in edges:
        n = g.nodes[e["src"]]
        e.update(label=n["label"], type=n["type"], agent=n["agent"], seq=n["seq"], trust=n.get("trust", "trusted"))


def untrusted(edges: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The edge that ties a call to untrusted content, or None: the signer traced one of its arguments to content from
    outside the run's agents (observed content or a tool's result, not another agent's message: exact), or a replay
    showed untrusted content caused it (measured)."""
    return next((e for e in edges if e["grade"] == "exact" and e["type"] in ("input", "action")
                 or e["grade"] == "measured" and e["trust"] == "untrusted"), None)


def drifted(got: Dict[str, Any], goal: List[str]) -> bool:
    """Whether a call serves no step of the task, from its graded() edges: the strongest replay without each part of
    the goal kept it (with several prompts, a test of one alone proves nothing)."""
    gs = set(goal)
    return bool(gs) and gs <= set(got["ruled"])


Edges = List[Dict[str, Any]]


def _context(g: Graph, dec: str, memo: Optional[Dict[Any, Any]] = None) -> Tuple[Edges, Edges]:
    """(the context edges into model call `dec`, those from untrusted sources, the latest first), read once per model
    call for the calls of a run (`memo`: influences' own, which every call shares)."""
    if memo is not None and dec in memo:
        return memo[dec]
    edges = [e for e in g.in_edges(dec, ("observed",)) if e["kind"].startswith("context")]
    bad = [e for e in edges if g.nodes[e["src"]].get("trust") == "untrusted"]
    bad.sort(key=lambda e: g.nodes[e["src"]]["seq"], reverse=True)
    if memo is not None:
        memo[dec] = edges, bad
    return edges, bad


def chain(g: Graph, nid: str, keys: Set[str], goal: Set[str], memo=None) -> Tuple[List[str], bool]:
    """(node ids from where the chain starts to call `nid`, whether it was cut at MAX_CHAIN steps): see the module
    docstring. `keys`: the sources of the call's exact and measured edges."""
    carries: Optional[Set[str]] = None   # what the keys' content reached: worked out only when a model call didn't see one
    steps, x = [nid], nid
    while True:
        n = g.nodes[x]
        nxt: Optional[str] = None
        if n["type"] in ("action", "message"):
            d = n["event"].get("decision")
            nxt = "ev:" + d if d and "ev:" + d in g.nodes else None
        elif n["type"] == "decision":
            ctx = [e["src"] for e in _context(g, x, memo)[0] if e["src"] not in steps]
            pick = [s for s in ctx if s in keys]
            # a key from before this model call that it didn't see itself: another agent's message may carry it
            if not pick and any(k not in steps and g.nodes[k]["seq"] < n["seq"] for k in keys):
                carries = set(g.descendants(keys)) if carries is None else carries
                pick = [s for s in ctx if s in carries]
            pick = pick or [s for s in ctx if s in goal] or [s for s in ctx if g.nodes[s]["type"] == "message"]
            nxt = max(pick, key=lambda s: g.nodes[s]["seq"]) if pick else None
        elif n["type"] == "input" and x not in goal:
            nxt = next((e["src"] for e in g.in_edges(x, ("observed",)) if e["kind"] == "same-content"), None)
        if nxt is None or nxt in steps:
            return steps[::-1], False
        if len(steps) == MAX_CHAIN:
            return steps[::-1], True
        steps.append(nxt)
        x = nxt


def call_influence(run: Run, g: Graph, nid: str, goal: Optional[List[str]] = None, texts=None,
                   memo=None) -> Dict[str, Any]:
    """Graded edges, hints, chain, goal and what the call serves, for call node `nid`. `memo`: model calls' contexts
    already read (_context), shared by the calls of a run."""
    goal = goals(run, g) if goal is None else goal
    memo = {} if memo is None else memo
    gs = set(goal)
    ev = g.nodes[nid]["event"]
    got = graded(g, nid, seen=False)
    edges = got["edges"]   # exact (or claimed) and measured
    dec = _decision(g, ev)
    ctx, bad = _context(g, dec, memo) if dec else ([], [])
    # the seen edges listed: the untrusted first, then the latest; each one built only for those
    first = bad[:SHOWN]
    if len(first) < SHOWN:
        first += heapq.nlargest(SHOWN - len(first), (e for e in ctx if g.nodes[e["src"]].get("trust") != "untrusted"),
                                key=lambda e: g.nodes[e["src"]]["seq"])
    seen = _seen(g, dec, first) if dec else []
    steps, cut = chain(g, nid, {e["src"] for e in edges if e["grade"] in ("exact", "measured")}, gs, memo)
    needs = any(e["grade"] == "measured" and e["src"] in gs for e in edges)   # a replay without the task changed it
    serves = "drift" if drifted(got, goal) else "task" if needs else "unknown"
    step = next((s for s in steps if g.nodes[s]["type"] == "decision"), None) if serves == "task" else None
    prov = arg_provenance(run, g, ev, texts)
    hinted = hints(g, nid, prov, {e["src"] for e in edges if e["grade"] in ("exact", "measured")})
    u = untrusted(edges)
    args = run.value(ev.get("args_ref"))
    traced = args.get(u["field"]) if u and u["grade"] == "exact" and isinstance(args, dict) else None
    out = {"node": nid, "tool": ev["tool"], "agent": ev["agent"], "seq": ev["seq"], "ended": _ended(ev),
           "goal": [_goal_text(run, g, s) for s in goal], "seen": len(ctx), "hinted": len(hinted),
           "edges": edges + seen, "hints": _first(hinted), "ruled_out": [g.nodes[s]["label"] for s in got["ruled"]],
           "chain": [_step(g, s, nid, edges, memo) for s in steps], "truncated": cut, "serves": serves,
           "untrusted": u,
           # the trusted content that holds the traced value too (the task, a trusted result): said beside
           "also": trusted_holders(run, ev["seq"], traced, texts, memo) if traced is not None else [],
           "in_context": list(dict.fromkeys(g.nodes[e["src"]]["label"] for e in bad)),
           "step": _step(g, step, nid, edges, memo)["text"] if step else None,
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


def _step(g: Graph, s: str, nid: str, edges: List[Dict[str, Any]], memo=None) -> Dict[str, Any]:
    n, ev = g.nodes[s], g.nodes[s]["event"]
    t = n["type"]
    if s == nid:
        text = "this call"
    elif t == "input":
        text = "the task" if n.get("kind") == "task" and ev.get("source") == "task" else f"read {n['label']}"
    elif t == "decision":
        ctx, bad = _context(g, s, memo)
        text = f"{n['agent']} decided ({n['label']}; {len(ctx)} in context" + (f", {len(bad)} untrusted)" if bad else ")")
    elif t == "message":
        text = f"message {ev['agent']} → {ev['to']}"
    else:
        text = f"called {n['label']}"
    e = _best(edges, s) if s != nid else None
    return {"node": s, "type": t, "text": text, "trust": n.get("trust", "trusted"),
            "grade": e["grade"] if e else None, "how": _how(e) if e else None}


def _how(e: Dict[str, Any]) -> str:
    if e["grade"] == "exact":
        return f"exact: `{e['field']}`"
    if e["grade"] == "measured":
        return "measured: effect " + (f"{e['effect']:+.2f}" if isinstance(e.get("effect"), (int, float)) else "?")
    return e["grade"]


def _named(labels: List[str]) -> str:
    return ", ".join(labels[:NAMED]) + (f" and {len(labels) - NAMED} more" if len(labels) > NAMED else "")


def words(inf: Dict[str, Any]) -> str:
    """The answer in words, first: what a replay says about the task, where the call came from, and the untrusted
    content around it; or that nothing links it."""
    head = f"{inf['tool']} ({inf['agent']}" + (f", {inf['ended']}" if inf["ended"] else "") + ")"
    goal = next((t for t in inf["goal"] if t), None)

    def say(st):
        text = f"task '{goal}'" if st["text"] == "the task" and goal else st["text"]
        notes = [x for x in ("untrusted" if st["trust"] == "untrusted" else "", st["how"] or "") if x]
        return text + (f" ({'; '.join(notes)})" if notes else "")
    path = ("… → " if inf["truncated"] else "") + " → ".join(say(s) for s in inf["chain"])
    if not inf["edges"]:
        return f"{head}: no influence found. Nothing exact, measured or seen links it to what the agents read."
    if inf["serves"] == "drift":
        return f"{head} serves no step of the task: a replay without the task kept it. Chain: {path}."
    u = inf["untrusted"]
    note = "" if not u else " " + (
        f"{u['label']} holds its `{u['field']}`, and nothing the signer indexed as trusted does"
        + (f" (why's search finds the value in {_named(inf['also'])} too)" if inf["also"] else "")
        if u["grade"] == "exact" else f"A replay without {u['label']} (untrusted) changed it ({_how(u)})") + \
        ": test it without the task to see whether it serves the task."
    if inf["serves"] == "task":
        return f"{head} came from: {path}.{note}"
    around = f" Untrusted content in its model call's context: {_named(inf['in_context'])}." if inf["in_context"] else ""
    return f"{head}: no replay has tested it without the task.{around} Chain: {path}.{note}"


def influences(run: Run, g: Graph, texts=None, risky: bool = False) -> List[Dict[str, Any]]:
    """call_influence() of every consequential call of the run, in log order; `risky`: the calls stopped or flagged,
    with an exact or measured edge, that serve no step of the task, or whose model call had untrusted content in its
    context, whatever their tool."""
    goal, memo = goals(run, g), {}
    texts = _texts(run) if texts is None else texts   # read once for every call's hints

    def shown(nid: str, ev: Dict[str, Any]) -> bool:
        got, dec = graded(g, nid, seen=False), _decision(g, ev)
        return bool(_ended(ev)) or drifted(got, goal) or any(e["grade"] in ("exact", "measured") for e in got["edges"]) \
            or bool(dec and _context(g, dec, memo)[1])
    return [call_influence(run, g, nid, goal, texts, memo) for nid, n in
            sorted(g.nodes.items(), key=lambda kv: kv[1]["seq"])
            if n["type"] == "action" and (shown(nid, n["event"]) if risky else consequential(run, n["event"]))]
