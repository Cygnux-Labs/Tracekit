"""Multi-agent evaluation and the cross-run influence index.

structure()          per-agent activity, messages that were delivered but never used, critical path
influence_matrix()   counterfactual test of every channel and every untrusted input against a target:
                     which agents and sources actually change the outcome
influence_index()    across many runs: how often each piece of content reached actions, and its
                     tested effects. The citation-like layer: content cited by decisions, ranked.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional

from .core import Run, load_run
from .graph import Graph, build_graph, target_hits
from .replay import System, counterfactual


def structure(run: Run, graph: Optional[Graph] = None) -> Dict[str, Any]:
    g = graph or build_graph(run)
    agents: Dict[str, Dict[str, int]] = {}
    for ev in run.events:
        if ev["type"] in ("decision", "action", "message", "input"):
            a = agents.setdefault(ev["agent"], {"inputs": 0, "decisions": 0, "actions": 0, "sent": 0, "received": 0})
            a[{"input": "inputs", "decision": "decisions", "action": "actions", "message": "sent"}[ev["type"]]] += 1
            if ev["type"] == "message":
                agents.setdefault(ev["to"], {"inputs": 0, "decisions": 0, "actions": 0, "sent": 0, "received": 0})
                agents[ev["to"]]["received"] += 1

    unused = []
    for n in g.nodes.values():
        if n["type"] == "message" and not g.out_edges(n["id"], ("observed",)):
            unused.append({"from": n["agent"], "to": n["to"], "seq": n["seq"]})

    # longest observed path ending at an action (by hop count): the run's critical chain
    order = sorted(g.nodes, key=lambda x: g.nodes[x]["seq"])
    best: Dict[str, int] = {}
    prev: Dict[str, Optional[str]] = {}
    for nid in order:
        ins = g.in_edges(nid, ("observed",))
        best[nid], prev[nid] = 0, None
        for e in ins:
            if best.get(e["src"], 0) + 1 > best[nid]:
                best[nid], prev[nid] = best[e["src"]] + 1, e["src"]
    actions = [n for n in order if g.nodes[n]["type"] == "action"]
    critical: List[str] = []
    if actions:
        end = max(actions, key=lambda n: best[n])
        while end:
            critical.append(f"{g.nodes[end]['label']} [{g.nodes[end]['agent']}]")
            end = prev[end]
        critical.reverse()

    return {"agents": agents, "unused_messages": unused, "critical_path": critical,
            "edges_by_evidence": {k: sum(1 for e in g.edges if e["evidence"] == k)
                                  for k in ("observed", "inferred", "tested")}}


def candidate_interventions(run: Run) -> List[str]:
    """Every message channel, and every input source (task excluded)."""
    specs: List[str] = []
    for ev in run.events:
        if ev["type"] == "message":
            s = f"msg:{ev['agent']}->{ev['to']}"
        elif ev["type"] == "input" and ev.get("kind") != "task":
            s = f"input:{ev['source']}"
        else:
            continue
        if s not in specs:
            specs.append(s)
    return specs


def influence_matrix(run: Run, targets: Iterable[str], *, n: int = 30, system: Optional[System] = None,
                     interventions: Optional[List[str]] = None, save: bool = True) -> List[Dict[str, Any]]:
    rows = []
    for spec in interventions or candidate_interventions(run):
        for t in targets:
            r = counterfactual(run, spec, t, n=n, system=system, save=save)
            rows.append(r)
    return rows


def influence_index(paths: Iterable[str], targets: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """Aggregate over runs. For each input content hash: how many runs it appeared in ("cited"),
    how many of those runs it reached an action from, how many runs a target fired in while it
    was present, and the tested effects recorded for it."""
    targets = list(targets)
    idx: Dict[str, Dict[str, Any]] = {}
    for p in paths:
        try:
            run = load_run(p)
        except (OSError, ValueError):
            continue
        g = build_graph(run, infer=False)
        fired = {t: bool(target_hits(run, t)) for t in targets}
        for nid, node in g.nodes.items():
            if node["type"] != "input" or node["kind"] == "task":
                continue
            ev = node["event"]
            row = idx.setdefault(ev["ref"], {"ref": ev["ref"], "sources": set(), "trust": ev.get("trust"),
                                             "runs": 0, "reached_action_runs": 0, "target_runs": {t: 0 for t in targets},
                                             "tested": [], "preview": str(run.value(ev["ref"]))[:90]})
            row["sources"].add(ev["source"])
            row["runs"] += 1
            reach = g.descendants([nid])
            if any(g.nodes[x]["type"] == "action" for x in reach if x != nid):
                row["reached_action_runs"] += 1
            for t in targets:
                row["target_runs"][t] += fired[t]
        for test in run.tests:
            if test.get("group"):
                continue  # a group test is not evidence about any single member
            for nid in _nodes_for(g, test["intervention"]):
                ev = g.nodes[nid]["event"]
                if ev["ref"] in idx:
                    idx[ev["ref"]]["tested"].append({k: test[k] for k in ("target", "effect", "ci", "verdict", "n")}
                                                    | {"run": run.run_id})
    out = []
    for row in idx.values():
        row["sources"] = sorted(row["sources"])
        out.append(row)
    out.sort(key=lambda r: (-max([t["effect"] for t in r["tested"]] or [0]), -r["reached_action_runs"], -r["runs"]))
    return out


def _nodes_for(g: Graph, spec: str) -> List[str]:
    from .graph import nodes_matching
    return [n for n in nodes_matching(g, spec) if g.nodes[n]["type"] == "input"]


def list_runs(root: str) -> List[str]:
    if os.path.exists(os.path.join(root, "events.jsonl")):
        return [root]
    return sorted(os.path.join(root, d) for d in os.listdir(root)
                  if os.path.exists(os.path.join(root, d, "events.jsonl")))
