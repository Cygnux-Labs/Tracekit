"""Investigation: alerts, argument provenance, candidate causes, timeline and workspace summaries.

Everything here is derived from the log and the tests recorded against it. Nothing calls a model.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, List, Optional

from .core import Run, load_run, verify
from .graph import Graph, build_graph, nodes_matching, target_hits

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"https?://[^\s\"'<>]+")
SENSITIVE_HINT = re.compile(r"send|email|mail|post|publish|transfer|pay|refund|delete|remove|export|upload|"
                            r"exec|shell|bash|write|deploy|sign|approve", re.I)


def _txt(v: Any) -> str:
    return v if isinstance(v, str) else json.dumps(v, sort_keys=True, ensure_ascii=False, default=str)


def is_sensitive(run: Run, ev: Dict[str, Any]) -> Optional[str]:
    """'declared' if the run marked it sensitive, 'heuristic' if only the tool name suggests it."""
    if ev.get("sensitive"):
        return "declared"
    if not run.start.get("sensitive_tools") and SENSITIVE_HINT.search(ev.get("tool", "")):
        return "heuristic"
    return None


# --------------------------------------------------------------------------- argument provenance

def atoms(args: Any) -> List[str]:
    """Values worth tracing back: addresses, URLs, and whole string arguments of 6+ characters."""
    out: List[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            found = _EMAIL.findall(v) + _URL.findall(v)
            out.extend(found)
            if not found and len(v) >= 6:
                out.append(v)

    walk(args)
    seen, uniq = set(), []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq


def arg_provenance(run: Run, g: Graph, action_ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    """For each argument value, which earlier inputs or tool results contained it verbatim.
    untrusted-only: only untrusted inputs carried it (the classic injection signature)
    trusted:        some trusted input (the task included) or tool result carried it
    generated:      no earlier source; the model produced it"""
    return value_provenance(run, run.value(action_ev["args_ref"]), action_ev["seq"])


def value_provenance(run: Run, args: Any, before_seq: int) -> List[Dict[str, Any]]:
    """arg_provenance for argument values that need not be recorded yet: the live guard calls this
    before a tool runs, with before_seq past the end of the log."""
    rows = []
    untrusted_refs = {e["ref"] for e in run.of_type("input") if e.get("trust") == "untrusted"}
    # a tool result is untrusted when its content was also recorded as untrusted input, or when the
    # action itself is marked untrusted (e.g. a subagent's answer after it read untrusted content).
    # Not every result downstream of untrusted content: a trusted tool's own output stays trusted.
    hashed = (run.start.get("meta") or {}).get("content_capture") == "hashed"
    texts = []
    for ev in run.events:
        if ev["seq"] >= before_seq:
            break
        if ev["type"] == "input":
            texts.append((ev, _txt(run.value(ev["ref"])).lower(), ev.get("trust", "trusted"),
                          "task" if ev.get("kind") == "task" else ev.get("source", "input")))
        elif ev["type"] == "action" and ev.get("status") != "blocked":
            # a tool result counts as untrusted if the same content was also recorded as untrusted input
            untrusted = ev["result_ref"] in untrusted_refs or ev.get("trust") == "untrusted"
            texts.append((ev, _txt(run.value(ev["result_ref"])).lower(),
                          "untrusted" if untrusted else "trusted", ev["tool"]))
    for a in atoms(args):
        if hashed and a.startswith("sha256:"):  # a hash placeholder, not a value
            rows.append({"value": a, "status": "hashed", "sources": []})
            continue
        low = a.lower()
        srcs = [{"node": "ev:" + ev["id"], "label": label, "trust": trust}
                for ev, text, trust, label in texts if low in text]
        if not srcs:
            status = "hashed" if hashed else "generated"  # with hashed capture there is no text to search
        elif all(s["trust"] == "untrusted" for s in srcs):
            status = "untrusted-only"
        else:
            status = "trusted"
        rows.append({"value": a, "status": status, "sources": srcs})
    return rows


def suggest_target(run: Run, action_ev: Dict[str, Any], prov: Optional[List[Dict[str, Any]]] = None) -> str:
    spec = f"tool={action_ev['tool']}"
    pick = None
    if prov:
        pick = next((p["value"] for p in prov if p["status"] == "untrusted-only"), None)
    if pick is None:
        pick = next((a for a in atoms(run.value(action_ev["args_ref"])) if _EMAIL.fullmatch(a) or _URL.match(a)), None)
    if pick and "," not in pick and "=" not in pick and "~" not in pick:
        spec += f",arg~{pick}"
    return spec


# --------------------------------------------------------------------------- causes

def intervention_for(node: Dict[str, Any]) -> Optional[str]:
    ev = node["event"]
    if node["type"] == "input" and node.get("kind") != "task":
        return f"input:{ev['source']}"
    if node["type"] == "message":
        return f"msg:{ev['agent']}->{ev['to']}"
    return None


def candidates(run: Run, g: Graph, action_node: str) -> List[Dict[str, Any]]:
    """Every upstream input and message channel of an action, with what is known about it:
    confirmed (tested, CI excludes 0), ruled-out (tested, any effect bounded below the minimum of
    interest), inconclusive (tested, the interval is too wide to say), or untested."""
    ev = g.nodes[action_node]["event"]
    anc = g.ancestors(action_node, ("observed",))
    hit_cache: Dict[str, bool] = {}

    def targets_this(spec: str) -> bool:
        if spec not in hit_cache:
            try:
                hit_cache[spec] = any(h["id"] == ev["id"] for h in target_hits(run, spec))
            except ValueError:
                hit_cache[spec] = False
        return hit_cache[spec]

    match_cache: Dict[str, set] = {}

    def matched(spec: str) -> set:
        if spec not in match_cache:
            try:
                match_cache[spec] = set(nodes_matching(g, spec))
            except ValueError:
                match_cache[spec] = set()
        return match_cache[spec]

    rows, seen = [], set()
    for nid in sorted(anc, key=lambda x: g.nodes[x]["seq"]):
        node = g.nodes[nid]
        spec = intervention_for(node)
        if not spec or spec in seen:
            continue
        seen.add(spec)
        tests = [t for t in run.tests if t.get("scope", "run") == "run" and targets_this(t["target"])
                 # a glob that removed several upstream items at once is not evidence about any single one
                 and (t["intervention"] == spec or matched(t["intervention"]) & anc == {nid})]
        best = max(tests, key=lambda t: (t["n"], abs(t["effect"])), default=None)
        if best is None:
            status = "untested"
        elif best["verdict"] == "causal":
            status = "contributing" if _role(best) == "contributing" else "confirmed"
        elif best["verdict"] == "suppressive":
            status = "suppressive"
        elif best["verdict"] == "not-applied":
            status = "untested"
        else:
            status = _settled(best)
        reuse = max((e.get("reuse", 0) for e in g.out_edges(nid, ("observed",))), default=0)
        rows.append({"node": nid, "label": node["label"], "kind": node["type"], "agent": node["agent"],
                     "trust": node.get("trust", "trusted"), "intervention": spec, "status": status,
                     "role": _role(best) if status in ("confirmed", "contributing") and best.get("p_with") is not None
                     else None,
                     "test": best, "reuse": reuse})
    order = {"confirmed": 0, "contributing": 1, "suppressive": 2, "inconclusive": 3, "untested": 4,
             "no-effect-seen": 5, "ruled-out": 6}
    rows.sort(key=lambda r: (order[r["status"]], -(r["test"]["effect"] if r["test"] else 0),
                             r["trust"] != "untrusted", -r["reuse"]))
    return rows


def _role(t: Dict[str, Any]) -> str:
    from .replay import role_for
    return t.get("role") or role_for(t.get("p_with") or 0, t["ci"])


def _settled(t: Dict[str, Any]) -> str:
    """ruled-out or inconclusive, also for tests saved before the two were told apart."""
    if t["verdict"] == "inconclusive" and t.get("stopped") == "futility":
        return "no-effect-seen"
    if t["verdict"] in ("ruled-out", "inconclusive"):
        return t["verdict"]
    lo, hi = t["ci"]
    m = t.get("min_effect", 0.2)
    return "ruled-out" if hi < m and lo > -m else "inconclusive"


def lineage(g: Graph, action_node: str) -> List[List[str]]:
    """The observed chains from each untrusted input (or, if none, each input) to the action."""
    anc = g.ancestors(action_node, ("observed",))
    roots = [n for n in anc if g.nodes[n]["type"] == "input" and g.nodes[n].get("trust") == "untrusted"] or \
            [n for n in anc if g.nodes[n]["type"] == "input"]
    chains = []
    for r in sorted(roots, key=lambda x: g.nodes[x]["seq"]):
        parent = g.descendants([r], ("observed",))
        if action_node in parent:
            chains.append(Graph.path(parent, action_node))
    return chains


# --------------------------------------------------------------------------- alerts

def alerts(run: Run, g: Graph) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    problems = verify(run)
    if problems:
        out.append({"severity": "high", "title": "Log failed integrity check", "detail": problems[0], "node": None})
    for e in (run.start.get("meta") or {}).get("evidence_alerts") or []:  # e.g. Tracekit capture gaps
        out.append({"severity": "high", "title": e.get("title", "Evidence problem"), "detail": e.get("detail", ""),
                    "node": None})
    for nid, n in sorted(g.nodes.items(), key=lambda kv: kv[1]["seq"]):
        if n["type"] != "action":
            continue
        ev = n["event"]
        sens = is_sensitive(run, ev)
        untrusted_up = [g.nodes[a]["label"] for a in g.ancestors(nid, ("observed",))
                        if g.nodes[a]["type"] == "input" and g.nodes[a].get("trust") == "untrusted"]
        prov = arg_provenance(run, g, ev)
        bad = [p for p in prov if p["status"] == "untrusted-only"]
        base = {"node": nid, "tool": ev["tool"], "agent": ev["agent"], "seq": ev["seq"],
                "target": suggest_target(run, ev, prov), "sensitive": sens}
        if ev.get("status") == "blocked":
            pass  # reported below, once
        elif sens and bad:
            out.append({**base, "severity": "high",
                        "title": f"{ev['tool']} used a value that only untrusted content supplied",
                        "detail": f"'{bad[0]['value']}' appears only in " +
                                  ", ".join(s["label"] for s in bad[0]["sources"]) + "."})
        elif sens and untrusted_up:
            out.append({**base, "severity": "review",
                        "title": f"Sensitive action {ev['tool']} is downstream of untrusted input",
                        "detail": "Reached from " + ", ".join(untrusted_up) + ". Reach is not cause; test it."})
        if ev.get("status") == "blocked":
            by = "Tracekit policy" if (ev.get("policy") or {}).get("decision") in ("deny", "ask") else "the guard"
            out.append({**base, "severity": "high", "title": f"{ev['tool']} was blocked by {by}",
                        "detail": (ev.get("guard") or {}).get("reason", "")})
        elif ev.get("status") == "error":
            out.append({**base, "severity": "review", "title": f"{ev['tool']} failed",
                        "detail": _txt(run.value(ev["result_ref"]))[:200]})
        if ev.get("mode") == "stub":
            out.append({**base, "severity": "info", "title": f"{ev['tool']} was stubbed in replay", "detail": ""})
    for ev in run.of_type("decision"):
        if ev.get("status") == "error":
            out.append({"severity": "review", "title": f"Model call failed ({ev['agent']})",
                        "detail": _txt(run.value(ev["output"]))[:200], "node": "ev:" + ev["id"]})
    rank = {"high": 0, "review": 1, "info": 2}
    out.sort(key=lambda a: (rank[a["severity"]], a.get("seq", 0)))
    return out


# --------------------------------------------------------------------------- timeline

def _short(v: Any, n: int = 90) -> str:
    s = _txt(v).replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def timeline(run: Run) -> List[Dict[str, Any]]:
    rows = []
    t0 = None
    for ev in run.events:
        ts = ev["ts"]
        sec = int(ts[11:13]) * 3600 + int(ts[14:16]) * 60 + float(ts[17:26])
        t0 = sec if t0 is None else t0
        t = ev["type"]
        if t == "run.start":
            text = f"Run started ({ev.get('program') or 'unnamed program'})"
        elif t == "agent.start":
            text = f"{ev['agent']} joined" + (f", spawned by {ev['parent']}" if ev.get("parent") else "") + \
                   (f" ({ev['role']})" if ev.get("role") else "")
        elif t == "input":
            text = ("Task: " + _short(run.value(ev["ref"]), 120)) if ev.get("kind") == "task" else \
                   f"{ev['agent']} read {ev['source']}"
        elif t == "decision":
            srcs = [c["source"] or c["kind"] for c in ev["context"]]
            text = f"{ev['agent']} called {ev['model']} to {ev.get('purpose') or 'decide'} using {len(srcs)} inputs"
        elif t == "action":
            text = f"{ev['agent']} ran {ev['tool']}({_short(run.value(ev['args_ref']), 70)})"
        elif t == "message":
            text = f"{ev['agent']} sent a message to {ev['to']}"
        elif t == "run.end":
            text = "Run finished"
        else:
            text = t
        rows.append({"seq": ev["seq"], "id": ev["id"], "node": "ev:" + ev["id"], "type": t, "agent": ev["agent"],
                     "t_ms": round((sec - t0) * 1000, 2), "duration_ms": ev.get("duration_ms"), "text": text,
                     "trust": ev.get("trust"), "status": ev.get("status"), "sensitive": ev.get("sensitive", False),
                     "mode": ev.get("mode"), "usage": ev.get("usage") or None})
    return rows


# --------------------------------------------------------------------------- summaries

def run_summary(run: Run, g: Optional[Graph] = None, al: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    g = g or build_graph(run)
    al = alerts(run, g) if al is None else al
    task = next((run.value(e["ref"]) for e in run.of_type("input") if e.get("kind") == "task"), None)
    acts = run.of_type("action")
    decs = run.of_type("decision")
    usage = {"input_tokens": 0, "output_tokens": 0}
    for d in decs:
        for k in usage:
            usage[k] += int((d.get("usage") or {}).get(k, 0) or 0)
    return {
        "run_id": run.run_id, "program": run.start.get("program", ""), "started": run.events[0]["ts"] if run.events else "",
        "task": task, "agents": sorted({e["agent"] for e in run.of_type("agent.start")}),
        "decisions": len(decs), "actions": len(acts), "messages": len(run.of_type("message")),
        "inputs": len([e for e in run.of_type("input") if e.get("kind") != "task"]),
        "untrusted_inputs": len([e for e in run.of_type("input") if e.get("trust") == "untrusted"]),
        "errors": len([e for e in acts + decs if e.get("status") == "error"]),
        "model_ms": round(sum(d.get("duration_ms") or 0 for d in decs), 2),
        "tool_ms": round(sum(a.get("duration_ms") or 0 for a in acts), 2),
        "usage": usage, "tests": len(run.tests),
        "confirmed_causes": len([t for t in run.tests if t["verdict"] == "causal" and not t.get("group")]),
        "alerts": {s: len([a for a in al if a["severity"] == s]) for s in ("high", "review", "info")},
        "integrity": "ok" if not verify(run) else "failed",
        "tools_run": [a["tool"] for a in acts],
        "replayable": bool(run.start.get("program")),
        "finished": bool(run.events) and run.events[-1]["type"] == "run.end",
        "blocked": len([a for a in acts if a.get("status") == "blocked"]),
        "guard": (run.start.get("guard") or {}).get("mode"),
    }


def test_matrix(run: Run) -> Dict[str, Any]:
    rows: List[str] = []
    cols: List[str] = []
    cells: Dict[str, Dict[str, Any]] = {}
    for t in run.tests:
        if t.get("scope", "run") != "run":
            continue
        if t["intervention"] not in rows:
            rows.append(t["intervention"])
        if t["target"] not in cols:
            cols.append(t["target"])
        cells[t["intervention"] + "\u0000" + t["target"]] = t
    return {"rows": rows, "cols": cols,
            "cells": {k.replace("\u0000", "||"): v for k, v in cells.items()}}


def channel_report(run: Run, g: Graph) -> List[Dict[str, Any]]:
    """Per message channel: messages sent, how many were used by a later decision, and tested influence."""
    chans: Dict[str, Dict[str, Any]] = {}
    for n in g.nodes.values():
        if n["type"] != "message":
            continue
        key = f"{n['agent']}->{n['to']}"
        c = chans.setdefault(key, {"channel": key, "sent": 0, "used": 0, "tests": []})
        c["sent"] += 1
        if g.out_edges(n["id"], ("observed",)):
            c["used"] += 1
    for t in run.tests:
        if not t.get("group") and t["intervention"].startswith("msg:") and t["intervention"][4:] in chans:
            chans[t["intervention"][4:]]["tests"].append(t)
    return list(chans.values())


def investigation(run: Run) -> Dict[str, Any]:
    """Everything the investigation app needs for one run."""
    g = build_graph(run)
    al = alerts(run, g)
    actions = {}
    for nid, n in g.nodes.items():
        if n["type"] == "action":
            ev = n["event"]
            prov = arg_provenance(run, g, ev)
            actions[nid] = {"provenance": prov, "candidates": candidates(run, g, nid),
                            "lineage": lineage(g, nid), "target": suggest_target(run, ev, prov),
                            "sensitive": is_sensitive(run, ev)}
    return {"graph": g, "alerts": al, "summary": run_summary(run, g, al), "timeline": timeline(run),
            "actions": actions, "matrix": test_matrix(run), "channels": channel_report(run, g)}


# --------------------------------------------------------------------------- workspace / influence graph

def influence_graph(paths: List[str]) -> Dict[str, Any]:
    """Cross-run, citation-like graph. Sources are content (by hash); outcomes are tools.
    An edge says: in k runs this content was upstream of this tool (cited), and tests measured effect e."""
    sources: Dict[str, Dict[str, Any]] = {}
    outcomes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}
    for p in paths:
        try:
            run = load_run(p)
            g = build_graph(run, infer=False)
        except Exception:  # unreadable or malformed run: leave it out rather than fail the whole view
            continue
        for nid, n in g.nodes.items():
            if n["type"] != "input" or n.get("kind") == "task":
                continue
            ev = n["event"]
            s = sources.setdefault(ev["ref"], {"id": ev["ref"], "labels": [], "trust": ev.get("trust"), "runs": 0,
                                               "cited_by": 0, "preview": _short(run.value(ev["ref"]), 140)})
            if ev["source"] not in s["labels"]:
                s["labels"].append(ev["source"])
            s["runs"] += 1
            s["cited_by"] += len([e for e in g.out_edges(nid, ("observed",)) if e["kind"].startswith("context")])
            reached = g.descendants([nid])
            tools = {g.nodes[x]["event"]["tool"] for x in reached if g.nodes[x]["type"] == "action"}
            for tool in tools:
                outcomes.setdefault(tool, {"id": tool, "runs": 0})
                e = edges.setdefault(ev["ref"] + "|" + tool, {"source": ev["ref"], "tool": tool, "reach_runs": 0,
                                                              "tests": []})
                e["reach_runs"] += 1
            spec = f"input:{ev['source']}"
            for t in run.tests:
                if t.get("scope", "run") == "run" and t["intervention"] == spec:
                    tool = t["target"].split(",")[0].split("=", 1)[-1]
                    outcomes.setdefault(tool, {"id": tool, "runs": 0})
                    e = edges.setdefault(ev["ref"] + "|" + tool, {"source": ev["ref"], "tool": tool,
                                                                  "reach_runs": 0, "tests": []})
                    e["tests"].append({"run": run.run_id, "target": t["target"], "effect": t["effect"],
                                       "ci": t["ci"], "verdict": t["verdict"], "n": t["n"]})
        for tool in {a["tool"] for a in run.of_type("action")}:
            outcomes.setdefault(tool, {"id": tool, "runs": 0})["runs"] += 1
    for e in edges.values():
        eff = [t["effect"] for t in e["tests"]]
        e["max_effect"] = max(eff) if eff else None
        e["confirmed"] = any(t["verdict"] == "causal" for t in e["tests"])
        e["ruled_out"] = bool(e["tests"]) and not e["confirmed"] and all(
            t["verdict"] != "causal" and _settled(t) == "ruled-out" for t in e["tests"])
    for s in sources.values():
        es = [e for e in edges.values() if e["source"] == s["id"]]
        s["max_effect"] = max([e["max_effect"] for e in es if e["max_effect"] is not None], default=None)
        s["confirmed_tools"] = sorted({e["tool"] for e in es if e["confirmed"]})
    src = sorted(sources.values(), key=lambda s: (-(s["max_effect"] or 0), -s["cited_by"]))
    return {"sources": src, "outcomes": sorted(outcomes.values(), key=lambda o: -o["runs"]),
            "edges": list(edges.values())}


def workspace(paths: List[str]) -> Dict[str, Any]:
    runs = []
    for p in paths:
        try:
            runs.append(run_summary(load_run(p)))
        except Exception as e:  # unreadable or malformed run: leave it out rather than fail the whole view
            print(f"tracekit why: skipping {p}: {e}", file=sys.stderr)
    runs.sort(key=lambda r: r["started"], reverse=True)
    return {"runs": runs, "influence": influence_graph(paths)}
