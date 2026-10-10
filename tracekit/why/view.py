"""The investigation app. One HTML file; works as a static report or served by `tracekit why serve`."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ..core import read_text
from .analysis import investigation, workspace
from .core import Run, load_run
from .evals import structure


def _pretty(v: Any, limit: int = 4000) -> str:
    s = v if isinstance(v, str) else json.dumps(v, indent=2, ensure_ascii=False, default=str)
    return s if len(s) <= limit else s[:limit] + "\n…"


def _evidence(run: Run) -> Dict[str, Any]:
    """Signed Tracekit records behind each event, when the run was imported from Tracekit."""
    p = os.path.join(run.path, "tracekit-map.json") if run.path else ""
    if not p or not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f).get("events") or {}
    except (OSError, ValueError):
        return {}


def run_detail(run: Run) -> Dict[str, Any]:
    inv = investigation(run)
    evidence = _evidence(run)
    g = inv["graph"]
    agents: List[Dict[str, Any]] = []
    for ev in run.of_type("agent.start"):
        agents.append({"name": ev["agent"], "parent": ev.get("parent"), "role": ev.get("role", "")})
    st = structure(run, g)
    for a in agents:
        decs = [e for e in run.of_type("decision") if e["agent"] == a["name"]]
        a.update(st["agents"].get(a["name"], {}))
        a["model_ms"] = round(sum(d.get("duration_ms") or 0 for d in decs), 2)
        a["tokens"] = sum(int((d.get("usage") or {}).get("input_tokens", 0) or 0) +
                          int((d.get("usage") or {}).get("output_tokens", 0) or 0) for d in decs)
    nodes = []
    for n in sorted(g.nodes.values(), key=lambda x: x["seq"]):
        ev = n["event"]
        d: Dict[str, Any] = {"id": n["id"], "type": n["type"], "agent": n["agent"], "seq": n["seq"],
                             "label": n["label"], "trust": n.get("trust", "trusted"), "kind": n.get("kind"),
                             "to": n.get("to"), "hash": ev["hash"], "prev": ev["prev_hash"], "ts": ev["ts"],
                             "duration_ms": ev.get("duration_ms"), "status": ev.get("status"),
                             "sensitive": ev.get("sensitive", False), "mode": ev.get("mode"),
                             "evidence": evidence.get(ev["id"]), "policy": ev.get("policy"),
                             "context_mode": ev.get("context_mode")}
        if n["type"] == "decision":
            d.update(model=ev["model"], purpose=ev.get("purpose"), usage=ev.get("usage") or {},
                     context=[{"source": c["source"] or c["kind"], "kind": c["kind"], "trust": c["trust"],
                               "node": "ev:" + c["from_event"] if c.get("from_event") else None}
                              for c in ev["context"]],
                     ablated=ev.get("ablated", []), output=_pretty(run.value(ev["output"])))
        elif n["type"] == "action":
            d.update(args=run.value(ev["args_ref"]), result=_pretty(run.value(ev["result_ref"])), tool=ev["tool"],
                     guard=ev.get("guard"))
        else:
            d.update(content=_pretty(run.value(ev.get("ref"))), source=ev.get("source"))
        nodes.append(d)
    edges = [{k: v for k, v in e.items() if k in ("src", "dst", "kind", "evidence", "reuse", "score", "effect",
                                                     "ci", "verdict", "n", "target")} for e in g.edges]
    return {"run_id": run.run_id, "path": run.path, "summary": inv["summary"], "alerts": inv["alerts"],
            "timeline": inv["timeline"], "nodes": nodes, "edges": edges, "actions": inv["actions"],
            "matrix": inv["matrix"], "channels": inv["channels"], "agents": agents,
            "critical_path": st["critical_path"], "tests": run.tests,
            "source": (run.start.get("meta") or {}) if (run.start.get("meta") or {}).get("source") == "tracekit" else None,
            "outcome": run.events[-1].get("outcome") if run.events and run.events[-1]["type"] == "run.end" else None}


def app_data(paths: List[str]) -> Dict[str, Any]:
    ws = workspace(paths)
    details = {}
    for p in paths:
        try:
            r = load_run(p)
            details[r.run_id] = run_detail(r)
        except Exception:  # workspace() already reported it
            continue
    ws["details"] = details
    return ws


def render_app(data: Optional[Dict[str, Any]], *, server: bool = False) -> str:
    payload = json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/") if data else "null"
    return (TEMPLATE.replace("__DATA__", payload).replace("__SERVER__", "true" if server else "false"))


def render_html(run: Run) -> str:
    """Static report for one run (kept for the old `view` command)."""
    return render_app(app_data([run.path]) if run.path else None)


def render_workspace(root_or_paths) -> str:
    from .evals import list_runs
    paths = list_runs(root_or_paths) if isinstance(root_or_paths, str) else list(root_or_paths)
    return render_app(app_data(paths))


TEMPLATE = read_text(os.path.join(os.path.dirname(__file__), "app.html"))
