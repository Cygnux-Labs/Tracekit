"""What the viewer's why views show of one run (served by why.server.Store.detail)."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from .analysis import investigation
from .core import Run
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


def _cited(ev: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """The signed record an event of the signer-backed runtime (or a v2 import) cites, as the drawer lists them: its
    log seq and hash once imported, else run and run_seq."""
    t = ev.get("tracekit")
    if not t:
        return None
    return [{"seq": t.get("seq", f"{t['run_seq']} of run {t['run_id']}"), "hash": t.get("hash", ""),
             "type": t["type"] + (f" · log {t['log_id']}" if t.get("log_id") else "")
             + (" · DOES NOT MATCH: " + ev["tracekit_mismatch"] if ev.get("tracekit_mismatch") else "")}]


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
                             "evidence": evidence.get(ev["id"]) or _cited(ev), "policy": ev.get("policy"),
                             "context_mode": ev.get("context_mode"), "tracekit": ev.get("tracekit")}
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
