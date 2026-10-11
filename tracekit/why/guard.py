"""Live guard: check a sensitive tool call before it runs, while the agents are still running.

    from tracekit.why import Runtime
    from tracekit.why.guard import Guard, webhook

    guard = Guard(mode="block", on_alert=webhook("https://hooks.example/tracekit-why"))
    rt = Runtime(models, tools, sensitive_tools=["send_email"], untrusted_tools=["web_fetch"], guard=guard)

The built-in rule is the same one the investigation app uses after the fact, applied before execution:

high    a sensitive call would use a value (address, URL, string argument) that only untrusted content
        supplied: the classic prompt-injection signature
review  a sensitive call was asked for by a decision whose context held untrusted content

mode="alert" records the verdict on the action and calls on_alert (for severities in `notify`, default high). mode="block" also refuses calls
with an alert in `block_on` (default: high): the tool does not run, the agent gets an error result,
and the action is recorded with status "blocked". Extra rules are plain functions of a CheckContext
that return an alert dict or None.

The guard sees only what the log has recorded so far, so it is exactly as good as the instrumentation:
content an agent read without observe() (or an adapter) is invisible to it.
"""
from __future__ import annotations

import json
import threading
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .analysis import SENSITIVE_HINT, value_provenance
from .core import Ref, Run

MODES = ("off", "alert", "block")


@dataclass
class CheckContext:
    run: Run                 # the log so far
    agent: str
    tool: str
    args: Dict[str, Any]
    decision: Optional[Ref]
    sensitive: bool
    provenance: List[Dict[str, Any]]


Rule = Callable[[CheckContext], Optional[Dict[str, Any]]]


@dataclass
class Check:
    agent: str
    tool: str
    args: Dict[str, Any]
    sensitive: bool
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    blocked: bool = False
    reason: str = ""
    guard: Optional["Guard"] = None

    @property
    def verdict(self) -> str:
        return "block" if self.blocked else "alert" if self.alerts else "allow"

    def record(self) -> Dict[str, Any]:
        """What gets stored on the action event (hash-chained with it)."""
        return {"verdict": self.verdict, "reason": self.reason,
                "alerts": [{k: a[k] for k in ("severity", "title", "detail") if k in a} for a in self.alerts]}

    def notify(self, rt: Any, ev: Dict[str, Any]) -> None:
        """Called once the action is recorded, so alerts can point at it."""
        for a in self.alerts:
            full = {**a, "run_id": rt.run_id, "seq": ev["seq"], "node": "ev:" + ev["id"], "agent": self.agent,
                    "tool": self.tool, "args": self.args, "blocked": self.blocked}
            with rt._lock:
                rt.alerts.append(full)
            if self.guard is not None and self.guard.on_alert is not None and a["severity"] in self.guard.notify:
                try:
                    self.guard.on_alert(full)
                except Exception:  # a broken notifier must not take the agent down
                    pass


class Guard:
    def __init__(self, mode: str = "alert", *, block_on: Sequence[str] = ("high",),
                 on_alert: Optional[Callable[[Dict[str, Any]], Any]] = None, rules: Sequence[Rule] = (),
                 builtin: bool = True, notify: Sequence[str] = ("high",)):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.mode = mode
        self.block_on = set(block_on)
        self.on_alert = on_alert
        self.rules = list(rules)
        self.builtin = builtin
        self.notify = set(notify)  # severities passed to on_alert; every alert is recorded either way

    def describe(self) -> Dict[str, Any]:
        return {"mode": self.mode, "block_on": sorted(self.block_on), "rules": len(self.rules),
                "builtin": self.builtin}

    def check(self, rt: Any, agent: str, tool: str, args: Dict[str, Any], decision: Optional[Ref],
              sensitive: bool) -> Check:
        c = Check(agent, tool, args, sensitive, guard=self)
        if self.mode == "off":
            return c
        if not sensitive and not rt.sensitive_tools and SENSITIVE_HINT.search(tool):
            sensitive = c.sensitive = True  # same "by name" fallback as the app, for runs that declare nothing
        if not sensitive and not self.rules:
            return c
        with rt._lock:  # a consistent snapshot; other agents may be writing
            run = Run(rt.run_id, list(rt.events), rt.blobs, rt.path)
        prov = value_provenance(run, args, len(run.events)) if sensitive else []
        if sensitive and self.builtin:
            bad = [p for p in prov if p["status"] == "untrusted-only"]
            if bad:
                c.alerts.append({"severity": "high", "rule": "untrusted-value",
                                 "title": f"{tool} would use a value that only untrusted content supplied",
                                 "detail": f"'{bad[0]['value']}' appears only in "
                                           + ", ".join(s["label"] for s in bad[0]["sources"]) + "."})
            elif decision is not None and decision.trust == "untrusted":
                c.alerts.append({"severity": "review", "rule": "untrusted-upstream",
                                 "title": f"Sensitive call {tool} was decided with untrusted content in context",
                                 "detail": "Reach is not cause; test it."})
        ctx = CheckContext(run, agent, tool, args, decision, sensitive, prov)
        for rule in self.rules:
            a = rule(ctx)
            if a:
                c.alerts.append({"severity": "high", "rule": getattr(rule, "__name__", "rule"), "detail": "", **a})
        if self.mode == "block":
            hit = next((a for a in c.alerts if a["severity"] in self.block_on), None)
            if hit is not None:
                c.blocked = True
                c.reason = hit["title"] + (": " + hit["detail"] if hit.get("detail") else "")
        return c


def webhook(url: str, *, timeout: float = 5.0, min_severity: str = "high") -> Callable[[Dict[str, Any]], None]:
    """on_alert helper: POST each alert as JSON ({"text": ..., "alert": {...}}, which Slack-style incoming
    webhooks accept) from a background thread, so a slow endpoint never stalls the agent."""
    rank = {"high": 0, "review": 1, "info": 2}

    def send(alert: Dict[str, Any]) -> None:
        if rank.get(alert.get("severity"), 2) > rank[min_severity]:
            return
        verb = "BLOCKED" if alert.get("blocked") else alert.get("severity", "").upper()
        body = json.dumps({"text": f"[tracekit why {verb}] {alert['run_id']} {alert['agent']}.{alert['tool']}: "
                                   f"{alert['title']}. {alert.get('detail', '')}",
                           "alert": alert}, default=str).encode()

        def post() -> None:
            try:
                req = urllib.request.Request(url, data=body, method="POST",
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=timeout).close()
            except Exception:
                pass

        threading.Thread(target=post, daemon=True).start()

    return send
