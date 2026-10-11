"""The why logs behind the viewer (`tracekit view --why DIR`, `tracekit why serve DIR`): ingest, the live watcher, the
analysis the page shows and the allow-listed replays. observe.make_handler serves them (`why=`, a Store), on the
viewer's own session and security conventions:

GET  /api/why/workspace            run summaries, the cross-run influence graph, every run's alerts and the signed calls
                                   each why event cites
GET  /api/why/runs/<id>            everything the page's WHY, GRAPH and AGENTS views show of one run
POST /api/why/runs/<id>/tests      {"intervention","target","n"} -> counterfactual replay (allow-listed programs only)
POST /api/why/runs/<id>/attribute  {"target","n","n_max"} -> group test, then narrow down to the causes
POST /v1/ingest                    Authorization: Bearer <token>; {"events":[...], "blobs":{ref: value}}

Live: a watcher polls the runs folder, so runs written to disk by a local Runtime show up as they are recorded, the
same as ingested ones. Each change recomputes that run's alerts; the change and its new alerts go out on the viewer's
event stream as a `why` record and, with a webhook, new high alerts are POSTed out. With `tape` (`tracekit why serve`,
which has no signed records to show), each run's events also go out as the viewer's records (tape()), so its calls
are on the tape.

Ingest validates every event's hash, its link to the previous event and every blob's content hash before anything is
written. Replay imports the program a run names, so only programs passed with --allow-program can be replayed.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..observe import _epoch
from .analysis import alerts, workspace
from .core import EVENT_TYPES, GENESIS, SCHEMA, content_hash, event_hash, load_run
from .evals import list_runs
from .graph import build_graph
from .replay import attribute, counterfactual, load_system
from .view import run_detail

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
# fields each event type must carry for the analysis to read it
REQUIRED = {"run.start": (), "agent.start": (), "run.end": (), "input": ("ref", "source", "trust"),
            "decision": ("model", "context", "output"), "action": ("tool", "args_ref", "result_ref"),
            "message": ("to", "ref")}


class IngestError(ValueError):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


def _int(val) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        raise IngestError(400, "n and n_max must be integers")


class Feed:
    """observe.make_handler's feed of a server with no signed records (`tracekit why serve`, `tracekit why watch`): the
    why records Store publishes."""

    def __init__(self):
        self.records, self.base, self.lock = [], 0, threading.Condition()

    def verify(self, tenant=None):
        return 0, [], None


def _agent(ev: Dict[str, Any]) -> Dict[str, Any]:
    """The viewer's agent fields of a why event: the run's own events are its main agent, each why agent a subagent."""
    return {} if ev["agent"] == "run" else {"agent_id": ev["agent"], "agent_type": ev["agent"]}


def _brief(v: Any, n: int = 300) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    return s[:n]


def tape(run, start: int = 0) -> List[Dict[str, Any]]:
    """The viewer's records (observe.Translator's shape) of `run`'s events from the `start`th: what its tape, agents
    and detail show of a why log. Every record carries `why` (run id, graph node id), so the page opens it in WHY."""
    out = []
    for ev in run.events[start:]:
        t = ev["type"]
        r = {"ts": _epoch(ev["ts"]), "session_id": run.run_id, "seq": ev["seq"], "hash": ev["hash"],
             "prev": ev["prev_hash"], "why": {"run": run.run_id, "node": "ev:" + ev["id"]}, **_agent(ev)}
        if t == "run.start":
            out.append({**r, "event": "SessionStart", "source": f"why log · {ev.get('program') or 'no program'}"})
        elif t == "agent.start":
            out.append({**r, "event": "SubagentStart", "parent_id": ev.get("parent")})
        elif t == "input":
            r.update(event="log", text=f"{'TASK' if ev.get('kind') == 'task' else 'INPUT'} {ev['source']} "
                                       f"({ev['trust']}) · {_brief(run.value(ev['ref']))}")
            if ev.get("kind") == "task":
                out.append({**r, "event": "UserPromptSubmit", "prompt": _brief(run.value(ev["ref"]), 2000)})
            out.append(r)
        elif t == "decision":
            out.append({**r, "event": "tk_model", "model": ev["model"], "usage": ev.get("usage"),
                        "text": f"{ev.get('purpose') or 'model call'} · {_brief(run.value(ev['output']), 200)}"})
        elif t == "action":
            uid = ev["id"]
            blocked = ev.get("status") == "blocked"
            out.append({**r, "event": "PreToolUse", "tool_name": ev["tool"], "tool_use_id": uid,
                        "tool_input": run.value(ev["args_ref"]) or {},
                        "policy": {"decision": "deny" if blocked else "allow",
                                   "reasons": list((ev.get("policy") or {}).get("rule_ids") or [])}})
            if not blocked:
                out.append({**r, "event": "PostToolUse", "tool_name": ev["tool"], "tool_use_id": uid,
                            "tool_response": run.value(ev["result_ref"]), "failed": ev.get("status") == "error",
                            "duration_ms": ev.get("duration_ms")})
        elif t == "message":
            out.append({**r, "event": "log", "text": f"MESSAGE → {ev['to']} · {_brief(run.value(ev['ref']))}"})
        elif t == "run.end":
            out.append({**r, "event": "SessionEnd", "reason": _brief(ev.get("outcome"), 200)})
    return out


class Store:
    """The why logs under `root`. Live changes are published into `out` (an observe.make_handler feed: the viewer's,
    or a Feed) as `{"event": "why", "why": {...}}` records; with `tape`, each run's events too (tape())."""

    def __init__(self, root: str, allow_programs: Iterable[str] = (), webhook: Optional[str] = None,
                 out=None, tape: bool = False):
        self.root = root
        self.allow = set(allow_programs)
        self.webhook = webhook
        self.out = out or Feed()
        self.tape = tape
        self.lock = threading.Lock()
        os.makedirs(root, exist_ok=True)
        self._stat: Dict[str, Tuple[int, float]] = {}
        self._seen: Dict[str, set] = {}
        self._sent: Dict[str, int] = {}   # with tape: events of each run already published
        self._watching = False
        self._analyse = threading.Lock()  # ingest and the watcher may both see the same change

    # -- live
    def publish(self, msg: Dict[str, Any], records: Iterable[Dict[str, Any]] = ()) -> None:
        with self.out.lock:
            # lean: kept for the server's life, like the viewer's own records; trim with feed.base if that grows
            self.out.records.extend(records)
            self.out.records.append({"event": "why", "ts": time.time(), "why": msg})
            self.out.lock.notify_all()

    def changed(self, path: str, announce: bool = True) -> None:
        """A run's log grew: recompute its alerts and announce the new ones (each one once)."""
        with self._analyse:
            self._changed(path, announce)

    def _changed(self, path: str, announce: bool) -> None:
        try:
            st = os.stat(os.path.join(path, "events.jsonl"))
            self._stat[path] = (st.st_size, st.st_mtime)
            run = load_run(path)
            al = alerts(run, build_graph(run, infer=False))
        except Exception as e:  # a half-written line or a broken run must not stop the feed
            print(f"tracekit why: could not analyse {path}: {e}", file=sys.stderr)
            return
        seen = self._seen.setdefault(path, set())
        new = []
        for a in al:
            key = (a["title"], a.get("node"))
            if key not in seen:
                seen.add(key)
                new.append({k: a.get(k) for k in ("severity", "title", "detail", "node", "tool", "agent", "seq")})
        records = tape(run, self._sent.get(path, 0)) if self.tape else []
        self._sent[path] = len(run.events)
        finished = bool(run.events) and run.events[-1]["type"] == "run.end"
        if announce or records:
            self.publish({"type": "run", "run_id": run.run_id, "events": len(run.events), "finished": finished,
                          "alerts": new if announce else []}, records)
        if announce and self.webhook:
            for a in new:
                if a["severity"] == "high":
                    self._post_webhook(run.run_id, a)

    def _post_webhook(self, run_id: str, a: Dict[str, Any]) -> None:
        import urllib.request
        body = json.dumps({"text": f"[tracekit why HIGH] {run_id} {a.get('agent')}.{a.get('tool')}: {a['title']}. "
                                   f"{a.get('detail') or ''}", "run_id": run_id, "alert": a}).encode()

        def post() -> None:
            try:
                req = urllib.request.Request(self.webhook, data=body, method="POST",
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as e:
                print(f"tracekit why: webhook failed: {e}", file=sys.stderr)

        threading.Thread(target=post, daemon=True).start()

    def scan(self, announce: bool = True) -> None:
        for p in list_runs(self.root) if os.path.isdir(self.root) else []:
            try:
                st = os.stat(os.path.join(p, "events.jsonl"))
            except OSError:
                continue
            if self._stat.get(p) != (st.st_size, st.st_mtime):
                with self._analyse:  # re-check: ingest may have just handled this change
                    if self._stat.get(p) == (st.st_size, st.st_mtime):
                        continue
                    self._changed(p, announce)

    def watch(self, interval: float = 0.5) -> None:
        """Poll the runs folder in a daemon thread. Existing runs are indexed silently first, so only
        alerts raised after the server started are announced."""
        if self._watching:
            return
        self._watching = True

        def loop() -> None:
            self.scan(announce=False)
            while self._watching:
                time.sleep(interval)
                try:
                    self.scan()
                except Exception as e:
                    print(f"tracekit why: watcher: {e}", file=sys.stderr)

        threading.Thread(target=loop, daemon=True).start()

    def paths(self) -> List[str]:
        return list_runs(self.root) if os.listdir(self.root) else []

    def run_path(self, run_id: str) -> str:
        if not RUN_ID.match(run_id):
            raise IngestError(400, "bad run id")
        return os.path.join(self.root, run_id)

    # -- what the page reads
    def workspace(self) -> Dict[str, Any]:
        """workspace() of every run, plus `alerts` (every run's, with its run id) and `calls`: "<signed run id>|<run_seq>"
        -> [why run id, node id] of each tool call whose why event cites the signed record it produced."""
        paths = self.paths()
        out = workspace(paths)
        out["alerts"], out["calls"] = [], {}
        # lean: reads every run again on each request; cache by (size, mtime) as scan() does if workspaces grow large
        for p in paths:
            try:
                run = load_run(p)
                al = alerts(run, build_graph(run, infer=False))
            except Exception:  # workspace() already reported it
                continue
            out["alerts"] += [{"run_id": run.run_id, **{k: a.get(k) for k in ("severity", "title", "detail", "node",
                                                                                "tool", "agent", "seq")}} for a in al]
            for ev in run.of_type("action"):
                tk = ev.get("tracekit")
                if isinstance(tk, dict):
                    out["calls"][f"{tk.get('run_id')}|{tk.get('run_seq')}"] = [run.run_id, "ev:" + ev["id"]]
        return out

    def detail(self, run_id: str) -> Dict[str, Any]:
        """run_detail() of one run, plus `replay`: its program and whether this server may replay it."""
        path = self.run_path(run_id)
        if not os.path.exists(os.path.join(path, "events.jsonl")):
            raise IngestError(404, "no such run")
        run = load_run(path)
        prog = run.start.get("program")
        return {**run_detail(run), "replay": {"program": prog, "allowed": bool(prog) and prog in self.allow}}

    # -- ingest
    def ingest(self, body: Dict[str, Any]) -> Dict[str, Any]:
        events, blobs = body.get("events"), body.get("blobs") or {}
        if not isinstance(events, list) or not events or not isinstance(blobs, dict):
            raise IngestError(400, "expected {events: [...], blobs: {...}}")
        for ref, val in blobs.items():
            if content_hash(val) != ref:
                raise IngestError(422, f"blob {str(ref)[:20]} does not match its hash")
        run_id = events[0].get("run_id", "") if isinstance(events[0], dict) else ""
        if any(not isinstance(e, dict) or e.get("run_id") != run_id for e in events):
            raise IngestError(400, "one batch must belong to one run")
        for e in events:
            missing = [k for k in REQUIRED.get(e.get("type"), ("type",)) if k not in e]
            if e.get("type") not in EVENT_TYPES or missing or not isinstance(e.get("context", []), list) \
                    or not all(isinstance(c, dict) and "ref" in c for c in e.get("context", [])):
                raise IngestError(422, f"seq {e.get('seq')}: malformed {e.get('type')!r} event {missing or ''}")
        path = self.run_path(run_id)
        with self.lock:
            os.makedirs(os.path.join(path, "blobs"), exist_ok=True)
            ev_path = os.path.join(path, "events.jsonl")
            last_seq, last_hash = -1, GENESIS
            if os.path.exists(ev_path):
                with open(ev_path, "rb") as f:
                    lines = [l for l in f.read().splitlines() if l.strip()]
                if lines:
                    last = json.loads(lines[-1])
                    last_seq, last_hash = last["seq"], last["hash"]
            for ev in events:
                if ev.get("schema") != SCHEMA:
                    raise IngestError(422, "unknown schema")
                if ev.get("seq") != last_seq + 1:
                    raise IngestError(409, f"expected seq {last_seq + 1}, got {ev.get('seq')}")
                if ev.get("prev_hash") != last_hash:
                    raise IngestError(409, f"seq {ev['seq']}: does not link to the stored chain")
                if event_hash(ev) != ev.get("hash"):
                    raise IngestError(422, f"seq {ev['seq']}: hash mismatch")
                last_seq, last_hash = ev["seq"], ev["hash"]
            known = set()
            bdir = os.path.join(path, "blobs")
            known.update("sha256:" + n[:-5] for n in os.listdir(bdir))
            known.update(blobs)
            for ev in events:
                for k in ("ref", "output", "args_ref", "result_ref"):
                    if ev.get(k) and ev[k] not in known:
                        raise IngestError(422, f"seq {ev['seq']}: missing blob {ev[k][:20]}")
                for c in ev.get("context", []):
                    if c["ref"] not in known:
                        raise IngestError(422, f"seq {ev['seq']}: missing blob {c['ref'][:20]}")
            for ref, val in blobs.items():
                p = os.path.join(bdir, ref[7:] + ".json")
                if not os.path.exists(p):
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump({"v": val}, f, sort_keys=True, ensure_ascii=False, default=str)
            with open(ev_path, "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
        self.changed(path)
        return {"run_id": run_id, "accepted": len(events), "head_seq": last_seq}

    # -- tests
    def _replayable(self, run_id: str):
        path = self.run_path(run_id)
        if not os.path.exists(os.path.join(path, "events.jsonl")):
            raise IngestError(404, "no such run")
        run = load_run(path)
        prog = run.start.get("program")
        if not prog or prog not in self.allow:
            raise IngestError(403, f"replay of {prog!r} is not allowed here: start the viewer with --allow-program "
                                   f"{prog}, or run the test with `tracekit why test`" if prog else
                              "this run names no program to replay: record it with a System")
        return run, prog

    def attribute(self, run_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        run, prog = self._replayable(run_id)
        n, n_max = _int(body.get("n", 10)), _int(body.get("n_max", 80))
        target = str(body.get("target", ""))
        if not target or not 1 <= n <= n_max <= 400:
            raise IngestError(400, "target is required; 1 <= n <= n_max <= 400")
        try:
            result = attribute(run, target, body.get("suspects") or None, n=n, n_max=n_max, system=load_system(prog))
        except ValueError as e:
            raise IngestError(400, str(e))
        self.publish({"type": "test", "run_id": run.run_id, "verdict": result["summary"]})
        out = {k: v for k, v in result.items() if k != "tests"}
        out["tests"] = len(result["tests"])
        return out

    def test(self, run_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        run, prog = self._replayable(run_id)
        n = _int(body.get("n", 30))
        n_max = _int(body["n_max"]) if body.get("n_max") else None
        if not 1 <= n <= 200 or (n_max is not None and not n <= n_max <= 400):
            raise IngestError(400, "n must be 1..200 and n_max n..400")
        inter, target = str(body.get("intervention", "")), str(body.get("target", ""))
        if not inter or not target:
            raise IngestError(400, "intervention and target are required")
        try:
            result = counterfactual(run, inter, target, n=n, system=load_system(prog), n_max=n_max)
        except ValueError as e:
            raise IngestError(400, str(e))
        self.publish({"type": "test", "run_id": run.run_id, "verdict": result["verdict"]})
        return result
