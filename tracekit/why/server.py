"""The why logs behind the viewer (`tracekit view --why DIR`, `tracekit why serve DIR`): ingest, the live watcher, the
analysis the page shows and the allow-listed replays. observe.make_handler serves them (`why=`, a Store), on the
viewer's own session and security conventions:

GET  /api/why/workspace            run summaries, the cross-run influence graph, every run's alerts and the signed calls
                                   each why event cites
GET  /api/why/runs/<id>            everything the page's WHY, GRAPH and AGENTS views show of one run
POST /api/why/runs/<id>/tests      {"intervention","target","n"} -> counterfactual replay (allow-listed programs only)
POST /api/why/runs/<id>/attribute  {"target","n","n_max"} -> group test, then narrow down to the causes
POST /v1/ingest                    Authorization: Bearer <ingest token>; {"events":[...], "blobs":{ref: value}}

Live: a watcher polls the runs folder, so runs written to disk by a local Runtime show up as they are recorded, the
same as ingested ones. Each change recomputes that run's alerts; the change and its new alerts go out on the viewer's
event stream as a `why` record and, with a webhook, new high alerts are POSTed out (rule, title and run; never the
call's arguments). With `tape` (`tracekit why serve`, which has no signed records to show), each run's events also go
out as the viewer's records (tape()), so its calls are on the tape.

Ingest validates every event (event_problem), its hash, its link to the previous event, that its id is new in the run,
and every blob's content hash, before anything is written; a blob no event of the batch references is refused. It
answers once the batch is appended: the analysis runs in the watcher, once per change of a run however many batches
made it. Ingest tokens (`ingest_tokens`, else the viewer's token) only ingest; a run belongs to the token that created
it, only that token may append to it, and nothing may after its run.end. Replay imports the program a run names, so
only programs passed with --allow-program can be replayed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .analysis import analyse, workspace
from .core import GENESIS, REF, SCHEMA, content_hash, event_hash, event_problem, load_run, referenced_refs, ts_seconds
from .evals import list_runs
from .guard import Webhook
from .replay import attribute, counterfactual, load_system
from .view import run_detail

RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")   # fullmatch
OWNER = "ingest-owner"   # in a run folder: the digest of the ingest token that created the run
MAX_DEPTH = 64           # nesting of an ingest body, its blobs included


class IngestError(ValueError):
    def __init__(self, status: int, msg: str, **extra: Any):
        super().__init__(msg)
        self.status = status
        self.extra = extra   # more fields of the JSON answer


def _int(val) -> int:
    try:
        return int(val)
    except (TypeError, ValueError, OverflowError):   # OverflowError: 1e999, read as infinity
        raise IngestError(400, "n and n_max must be integers")


def _too_deep(obj: Any, limit: int = MAX_DEPTH) -> bool:
    stack = [(obj, 0)]
    while stack:
        v, d = stack.pop()
        if d > limit:
            return True
        if isinstance(v, dict):
            stack.extend((x, d + 1) for x in v.values())
        elif isinstance(v, list):
            stack.extend((x, d + 1) for x in v)
    return False


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _stat(path: str) -> Optional[Tuple]:
    """What changes when a run changes: its events and its tests."""
    try:
        st = os.stat(os.path.join(path, "events.jsonl"))
    except OSError:
        return None
    try:
        tt = os.stat(os.path.join(path, "tests.jsonl"))
        tests = (tt.st_size, tt.st_mtime_ns)
    except OSError:
        tests = None
    return (st.st_size, st.st_mtime_ns, tests)


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
        try:
            ts = {"ts": ts_seconds(ev["ts"])}
        except ValueError:   # load_run does not check a log's ts: shown as now, and HORIZON sorts it oldest
            ts = {"ts": time.time(), "ts_unread": True}
        r = {**ts, "session_id": run.run_id, "seq": ev["seq"], "hash": ev["hash"],
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
    or a Feed) as `{"event": "why", "why": {...}}` records; with `tape`, each run's events too (tape()).
    `ingest_tokens`: the bearer tokens /v1/ingest takes (none: the viewer's own token); with `ingest` False it takes
    none."""

    def __init__(self, root: str, allow_programs: Iterable[str] = (), webhook: Optional[str] = None,
                 out=None, tape: bool = False, ingest_tokens: Iterable[str] = (), ingest: bool = True):
        self.root = root
        self.allow = set(allow_programs)
        self.webhook = Webhook(webhook) if webhook else None
        self.out = out or Feed()
        self.tape = tape
        self.ingest_tokens = [t for t in ingest_tokens if t]
        self.ingest_open = ingest   # False: the runs are the viewer's imports of a signer store; nothing else writes
        self.lock = threading.Lock()
        os.makedirs(root, exist_ok=True)
        self._stat: Dict[str, Tuple] = {}
        self._seen: Dict[str, set] = {}
        self._sent: Dict[str, int] = {}   # with tape: events of each run already published
        self._heads: Dict[str, Dict[str, Any]] = {}   # run folder -> what ingest needs of it (_head)
        self._cache: Dict[str, Tuple[Tuple, Dict[str, Any]]] = {}   # run folder -> (its _stat, analyse())
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._watcher: Optional[threading.Thread] = None

    # -- live
    def publish(self, msg: Dict[str, Any], records: Iterable[Dict[str, Any]] = ()) -> None:
        with self.out.lock:
            # lean: kept for the server's life, like the viewer's own records; trim with feed.base if that grows
            self.out.records.extend(records)
            self.out.records.append({"event": "why", "ts": time.time(), "why": msg})
            self.out.lock.notify_all()

    def analysed(self, path: str) -> Dict[str, Any]:
        """analyse() of a run folder, cached until its events or tests change."""
        st = _stat(path)
        hit = self._cache.get(path)
        if hit and hit[0] == st:
            return hit[1]
        # lean: keeps each run (blobs included) in memory for the server's life; cache summaries only if that grows
        a = analyse(path)
        self._cache[path] = (st, a)
        return a

    def _changed(self, path: str, announce: bool) -> None:
        """A run's log grew: recompute its alerts and announce the new ones (each one once)."""
        self._stat[path] = _stat(path)
        a = self.analysed(path)
        run = a.get("run")
        if run is None:   # analyse() reported why; the workspace lists it as broken
            return
        seen = self._seen.setdefault(path, set())
        new = []
        for al in a["alerts"]:
            key = (al["title"], al.get("node"))
            if key not in seen:
                seen.add(key)
                new.append({k: al.get(k) for k in ("severity", "title", "detail", "node", "tool", "agent", "seq")})
        records = tape(run, self._sent.get(path, 0)) if self.tape else []
        self._sent[path] = len(run.events)
        finished = bool(run.events) and run.events[-1]["type"] == "run.end"
        if announce or records:
            self.publish({"type": "run", "run_id": run.run_id, "events": len(run.events), "finished": finished,
                          "alerts": new if announce else []}, records)
        if announce and self.webhook:
            for al in new:
                if al["severity"] == "high":
                    self.webhook.send(al, run.run_id)

    def scan(self, announce: bool = True) -> None:
        """Analyses each run that changed since the last scan (once, however many batches changed it), and forgets
        runs that are gone."""
        paths = self.paths()
        for p in paths:
            st = _stat(p)
            if st is not None and self._stat.get(p) != st:
                self._changed(p, announce)
        gone = set(self._stat) - set(paths)
        with self.lock:   # ingest reads _heads under it
            for d in (self._stat, self._seen, self._sent, self._cache, self._heads):
                for p in gone:
                    d.pop(p, None)

    def watch(self, interval: float = 0.5) -> None:
        """Poll the runs folder in a daemon thread (ingest wakes it at once). Existing runs are indexed silently
        first, so only alerts raised after the server started are announced. stop() ends it."""
        if self._watcher is not None:
            return

        def loop() -> None:
            self.scan(announce=False)
            while not self._stop.is_set():
                self._wake.wait(interval)
                self._wake.clear()
                if self._stop.is_set():
                    return
                try:
                    self.scan()
                except Exception as e:
                    print(f"tracekit why: watcher: {e}", file=sys.stderr)

        self._watcher = threading.Thread(target=loop, daemon=True)
        self._watcher.start()

    def stop(self) -> None:
        """Ends the watcher (the server is shutting down)."""
        self._stop.set()
        self._wake.set()
        if self._watcher is not None:
            self._watcher.join(5)

    def paths(self) -> List[str]:
        return list_runs(self.root) if os.path.isdir(self.root) and os.listdir(self.root) else []

    def run_path(self, run_id: str) -> str:
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise IngestError(400, "bad run id")
        return os.path.join(self.root, run_id)

    # -- what the page reads
    def workspace(self) -> Dict[str, Any]:
        """workspace() of every run, plus `alerts` (every run's, with its run id) and `calls`: "<signed run id>|<run_seq>"
        -> [why run id, node id] of each tool call whose why event cites a signed record of the same tool (the citation
        is the why log's own claim, so a signed record of another tool, or none, joins nothing)."""
        paths = self.paths()
        items = [self.analysed(p) for p in paths]
        out = workspace(paths, items)
        out["alerts"], out["calls"] = [], {}
        with self.out.lock:
            rows = [r for r in self.out.records if isinstance(r.get("v2"), dict)]
        # a call's result record names no tool: it is its decision's (a call that ran cites its result)
        tools = {(r.get("session_id"), r.get("tool_use_id")): r["tool_name"] for r in rows if r.get("tool_name")}
        signed = {f"{r.get('session_id')}|{r['v2'].get('run_seq')}": r.get("tool_name")
                  or tools.get((r.get("session_id"), r.get("tool_use_id"))) for r in rows}
        for a in items:
            run = a.get("run")
            if run is None:
                continue
            out["alerts"] += [{"run_id": run.run_id, **{k: al.get(k) for k in ("severity", "title", "detail", "node",
                                                                                 "tool", "agent", "seq")}}
                              for al in a["alerts"]]
            for ev in run.of_type("action"):
                tk = ev.get("tracekit")
                key = isinstance(tk, dict) and f"{tk.get('run_id')}|{tk.get('run_seq')}"
                if key and signed.get(key) == ev["tool"]:
                    out["calls"][key] = [run.run_id, "ev:" + ev["id"]]
        return out

    def detail(self, run_id: str) -> Dict[str, Any]:
        """run_detail() of one run, plus `replay`: its program and whether this server may replay it."""
        path = self.run_path(run_id)
        if not os.path.exists(os.path.join(path, "events.jsonl")):
            raise IngestError(404, "no such run")
        a = self.analysed(path)
        if "run" not in a:
            raise IngestError(422, "this run cannot be analysed: " + a["summary"]["broken"])
        run = a["run"]
        prog = run.start.get("program")
        return {**run_detail(run), "replay": {"program": prog, "allowed": bool(prog) and prog in self.allow}}

    # -- ingest
    def _head(self, path: str) -> Dict[str, Any]:
        """seq, hash and type of a run's last event, its event ids and its owner (the digest of the token that
        created it by ingest; None for a run written otherwise, "" for a new one), read once, then kept here (a new
        run's once ingest writes it)."""
        h = self._heads.get(path)
        if h is None:
            h = {"seq": -1, "hash": GENESIS, "ended": False, "ids": set(), "owner": ""}
            ev_path = os.path.join(path, "events.jsonl")
            if os.path.exists(ev_path):
                try:
                    with open(os.path.join(path, OWNER), encoding="utf-8") as f:
                        h["owner"] = f.read().strip()
                except OSError:
                    h["owner"] = None   # written to disk by a local Runtime, or an import: never appended to here
                if h["owner"]:
                    with open(ev_path, encoding="utf-8") as f:
                        for line in f:
                            if line.strip():
                                ev = json.loads(line)
                                h["ids"].add(str(ev.get("id")))
                                h.update(seq=ev["seq"], hash=ev["hash"], ended=ev.get("type") == "run.end")
            if h["owner"] != "":
                self._heads[path] = h
        return h

    def ingest(self, body: Dict[str, Any], token: str = "") -> Dict[str, Any]:
        """Appends a batch of one run's events (with the blobs they reference) sent with the ingest `token`."""
        if not self.ingest_open:
            raise IngestError(404, "this viewer takes no ingest: its why runs are imported from the signer's store")
        events, blobs = body.get("events"), body.get("blobs") or {}
        if not isinstance(events, list) or not events or not isinstance(blobs, dict):
            raise IngestError(400, "expected {events: [...], blobs: {...}}")
        if _too_deep(body):
            raise IngestError(400, f"nested deeper than {MAX_DEPTH} levels")
        for ref, val in blobs.items():
            if not REF.fullmatch(ref):
                raise IngestError(400, "blob keys must be sha256:<64 hex>")
            if content_hash(val) != ref:
                raise IngestError(422, f"blob {ref[:20]} does not match its hash")
        run_id = events[0].get("run_id", "") if isinstance(events[0], dict) else ""
        if any(not isinstance(e, dict) or e.get("run_id") != run_id for e in events):
            raise IngestError(400, "one batch must belong to one run")
        for e in events:
            problem = event_problem(e)
            if problem:
                raise IngestError(422, f"seq {str(e.get('seq'))[:20]}: malformed event: {problem}")
        ids = [e["id"] for e in events]
        if len(set(ids)) != len(ids):
            raise IngestError(422, "duplicate event ids in the batch")
        refs = {r for e in events for r in referenced_refs(e)}
        if set(blobs) - refs:
            raise IngestError(422, "a blob no event of the batch references")
        path = self.run_path(run_id)
        with self.lock:
            h = self._head(path)
            if h["owner"] is None or (h["owner"] and h["owner"] != _digest(token)):
                raise IngestError(403, "this run was not created with this ingest token: only the token that "
                                       "created a run may append to it")
            head = {"seq": h["seq"], "hash": h["hash"]}
            if h["ended"]:
                raise IngestError(409, "the run has ended (run.end): nothing may follow it", head=head)
            last_seq, last_hash = h["seq"], h["hash"]
            for ev in events:
                if ev.get("schema") != SCHEMA:
                    raise IngestError(422, "unknown schema")
                if ev["seq"] != last_seq + 1:
                    raise IngestError(409, f"expected seq {last_seq + 1}, got {ev['seq']}", head=head)
                if ev.get("prev_hash") != last_hash:
                    raise IngestError(409, f"seq {ev['seq']}: does not link to the stored chain", head=head)
                if event_hash(ev) != ev.get("hash"):
                    raise IngestError(422, f"seq {ev['seq']}: hash mismatch")
                if ev["id"] in h["ids"]:
                    raise IngestError(422, f"seq {ev['seq']}: event id already in the run")
                last_seq, last_hash = ev["seq"], ev["hash"]
            bdir = os.path.join(path, "blobs")
            for r in refs - set(blobs):
                if not os.path.exists(os.path.join(bdir, r[7:] + ".json")):
                    raise IngestError(422, f"missing blob {r[:20]}")
            os.makedirs(bdir, exist_ok=True)
            if h["owner"] == "":
                with open(os.path.join(path, OWNER), "w", encoding="utf-8") as f:
                    f.write(_digest(token))
                h["owner"] = _digest(token)
            for ref, val in blobs.items():
                p = os.path.join(bdir, ref[7:] + ".json")
                if not os.path.exists(p):
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump({"v": val}, f, sort_keys=True, ensure_ascii=False, default=str)
            with open(os.path.join(path, "events.jsonl"), "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
            h["ids"].update(ids)
            h.update(seq=last_seq, hash=last_hash, ended=events[-1]["type"] == "run.end")
            self._heads[path] = h
        self._wake.set()   # the watcher analyses it
        return {"run_id": run_id, "accepted": len(events), "head_seq": last_seq}

    # -- tests
    def _replayable(self, run_id: str):
        path = self.run_path(run_id)
        if not os.path.exists(os.path.join(path, "events.jsonl")):
            raise IngestError(404, "no such run")
        a = self.analysed(path)
        if "run" not in a:
            raise IngestError(422, "this run cannot be analysed: " + a["summary"]["broken"])
        run = load_run(path)   # its own copy: the test results it records go to this run, not the cache's
        prog = run.start.get("program")
        if not prog or prog not in self.allow:
            raise IngestError(403, f"replay of {prog!r} is not allowed here: start the viewer with --allow-program "
                                   f"{prog}, or run the test with `tracekit why test`" if prog else
                              "this run names no program to replay: record it with a System")
        return run, prog

    def attribute(self, run_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        run, prog = self._replayable(run_id)
        n, n_max = _int(body.get("n", 10)), _int(body.get("n_max", 80))
        target, suspects = str(body.get("target", "")), body.get("suspects") or None
        if not target or not 1 <= n <= n_max <= 400:
            raise IngestError(400, "target is required; 1 <= n <= n_max <= 400")
        if suspects is not None and not (isinstance(suspects, list) and all(isinstance(s, str) for s in suspects)):
            raise IngestError(400, "suspects must be a list of intervention specs")
        try:
            result = attribute(run, target, suspects, n=n, n_max=n_max, system=load_system(prog))
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
