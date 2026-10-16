"""tracekit why core: content-addressed refs, hash-chained causal events, and the agent runtime.

Every value an agent sees or produces is stored once under its content hash (a *ref*).
A decision records the exact refs that were in its context and the ref it produced, so
"X was in the context of D" becomes an edge X -> D with no guessing. Actions, results
and messages are linked the same way. The event log is hash-chained (unsigned here;
Tracekit can sign and witness it).
"""
from __future__ import annotations

import calendar
import fnmatch
import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

SCHEMA = "tracekit.why.event.v1"
GENESIS = "0" * 64
COMMITTED = "content committed, not in the log"   # a signed run's content: only its commitment is known

TRUST_LEVELS = ("trusted", "untrusted")
EVENT_TYPES = ("run.start", "agent.start", "input", "decision", "action", "message", "run.end")


# --------------------------------------------------------------------------- hashing

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def content_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical({"v": value})).hexdigest()


def event_hash(ev: Dict[str, Any]) -> str:
    body = {k: v for k, v in ev.items() if k != "hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


def _now() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%06dZ" % int((t % 1) * 1e6)


def derive_seed(*parts: Any) -> int:
    return int(hashlib.sha256(canonical(list(parts))).hexdigest()[:12], 16)


# --------------------------------------------------------------------------- refs

@dataclass(frozen=True)
class Ref:
    """A value plus where it came from. Identity (for graph edges) is `ref`, the content hash."""

    ref: str
    value: Any
    kind: str  # task | input | output | message | result
    agent: str
    source: str = ""  # input: source label; message: "from->to"; result: tool name; output: purpose
    trust: str = "trusted"
    event_id: str = ""

    def __repr__(self) -> str:  # keep reprs short in logs
        return f"Ref({self.kind}:{self.source or self.agent} {self.ref[:15]})"


def glob_escape(label: str) -> str:
    """A source label as a glob that matches only itself, for an `input:`/`msg:` spec built from a recorded label."""
    return "".join(f"[{c}]" if c in "*?[" else c for c in label)


def ablation_matches(spec: str, r: Ref) -> bool:
    """Intervention specs:
    ref:<hash prefix>        a specific content (with or without the sha256: prefix)
    input:<glob>             inputs whose source matches the glob
    msg:<from>-><to>         messages on a channel (globs allowed, e.g. msg:*->planner)
    result:<tool glob>       tool results
    untrusted                anything marked untrusted
    """
    if spec == "untrusted":
        return r.trust == "untrusted"
    kind, _, pat = spec.partition(":")
    if kind == "ref":
        pat = pat if pat.startswith("sha256:") else "sha256:" + pat
        return r.ref.startswith(pat)
    if kind == "input":
        return r.kind == "input" and fnmatch.fnmatch(r.source, pat)
    if kind == "msg":
        return r.kind == "message" and fnmatch.fnmatch(r.source, pat)
    if kind == "result":
        return r.kind == "result" and fnmatch.fnmatch(r.source, pat)
    raise ValueError(f"unknown intervention spec: {spec!r}")


# --------------------------------------------------------------------------- run (loaded log)

@dataclass
class Run:
    run_id: str
    events: List[Dict[str, Any]]
    blobs: Dict[str, Any]
    path: Optional[str] = None
    tests: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def start(self) -> Dict[str, Any]:
        return self.events[0] if self.events and self.events[0]["type"] == "run.start" else {}

    def of_type(self, t: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["type"] == t]

    def by_id(self) -> Dict[str, Dict[str, Any]]:
        return {e["id"]: e for e in self.events}

    def value(self, ref: Optional[str]) -> Any:
        return self.blobs.get(ref) if ref else None

    def add_test(self, result: Dict[str, Any]) -> None:
        """Appends a test result, chained: `prev` is the previous line's hash and `head` the hash of the run's last
        event when it was tested, so a line edited, removed or inserted later breaks the chain (verify)."""
        result["prev"] = self.tests[-1].get("hash", GENESIS) if self.tests else GENESIS
        result["head"] = self.events[-1]["hash"] if self.events else GENESIS
        result["hash"] = chain_hash(result)
        self.tests.append(result)
        if self.path:
            with open(os.path.join(self.path, "tests.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(result, sort_keys=True) + "\n")


def load_run(path: str) -> Run:
    events = []
    with open(os.path.join(path, "events.jsonl"), encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    blobs: Dict[str, Any] = {}
    bdir = os.path.join(path, "blobs")
    if os.path.isdir(bdir):
        for name in os.listdir(bdir):
            with open(os.path.join(bdir, name), encoding="utf-8") as f:
                blobs["sha256:" + name[:-5]] = json.load(f)["v"]
    tests = []
    tpath = os.path.join(path, "tests.jsonl")
    if os.path.exists(tpath):
        with open(tpath, encoding="utf-8") as f:
            tests = [json.loads(l) for l in f if l.strip()]
    run_id = events[0]["run_id"] if events else os.path.basename(path)
    return Run(run_id=run_id, events=events, blobs=blobs, path=path, tests=tests)


UNFINISHED = "no run.end"   # how verify() reports a log without its end record
REF = re.compile(r"sha256:[0-9a-f]{64}")
TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?Z")
# fields each event type must carry for the analysis to read it, and the string fields among them
REQUIRED = {"run.start": (), "agent.start": (), "run.end": (), "input": ("ref", "source", "trust"),
            "decision": ("model", "context", "output"), "action": ("tool", "args_ref", "result_ref"),
            "message": ("to", "ref")}
_STRINGS = ("source", "model", "tool", "to")
_REFS = ("ref", "output", "args_ref", "result_ref")


def ts_seconds(ts: Any) -> float:
    """Seconds since the epoch of a TS timestamp (a fraction of any length, or none); ValueError for anything else."""
    if not (isinstance(ts, str) and TS.fullmatch(ts)):
        raise ValueError(f"not a log timestamp: {str(ts)[:40]!r}")
    whole, _, frac = ts[:-1].partition(".")
    return calendar.timegm(time.strptime(whole, "%Y-%m-%dT%H:%M:%S")) + float("0." + (frac or "0"))


def event_problem(ev: Any) -> Optional[str]:
    """Why an event from outside (ingest, an import) is not one the analysis can read, else None: the common fields
    (id, agent, ts, type, seq), the type's own fields and their types, refs as content hashes, token counts as
    integers >= 0."""
    if not isinstance(ev, dict):
        return "not an object"
    t = ev.get("type")
    if t not in EVENT_TYPES:
        return f"unknown type {str(t)[:40]!r}"
    for k in ("id", "agent"):
        if not isinstance(ev.get(k), str) or not 0 < len(ev[k]) <= 256:
            return f"{k} must be a non-empty string"
    try:
        ts_seconds(ev.get("ts"))
    except ValueError:
        return "ts must be a UTC timestamp (YYYY-MM-DDTHH:MM:SS[.ffffff]Z)"
    if type(ev.get("seq")) is not int:
        return "seq must be an integer"
    missing = [k for k in REQUIRED[t] if k not in ev]
    if missing:
        return f"missing {', '.join(missing)}"
    if any(k in ev and not isinstance(ev[k], str) for k in _STRINGS):
        return f"{', '.join(k for k in _STRINGS if k in ev)} must be strings"
    if "trust" in REQUIRED[t] and ev["trust"] not in TRUST_LEVELS:
        return f"trust must be one of {TRUST_LEVELS}"
    if any(ev.get(k) is not None and not (isinstance(ev[k], str) and REF.fullmatch(ev[k])) for k in _REFS):
        return "refs must be sha256:<64 hex> strings"
    ctx = ev.get("context", [])
    if not isinstance(ctx, list) or not all(isinstance(c, dict) and isinstance(c.get("ref"), str)
                                            and REF.fullmatch(c["ref"]) and isinstance(c.get("kind"), str)
                                            and "source" in c and isinstance(c["source"] or "", str)
                                            and c.get("trust") in TRUST_LEVELS
                                            and isinstance(c.get("from_event") or "", str) for c in ctx):
        return "context must be a list of {ref: sha256:<64 hex>, kind, source, trust[, from_event]}"
    usage = ev.get("usage")
    if usage is not None and not (isinstance(usage, dict) and all(type(v) is int and v >= 0 for k, v in usage.items()
                                                                  if k.endswith("tokens"))):
        return "usage must be an object whose token counts are integers >= 0"
    return None


def chain_hash(t: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical({k: v for k, v in t.items() if k not in ("hash", "chain")})).hexdigest()


def check_tests(run: Run) -> List[str]:
    """Checks the chain of tests.jsonl and marks each test's `chain`: ok, unchained (a line written without the chain,
    by hand or by an older version) or broken. Returns the problems of the broken ones."""
    problems: List[str] = []
    heads = {e.get("hash") for e in run.events}
    prev = GENESIS
    for i, t in enumerate(run.tests):
        if "hash" not in t:
            t["chain"] = "unchained"
        elif t.get("prev") != prev or chain_hash(t) != t["hash"] or t.get("head") not in heads:
            t["chain"] = "broken"
            problems.append(f"test {i}: does not link to the tests before it or to an event of the run "
                            "(edited, removed or inserted)")
        else:
            t["chain"] = "ok"
        prev = t.get("hash", GENESIS)
    return problems


def verify(run: Run) -> List[str]:
    """Integrity check: chain links, event hashes, contiguous seq, unique event ids, blob content hashes, that every
    referenced ref exists, that the log ends with run.end (else it was cut short, or the run is still going) and the
    chain of its tests. Returns a list of problems (empty = ok). The chain is unsigned: it shows edits, insertions and
    deletions, not who made them."""
    problems: List[str] = []
    prev = GENESIS
    ids: set = set()
    for i, ev in enumerate(run.events):
        if str(ev.get("id")) in ids:
            problems.append(f"seq {i}: duplicate event id {str(ev.get('id'))[:32]}")
        ids.add(str(ev.get("id")))
        if ev.get("seq") != i:
            problems.append(f"seq {ev.get('seq')} at position {i}: not contiguous")
        if ev.get("prev_hash") != prev:
            problems.append(f"seq {i}: prev_hash does not link (record deleted, reordered or inserted)")
        if event_hash(ev) != ev.get("hash"):
            problems.append(f"seq {i}: hash mismatch (event content was edited)")
        prev = ev.get("hash", "")
    for ref, val in run.blobs.items():
        if content_hash(val) != ref:
            problems.append(f"blob {ref[:20]}: content does not match its hash")
    for ev in run.events:
        for r in referenced_refs(ev):
            if r not in run.blobs:
                problems.append(f"seq {ev['seq']}: references missing blob {r[:20]}")
    if not run.events or run.events[-1].get("type") != "run.end":
        problems.append(f"{UNFINISHED}: the log ends at seq {len(run.events) - 1}; it was cut short, or the run has "
                        "not finished")
    return problems + check_tests(run)


def referenced_refs(ev: Dict[str, Any]) -> List[str]:
    out = []
    for k in ("ref", "output", "args_ref", "result_ref"):
        if ev.get(k):
            out.append(ev[k])
    out.extend(c["ref"] for c in ev.get("context", []))
    return out


# --------------------------------------------------------------------------- sinks

class HttpSink:
    """Ships events and their blobs to a `tracekit why serve` collector (POST /v1/ingest).
    Batches, but sends at once after every tool call and when `interval` seconds have passed, so the
    collector sees a running system live. Call flush() (Runtime.finish does) to send the rest.
    Raises on HTTP errors so a lost batch is visible to the caller rather than silently dropped."""

    def __init__(self, url: str, token: str, batch: int = 50, timeout: float = 10.0, interval: float = 1.0):
        self.url = url.rstrip("/") + "/v1/ingest"
        self.token = token
        self.batch = batch
        self.timeout = timeout
        self.interval = interval
        self._events: List[Dict[str, Any]] = []
        self._blobs: Dict[str, Any] = {}
        self._last = time.monotonic()

    def write(self, ev: Dict[str, Any], blobs: Dict[str, Any]) -> None:
        self._events.append(ev)
        self._blobs.update(blobs)
        if (len(self._events) >= self.batch or ev.get("type") in ("action", "run.end")
                or time.monotonic() - self._last >= self.interval):
            self.flush()

    def flush(self) -> None:
        """Sends the batch. A batch the collector committed although the answer never arrived (a timeout) is kept and
        sent again with what came after; the collector's 409 then names its head, and the events up to it are
        dropped as delivered when that head is one of them (same seq and hash)."""
        while True:   # each retry has fewer events
            if not self._events:
                self._blobs = {}
                return
            try:
                self._post()
            except urllib.error.HTTPError as e:
                head = _head_of(e) if e.code == 409 else None
                done = next((i for i, ev in enumerate(self._events)
                             if head and ev.get("seq") == head.get("seq") and ev.get("hash") == head.get("hash")), None)
                if done is None:
                    raise
                del self._events[:done + 1]
                refs = {r for ev in self._events for r in referenced_refs(ev)}
                self._blobs = {r: v for r, v in self._blobs.items() if r in refs}
                continue
            self._events, self._blobs = [], {}
            self._last = time.monotonic()
            return

    def _post(self) -> None:
        body = json.dumps({"events": self._events, "blobs": self._blobs}, ensure_ascii=False, default=str).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self.token}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            if r.status >= 300:
                raise RuntimeError(f"ingest failed: HTTP {r.status}")


def _head_of(err: Any) -> Optional[Dict[str, Any]]:
    """The run head a collector's 409 names ({"head": {"seq", "hash"}}), if any."""
    try:
        head = json.loads(err.read()).get("head")
    except (OSError, ValueError, AttributeError):
        return None
    return head if isinstance(head, dict) else None


@dataclass
class ModelOutput:
    """Optional richer return type for model functions: the value plus usage (tokens, cost)."""
    value: Any
    usage: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- runtime

ModelFn = Callable[..., Any]   # fn(context_values, *, purpose, seed, params, agent) -> value
ToolFn = Callable[..., Any]    # fn(**args) -> value


class Tape:
    """Recorded tool results from an earlier run, replayed VCR-style.
    Keyed by (agent, tool, args hash, occurrence) so repeated identical calls replay in order."""

    def __init__(self, run: Optional[Run] = None):
        self._results: Dict[tuple, Any] = {}
        if run is not None:
            seen: Dict[tuple, int] = {}
            for ev in run.of_type("action"):
                key = (ev["agent"], ev["tool"], ev["args_ref"])
                n = seen.get(key, 0)
                seen[key] = n + 1
                self._results[key + (n,)] = run.value(ev["result_ref"])

    def get(self, key: tuple):
        return self._results.get(key, _MISSING)


_MISSING = object()


class Runtime:
    """Records a multi-agent run. The same class runs counterfactual replays:
    pass `interventions` (ablation specs), a `tape` of recorded tool results and a new `seed`.

    `signer`: a tracekit.sdk.client.Client, False for none, or None to use one when the SDK finds a signer
    ($TRACEKIT_SIGNER or system mode). With a signer each agent gets a Tracekit run (registered on first use, the
    task observed in it as trusted) and every event also goes through it: observe() and messages delivered to the
    agent are observed, act() is decided first (a deny, or an ask nobody approves within `approval_wait_s`, blocks
    it) and completed after, model calls are model_events (unless `record_models` is False: a gateway records
    them). Each event stores the citation of its record (`tracekit`); the signer is the gate, not the guard. A call held
    for approval is held again, under the same tool call and approval, when the agent retries it with the same arguments:
    an approval given meanwhile lets the retry run. finish() (or close()) abandons the approvals still held, except
    those escalated to people (they expire with the run)."""

    def __init__(
        self,
        models: Dict[str, ModelFn],
        tools: Optional[Dict[str, ToolFn]] = None,
        *,
        out_dir: Optional[str] = None,
        run_id: Optional[str] = None,
        task: Any = None,
        program: str = "",
        seed: int = 0,
        interventions: Sequence[str] = (),
        tape: Optional[Tape] = None,
        live_tools: bool = True,
        meta: Optional[Dict[str, Any]] = None,
        sensitive_tools: Sequence[str] = (),
        untrusted_tools: Sequence[str] = (),
        sink: Optional[HttpSink] = None,
        guard: Optional[Any] = None,
        signer: Any = None,
        approval_wait_s: float = 300,
        record_models: bool = True,
    ):
        self._own_signer = signer is None   # a client the runtime opens itself, it closes
        if signer is None:
            from tracekit.sdk.client import Client, _default_signer
            signer = Client() if _default_signer() else None
        self.signer = signer or None
        self._held: Dict[tuple, Dict[str, Any]] = {}   # (agent, tool, args digest) -> a call held for approval
        self.approval_wait_s = approval_wait_s
        self.record_models = record_models
        self._tk_runs: Dict[str, Any] = {}
        self._exchanges: Dict[str, Dict[str, Any]] = {}  # decision event id -> its model.exchange, until finish()
        self.models = dict(models)
        self.tools = dict(tools or {})
        self.run_id = run_id or time.strftime("run-%Y%m%d-%H%M%S-") + secrets.token_hex(3)
        self.seed = seed
        self.interventions = list(interventions)
        self.tape = tape
        self.live_tools = live_tools
        self.events: List[Dict[str, Any]] = []
        self.blobs: Dict[str, Any] = {}
        self._prev = GENESIS
        self._agents: Dict[str, "Agent"] = {}
        self._mail: Dict[str, List[Ref]] = {}
        self._tape_seen: Dict[tuple, int] = {}
        self.path: Optional[str] = None
        self.sensitive_tools = set(sensitive_tools)
        self.untrusted_tools = set(untrusted_tools)
        self.sink = sink
        self.guard = guard  # tracekit.why.guard.Guard: checks sensitive tool calls before they run
        self.alerts: List[Dict[str, Any]] = []  # raised by the guard during this run
        self._pending_blobs: Dict[str, Any] = {}
        self._outbox: List[tuple] = []        # (event, its new blobs) not yet handed to the sink
        self._sink_lock = threading.Lock()    # one thread at a time hands events to the sink, in order
        # agents may run in threads: every write to the log, blob store, mail and counters takes this lock
        self._lock = threading.RLock()
        if out_dir:
            self.path = os.path.join(out_dir, self.run_id)
            os.makedirs(os.path.join(self.path, "blobs"), exist_ok=True)
            open(os.path.join(self.path, "events.jsonl"), "w").close()
            try:
                os.remove(os.path.join(self.path, "tests.jsonl"))   # the tests of the run this one replaces
            except FileNotFoundError:
                pass
        self._emit("run", "run.start", program=program, seed=seed, interventions=self.interventions,
                   models=sorted(self.models), tools=sorted(self.tools), meta=meta or {},
                   sensitive_tools=sorted(self.sensitive_tools), untrusted_tools=sorted(self.untrusted_tools),
                   guard=self.guard.describe() if self.guard is not None else None)
        self.task_ref: Optional[Ref] = None
        if task is not None:
            self.task_ref = self._input("run", task, source="task", trust="trusted", kind="task")

    # -- storage
    def _blob(self, value: Any) -> str:
        ref = content_hash(value)
        with self._lock:
            return self._store_blob(ref, value)

    def _store_blob(self, ref: str, value: Any) -> str:
        if ref not in self.blobs:
            self.blobs[ref] = value
            if self.sink is not None:
                self._pending_blobs[ref] = value
            if self.path:
                p = os.path.join(self.path, "blobs", ref[7:] + ".json")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump({"v": value}, f, sort_keys=True, ensure_ascii=False, default=str)
        return ref

    def _emit(self, agent: str, etype: str, **body: Any) -> Dict[str, Any]:
        with self._lock:
            ev = self._emit_locked(agent, etype, body)
        self._ship()
        return ev

    def _ship(self, wait: bool = False) -> None:
        """Hands the events emitted so far to the sink, in order, outside the runtime's lock (the sink may send them
        over the network), so other agents keep recording meanwhile. One thread ships at a time; another that finds
        it busy leaves its events to it (`wait`: ships them itself, after it). A caller holding the runtime's lock
        ships after releasing it."""
        if self.sink is None or self._lock._is_owned():  # type: ignore[attr-defined]
            return
        while self._outbox:   # read unlocked; rechecked under both locks
            if not self._sink_lock.acquire(blocking=wait):
                return
            try:
                while True:
                    with self._lock:
                        if not self._outbox:
                            break
                        ev, blobs = self._outbox.pop(0)
                    self.sink.write(ev, blobs)
            finally:
                self._sink_lock.release()

    def _emit_locked(self, agent: str, etype: str, body: Dict[str, Any]) -> Dict[str, Any]:
        ev = {"schema": SCHEMA, "seq": len(self.events), "id": secrets.token_hex(16), "prev_hash": self._prev,
              "ts": _now(), "run_id": self.run_id, "agent": agent, "type": etype}
        ev.update(body)
        ev["hash"] = event_hash(ev)
        self._prev = ev["hash"]
        self.events.append(ev)
        if self.path:
            with open(os.path.join(self.path, "events.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
        if self.sink is not None:   # each blob goes with the first event that references it
            ship = {r: self._pending_blobs.pop(r) for r in referenced_refs(ev) if r in self._pending_blobs}
            self._outbox.append((ev, ship))
        return ev

    def _input(self, agent: str, value: Any, *, source: str, trust: str, kind: str = "input") -> Ref:
        if trust not in TRUST_LEVELS:
            raise ValueError(f"trust must be one of {TRUST_LEVELS}")
        ref = self._blob(value)
        extra = {}
        if self.signer is not None and agent != "run":  # the task goes into each agent's run as it registers
            extra["tracekit"] = self._observe(agent, value, source, trust)
        ev = self._emit(agent, "input", ref=ref, source=source, trust=trust, kind=kind, **extra)
        return Ref(ref, value, kind, agent, source, trust, ev["id"])

    # -- signer
    def _tk(self, agent: str, parent: Optional[str] = None) -> Any:
        """The Tracekit run of `agent`, registered on first use (a child of `parent`'s run when it has one) with the
        task observed in it as trusted."""
        with self._lock:
            run = self._tk_runs.get(agent)
            if run is None:
                run = self._tk_runs[agent] = self.signer.run(agent=agent, parent=self._tk_runs.get(parent))
                if self.task_ref is not None:
                    run.observe(self.task_ref.value, "task", "trusted")
            return run

    def _observe(self, agent: str, value: Any, source: str, trust: str) -> Dict[str, Any]:
        run = self._tk(agent)
        return _cite(run, run.observe(value, source[:256], trust)["run_seq"], "input.observed")

    def _close_signer(self) -> None:
        """Sends each model call's response (with the tool calls it led to) and closes the agents' runs."""
        # lean: responses go out at finish, so their records come last in each run; send each when its agent next
        # decides if record order ever matters more than reconciliation, which runs at the run's end
        from tracekit.sdk.client import SignerUnavailable
        from tracekit.signer.rpc_schema import RPCError
        calls = [(lambda ex=ex: ex["run"].call(
            "model_event", provider="tracekit-why", model=ex["model"], phase="response", exchange_id=ex["id"],
            **({"tool_uses": ex["tool_uses"][:128]} if ex["tool_uses"] else {}))) for ex in self._exchanges.values()]
        calls += [(lambda h=h: h["run"].call("approval_wait", approval_id=h["aid"], timeout_ms=0).get("escalated") or
                   h["run"].call("approval_abandon", approval_id=h["aid"],   # people answer an escalated one
                                 reason="the run ended before the call was retried"))
                  for h in self._held.values()]
        calls += [run.close for run in self._tk_runs.values()]
        self._exchanges.clear()
        self._held.clear()
        for call in calls:   # a signer gone at the end still leaves a finished why log
            try:
                call()
            except (RPCError, SignerUnavailable) as e:
                warnings.warn(f"tracekit why: the signer did not record the run's end: {e}", stacklevel=3)

    def _ablated(self, r: Ref) -> bool:
        return any(ablation_matches(s, r) for s in self.interventions)

    # -- public
    def agent(self, name: str, *, parent: Optional[str] = None, role: str = "") -> "Agent":
        with self._lock:
            if name in self._agents:
                return self._agents[name]
            extra = {"tracekit": _cite(self._tk(name, parent), 0, "run.registered")} if self.signer is not None else {}
            self._emit(name, "agent.start", parent=parent, role=role, **extra)
            a = Agent(self, name)
            self._agents[name] = a
        self._ship()
        return a

    def close(self) -> None:
        """Ends the agents' Tracekit runs and closes a client the runtime opened itself. finish() calls it; call it
        when a program fails before finish(). A second call does nothing."""
        if self.signer is not None:
            self._close_signer()
            if self._own_signer:
                self.signer.close()
            self.signer = None

    def finish(self, outcome: Any = None) -> Run:
        self.close()
        self._emit("run", "run.end", outcome=outcome)
        if self.sink is not None:
            self._ship(wait=True)
            with self._sink_lock:
                self.sink.flush()
        return self.run()

    def run(self) -> Run:
        return Run(self.run_id, self.events, self.blobs, self.path)


class Agent:
    def __init__(self, rt: Runtime, name: str):
        self.rt = rt
        self.name = name
        self._n_decisions = 0

    def _next_seed(self) -> int:
        with self.rt._lock:
            seed = derive_seed(self.rt.seed, self.name, self._n_decisions)
            self._n_decisions += 1
            return seed

    def observe(self, value: Any, *, source: str, trust: str = "untrusted") -> Ref:
        """Bring an outside value into this agent's world (file, web page, email, user message)."""
        return self.rt._input(self.name, value, source=source, trust=trust)

    def decide(self, context: Iterable[Ref], *, model: str, purpose: str = "", params: Optional[dict] = None) -> Ref:
        """One model call. `context` is exactly what the model saw; under an intervention,
        matching refs are removed before the call and listed in `ablated`."""
        rt = self.rt
        context = [c for c in context if c is not None]
        kept = [c for c in context if not rt._ablated(c)]
        ablated = [c.ref for c in context if rt._ablated(c)]
        seed = self._next_seed()
        params = params or {}
        if model not in rt.models:
            raise KeyError(f"model {model!r} not registered")
        t0 = time.perf_counter()
        try:
            value = rt.models[model]([c.value for c in kept], purpose=purpose, seed=seed, params=params,
                                     agent=self.name)
        except Exception as e:
            self.record_decision(kept, {"error": f"{type(e).__name__}: {e}"}, model=model, purpose=purpose,
                                 params=params, seed=seed, ablated=ablated, status="error",
                                 duration_ms=(time.perf_counter() - t0) * 1000)
            raise
        usage = {}
        if isinstance(value, ModelOutput):
            value, usage = value.value, value.usage
        return self.record_decision(kept, value, model=model, purpose=purpose, params=params, seed=seed,
                                    ablated=ablated, usage=usage, duration_ms=(time.perf_counter() - t0) * 1000)

    def record_decision(self, context: Iterable[Ref], output: Any, *, model: str, purpose: str = "",
                        params: Optional[dict] = None, seed: Optional[int] = None, ablated: Sequence[str] = (),
                        usage: Optional[dict] = None, duration_ms: Optional[float] = None,
                        status: str = "ok") -> Ref:
        """Record a model call you made yourself (adapters use this). Replay of such a decision
        needs the model to be registered under the same name."""
        rt = self.rt
        kept = [c for c in context if c is not None]
        out = rt._blob(output)
        extra, ex = {}, None
        if rt.signer is not None and rt.record_models:
            from tracekit.format.canon import event_hash as jcs_hash
            from tracekit.usage import FIELDS as USAGE_FIELDS
            run, ex = rt._tk(self.name), {"id": secrets.token_hex(16), "model": model[:128], "tool_uses": []}
            ex["run"] = run
            counts = {k: v for k, v in (usage or {}).items() if k in USAGE_FIELDS and type(v) is int and v >= 0}
            seq = run.call("model_event", provider="tracekit-why", model=ex["model"], phase="request",
                           exchange_id=ex["id"], content_digest=jcs_hash([c.value for c in kept]),
                           **({"error": str(output.get("error"))[:500]} if status == "error" else {}),
                           **({"usage": counts} if {"input_tokens", "output_tokens"} <= counts.keys() else {}))["run_seq"]
            extra["tracekit"] = _cite(run, seq, "model.exchange")
        ev = rt._emit(self.name, "decision", model=model, purpose=purpose, params=params or {}, seed=seed,
                      context=[{"ref": c.ref, "kind": c.kind, "source": c.source, "trust": c.trust,
                                "from_event": c.event_id} for c in kept],
                      ablated=list(ablated), output=out, usage=usage or {}, status=status,
                      duration_ms=round(duration_ms, 3) if duration_ms is not None else None, **extra)
        if ex is not None:
            with rt._lock:
                rt._exchanges[ev["id"]] = ex
        trust = "untrusted" if any(c.trust == "untrusted" for c in kept) else "trusted"
        return Ref(out, output, "output", self.name, purpose, trust, ev["id"])

    def act(self, tool: str, args: Optional[dict] = None, *, decision: Optional[Ref] = None,
            sensitive: Optional[bool] = None, untrusted: Optional[bool] = None) -> Ref:
        """Run a tool. Under replay, results come from the tape when the call matches a recorded one.

        With a guard on the runtime, a sensitive call is checked first and may be blocked: the tool
        does not run and the caller gets {"error": "blocked by tracekit why guard: ..."} back. With a signer the
        signer decides instead (the guard is not asked) and a call it refuses gets {"error": "blocked by policy: ..."}.
        `untrusted=True` (or the tool listed in the runtime's untrusted_tools) records the result as
        untrusted content, like observe(), so later decisions that read it are tainted."""
        rt = self.rt
        args = args or {}
        args_ref = rt._blob(args)
        is_sensitive = bool(sensitive) if sensitive is not None else tool in rt.sensitive_tools
        mode = "live"
        t0 = time.perf_counter()
        result: Any = _MISSING
        gate: Dict[str, Any] = {}
        check = None
        if rt.signer is not None:
            gate = self._gate(tool, args, decision)
            ids = gate.pop("ids", {})
            if "blocked" in gate:
                result, mode = gate.pop("blocked"), "blocked"
        elif rt.guard is not None:
            check = rt.guard.check(rt, self.name, tool, args, decision, is_sensitive)
            if check.blocked:
                result, mode = {"error": "blocked by tracekit why guard: " + check.reason}, "blocked"
        if result is _MISSING and rt.tape is not None:
            key = (self.name, tool, args_ref)
            with rt._lock:
                n = rt._tape_seen.get(key, 0)
                rt._tape_seen[key] = n + 1
            result = rt.tape.get(key + (n,))
            mode = "tape"
        if result is _MISSING:
            if rt.live_tools and tool in rt.tools:
                mode = "live"
                try:
                    result = rt.tools[tool](**args)
                except Exception as e:  # recorded, not raised: the log is the point
                    result = {"error": f"{type(e).__name__}: {e}"}
            else:
                mode = "stub"
                result = {"_unrecorded": True, "tool": tool}
        status = "blocked" if mode == "blocked" else _status(result)
        res_ref = rt._blob(result)
        extra = {"guard": check.record()} if check is not None and check.alerts else {}
        if gate:
            if mode != "blocked":
                gate["tracekit"] = self._complete(gate["tracekit"], ids, status, result, stub=mode == "stub")
            extra.update(gate)
        ev = rt._emit(self.name, "action", tool=tool, args_ref=args_ref, result_ref=res_ref,
                      decision=decision.event_id if decision else None, status=status, mode=mode,
                      sensitive=is_sensitive, duration_ms=round((time.perf_counter() - t0) * 1000, 3), **extra)
        if check is not None:
            check.notify(rt, ev)
        trust = decision.trust if decision else "trusted"
        ref = Ref(res_ref, result, "result", self.name, tool, trust, ev["id"])
        if mode != "blocked" and (untrusted if untrusted is not None else tool in rt.untrusted_tools):
            # same content as the action's result, so the graph links action -> input (same-content)
            ref = rt._input(self.name, result, source=f"tool:{tool}", trust="untrusted")
        return ref

    def _gate(self, tool: str, args: dict, decision: Optional[Ref]) -> Dict[str, Any]:
        """The signer's verdict on a call about to run: {"policy", "tracekit": its decision record, "ids": what
        `complete` names}, plus "blocked", the result the agent gets instead, when the call may not run."""
        from tracekit.format.canon import event_hash as jcs_hash
        from tracekit.sdk.client import SignerUnavailable
        from tracekit.signer.rpc_schema import RPCError
        rt = self.rt
        try:
            digest: Optional[str] = jcs_hash({"tool": tool, "args": args})
        except ValueError:
            digest = None
        key = (self.name, tool, digest)
        with rt._lock:
            held = rt._held.pop(key, None) if digest else None
        try:
            run = rt._tk(self.name)
            if held:   # a retry of a call held for approval: the same tool call, decision and approval
                tcid, d, aid = held["tcid"], held["d"], held["aid"]
            else:
                tcid, aid = "why-" + secrets.token_hex(12), None
                d = run.decide(tcid, tool, args)
                if d.get("unavailable"):   # no fail mode here: a replay never runs a call the signer didn't decide
                    raise SignerUnavailable(d["reason"])
        except (RPCError, SignerUnavailable) as e:
            return {"blocked": {"error": f"blocked: the signer did not decide this call ({e}); it did not run. "
                                         "Check that the signer is up and the run still open, then retry"}}
        policy = {"decision": d["decision"], "rule_ids": d["rule_ids"]}
        out = {"policy": policy, "tracekit": dict(_cite(run, d["run_seq"], "policy.decision"), tool_call_id=tcid),
               "ids": {"decision_id": d["decision_id"], "args_digest": digest} if digest else {}}
        with rt._lock:
            ex = rt._exchanges.get(decision.event_id) if decision is not None and not held else None
            if ex is not None and ex["run"] is run:  # the model call that asked for it, for reconciliation
                use = {"id": tcid, "name": tool[:256], "executed_by": "client", "args_source": "parsed"}
                if digest:
                    use["args_digest"] = digest
                ex["tool_uses"].append(use)
        why = "blocked by policy: " + (", ".join(d["rule_ids"]) or d["decision"])
        if d["decision"] == "deny":
            out["blocked"] = {"error": why}
            return out
        try:
            if d["decision"] == "ask":
                if aid is None:
                    aid = run.call("approval_request", tool_call_id=tcid)["approval_id"]
                state, deadline = "requested", time.monotonic() + rt.approval_wait_s
                while True:
                    left_ms = int(max(min(deadline - time.monotonic(), 300), 0.001) * 1000)
                    state = run.call("approval_wait", approval_id=aid, timeout_ms=left_ms)["state"]
                    if state != "requested" or time.monotonic() >= deadline:
                        break
                policy["approval"] = {"id": aid, "state": state}
                if state != "approved":
                    if state == "requested" and digest:
                        with rt._lock:
                            rt._held[key] = {"tcid": tcid, "d": d, "aid": aid, "run": run}
                    out["blocked"] = {"error": why + (
                        "; a person rejected it" if state == "rejected" else
                        f"; approval {aid} is requested: answer it (`tracekit approvals`), then retry the same call "
                        "in this run: the retry runs once it is approved" if state == "requested" and digest else
                        f"; approval {aid} is {state}"), "approval": state}
                    return out
            c = run.approval_consume(tcid, tool, args, approval_id_hint=aid)
        except (RPCError, SignerUnavailable) as e:
            c = {"ok": False, "rule_ids": d["rule_ids"], "reason": str(e)}
        if not c["ok"]:
            out["blocked"] = {"error": "blocked by policy: " + (", ".join(c["rule_ids"]) or d["decision"]),
                              "reason": c.get("reason")}
        return out

    def _complete(self, cite: Dict[str, Any], ids: Dict[str, Any], status: str, result: Any,
                  stub: bool) -> Dict[str, Any]:
        """Records the outcome of a call the signer let run, citing its result and, under `decision`, its decision.
        A stub (no tool ran) is recorded as an error, and a result the signer refuses (not JSON, over its quota) as
        the error "result not recordable", so the record never says a call that ran did not. A failure to record it
        warns and keeps the decision's citation."""
        from tracekit.sdk.client import SignerUnavailable
        from tracekit.signer.rpc_schema import RPCError
        run, tcid = self.rt._tk(self.name), cite["tool_call_id"]
        outcome = {"error": "not run: no tool registered"} if stub else {"result": result}
        try:
            try:
                seq = run.call("complete", tool_call_id=tcid, status="error" if stub else status, **ids,
                               **outcome)["run_seq"]
            except RPCError as e:
                if stub or e.code not in ("invalid_request", "quota_exceeded"):
                    raise
                outcome = {"error": f"result not recordable: {e.message}"[:4096]}
                seq = run.call("complete", tool_call_id=tcid, status="error", **ids, **outcome)["run_seq"]
        except (RPCError, SignerUnavailable) as e:
            warnings.warn(f"tracekit why: the signer did not record the outcome of {tcid}: {e}", stacklevel=3)
            return cite
        return dict(cite, run_seq=seq, type="tool.result", decision={k: cite[k] for k in ("run_id", "run_seq", "type")},
                    **({"error": outcome["error"]} if "error" in outcome else {}))

    def check(self, tool: str, args: Optional[dict] = None, *, decision: Optional[Ref] = None,
              sensitive: Optional[bool] = None) -> Any:
        """Ask the runtime's guard about a tool call your own code is about to execute (adapters use
        this). Returns a tracekit.why.guard.Check, or None when the runtime has no guard."""
        rt = self.rt
        if rt.guard is None:
            return None
        is_sensitive = bool(sensitive) if sensitive is not None else tool in rt.sensitive_tools
        return rt.guard.check(rt, self.name, tool, args or {}, decision, is_sensitive)

    def record_action(self, tool: str, args: Optional[dict], result: Any, *, decision: Optional[Ref] = None,
                      sensitive: Optional[bool] = None, duration_ms: Optional[float] = None,
                      status: Optional[str] = None, check: Any = None) -> Ref:
        """Record a tool call your own code executed (adapters use this). Pass the `check` you got
        from check() so the guard's verdict is stored with the action; a blocked check records the
        call as blocked. In a replay the call your code ran was real: it is recorded as live (an off-tape action),
        with a warning; run tools through act() (or TracedMessages.run_tool) for the tape to serve them."""
        rt = self.rt
        if rt.tape is not None or not rt.live_tools:
            warnings.warn(f"tracekit why: {tool} ran for real during a replay (your code ran it and recorded it with "
                          "record_action); run it through act() or TracedMessages.run_tool so replays serve it from "
                          "the tape", stacklevel=2)
        args_ref, res_ref = rt._blob(args or {}), rt._blob(result)
        blocked = check is not None and check.blocked
        if status is None:
            status = "blocked" if blocked else _status(result)
        extra = {"guard": check.record()} if check is not None and check.alerts else {}
        ev = rt._emit(self.name, "action", tool=tool, args_ref=args_ref, result_ref=res_ref,
                      decision=decision.event_id if decision else None, status=status,
                      mode="blocked" if blocked else "live",
                      sensitive=bool(sensitive) if sensitive is not None else tool in rt.sensitive_tools,
                      duration_ms=round(duration_ms, 3) if duration_ms is not None else None, **extra)
        if check is not None:
            check.notify(rt, ev)
        return Ref(res_ref, result, "result", self.name, tool, decision.trust if decision else "trusted", ev["id"])

    def send(self, to: str, content: Any, *, decision: Optional[Ref] = None) -> Ref:
        """Message another agent. Delivered refs carry the channel (from->to) so a channel
        can be ablated in replay (`msg:researcher->planner`)."""
        rt = self.rt
        value = content.value if isinstance(content, Ref) else content
        trust = content.trust if isinstance(content, Ref) else "trusted"
        if decision is None and isinstance(content, Ref) and content.kind == "output":
            decision = content
        ref = rt._blob(value)
        # the recipient's run observes what it was sent, naming the sender's run: the link between the agents' runs
        extra = {"tracekit": rt._observe(to, value, f"msg:{self.name}->{to} run:{rt._tk(self.name).run_id}", trust)} \
            if rt.signer is not None else {}
        with rt._lock:
            ev = rt._emit(self.name, "message", to=to, ref=ref, decision=decision.event_id if decision else None,
                          trust=trust, **extra)
            r = Ref(ref, value, "message", to, f"{self.name}->{to}", trust, ev["id"])
            rt._mail.setdefault(to, []).append(r)
        rt._ship()
        return r

    def inbox(self) -> List[Ref]:
        with self.rt._lock:
            return list(self.rt._mail.get(self.name, []))


def _cite(run: Any, run_seq: int, rtype: str) -> Dict[str, Any]:
    return {"run_id": run.run_id, "run_seq": run_seq, "type": rtype}


def _status(result: Any) -> str:
    """A tool result reads as an error when it is {"error": <something>}; {"error": None} is a success."""
    return "error" if isinstance(result, dict) and result.get("error") not in (None, "", False) else "ok"
