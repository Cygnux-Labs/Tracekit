"""The single writer of a record log (04-design §2.4, decision S1).

Handlers enqueue a function with a Future and wait. One writer thread drains up to BATCH queued items (no linger) and
runs each against the cached run state: the request_id check, lifecycle and client counters here, then the item's own
checks and writes. A refused item is rolled back through the batch's undo log, so it leaves no state anywhere. The
writer assigns seq/prev_hash and run_seq/run_prev_hash, signs with the cached key and hands the whole batch to one
storage `append_batch` (which also appends the Merkle leaves); with ack-on-write the storage syncs in the background.

When the storage refuses a write (EIO, ENOSPC) the whole batch is rolled back and answered `unavailable`. The next item
after RECOVER_S reopens the storage, rebuilds the run state from it and writes a signed `signer_unavailable` gap first.
"""
import base64
import copy
import hashlib
import json
import logging
import queue
import secrets
import threading
import time
import types
from collections import OrderedDict, deque
from concurrent.futures import Future

from tracekit.core import now_ts
from tracekit.format import registry
from tracekit.format.records import RecordError, RecordSigner, verify_record
from tracekit.schema import V2
from tracekit.signer import detect, reconcile
from tracekit.signer.detect import epoch
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.runtoken import subject
from tracekit.storage.base import ZERO_HASH, StorageCorrupt, registry_tree

BATCH = 512
TAIL = 1024          # records whose signatures are checked on every open; `tracekit signer fsck` checks them all
RECOVER_S = 1.0
DONE_MAX = 100_000   # request_ids remembered for retries
DONE_PER_IDENTITY = 10_000   # of them, at most this many per identity, so no caller evicts another's
SIGNER_RUN = ("tracekit", "tracekit/signer")   # signer-level records; "/" keeps it out of reach of client run_ids
# a tenant's signer records (content.accessed, content.erased) go in that tenant's run SIGNER_RUN[1]: never swept
EXPIRED = "the record key's certificate has expired and the issuer has not renewed it yet"
_MISSING = object()


def new_run(tenant, run_id):
    """`closed`: run.closing written, late records only; `final`: run.final written, nothing more. `active` and
    `closing_at` are monotonic times for the idle and grace clocks; `registered`, its run.registered's time (none in a
    snapshot before 1.4). `prov`: the provenance index of a run registered
    since this signer started (SignerService._index), memory only; None after a restart (unavailable). `writers`: who
    wrote each stream first (writer()), `tails`: the last client_seq a close_run said each stream ended at; both memory
    and snapshot only. `results`: tool_call_id -> [[decision_id, output hash, comparable, redacted, the form digest it
    matched or None], ...] of its tool.results (the newest RESULTS_PER_CALL: an id may be reused), which a gateway's
    tool result digests are checked against (SignerService._results_checked)."""
    return {"tenant": tenant, "run_id": run_id, "run_seq": 0, "head": ZERO_HASH, "streams": {}, "writers": {},
            "tails": {}, "closed": False, "results": {},
            "final": False, "calls": {}, "decisions": {}, "denied": {}, "states": {}, "owner": None, "source": "sdk",
            "principal": None, "people": (None, None), "harness": None, "active": time.monotonic(), "closing_at": None,
            "rec": reconcile.new(), "digests": {}, "prov": None, "replay": False}


# the streams: a gateway's close_run may still name one (SignerService._close_run); `replay`: a findings or replay run,
# which no findings or replay run may be about (SignerService._register_run)
FINAL_KEYS = ("tenant", "run_id", "run_seq", "head", "closed", "final", "owner", "source", "streams", "writers",
              "tails", "replay")
# a call as replay has it; `via`, `caller`: the gateway that decided it and the client it named (SignerService._hold)
CALL_KEYS = ("tool_call_id", "attempt", "decision", "rule_ids", "decision_id", "commitment", "nondeterministic",
             "detect_ids", "via", "caller")
TENANT_GAPS = ("witness_failed", "witness_late", "clock_skew", "degraded_unanchored")
RESULTS_PER_CALL = 8   # tool.results kept per tool_call_id for checking what a gateway saw sent (an id may be reused)
NO_RESULT = len(b"{}")   # a tool.result output's size when complete sent neither result nor error


def final_run(run):
    """What a final run keeps: enough to refuse late writes, check a token's run and answer its owner."""
    return {k: run[k] for k in FINAL_KEYS}


def _monotonic(t):
    """The monotonic time of wall-clock time `t` (never in the future)."""
    return time.monotonic() - max(0.0, time.time() - t)


def since(ts):
    """The monotonic time at which a record with wall-clock `ts` was written (never in the future)."""
    return _monotonic(epoch(ts))


def approval(tenant, run_id, data, ts):
    """The signer's state for the approval an `approval.request` record (`data`, written at `ts`) opened. `agent`: the
    record's agent eligibility; `escalated`: only people answer it now (`escalation`: by whom and why); an answer adds
    `answered` (by, kind) and `answer` (its self_approved and person, when the record has them); an agent's approval
    adds `kind` agent and the times it may be consumed between (`not_before`, `consume_by`)."""
    b = data["binding"]
    return {"run_key": (tenant, run_id), "tool_call_id": b["tool_call_id"], "attempt": b["attempt"], "tool": b["tool"],
            "args_source": b["args_source"], "decision_id": data["decision_id"], "commitment": b["args_commitment"],
            "rule_ids": data["rule_ids"], "policy_hash": data["policy_hash"], "requester": data["requester"],
            "expires_at": data["expires_at"], "binding_digest": data["binding_digest"], "state": "requested",
            "executor": data.get("executor", "t1"), "passkey": data.get("passkey", False),
            "requester_person": data.get("requester_person"), "label": salt_label({"type": "approval.request", "data": data}),
            "agent": data.get("agent"), "escalated": False, "requested_at": ts, "incident_id": data.get("incident_id")}


APPROVAL_ENDS = {"approval.consumed": "consumed", "approval.expired": "expired", "approval.abandoned": "expired",
                 "approval.revoked": "rejected"}


def person_only_keys(a):
    """The keys a call whose agent answer said no is a person's to answer by, in its run, from then on: the same tool
    with the same arguments (`args_key`), and the same tool call id in any attempt."""
    return [f"c:{a['tool']}:{a['tool_call_id']}"] + ([f"d:{a['tool']}:{a['agent']['args_key']}"]
                                                     if (a.get("agent") or {}).get("args_key") else [])


LOST = ": the signer never got those events, and an input observed or a tool's result in them is not in the index"


def last_seq(run, stream):
    """The last client_seq of `stream` the run has: recorded, or named by a close_run whose gap had the rest."""
    return max(run["streams"].get(stream, -1), run["tails"].get(stream, -1))


def skipped(run, req):
    """The client_counter_gap reason of client event `req` when it skips client_seq values of its stream, else None."""
    last = last_seq(run, req["stream"])
    if req["client_seq"] > last + 1:
        return f"stream {req['stream']} skipped client_seq {last + 1}..{req['client_seq'] - 1}"
    return None


def degrade(tx, prov, state, reason):
    """Set a run's provenance index `state` (partial, truncated) with its `reason`, unless it is degraded already."""
    if prov is not None and prov["state"] == "complete":
        tx.set(prov, "state", state)
        tx.set(prov, "reason", reason[:256])


def agent_state(set_, log, run, e):
    """Follow record `e` of `run` in the agent-approval state that budgets, review caps and the person-only set are
    counted from: `log.agent` {off: the kill switch, uses: approval id -> {requested, tenant, requester, rules,
    approved, spent}} and the run's `person_only` and `agent_reviews`. `set_(d, k, v)`: the writer's undoable set, or a
    plain one on replay. Called after the record's own state change."""
    typ, d = e["type"], e["data"]
    a = log.approvals.get(d.get("approval_id"))
    if typ == "approval.agents":
        set_(log.agent, "off", not d["enabled"])
    elif typ == "approval.request" and (d.get("agent") or {}).get("eligible"):
        set_(run, "agent_reviews", run.get("agent_reviews", 0) + 1)
        set_(log.agent["uses"], d["approval_id"], {"requested": epoch(e["ts"]), "tenant": e["tenant"],
                                                   "requester": d["requester"], "rules": d["agent"]["rules"],
                                                   "approved": None, "spent": {}})
    elif a is None:
        return
    elif typ == "approval" and d.get("approver_kind") == "agent" and d["decision"] == "approve":
        for k in ("not_before", "consume_by"):
            set_(a, k, d[k])
        set_(a, "kind", "agent")
        use = log.agent["uses"].get(d["approval_id"])
        if use is not None:
            set_(log.agent["uses"], d["approval_id"], dict(use, approved=epoch(e["ts"]), spent=d.get("spent", {})))
    elif typ == "approval.escalated":
        set_(a, "escalated", True)
        set_(a, "escalation", {k: d[k] for k in ("by", "reason") if k in d})
    if typ == "approval":   # who answered, for the bridges; and as whom, for a root grant (SignerService._pcm_grant)
        set_(a, "answered", {"by": d["approver"], "kind": d.get("approver_kind", "person")})
        set_(a, "answer", {k: d[k] for k in ("self_approved", "person") if k in d})
    if typ in ("approval.escalated", "approval.revoked") or typ == "approval" and d["decision"] != "approve":
        # anyone's reject sticks: a person's veto as much as an agent's
        set_(run, "person_only", {**run.get("person_only", {}), **{k: True for k in person_only_keys(a)}})


def new_contain():
    return {"incidents": {}, "cooldown": {}, "paused": {}, "enforcing": {}}


def cooldown_key(tenant, run):
    """Who a run's held successors are: its tenant, owner and attested principal (evasion: a new run inherits a hold)."""
    return f"{tenant}\0{run['owner']}\0{run['people'][1] or ''}"


def contain_state(set_, log, run, e, pop=lambda d, k: d.pop(k, None)):
    """Follow record `e` of `run` in the containment state (SignerService._respond), `log.contain`: each incident
    ({tenant, run_id, run_seq, ts, trigger, rule_ids, scope, mode, actions, state: open|resolved, runs: the runs it held
    or quarantined}), the holds new runs inherit by cooldown_key ({incident id: [until ts, held|quarantined]}, an
    incident leaving once resolved), the tenants whose response engine is paused and the suspension entries this signer
    enforces; and the run's `held` (the incident ids holding it, in order, or None), `quarantined` incident id and
    `quarantine_denies`. `set_`: as agent_state's."""
    c, typ, d = log.contain, e["type"], e["data"]
    inc = c["incidents"].get(d.get("incident_id"))
    if typ == "incident.opened":
        set_(c["incidents"], d["incident_id"], {"tenant": e["tenant"], "run_id": e["run_id"], "run_seq": e["run_seq"],
                                                "ts": e["ts"], "state": "open", "runs": [],
                                                **{k: d[k] for k in ("trigger", "rule_ids", "scope", "mode", "actions")}})
    elif typ in ("run.held", "run.quarantined"):
        kind = "held" if typ == "run.held" else "quarantined"
        if kind == "quarantined":
            set_(run, "quarantined", d["incident_id"])
            set_(run, "held", None)
        else:
            set_(run, "held", [*(run.get("held") or ()), d["incident_id"]])
        if inc is not None:
            set_(inc, "runs", inc["runs"] + [e["run_id"]])
        if d.get("inherit_until"):   # the key's expired holds go as a new one comes
            k = cooldown_key(e["tenant"], run)
            live = {i: x for i, x in (c["cooldown"].get(k) or {}).items() if x[0] > e["ts"]}
            set_(c["cooldown"], k, {**live, d["incident_id"]: [d["inherit_until"], kind]})
    elif typ == "run.resumed":
        set_(run, "held", [x for x in run.get("held") or () if x != d["incident_id"]] or None)
    elif typ == "incident.resolved" and inc is not None:
        set_(inc, "state", "resolved")
        for k, v in list(c["cooldown"].items()):
            if d["incident_id"] in v:
                rest = {i: x for i, x in v.items() if i != d["incident_id"] and x[0] > e["ts"]}
                set_(c["cooldown"], k, rest) if rest else pop(c["cooldown"], k)
    elif typ == "incident.response":
        set_(c["paused"], e["tenant"], not d["enabled"])
    elif typ == "identity.suspension":
        set_(c["enforcing"], f"{e['tenant']}\0{d['identity']}", d["state"] != "lifted")
    elif typ == "policy.decision" and "TK-QUARANTINE" in d["rule_ids"]:
        set_(run, "quarantine_denies", run.get("quarantine_denies", 0) + 1)


def salt_label(e):
    """What the salt of event `e`'s commitments is derived from; None when it has none. A record with a `salt_id` (one
    the signer chose for that record alone) uses it; records written before `salt_id` keep their old labels."""
    d = e["data"]
    if "salt_id" in d:
        return f"{e['type']}:{d['salt_id']}"
    if e["type"] in ("policy.decision", "approval.request", "approval.binding_mismatch"):
        return d.get("decision_id")
    if e["type"] == "tool.result":
        return "result:" + d["decision_id"]
    if e["type"] in ("model.exchange", "state.write"):
        return f"{e['type']}:{e['tenant']}:{e['run_id']}:{e['request_id']}"
    return None


def constraint_state(e):
    """A live constraint as a run's state keeps it (SignerService._constrained), from its constraint.added `e`:
    [kind, the salt label of its object's commitment, that commitment or None, its run_seq]."""
    return [e["data"]["kind"], salt_label(e), e["data"].get("object_commitment"), e["run_seq"]]


def writer(identity, req):
    """Who writes a stream: the caller, and whether through a gateway (a request with `caller`)."""
    return subject(identity) + (" through a gateway" if "caller" in req else "")


def owner(identity):
    """A run's owner as run.registered records it, so the signer answers the same after a restart."""
    # lean: identities whose first 256 subject characters agree count as one owner; record a digest of the full
    # subject in run.registered if such subjects appear
    return f"{identity.scheme}:{identity.subject[:256]}"


class Tx:
    """One batch: the records to append and an undo log covering every state change made while building them."""

    def __init__(self, log):
        self.log, self.records, self.undo = log, [], []

    def set(self, d, k, v):
        self.undo.append((d, k, d.get(k, _MISSING)))
        d[k] = v

    def pop(self, d, k):
        self.undo.append((d, k, d.pop(k)))

    def mark(self):
        return len(self.undo), len(self.records)

    def rollback(self, mark):
        while len(self.undo) > mark[0]:
            d, k, old = self.undo.pop()
            if old is _MISSING:
                del d[k]
            else:
                d[k] = old
        del self.records[mark[1]:]

    def new_run(self, tenant, run_id):
        run = new_run(tenant, run_id)
        self.set(self.log.runs, (tenant, run_id), run)
        if run_id != SIGNER_RUN[1]:
            self.set(self.log.live, (tenant, run_id), True)
        return run

    def emit(self, run, typ, data, source=None, digests=None, **top):
        """Sign one event into `run` (source: the run's unless given) and feed it to the run's reconcile index
        (`digests`: see reconcile.observe) and the detector, whose incident records follow it; returns its run_seq.
        Nothing follows log.closed."""
        log = self.log
        if log.head["closed"]:
            raise RPCError("unavailable", "the log is closed (log.closed): it takes no more records")
        if log.cert and time.time() >= log.cert["certificate"]["cert"]["not_after"]:   # epoch() sets a new cert first
            raise RPCError("unavailable", EXPIRED)
        if typ == "log.closed":
            self.set(log.head, "closed", True)
        e = {"schema_version": V2, "id": secrets.token_hex(16), "seq": log.head["seq"], "prev_hash": log.head["prev"],
             "ts": now_ts(), "run_id": run["run_id"], "agent_id": "main", "parent_id": None, "source": source or run["source"],
             "type": typ, "data": data, "tenant": run["tenant"], "log_id": log.log_id, "run_seq": run["run_seq"],
             "run_prev_hash": run["head"], **top}
        view, incidents = log.detector.observe(self, log.det, e) if log.detector else (None, ())
        if view is not None:
            e["data"] = {**data, "detect": view}
        r = log.sign(e)
        self.records.append(r)
        self.set(log.head, "seq", e["seq"] + 1)
        self.set(log.head, "prev", r["hash"])
        self.set(run, "run_seq", e["run_seq"] + 1)
        self.set(run, "head", r["hash"])
        if typ == "run.registered":
            self.set(run, "registered", e["ts"])
        found = reconcile.observe(self.set, run, e, digests, log.handoff)
        agent_state(self.set, log, run, e)
        contain_state(self.set, log, run, e, self.pop)
        for t, d in incidents:   # first, as detect.backtest feeds them; an enforced incident is the responder's to write
            if t == "incident.opened" and d["mode"] == "enforce" and log.respond:
                log.respond(self, run, e, d)
            else:
                self.emit(run, t, d, source="signer")
        if view is not None and view["state"] == "unavailable" and log.respond:
            log.respond(self, run, e, None)
        for kind, tcid, layers, detail in found:
            self.emit(run, "reconcile." + kind, {"layers": layers, "detail": detail}, source="signer", tool_call_id=tcid)
        return e["run_seq"]

    def event(self, run, req, typ, data, digests=None, **top):
        """A client event call: skipped client_seq values first become a signer-written gap, and make the run's
        provenance index partial."""
        stream, cseq, gap = req["stream"], req["client_seq"], skipped(run, req)
        if gap:
            self.emit(run, "capture.gap", {"kind": "client_counter_gap", "reason": gap,
                                           "missed_events": cseq - last_seq(run, stream) - 1},
                      source="signer", stream=stream)
            degrade(self, run.get("prov"), "partial", gap + LOST)
        self.set(run["streams"], stream, cseq)
        seq = self.emit(run, typ, data, digests=digests, request_id=req["request_id"], stream=stream, client_seq=cseq,
                        **top)
        self._overlap(run)
        return seq

    def _overlap(self, run):
        """concurrent_run: a run registered from a harness process while another of its owner's runs, in another
        session, was open there (SignerService._register_run) gets the gap once both have recorded an event since."""
        # lean: which runs overlap is memory and snapshot state; a restart with no snapshot since forgets it
        if run.get("overlap") and run["overlap"][1]:   # the newer run, and the older one has recorded an event
            self._concurrent(run, run["overlap"][0])
        for newer in run.get("overlapped_by", ()):   # the older run
            n = self.log.runs[(run["tenant"], newer)]
            if not n.get("overlap"):
                continue
            if n["streams"]:   # it recorded an event already
                self._concurrent(n, run["run_id"])
            else:
                self.set(n, "overlap", [run["run_id"], True])

    def _concurrent(self, run, other):
        self.set(run, "overlap", None)
        self.emit(run, "capture.gap", {
            "kind": "concurrent_run", "run_id": other,
            "reason": f"run {other} of the same owner and harness process, in another session, was open when this run "
                      "registered, and both recorded events since: one harness process drives one session at a time, "
                      "so one of the two may not be what it says. Read which of them the harness's transcripts "
                      "show; a sub-agent's run passes `parent`"}, source="signer")

    def closing(self, run, reason, **top):
        reason = "quarantine" if run.get("quarantined") else reason
        self.set(run, "closed", True)
        count = run.get("quota", run["owner"])   # a gateway's run for a client counts in their entry (_register_run)
        n = self.log.open_runs[count] - 1
        if n:
            self.set(self.log.open_runs, count, n)
        else:
            self.pop(self.log.open_runs, count)
        self.set(run, "closing_at", time.monotonic())
        return self.emit(run, "run.closing", {"reason": reason}, **top)

    def gap(self, kind, reason, **data):
        """A signer-level gap; one of TENANT_GAPS is marked `tenant_level` and gets a leaf in every tenant's registry."""
        if kind in TENANT_GAPS:
            data["tenant_level"] = True
        return self.emit(self.log.signer_run(self), "capture.gap", {"kind": kind, "reason": reason, **data},
                         source="signer")


class RecordLog:
    def __init__(self, storage, open_storage, sign, quotas, salt, metrics, bridge=None, certify=None, detector=None):
        """`storage` is open (and holds its lock); `open_storage()` reopens it after a disk error. `sign` is a
        format.records.RecordSigner; `salt` the secret the registry's per-tenant salts derive from; `metrics` a
        signer.metrics.SignerMetrics. `bridge`: the v1 ledger this log continues (signer.epoch `bridge`), refused
        unless the log is empty or already starts with it. `certify(log_id)` -> (RecordSigner, issuance entry): a
        fresh certified record key (tracekit.issuer.certify), taken instead of `sign` once the log is replayed; its
        signer.epoch retires the key before it. `detector`: a detect.Detector, or None when the policy detects nothing.
        `respond(tx, run, e, incident)`, set by the service: writes an enforced incident.opened that record `e` fired
        and acts on it, or (incident None) acts on a decision `e` whose detection state is unavailable."""
        self.detector, self.respond = detector, None
        self.storage, self.open_storage, self.sign, self.quotas, self.salt = storage, open_storage, sign, quotas, salt
        self.metrics = metrics
        self.observers = []   # f(records), called on the writer once storage has taken a batch: must not block
        self.bridge, self.certify, self.cert = bridge, certify, None
        self.log_id = None
        self.done = OrderedDict()   # (scheme, subject, request_id) -> (payload digest, response)
        self._done_by = {}   # (scheme, subject) -> deque of its keys in `done`, oldest first
        self.refuse_writes = None   # a reason to answer client writes `unavailable`, e.g. an unacknowledged rollback
        # run key -> [first, last, {method: count}] of writes refused because the run was final, until
        # SignerService.flush_refusals writes them as late_activity (memory only)
        self.late = {}
        self.handoff = lambda tool: False   # the policy's handoffs (SignerService sets it): see reconcile.observe
        self.down, self._last_try = None, 0.0
        self._replay()
        if bridge and self.head["seq"]:
            first = next(storage.iter_range(0, 1))["event"]
            if first["type"] != "signer.epoch" or first["data"].get("bridge") != bridge:
                raise ValueError("the v2 store already has records: the format bridge must be its first record")
        if certify:
            self.sign, self.cert = certify(self.log_id)
        self._q, self._closed, self._closing = queue.SimpleQueue(), False, threading.Lock()
        self._writer = threading.Thread(target=self._loop, name="tracekit-signer-writer", daemon=True)
        self._writer.start()
        self.write(self._startup_records)

    # --- state from storage ---

    def _state(self):
        """The run state as replay rebuilds it, as JSON: no deny sets, args digests or pending arguments; monotonic
        times as wall clock times."""
        wall, runs = time.time() - time.monotonic(), []
        for run in self.runs.values():
            r = {k: v for k, v in run.items() if k not in ("denied", "digests", "prov")}
            if "calls" in r:
                r["calls"] = {t: {k: c.get(k) for k in CALL_KEYS} for t, c in run["calls"].items()}
                r["decisions"] = {d: c and {k: c.get(k) for k in CALL_KEYS} for d, c in run["decisions"].items()}
            for k in ("active", "closing_at"):
                if r.get(k) is not None:
                    r[k] += wall
            runs.append(r)
        return {"log_id": self.log_id, "closed": self.head["closed"], "runs": runs, "tenants": sorted(self.tenants),
                "open_runs": self.open_runs, "approvals": self.approvals, "index": [[*k, a] for k, a in
                                                                                   self.approval_index.items()],
                "registry": {t: size for t, (size, _) in self.storage.tail_state()["registry"].items()},
                "keys": self.keys, "agent": self.agent, "contain": self.contain,
                **({"detect": self.det} if self.detector else {})}

    def snapshot(self):
        """Have the storage snapshot its indexes and the run state, unless a write is in flight or the storage is
        down (the next snapshot covers it)."""
        # lean: serialised and written on the writer, pausing writes for O(state); copy the state on the writer and
        # write it off it once snapshots take more than a few hundred ms
        def fn(tx):
            if not tx.records and not self.down:
                if self.detector:
                    self.detector.prune(self.det, time.time())
                self.storage.snapshot_put(self._state())
        self.write(fn)

    def _replay(self):
        """Rebuild the run state from the storage's snapshot and the log after it (the whole log without one), checking
        every chain link replayed, the snapshot's last record and the signatures of the last TAIL records, and append
        the registry leaves a crash or disk error left out."""
        s = self.storage
        tail = s.tail_state()
        size = tail["tree_size"]
        runs, prev, leaves, approvals, index, tenants, closed = {}, ZERO_HASH, {}, {}, {}, set(), False
        open_runs, by_run, start, base, keys = {}, {}, 0, {}, []   # owner -> runs not closing; run key -> its approval ids
        agent, contain = {"off": False, "uses": {}}, new_contain()
        policy = self.detector and self.detector.engine.policy_hash
        det = detect.new(policy)

        def spkis():   # the keys replayed records verify under: certified keys the log declared, else the file key
            return [base64.b64decode(k) for _, k in keys] if self.certify else [self.sign.spki]
        if s.snapshot:
            st, start, prev = s.snapshot["state"], s.snapshot["size"], s.snapshot["hash"]
            keys = st.get("keys", [])
            # a snapshot written without detection, or under another policy, can't say what came before it
            det = st.get("detect")
            if not det or det.get("policy") != policy:
                det = detect.new(policy, self.detector and time.time() + self.detector.window)
            try:
                verify_record(next(s.iter_range(start - 1, start)), spkis(), {RecordSigner.alg})
            except RecordError as x:
                raise StorageCorrupt(f"seq {start - 1}: {x}; run `tracekit signer fsck`") from None
            for r in st["runs"]:
                for k in ("active", "closing_at"):
                    if r.get(k) is not None:
                        r[k] = _monotonic(r[k])
                if "states" in r:
                    r["denied"], r["digests"], r["prov"] = {}, {}, None
                    r.setdefault("writers", {})   # a snapshot written before 1.2
                    r.setdefault("tails", {})
                    r.setdefault("results", {})   # before 1.3: results recorded since the snapshot are checked
                    r.setdefault("replay", False)   # before 1.4: set already in a findings or replay run's state
                runs[(r["tenant"], r["run_id"])] = r
            approvals = {aid: dict(a, run_key=tuple(a["run_key"])) for aid, a in st["approvals"].items()}
            agent, contain = st.get("agent", agent), st.get("contain", contain)
            index = {tuple(k[:4]): k[4] for k in st["index"]}
            for aid, a in approvals.items():
                by_run.setdefault(a["run_key"], []).append(aid)
            self.log_id, closed, tenants, open_runs, base = (st["log_id"], st["closed"], set(st["tenants"]),
                                                             st["open_runs"], st["registry"])
        for r in s.iter_range(start, size):
            e = r["event"]
            run = runs.get((e["tenant"], e["run_id"]))
            if run is None:
                run = runs[(e["tenant"], e["run_id"])] = new_run(e["tenant"], e["run_id"])
            if (e["prev_hash"], e["run_seq"], e["run_prev_hash"]) != (prev, run["run_seq"], run["head"]):
                raise StorageCorrupt(f"seq {e['seq']} breaks the chain; run `tracekit signer fsck`")
            if e["type"] == "signer.epoch":
                keys = keys + [[k["kid"], k["spki"]] for k in e["data"]["keys"]]
            if e["seq"] >= size - TAIL:
                try:
                    verify_record(r, spkis(), {RecordSigner.alg})
                except RecordError as x:
                    raise StorageCorrupt(f"seq {e['seq']}: {x}; run `tracekit signer fsck`") from None
            self.log_id = self.log_id or e["log_id"]
            run["run_seq"], run["head"], prev = e["run_seq"] + 1, r["hash"], r["hash"]
            if "client_seq" in e:
                run["streams"][e["stream"]] = max(e["client_seq"], run["streams"].get(e["stream"], -1))
            elif e["type"] == "capture.gap" and e["data"].get("kind") == "client_counter_gap" and "stream" in e:
                # what a gap already covers, so values still arriving after a restart are no second gap
                run["tails"][e["stream"]] = last_seq(run, e["stream"]) + e["data"].get("missed_events", 0)
            for tenant, leaf in self.leaves(r, tenants):
                leaves.setdefault(tenant, []).append(leaf)
            closed = closed or e["type"] == "log.closed"
            if self.detector:
                self.detector.observe(detect.Plain, det, e)
            if not run["final"]:
                run["active"] = since(e["ts"])
                reconcile.observe(dict.__setitem__, run, e)
            if "span_id" in e:   # an imported record: its span and type are written once per run
                run["spans"][f"{e['span_id']}:{e['type']}"] = True
            if e["type"] == "run.registered":
                run["owner"], run["source"] = "{scheme}:{subject}".format(**e["data"]["identity"]), e["source"]
                run["registered"] = e["ts"]
                run["principal"] = e.get("principal")
                run["people"] = (e["data"]["identity"].get("person"), e.get("principal") if e.get("principal_attested") else None)
                h = e["data"].get("harness")
                run["harness"] = (h["pid"], h["start_time"]) if h else None   # the process its owner's calls come from
                if "session" in e["data"]:
                    run["session"] = e["data"]["session"]
                if {"replay_of", "analyzes"} & e["data"].keys():
                    run["replay"] = True
                open_runs[run["owner"]] = open_runs.get(run["owner"], 0) + 1
                if e["source"] == "import":   # not reconciled: no layer gates or reports its calls
                    run["rec"], run["spans"] = None, {}
                    if "request_id" in e:   # an importer's over RPC (tracekit follow, not OTLP): watched for its beats
                        run["tailed"] = True
                elif "replay_of" in e["data"]:   # not reconciled: a tracekit why replay run has no decisions by design
                    run["rec"] = None
            elif e["type"] == "run.closing":
                run["closed"], run["closing_at"] = True, run["active"]
                open_runs[run.get("quota", run["owner"])] -= 1
            elif e["type"] == "run.final":
                run["final"] = True
                key = (e["tenant"], e["run_id"])
                runs[key] = final_run(run)
                for aid in by_run.pop(key, ()):
                    a = approvals.pop(aid)
                    del index[(*key, a["tool_call_id"], a["attempt"])]
            elif e["type"] == "policy.decision":
                d = e["data"]
                call = {"tool_call_id": e["tool_call_id"], "attempt": e.get("attempt", 0), "decision": d["decision"],
                        "rule_ids": d["rule_ids"], "decision_id": d.get("decision_id"),
                        "commitment": d.get("args_commitment"), "tool": d.get("tool"), "via": d.get("via"),
                        "caller": d.get("caller"), "nondeterministic": bool(d.get("nondeterministic")),
                        "detect_ids": d.get("detect", {}).get("rule_ids")}
                run["calls"][e["tool_call_id"]] = call
                if call["decision_id"]:
                    run["decisions"][call["decision_id"]] = call
            elif e["type"] == "state.write":
                run["states"][e["data"]["key"]] = (salt_label(e), e["data"]["digest"])
            elif e["type"] == "constraint.added":
                run["constraints"] = [*(run.get("constraints") or ()), constraint_state(e)]
            elif e["type"] == "capture.gap" and e["data"].get("kind") == "constraint_refused":
                run["constraints_full"] = True   # SignerService._constraint_add: every write is held
            elif e["type"] == "tool.result" and "decision_id" in e["data"]:
                d, out = e["data"], e["data"].get("output") or {}
                if out.get("hash") and e.get("tool_call_id"):
                    # lean: an ok result that also carried `error` counts as comparable after a restart (no shipped
                    # client sends both); record whether it is comparable in tool.result if one ever does
                    run["results"][e["tool_call_id"]] = run["results"].get(e["tool_call_id"], [])[1 - RESULTS_PER_CALL:] + [
                        [d["decision_id"], out["hash"], d.get("ok") is True and out.get("size") != NO_RESULT,
                         out.get("redacted") is True, None]]
                run["decisions"].pop(e["data"]["decision_id"], None)
                aid = index.get((e["tenant"], e["run_id"], e["tool_call_id"], e.get("attempt", 0)))
                if aid and approvals[aid]["state"] == "consumed":   # its approved call completed (Service._complete)
                    # lean: by call and attempt; the writer also checks the arguments against the approval's
                    run["decisions"].pop(approvals[aid]["decision_id"], None)
            elif e["type"] == "approval.request":
                a = approvals[e["data"]["approval_id"]] = approval(e["tenant"], e["run_id"], e["data"], e["ts"])
                index[(e["tenant"], e["run_id"], a["tool_call_id"], a["attempt"])] = e["data"]["approval_id"]
                by_run.setdefault(a["run_key"], []).append(e["data"]["approval_id"])
            elif e["type"] == "approval":
                approvals[e["data"]["approval_id"]]["state"] = ("approved" if e["data"]["decision"] == "approve"
                                                                 else "rejected")
            elif e["type"] in APPROVAL_ENDS:
                approvals[e["data"]["approval_id"]]["state"] = APPROVAL_ENDS[e["type"]]
            if not run["final"]:
                agent_state(dict.__setitem__, types.SimpleNamespace(approvals=approvals, agent=agent), run, e)
                contain_state(dict.__setitem__, types.SimpleNamespace(contain=contain), run, e)
        self.log_id = self.log_id or secrets.token_hex(16)
        self.agent, self.contain = agent, contain
        self.runs, self.head, self.tenants, self.keys = runs, {"seq": size, "prev": prev, "closed": closed}, tenants, keys
        for (tenant, run_id), r in runs.items():   # open runs a fresh detection state never saw registered
            k = f"{tenant}\0{run_id}"
            if self.detector and not r["final"] and r["owner"] and k not in det["runs"]:
                det["runs"][k] = detect.run_entry(r.get("session", run_id), r["owner"], r["people"][1])
        self.det = det
        # lean: final runs stay in `runs` as final_run stubs, so tokens, run_exists and late writes answer from memory;
        # look them up in storage instead once a signer holds millions of runs
        self.live = {k: True for k, r in runs.items() if not r["final"] and k[1] != SIGNER_RUN[1]}   # the runs sweep visits
        self.approvals, self.approval_index = approvals, index   # approval_id -> state; (tenant, run, call, attempt) -> id
        self.open_runs = {k: n for k, n in open_runs.items() if n}
        keep, missing = {}, {}   # keep: past it, leaves of records a power loss lost (none under a note); set aside
        for tenant in sorted(set(leaves) | set(tail["registry"])):
            ls, stored = leaves.get(tenant, []), list(s.registry_iter(tenant, base.get(tenant, 0)))
            n, note = base.get(tenant, 0) + len(ls), s.checkpoint_latest(registry_tree(tenant))
            if (len(stored) > len(ls) and stored[:len(ls)] == ls and (note is None or note[0] <= n)
                    and all(registry.parse(x)[3] >= size for x in stored[len(ls):])):
                keep[tenant] = n
            elif stored != ls[:len(stored)]:
                raise StorageCorrupt(f"the registry log of tenant {tenant[:64]!r} holds leaves its records do not give")
            missing[tenant] = ls[len(stored):]
        if keep:
            s.registry_set_aside(keep)
        for tenant, ls in missing.items():
            for leaf in ls:
                s.registry_append(tenant, leaf)

    def tenant_salt(self, tenant):
        return registry.tenant_salt(self.salt, tenant)

    def leaf(self, r, tenant=None):
        """The registry leaf of a lifecycle record (format.registry) in `tenant`'s registry (default: its own)."""
        return registry.leaf(r, self.tenant_salt(tenant or r["event"]["tenant"]))

    def leaves(self, r, tenants):
        """[(tenant, leaf)] of record `r`: none, its tenant's (added to `tenants`, the tenants with a registry), or
        for a signer-level record (a gap or tamper record only when marked `tenant_level`) one in every registry. A gap
        in a tenant's signer run (late_activity) is in that tenant's registry only."""
        typ, tenant = r["event"]["type"], r["event"]["tenant"]
        if typ == "capture.gap" and r["event"]["run_id"] == SIGNER_RUN[1] and tenant != SIGNER_RUN[0]:
            tenants.add(tenant)
            return [(tenant, self.leaf(r))]
        if typ in registry.GAP_LEAVES and not r["event"]["data"].get("tenant_level"):
            return []
        if typ in registry.SIGNER_LEAVES:
            return [(t, self.leaf(r, t)) for t in sorted(tenants)]
        if typ not in registry.LEAF_TYPES:
            return []
        tenants.add(tenant)
        return [(tenant, self.leaf(r))]

    def _startup_records(self, tx):
        if self.head["seq"] == 0 or self.cert and self.keys[-1][0] != self.sign.kid:
            self.epoch(tx, self.sign, self.cert)
        for t in self.storage.torn:
            tx.gap("signer_unavailable", f"torn last line of {t['log']} set aside to {t['path']} "
                                         f"({t['length']} bytes at offset {t['offset']}): a write cut short")

    def epoch(self, tx, sign, cert=None):
        """signer.epoch declaring `sign`'s key (with `cert`, its issuance entry) and signed by it, then key.retire of
        the key declared before it, whose last record is the one before the epoch."""
        last, key = self.head["seq"] - 1, {"kid": sign.kid, "alg": sign.alg,
                                           "spki": base64.b64encode(sign.spki).decode("ascii")}
        tx.set(vars(self), "sign", sign)
        tx.set(vars(self), "cert", cert)
        tx.emit(self.signer_run(tx), "signer.epoch", {"keys": [{**key, **({"cert": cert} if cert else {})}],
                                                      **({"bridge": self.bridge} if self.bridge else {})},
                source="signer")
        if self.keys:
            tx.emit(self.signer_run(tx), "key.retire", {"kid": self.keys[-1][0], "last_seq": last}, source="signer")
        tx.set(vars(self), "keys", self.keys + [[key["kid"], key["spki"]]])

    def signer_run(self, tx, tenant=SIGNER_RUN[0]):
        """The signer-level run, or with `tenant` that tenant's signer run."""
        return self.runs.get((tenant, SIGNER_RUN[1])) or tx.new_run(tenant, SIGNER_RUN[1])

    # --- handlers ---

    def submit(self, identity, method, req, fn, run_key=None, late=False):
        """Run `fn(tx, run)` for a client request on the writer and return its response; refusals raise RPCError.
        `late`: also accepted while the run is closing (a late record), not only while it is open."""
        if self.refuse_writes:
            raise RPCError("unavailable", self.refuse_writes)
        digest = hashlib.sha256(json.dumps([method, req], sort_keys=True, default=repr).encode()).hexdigest()
        start = time.monotonic()
        out = self._wait(lambda tx: self._item(tx, identity, method, req, digest, fn, run_key, late))
        self.metrics.ack_seconds.observe(time.monotonic() - start)
        return out

    def write(self, fn):
        """Run `fn(tx)` on the writer: the signer's own records, which no refuse_writes holds back."""
        return self._wait(fn)

    def _wait(self, fn):
        fut = Future()
        with self._closing:   # nothing is queued behind close()'s None, which the writer never reads past
            if self._closed:
                raise RPCError("unavailable", "the signer is shutting down")
            self._q.put((fn, fut))
        return fut.result()

    def _item(self, tx, identity, method, req, digest, fn, run_key, late):
        rid = (identity.scheme, identity.subject, req["request_id"]) if "request_id" in req else None
        if rid in self.done:
            if self.done[rid][0] != digest:
                raise RPCError("conflict", f"request_id {rid[2]} was used with another payload")
            return copy.deepcopy(self.done[rid][1])
        run = None
        if run_key is not None:
            run = self.runs.get(run_key)
            if run is None:
                raise RPCError("unknown_run", run_key[1])
            if run["final"] and method != "close_run":
                # a client learns from its first write after run.final that its run ended (the idle timeout) and moves
                # to a new run: each identity's and stream's first one is not counted (up to streams_per_run of them)
                seen = run.setdefault("late_from", {})
                who = f"{identity.scheme}:{identity.subject}/{req.get('stream', '')}"
                if who in seen or len(seen) >= self.quotas.limits.streams_per_run:
                    now = time.time()
                    first, _, by = self.late.get(run_key) or (now, now, {})
                    self.late[run_key] = [first, now, {**by, method: by.get(method, 0) + 1}]
                else:
                    seen[who] = True
            if run["final"] or (run["closed"] and not late):
                raise RPCError("run_closed", run_key[1])
            tx.set(run, "active", time.monotonic())
            if "client_seq" in req:
                last = run["streams"].get(req["stream"])
                if last is None:
                    self.quotas.check_count("streams_per_run", len(run["streams"]))
                    if req["stream"] not in run["writers"]:
                        tx.set(run["writers"], req["stream"], writer(identity, req))
                elif req["client_seq"] <= last:
                    raise RPCError("client_seq_reused", f"{req['stream']}/{req['client_seq']}")
        try:
            out = fn(tx, run)
        except RPCError as e:
            if run is not None and "client_seq" in req:
                stream, cseq = req["stream"], req["client_seq"]
                if cseq == max(run["streams"].get(stream, -1), run["tails"].get(stream, -1)) + 1:
                    # the signer saw this value and refused it (the refusal is its record): not a gap at close. Only
                    # the next value: one that skipped others leaves them to a later client_counter_gap.
                    # lean: kept in the run's state and snapshots, not in a record: a replay from records forgets it;
                    # record it if restarts without a snapshot become common
                    e.keep = lambda t: t.set(run["tails"], stream, cseq)
            raise
        if rid is not None:
            tx.set(self.done, rid, (digest, copy.deepcopy(out)))
        return out

    # --- the writer thread ---

    def _loop(self):
        while True:
            batch = [self._q.get()]
            if batch[0] is None:
                return
            while len(batch) < BATCH:
                try:
                    item = self._q.get_nowait()
                except queue.Empty:
                    break
                if item is None:
                    self._q.put(None)
                    break
                batch.append(item)
            if self.down and not self._recover():
                for _, fut in batch:
                    fut.set_exception(self._unavailable())
                continue
            self._commit(batch)

    def _unavailable(self):
        return RPCError("unavailable", f"storage refused writes since {self.down[0]}: {self.down[1]}",
                        retry_after_ms=int(RECOVER_S * 1000))

    def queue_depth(self):
        return self._q.qsize()

    def _commit(self, batch):
        self.metrics.batch_size.observe(len(batch))
        tx, done = Tx(self), []
        for fn, fut in batch:
            mark = tx.mark()
            try:
                done.append((fut, fn(tx)))
            except Exception as e:   # a refusal, or a bug in one handler: either way the item leaves nothing
                tx.rollback(mark)
                if hasattr(e, "keep"):   # but what a refusal says the signer saw (_item)
                    e.keep(tx)
                fut.set_exception(e)
        if tx.records:
            try:
                self.storage.append_batch(tx.records)
            except Exception as e:   # StorageUnavailable, or anything else that leaves the disk state unknown
                tx.rollback((0, 0))
                self.down, self._last_try = (now_ts(), str(e) or type(e).__name__), time.monotonic()
                for fut, _ in done:
                    fut.set_exception(self._unavailable())
                return
            self.metrics.written(tx.records)
            for f in self.observers:   # the records are written: an observer's failure must not touch them or the writer
                try:
                    f(tx.records)
                except Exception:
                    logging.getLogger(__name__).exception("tracekit signer: an observer of written records failed")
            try:
                for r in tx.records:
                    for tenant, leaf in self.leaves(r, self.tenants):
                        self.storage.registry_append(tenant, leaf)
            except Exception as e:   # the records are written; the recovery's replay appends the missing leaves
                self.down, self._last_try = (now_ts(), str(e) or type(e).__name__), time.monotonic()
        for d, rid, _ in tx.undo:   # the request_ids this batch answered, oldest first
            if d is self.done:
                mine = self._done_by.setdefault(rid[:2], deque())
                mine.append(rid)
                if len(mine) > DONE_PER_IDENTITY:
                    del self.done[mine.popleft()]
        while len(self.done) > DONE_MAX:   # the oldest entry overall is also the oldest of its identity
            rid, _ = self.done.popitem(last=False)
            mine = self._done_by[rid[:2]]
            mine.popleft()
            if not mine:
                del self._done_by[rid[:2]]
        for fut, out in done:
            fut.set_result(out)

    def _recover(self):
        """Reopen the storage and rebuild the run state from it; the first record written is the outage's gap."""
        if time.monotonic() - self._last_try < RECOVER_S:
            return False
        self._last_try = time.monotonic()
        try:
            self.storage.close()
        except Exception:
            pass
        # the provenance indexes live in memory only: the replay can't rebuild them, and nothing in them was lost
        prov = {k: r["prov"] for k, r in self.runs.items() if r.get("prov") is not None}
        try:
            self.storage = self.open_storage()
            self._replay()
        except Exception:
            return False
        for k, p in prov.items():
            if k in self.runs and not self.runs[k]["final"]:
                self.runs[k]["prov"] = p
        since, err = self.down
        self.down = None
        fut = Future()
        self._commit([(lambda tx: (tx.gap("signer_unavailable", f"storage refused writes: {err}", from_ts=since,
                                          to_ts=now_ts()), self._startup_records(tx)), fut)])
        return self.down is None

    def close(self):
        with self._closing:
            self._closed = True
            self._q.put(None)
        self._writer.join()
        self.storage.close()
