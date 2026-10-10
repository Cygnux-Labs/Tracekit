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
import datetime
import hashlib
import json
import logging
import queue
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future

from tracekit.core import now_ts
from tracekit.format import registry
from tracekit.format.records import RecordError, RecordSigner, verify_record
from tracekit.schema import V2
from tracekit.signer import reconcile
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.base import ZERO_HASH, StorageCorrupt

BATCH = 512
TAIL = 1024          # records whose signatures are checked on every open; `tracekit signer fsck` checks them all
RECOVER_S = 1.0
DONE_MAX = 100_000   # request_ids remembered for retries
SIGNER_RUN = ("tracekit", "tracekit/signer")   # signer-level records; "/" keeps it out of reach of client run_ids
_MISSING = object()


def new_run(tenant, run_id):
    """`closed`: run.closing written, late records only; `final`: run.final written, nothing more. `active` and
    `closing_at` are monotonic times for the idle and grace clocks."""
    return {"tenant": tenant, "run_id": run_id, "run_seq": 0, "head": ZERO_HASH, "streams": {}, "closed": False,
            "final": False, "calls": {}, "decisions": {}, "denied": {}, "states": {}, "owner": None, "source": "sdk",
            "principal": None, "people": (None, None), "harness": None, "active": time.monotonic(), "closing_at": None,
            "rec": reconcile.new(), "digests": {}}


FINAL_KEYS = ("tenant", "run_id", "run_seq", "head", "closed", "final", "owner", "source")
CALL_KEYS = ("tool_call_id", "attempt", "decision", "rule_ids", "decision_id", "commitment")   # a call as replay has it
TENANT_GAPS = ("witness_failed", "witness_late", "clock_skew", "degraded_unanchored")


def final_run(run):
    """What a final run keeps: enough to refuse late writes, check a token's run and answer its owner."""
    return {k: run[k] for k in FINAL_KEYS}


def _monotonic(t):
    """The monotonic time of wall-clock time `t` (never in the future)."""
    return time.monotonic() - max(0.0, time.time() - t)


def since(ts):
    """The monotonic time at which a record with wall-clock `ts` was written (never in the future)."""
    return _monotonic(datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())


def approval(tenant, run_id, data):
    """The signer's state for the approval an `approval.request` record (`data`) opened."""
    b = data["binding"]
    return {"run_key": (tenant, run_id), "tool_call_id": b["tool_call_id"], "attempt": b["attempt"], "tool": b["tool"],
            "args_source": b["args_source"], "decision_id": data["decision_id"], "commitment": b["args_commitment"],
            "rule_ids": data["rule_ids"], "policy_hash": data["policy_hash"], "requester": data["requester"],
            "expires_at": data["expires_at"], "binding_digest": data["binding_digest"], "state": "requested",
            "executor": data.get("executor", "t1"),
            "requester_person": data.get("requester_person"), "label": salt_label({"type": "approval.request", "data": data})}


APPROVAL_ENDS = {"approval.consumed": "consumed", "approval.expired": "expired", "approval.abandoned": "expired"}


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


def subject(identity):
    return f"{identity.scheme}:{identity.subject}"


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
        return run

    def emit(self, run, typ, data, source=None, digests=None, **top):
        """Sign one event into `run` (source: the run's unless given) and feed it to the run's reconcile index
        (`digests`: see reconcile.observe); returns its run_seq. Nothing follows log.closed."""
        log = self.log
        if log.head["closed"]:
            raise RPCError("unavailable", "the log is closed (log.closed): it takes no more records")
        if typ == "log.closed":
            self.set(log.head, "closed", True)
        e = {"schema_version": V2, "id": secrets.token_hex(16), "seq": log.head["seq"], "prev_hash": log.head["prev"],
             "ts": now_ts(), "run_id": run["run_id"], "agent_id": "main", "parent_id": None, "source": source or run["source"],
             "type": typ, "data": data, "tenant": run["tenant"], "log_id": log.log_id, "run_seq": run["run_seq"],
             "run_prev_hash": run["head"], **top}
        r = log.sign(e)
        self.records.append(r)
        self.set(log.head, "seq", e["seq"] + 1)
        self.set(log.head, "prev", r["hash"])
        self.set(run, "run_seq", e["run_seq"] + 1)
        self.set(run, "head", r["hash"])
        reconcile.observe(self.set, run, e, digests)
        return e["run_seq"]

    def event(self, run, req, typ, data, digests=None, **top):
        """A client event call: skipped client_seq values first become a signer-written gap."""
        stream, cseq = req["stream"], req["client_seq"]
        last = run["streams"].get(stream, -1)
        if cseq > last + 1:
            self.emit(run, "capture.gap", {"kind": "client_counter_gap", "missed_events": cseq - last - 1,
                                           "reason": f"stream {stream} skipped client_seq {last + 1}..{cseq - 1}"},
                      source="signer", stream=stream)
        self.set(run["streams"], stream, cseq)
        return self.emit(run, typ, data, digests=digests, request_id=req["request_id"], stream=stream, client_seq=cseq,
                         **top)

    def closing(self, run, reason, **top):
        self.set(run, "closed", True)
        n = self.log.open_runs[run["owner"]] - 1
        if n:
            self.set(self.log.open_runs, run["owner"], n)
        else:
            self.pop(self.log.open_runs, run["owner"])
        self.set(run, "closing_at", time.monotonic())
        return self.emit(run, "run.closing", {"reason": reason}, **top)

    def gap(self, kind, reason, **data):
        """A signer-level gap; one of TENANT_GAPS is marked `tenant_level` and gets a leaf in every tenant's registry."""
        if kind in TENANT_GAPS:
            data["tenant_level"] = True
        return self.emit(self.log.signer_run(self), "capture.gap", {"kind": kind, "reason": reason, **data},
                         source="signer")


class RecordLog:
    def __init__(self, storage, open_storage, sign, quotas, salt, metrics, bridge=None, certify=None):
        """`storage` is open (and holds its lock); `open_storage()` reopens it after a disk error. `sign` is a
        format.records.RecordSigner; `salt` the secret the registry's per-tenant salts derive from; `metrics` a
        signer.metrics.SignerMetrics. `bridge`: the v1 ledger this log continues (signer.epoch `bridge`), refused
        unless the log is empty or already starts with it. `certify(log_id)` -> (RecordSigner, issuance entry): a
        fresh certified record key (tracekit.issuer.certify), taken instead of `sign` once the log is replayed; its
        signer.epoch retires the key before it."""
        self.storage, self.open_storage, self.sign, self.quotas, self.salt = storage, open_storage, sign, quotas, salt
        self.metrics = metrics
        self.observers = []   # f(records), called on the writer once storage has taken a batch: must not block
        self.bridge, self.certify, self.cert = bridge, certify, None
        self.log_id = None
        self.done = OrderedDict()   # (scheme, subject, request_id) -> (payload digest, response)
        self.refuse_writes = None   # a reason to answer client writes `unavailable`, e.g. an unacknowledged rollback
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
            r = {k: v for k, v in run.items() if k not in ("denied", "digests")}
            if "calls" in r:
                r["calls"] = {t: {k: c[k] for k in CALL_KEYS} for t, c in run["calls"].items()}
                r["decisions"] = {d: c and {k: c[k] for k in CALL_KEYS} for d, c in run["decisions"].items()}
            for k in ("active", "closing_at"):
                if r.get(k) is not None:
                    r[k] += wall
            runs.append(r)
        return {"log_id": self.log_id, "closed": self.head["closed"], "runs": runs, "tenants": sorted(self.tenants),
                "open_runs": self.open_runs, "approvals": self.approvals, "index": [[*k, a] for k, a in
                                                                                   self.approval_index.items()],
                "registry": {t: size for t, (size, _) in self.storage.tail_state()["registry"].items()},
                "keys": self.keys}

    def snapshot(self):
        """Have the storage snapshot its indexes and the run state, unless a write is in flight or the storage is
        down (the next snapshot covers it)."""
        # lean: serialised and written on the writer, pausing writes for O(state); copy the state on the writer and
        # write it off it once snapshots take more than a few hundred ms
        def fn(tx):
            if not tx.records and not self.down:
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

        def spkis():   # the keys replayed records verify under: certified keys the log declared, else the file key
            return [base64.b64decode(k) for _, k in keys] if self.certify else [self.sign.spki]
        if s.snapshot:
            st, start, prev = s.snapshot["state"], s.snapshot["size"], s.snapshot["hash"]
            keys = st.get("keys", [])
            try:
                verify_record(next(s.iter_range(start - 1, start)), spkis(), {RecordSigner.alg})
            except RecordError as x:
                raise StorageCorrupt(f"seq {start - 1}: {x}; run `tracekit signer fsck`") from None
            for r in st["runs"]:
                for k in ("active", "closing_at"):
                    if r.get(k) is not None:
                        r[k] = _monotonic(r[k])
                if "states" in r:
                    r["denied"], r["digests"] = {}, {}
                runs[(r["tenant"], r["run_id"])] = r
            approvals = {aid: dict(a, run_key=tuple(a["run_key"])) for aid, a in st["approvals"].items()}
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
            for tenant, leaf in self.leaves(r, tenants):
                leaves.setdefault(tenant, []).append(leaf)
            closed = closed or e["type"] == "log.closed"
            if not run["final"]:
                run["active"] = since(e["ts"])
                reconcile.observe(dict.__setitem__, run, e)
            if "span_id" in e:   # an imported record: its span and type are written once per run
                run["spans"][f"{e['span_id']}:{e['type']}"] = True
            if e["type"] == "run.registered":
                run["owner"], run["source"] = "{scheme}:{subject}".format(**e["data"]["identity"]), e["source"]
                run["principal"] = e.get("principal")
                run["people"] = (e["data"]["identity"].get("person"), e.get("principal") if e.get("principal_attested") else None)
                h = e["data"].get("harness")
                run["harness"] = (h["pid"], h["start_time"]) if h else None   # the process its owner's calls come from
                open_runs[run["owner"]] = open_runs.get(run["owner"], 0) + 1
                if e["source"] == "import":   # not reconciled: no layer gates or reports its calls
                    run["rec"], run["spans"] = None, {}
            elif e["type"] == "run.closing":
                run["closed"], run["closing_at"] = True, run["active"]
                open_runs[run["owner"]] -= 1
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
                        "commitment": d.get("args_commitment")}
                run["calls"][e["tool_call_id"]] = call
                if call["decision_id"]:
                    run["decisions"][call["decision_id"]] = call
            elif e["type"] == "state.write":
                run["states"][e["data"]["key"]] = (salt_label(e), e["data"]["digest"])
            elif e["type"] == "tool.result" and "decision_id" in e["data"]:
                run["decisions"][e["data"]["decision_id"]] = None
            elif e["type"] == "approval.request":
                a = approvals[e["data"]["approval_id"]] = approval(e["tenant"], e["run_id"], e["data"])
                index[(e["tenant"], e["run_id"], a["tool_call_id"], a["attempt"])] = e["data"]["approval_id"]
                by_run.setdefault(a["run_key"], []).append(e["data"]["approval_id"])
            elif e["type"] == "approval":
                approvals[e["data"]["approval_id"]]["state"] = ("approved" if e["data"]["decision"] == "approve"
                                                                 else "rejected")
            elif e["type"] in APPROVAL_ENDS:
                approvals[e["data"]["approval_id"]]["state"] = APPROVAL_ENDS[e["type"]]
        self.log_id = self.log_id or secrets.token_hex(16)
        self.runs, self.head, self.tenants, self.keys = runs, {"seq": size, "prev": prev, "closed": closed}, tenants, keys
        self.approvals, self.approval_index = approvals, index   # approval_id -> state; (tenant, run, call, attempt) -> id
        self.open_runs = {k: n for k, n in open_runs.items() if n}
        for tenant in sorted(set(leaves) | set(tail["registry"])):
            ls, stored = leaves.get(tenant, []), list(s.registry_iter(tenant, base.get(tenant, 0)))
            if stored != ls[:len(stored)]:
                raise StorageCorrupt(f"the registry log of tenant {tenant[:64]!r} holds leaves its records do not give")
            for leaf in ls[len(stored):]:
                s.registry_append(tenant, leaf)

    def tenant_salt(self, tenant):
        return registry.tenant_salt(self.salt, tenant)

    def leaf(self, r, tenant=None):
        """The registry leaf of a lifecycle record (format.registry) in `tenant`'s registry (default: its own)."""
        return registry.leaf(r, self.tenant_salt(tenant or r["event"]["tenant"]))

    def leaves(self, r, tenants):
        """[(tenant, leaf)] of record `r`: none, its tenant's (added to `tenants`, the tenants with a registry), or
        for a signer-level record (a gap or tamper record only when marked `tenant_level`) one in every registry."""
        typ, tenant = r["event"]["type"], r["event"]["tenant"]
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

    def signer_run(self, tx):
        return self.runs.get(SIGNER_RUN) or tx.new_run(*SIGNER_RUN)

    # --- handlers ---

    def submit(self, identity, method, req, fn, run_key=None, late=False):
        """Run `fn(tx, run)` for a client request on the writer and return its response; refusals raise RPCError.
        `late`: also accepted while the run is closing (a late record), not only while it is open."""
        if self.refuse_writes:
            raise RPCError("unavailable", self.refuse_writes)
        digest = hashlib.sha256(json.dumps([method, req], sort_keys=True, default=repr).encode()).hexdigest()
        start = time.monotonic()
        out = self._wait(lambda tx: self._item(tx, identity, req, digest, fn, run_key, late))
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

    def _item(self, tx, identity, req, digest, fn, run_key, late):
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
            if run["final"] or (run["closed"] and not late):
                raise RPCError("run_closed", run_key[1])
            tx.set(run, "active", time.monotonic())
            if "client_seq" in req:
                last = run["streams"].get(req["stream"])
                if last is None:
                    self.quotas.check_count("streams_per_run", len(run["streams"]))
                elif req["client_seq"] <= last:
                    raise RPCError("client_seq_reused", f"{req['stream']}/{req['client_seq']}")
        out = fn(tx, run)
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
        while len(self.done) > DONE_MAX:
            self.done.popitem(last=False)
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
        try:
            self.storage = self.open_storage()
            self._replay()
        except Exception:
            return False
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
