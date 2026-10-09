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
import hmac
import json
import queue
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future

from tracekit.core import now_ts
from tracekit.format.records import RecordError, verify_record
from tracekit.schema import V2
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.base import ZERO_HASH, StorageCorrupt

BATCH = 512
TAIL = 1024          # records whose signatures are checked on every open; `tracekit signer fsck` checks them all
RECOVER_S = 1.0
DONE_MAX = 100_000   # request_ids remembered for retries
SIGNER_RUN = ("tracekit", "tracekit/signer")   # signer-level records; "/" keeps it out of reach of client run_ids
LEAF_TYPES = {"run.registered": 1, "run.final": 2}   # records with a registry leaf, and the leaf's type byte
_MISSING = object()


def new_run(tenant, run_id):
    """`closed`: run.closing written, late records only; `final`: run.final written, nothing more. `active` and
    `closing_at` are monotonic times for the idle and grace clocks."""
    return {"tenant": tenant, "run_id": run_id, "run_seq": 0, "head": ZERO_HASH, "streams": {}, "closed": False,
            "final": False, "calls": {}, "decisions": {}, "denied": {}, "owner": None, "source": "sdk",
            "active": time.monotonic(), "closing_at": None}


def approval(tenant, run_id, data):
    """The signer's state for the approval an `approval.request` record (`data`) opened."""
    b = data["binding"]
    return {"run_key": (tenant, run_id), "tool_call_id": b["tool_call_id"], "attempt": b["attempt"], "tool": b["tool"],
            "args_source": b["args_source"], "decision_id": data["decision_id"], "commitment": b["args_commitment"],
            "rule_ids": data["rule_ids"], "policy_hash": data["policy_hash"], "requester": data["requester"],
            "expires_at": data["expires_at"], "binding_digest": data["binding_digest"], "state": "requested"}


APPROVAL_ENDS = {"approval.consumed": "consumed", "approval.expired": "expired"}


def subject(identity):
    return f"{identity.scheme}:{identity.subject}"


class Tx:
    """One batch: the records to append and an undo log covering every state change made while building them."""

    def __init__(self, log):
        self.log, self.records, self.undo = log, [], []

    def set(self, d, k, v):
        self.undo.append((d, k, d.get(k, _MISSING)))
        d[k] = v

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

    def emit(self, run, typ, data, source=None, **top):
        """Sign one event into `run` (source: the run's unless given); returns its run_seq."""
        log = self.log
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
        return e["run_seq"]

    def event(self, run, req, typ, data, **top):
        """A client event call: skipped client_seq values first become a signer-written gap."""
        stream, cseq = req["stream"], req["client_seq"]
        last = run["streams"].get(stream, -1)
        if cseq > last + 1:
            self.emit(run, "capture.gap", {"kind": "client_counter_gap", "missed_events": cseq - last - 1,
                                           "reason": f"stream {stream} skipped client_seq {last + 1}..{cseq - 1}"},
                      source="signer", stream=stream)
        self.set(run["streams"], stream, cseq)
        return self.emit(run, typ, data, request_id=req["request_id"], stream=stream, client_seq=cseq, **top)

    def closing(self, run, reason, **top):
        self.set(run, "closed", True)
        self.set(run, "closing_at", time.monotonic())
        return self.emit(run, "run.closing", {"reason": reason}, **top)

    def gap(self, kind, reason, **data):
        return self.emit(self.log.signer_run(self), "capture.gap", {"kind": kind, "reason": reason, **data},
                         source="signer")


class RecordLog:
    def __init__(self, storage, open_storage, sign, quotas, salt, metrics, bridge=None):
        """`storage` is open (and holds its lock); `open_storage()` reopens it after a disk error. `sign` is a
        format.records.RecordSigner; `salt` the secret the registry's per-tenant salts derive from; `metrics` a
        signer.metrics.SignerMetrics. `bridge`: the v1 ledger this log continues (signer.epoch `bridge`), refused
        unless the log is empty or already starts with it."""
        self.storage, self.open_storage, self.sign, self.quotas, self.salt = storage, open_storage, sign, quotas, salt
        self.metrics = metrics
        self.bridge = bridge
        self.log_id = None
        self.done = OrderedDict()   # (scheme, subject, request_id) -> (payload digest, response)
        self.refuse_writes = None   # a reason to answer client writes `unavailable`, e.g. an unacknowledged rollback
        self.down, self._last_try = None, 0.0
        self._replay()
        if bridge and self.head["seq"]:
            first = next(storage.iter_range(0, 1))["event"]
            if first["type"] != "signer.epoch" or first["data"].get("bridge") != bridge:
                raise ValueError("the v2 store already has records: the format bridge must be its first record")
        self._q = queue.SimpleQueue()
        self._writer = threading.Thread(target=self._loop, name="tracekit-signer-writer", daemon=True)
        self._writer.start()
        self.write(self._startup_records)

    # --- state from storage ---

    def _replay(self):
        """Rebuild the run state from the log, checking every chain link and the signatures of the last TAIL records,
        and append the registry leaves a crash or disk error left out."""
        s = self.storage
        tail = s.tail_state()
        size = tail["tree_size"]
        runs, prev, leaves, approvals, index = {}, ZERO_HASH, {}, {}, {}
        for r in s.iter_range(0, size):
            e = r["event"]
            run = runs.get((e["tenant"], e["run_id"]))
            if run is None:
                run = runs[(e["tenant"], e["run_id"])] = new_run(e["tenant"], e["run_id"])
            if (e["prev_hash"], e["run_seq"], e["run_prev_hash"]) != (prev, run["run_seq"], run["head"]):
                raise StorageCorrupt(f"seq {e['seq']} breaks the chain; run `tracekit signer fsck`")
            if e["seq"] >= size - TAIL:
                try:
                    verify_record(r, [self.sign.spki], {self.sign.alg})
                except RecordError as x:
                    raise StorageCorrupt(f"seq {e['seq']}: {x}; run `tracekit signer fsck`") from None
            self.log_id = self.log_id or e["log_id"]
            run["run_seq"], run["head"], prev = e["run_seq"] + 1, r["hash"], r["hash"]
            if "client_seq" in e:
                run["streams"][e["stream"]] = max(e["client_seq"], run["streams"].get(e["stream"], -1))
            if e["type"] in LEAF_TYPES:
                leaves.setdefault(e["tenant"], []).append(r)
            if e["type"] == "run.registered":
                run["owner"], run["source"] = "{scheme}:{subject}".format(**e["data"]["identity"]), e["source"]
            elif e["type"] == "run.closing":
                run["closed"], run["closing_at"] = True, time.monotonic()
            elif e["type"] == "run.final":
                run["final"] = True
            elif e["type"] == "policy.decision":
                d = e["data"]
                call = {"tool_call_id": e["tool_call_id"], "attempt": e.get("attempt", 0), "decision": d["decision"],
                        "rule_ids": d["rule_ids"], "decision_id": d.get("decision_id"),
                        "commitment": d.get("args_commitment")}
                run["calls"][e["tool_call_id"]] = call
                if call["decision_id"]:
                    run["decisions"][call["decision_id"]] = call
            elif e["type"] == "tool.result" and "decision_id" in e["data"]:
                run["decisions"][e["data"]["decision_id"]] = None
            elif e["type"] == "approval.request":
                a = approvals[e["data"]["approval_id"]] = approval(e["tenant"], e["run_id"], e["data"])
                index[(e["tenant"], e["run_id"], a["tool_call_id"], a["attempt"])] = e["data"]["approval_id"]
            elif e["type"] == "approval":
                approvals[e["data"]["approval_id"]]["state"] = ("approved" if e["data"]["decision"] == "approve"
                                                                 else "rejected")
            elif e["type"] in APPROVAL_ENDS:
                approvals[e["data"]["approval_id"]]["state"] = APPROVAL_ENDS[e["type"]]
        self.log_id = self.log_id or secrets.token_hex(16)
        self.runs, self.head = runs, {"seq": size, "prev": prev}
        self.approvals, self.approval_index = approvals, index   # approval_id -> state; (tenant, run, call, attempt) -> id
        for tenant, rs in leaves.items():
            for r in rs[tail["registry"].get(tenant, (0,))[0]:]:
                s.registry_append(tenant, self.leaf(r))

    def leaf(self, r):
        """The registry leaf of a lifecycle record (04-design §1.5):
        type u8 ‖ H(tenant_salt ‖ run_id) ‖ log_id 16B ‖ seq u64 ‖ record_hash."""
        e = r["event"]
        tenant_salt = hmac.new(self.salt, e["tenant"].encode("utf-8"), hashlib.sha256).digest()
        return (bytes([LEAF_TYPES[e["type"]]]) + hashlib.sha256(tenant_salt + e["run_id"].encode("utf-8")).digest()
                + bytes.fromhex(e["log_id"]) + e["seq"].to_bytes(8, "big") + bytes.fromhex(r["hash"][7:]))

    def _startup_records(self, tx):
        if self.head["seq"] == 0:
            key = {"kid": self.sign.kid, "alg": self.sign.alg, "spki": base64.b64encode(self.sign.spki).decode("ascii")}
            tx.emit(self.signer_run(tx), "signer.epoch", {"keys": [key], **({"bridge": self.bridge} if self.bridge else {})},
                    source="signer")
        for t in self.storage.torn:
            tx.gap("signer_unavailable", f"torn last line of {t['log']} set aside to {t['path']} "
                                         f"({t['length']} bytes at offset {t['offset']}): a write cut short")

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
            try:
                for r in tx.records:
                    if r["event"]["type"] in LEAF_TYPES:
                        self.storage.registry_append(r["event"]["tenant"], self.leaf(r))
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
        self._q.put(None)
        self._writer.join()
        self.storage.close()
