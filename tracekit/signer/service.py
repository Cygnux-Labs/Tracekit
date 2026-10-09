"""The v2 signer service: `SignerService` implements `SignerAPI` over the record log's single writer (pipeline.py).

    tracekit signer serve --config signer.yaml
    tracekit signer serve --dev               # the same-user dev signer clients auto-spawn (decision S3)
    tracekit signer fsck  --config signer.yaml
    tracekit signer vkey  [--dev | --config signer.yaml]               # the log's verifier key
    tracekit signer trust [--dev | --config signer.yaml] -o trust.json  # a v2 trust config pinning it, no witnesses
    tracekit signer reveal --record SEQ [--dev | --config signer.yaml]  # the salt of one record's commitments

signer.yaml:
    data_dir: /var/lib/tracekit-signer      # keys/ and store/; relative paths are from the config file
    socket: /run/tracekit/signer.sock        # Unix socket transport (peer uid, per frame on Linux)
    tcp_endpoint: /run/tracekit/endpoint.json   # loopback TCP dev transport (token, mutual HMAC)
    http: {listen: 0.0.0.0:8443, ...}        # HTTPS with k8s_sa, mtls or token identity (tracekit/transport/http.py)
    durability: ack-on-write                 # or ack-on-fsync
    tenant: default                          # tenant of callers not in `tenants`
    tenants: {"uid:1001": acme, "k8s_sa:system:serviceaccount:acme:*": acme}   # identity or prefix* -> tenant (attested)
    authorize: {"mtls:spiffe://acme/agent": [register_run, decide, complete, close_run]}   # identity or prefix* ->
                                             # methods; uid callers default to all, every other scheme to none
    multi_tenant_apps: ["uid:1002"]          # may assert a tenant per run (recorded as not attested)
    migrators: ["uid:1003"]                  # may register `migrated` runs
    analyzers: ["uid:1004"]                  # may register findings runs, each bound to the run it analyses
    fail_modes: {default: closed, read: open}   # tool class -> fail mode, recorded and returned by register_run
    grace_s: 5                               # reconciliation window between run.closing and run.final
    idle_s: 3600                             # a run without calls for this long is closed
    limits: {events_per_s: 200, burst: 400}  # tracekit.signer.quotas.Limits
    policy: /etc/tracekit/policy.yaml        # policy v2 (YAML or JSON); default tracekit/policy2/packs/dev.yaml
    origin: tracekit.example.org/log/1       # checkpoint origin, the log key's name; default tracekit.local/<log_id>
    metrics: {listen: 127.0.0.1:9464}        # Prometheus GET /metrics on its own port (tracekit.signer.metrics)
    acknowledge_rollback: false

Startup (04-design §2.6): the storage lock is taken before any socket is touched; the log is replayed, its chain
checked and its tail signatures verified; then the configured witnesses are asked for their latest cosigned checkpoint.
A witness is any object with `latest() -> (tree_size, root_bytes)` that raises when unreachable. A local log behind the
witnessed one is a rollback: a signed `trace.tamper{rollback}`, then client writes are refused until it is
acknowledged. No witness reachable: a signed `degraded_unanchored` gap, and the signer runs.

Run lifecycle (04-design §2.7): run.registered → events → close_run or the idle timeout (paused while an approval is
pending) → run.closing → grace window, where only late records (complete, state_write, model_event) are accepted →
run.final{head}. run.registered and run.final also get a leaf in the tenant's registry log. Gap and tamper records are
written by the signer only: no request can carry an event type, source, isolation or fail mode.

Checkpoints (04-design §1.6, §2.9): a C2SP note of the record tree, signed by the log key (keys/log.key, Ed25519, named
after the origin, signs notes only) and stored through the storage, after a run.final, on `checkpoint_nudge` (at most
one note per CHECKPOINT_MIN_S), every CHECKPOINT_S while the tree grows, and on close. The log key's vkey is written to
<data_dir>/log.vkey on start. Notes are signed off the writer thread; the writer only reads the tree head.


Policy (04-design §4): the signer classifies the tool and decides with policy2; every decide gets a fresh decision_id
that one `complete` with the same arguments consumes. Only deny and ask are memoised, per (tool_call_id, attempt).

Approvals (04-design §5, decision S6): one per (tenant, run, tool_call_id, attempt), under a random id. The
approval.request record binds it to the call (binding_digest); `approval_consume` lets the call run once, only with the
approved arguments, and records every refusal. Approvals and the index are rebuilt from the log on start; the
signer's copy of a pending call's arguments (what the approver is shown) is kept encrypted under keys/approval_args.key
and deleted once the approval is consumed, rejected or expired. An approval expires after APPROVAL_TTL_S, or when its
run ends. Dev stubs: any identity of the run's tenant may answer an approval, and a self-approval is labelled
(`self_approved`).

Privacy (04-design §1.2, §2.4; docs/privacy.md): a result and the approver's copy of the arguments go through
privacy.redact before they are committed or stored; a result's record carries a `redaction` manifest (the rules that
fired, never the values). A client may say it redacted already; the signer redacts again regardless and flags a secret
it still finds. Every published digest of agent content is an HMAC under a per-record salt derived from
keys/args_salt.key (`salt_label`), which `reveal` prints for one record. Policy decides on the unredacted arguments.
"""
import argparse
import collections
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import sys
import threading
import time

import rfc8785
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tracekit import __version__, crypto, privacy, yamlmini
from tracekit.deploy import files
from tracekit.format import checkpoint
from tracekit.format.canon import StrictJSONError, canonical, event_hash, loads_strict
from tracekit.format.records import RecordError, RecordSigner, verify_record
from tracekit.identity.base import CallerIdentity
from tracekit.locking import lock_file
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.signer import metrics, rpc_schema
from tracekit.signer.pipeline import SIGNER_RUN, RecordLog, approval, subject
from tracekit.signer.quotas import Limits, Quotas
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.signer.runtoken import RunTokens
from tracekit.storage.base import ACK_ON_WRITE, StorageUnavailable
from tracekit.storage.file import FileStorage, _mkdir
from tracekit.storage.file import fsck as fsck_store
from tracekit.transport import answering_hello, hello

DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy2", "packs", "dev.yaml")
APPROVAL_TTL_S = 3600
DECISION_TTL_S = 300
REFUSAL_WINDOW_S = 60
STRICTNESS = ("allow", "flag", "ask", "deny")
LIVE = ("requested", "approved")   # approval states that may still lead to a consume
LIST_MAX = 1000
TICK_S = 1.0
CHECKPOINT_S, CHECKPOINT_MIN_S = 10.0, 1.0
GRACE_S, IDLE_S = 5.0, 3600.0
FAIL_MODES = {"default": "closed"}
CONFIG_KEYS = {"data_dir", "socket", "tcp_endpoint", "http", "durability", "tenant", "tenants", "authorize", "limits",
               "acknowledge_rollback", "policy", "multi_tenant_apps", "migrators", "analyzers", "fail_modes", "grace_s",
               "idle_s", "origin", "metrics"}
DEV_GRANT = {"token:dev": sorted(REQUESTS)}   # the dev token of the loopback TCP transport (scoped by DevToken itself)


def load_policy(path=DEFAULT_POLICY, backend=None):
    """The policy2 Engine for a policy file; ValueError lists every lint error."""
    pol, errors = policy_compile.build(path)
    if errors:
        raise ValueError("; ".join(errors))
    return Engine(pol, backend)


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


MARK = re.compile(r"\[REDACTED:([a-z_]+)\]")


def _salt(key, label):
    return hmac.new(key, label.encode(), "sha256").digest()


def salt_label(e):
    """What the salt of event `e`'s commitments is derived from; None when it has none."""
    d = e["data"]
    if e["type"] in ("policy.decision", "approval.request", "approval.binding_mismatch"):
        return d.get("decision_id")
    if e["type"] == "tool.result":
        return "result:" + d["decision_id"]
    if e["type"] in ("model.exchange", "state.write"):
        return f"{e['type']}:{e['tenant']}:{e['run_id']}:{e['request_id']}"
    return None


def _redact(value, dotenv, claim=None):
    """(`value` through privacy.redact, its manifest). `claim`: the client's manifest when it says it redacted."""
    before = collections.Counter(MARK.findall(canonical(value).decode()))
    out = privacy.redact(value, dotenv)[0]
    fired = collections.Counter(MARK.findall(canonical(out).decode())) - before
    manifest = {"rules": sorted(fired), "count": sum(fired.values()), "client_claimed": claim is not None}
    if claim is not None:
        manifest["client"] = claim
        if fired:
            manifest["client_redaction_incomplete"] = True
    return out, manifest


def _dotenv(args):
    """Whether a call touched a .env path, as v1 decides it: from the fields that say which action ran."""
    return isinstance(args, dict) and privacy.mentions_dotenv(*(args.get(k) for k in privacy.ACTION_FIELDS))


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _secret(path, make):
    """The secret in `path`, created (0600) on first use. Called under the storage lock, so never by two signers."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        pass
    data = make()
    _write_new(path, data)
    return data


def lookup(table, sub, default=None):
    """table[sub], else the entry of the longest `prefix*` key that `sub` starts with, else `default`."""
    if sub in table:
        return table[sub]
    # lean: scans every key per call; a prefix trie if maps grow past a few hundred entries
    best = max((k for k in table if k.endswith("*") and sub.startswith(k[:-1])), key=len, default=None)
    return default if best is None else table[best]


def _process_identity():
    return CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)


class SignerService:
    def __init__(self, data_dir, policy=None, identity=None, tenant="default", tenants=None, limits=Limits(),
                 durability=ACK_ON_WRITE, witnesses=(), acknowledge_rollback=False, open_storage=None, isolation=None,
                 multi_tenant_apps=(), migrators=(), analyzers=(), fail_modes=None, grace_s=GRACE_S, idle_s=IDLE_S,
                 bridge=None, origin=None, authorize=None):
        """`identity` answers the in-process SignerAPI calls (default: this process's uid); transports call
        handle_frame with the identity they established. `policy` is a policy2 Engine (default: load_policy()).
        `open_storage()` defaults to file storage in data_dir/store. `origin` names the log in its checkpoints.
        `multi_tenant_apps`, `migrators` and `analyzers` are identities ("scheme:subject"); `tenants` and `authorize`
        map identities or `prefix*` to a tenant and to the methods they may call.
        `isolation` fixes the signer_isolation label of every run (a dev signer: same-user). `bridge`: see RecordLog."""
        fail_modes = dict(fail_modes or FAIL_MODES)
        if not all(isinstance(k, str) and v in ("open", "closed") for k, v in fail_modes.items()):
            raise ValueError("fail_modes maps tool classes to open or closed")
        self.metrics = metrics.SignerMetrics()
        authorize = dict(authorize or {})
        if not all(isinstance(m, list) and set(m) <= set(REQUESTS) for m in authorize.values()):
            raise ValueError(f"authorize maps identities to lists of methods out of {sorted(REQUESTS)}")
        open_storage = open_storage or (lambda: FileStorage(os.path.join(data_dir, "store"), durability,
                                                            self.metrics.fsync_seconds.observe))
        storage = open_storage()   # takes the storage lock before anything else
        try:
            keys = os.path.join(data_dir, "keys")
            _mkdir(keys)
            os.chmod(keys, 0o700)
            sign = RecordSigner(_secret(os.path.join(keys, "record.key"), lambda: crypto.generate()[0]))
            self.tokens = RunTokens(_secret(os.path.join(keys, "run_token.key"), lambda: os.urandom(32)))
            self._salt_key = _secret(os.path.join(keys, "args_salt.key"), lambda: os.urandom(32))
            self._args_key = AESGCM(_secret(os.path.join(keys, "approval_args.key"), lambda: os.urandom(32)))
            self.quotas = Quotas(limits)
            salt = _secret(os.path.join(keys, "registry_salt.key"), lambda: os.urandom(32))
            self._log_key = _secret(os.path.join(keys, "log.key"), lambda: crypto.generate()[0])
            self.log = RecordLog(storage, open_storage, sign, self.quotas, salt, self.metrics, bridge)
        except BaseException:
            storage.close()
            raise
        self.policy, self.isolation = policy or load_policy(), isolation
        self.identity = identity or _process_identity()
        self.tenant, self.tenants, self.authorize = tenant, dict(tenants or {}), authorize
        self.multi_tenant_apps, self.migrators, self.analyzers = set(multi_tenant_apps), set(migrators), set(analyzers)
        self.fail_modes, self.grace_s, self.idle_s = fail_modes, grace_s, idle_s
        self._swept = self._noted = time.monotonic()
        self._args_dir = os.path.join(data_dir, "approvals")   # approval_id -> the encrypted args of a live approval
        self._cond = threading.Condition()
        self._refusals, self._refusals_lock = {}, threading.Lock()
        self._stop, self._nudged = threading.Event(), threading.Event()
        self.origin = origin or f"tracekit.local/{self.log.log_id}"
        try:
            self.vkey = checkpoint.vkey(self.origin, checkpoint.ED25519, crypto.public_from_secret(self._log_key))
            d = files.open_dir(data_dir)
            try:
                files.write(d, "log.vkey", (self.vkey + "\n").encode("ascii"), 0o644)
            finally:
                files.close(d)
            _mkdir(self._args_dir)
            os.chmod(self._args_dir, 0o700)
            for aid in os.listdir(self._args_dir):   # left by a crash, or by an approval_request that was rolled back
                if self.log.approvals.get(aid, {}).get("state") not in LIVE:
                    self._drop_args(aid)
            self._check_witnesses(witnesses, acknowledge_rollback)
        except BaseException:
            self.log.close()
            raise
        for name, help, fn in (
                ("tracekit_signer_queue_depth", "Items waiting for the writer.", self.log.queue_depth),
                ("tracekit_signer_fsync_lag_seconds", "Seconds the oldest written but unsynced record has waited.",
                 lambda: self.log.storage.unsynced_s()),
                ("tracekit_signer_open_runs", "Runs registered and not yet closing.",
                 lambda: sum(not r["closed"] for k, r in list(self.log.runs.items()) if k != SIGNER_RUN)),
                ("tracekit_signer_pending_approvals", "Approvals requested and not yet answered.",
                 lambda: sum(a["state"] == "requested" for a in list(self.log.approvals.values()))),
                ("tracekit_signer_checkpoint_age_seconds", "Seconds since this signer last wrote a checkpoint note "
                 "(since start when it has written none).", lambda: time.monotonic() - self._noted)):
            self.metrics.add(metrics.Gauge(name, help, fn))
        self._ticker = threading.Thread(target=self._tick_loop, name="tracekit-signer-ticker", daemon=True)
        self._ticker.start()
        self._checkpointer = threading.Thread(target=self._checkpoint_loop, name="tracekit-signer-checkpointer",
                                              daemon=True)
        self._checkpointer.start()

    def _check_witnesses(self, witnesses, acknowledged):
        if not witnesses:
            return
        heads = []
        for w in witnesses:
            try:
                heads.append(w.latest())
            except Exception:   # unreachable or unreadable: counted as no answer
                pass
        if not heads:
            self.log.write(lambda tx: tx.gap("degraded_unanchored", "no configured witness answered at startup"))
            return
        size, root = max(heads)
        local = self.log.storage.tail_state()
        if local["tree_size"] >= size:
            return
        self.log.write(lambda tx: tx.emit(self.log.signer_run(tx), "trace.tamper", {
            "path": "records", "kind": "rollback",
            "before": {"length": size, "hash": "sha256:" + root.hex()},
            "after": {"length": local["tree_size"], "hash": "sha256:" + local["tree_root"].hex()}}, source="signer"))
        if not acknowledged:
            self.log.refuse_writes = (f"the local log ({local['tree_size']} records) is behind the witnessed checkpoint "
                                      f"({size}): rolled back; restart with acknowledge_rollback once investigated")

    # --- dispatch ---

    def handle_frame(self, identity, frame):
        req = dict(frame)
        return self.call(identity, req.pop("method", None), req)

    def call(self, identity, method, req):
        try:
            if not isinstance(method, str) or method not in REQUESTS:
                raise RPCError("invalid_request", f"unknown method {str(method)[:64]}")
            granted = lookup(self.authorize, subject(identity))
            if granted is None:   # unconfigured: a uid keeps every method, any other scheme gets none
                granted = REQUESTS if identity.scheme == "uid" else ()
            if method not in granted:
                raise RPCError("forbidden", f"{subject(identity)[:256]} is not authorized for {method}")
            errs = rpc_schema.validate(REQUESTS[method], req)
            if errs:
                raise RPCError("invalid_request", "; ".join(errs))
            self.quotas.check_strings(req)
            return getattr(self, "_" + method)(identity, req)
        except RPCError as e:
            self.metrics.refusals.inc(e.code)
            now, k = time.time(), (identity.scheme, identity.subject, e.code)
            with self._refusals_lock:
                first, _, n = self._refusals.get(k, (now, now, 0))
                self._refusals[k] = (first, now, n + 1)
            raise

    def _tick_loop(self):
        flushed = time.monotonic()
        while not self._stop.wait(TICK_S):
            try:
                self.sweep()
            except RPCError:   # storage down: the next tick retries
                pass
            if time.monotonic() - flushed >= REFUSAL_WINDOW_S:
                flushed = time.monotonic()
                self.flush_refusals()

    def _checkpoint_loop(self):
        """A note after each nudge (a run.final nudges too), at most one per CHECKPOINT_MIN_S, and every CHECKPOINT_S."""
        while True:
            self._nudged.wait(CHECKPOINT_S)
            if self._stop.is_set():   # close() writes the last note
                return
            self._nudged.clear()
            try:
                self.checkpoint()
            except (RPCError, StorageUnavailable, OSError):   # storage down: the next round retries
                pass
            self._stop.wait(CHECKPOINT_MIN_S)

    def checkpoint(self):
        """Sign and store a note of the record tree when it grew since the latest stored one."""
        def head(tx):
            t = self.log.storage.tree
            return t.size, t.root()
        size, root = self.log.write(head)
        latest = self.log.storage.checkpoint_latest()
        if size and (latest is None or size > latest[0]):
            text = checkpoint.body(self.origin, size, root)
            self.log.storage.checkpoint_put(size, text + "\n" + checkpoint.sign(text, self.origin, self._log_key))
            self.metrics.checkpoints.inc()
            self._noted = time.monotonic()

    def sweep(self, now=None, wall=None):
        """Close idle runs, write run.final for runs whose grace window has passed and expire approvals.
        `now`: a monotonic time; `wall`: a time.time() for approval expiry."""
        finals = []

        def fn(tx):
            t = time.monotonic() if now is None else now
            paused = max(0.0, t - self._swept)
            self._swept = max(self._swept, t)
            expired, live, deadline = [], {}, _iso(time.time() if wall is None else wall)
            # lean: visits every approval and run on each tick; keep deadline heaps once a signer holds ~100k of them
            for aid, a in self.log.approvals.items():
                if a["state"] in LIVE:
                    live.setdefault(a["run_key"], []).append(aid)

            def expire(run, aids):
                for aid in aids:
                    tx.set(self.log.approvals[aid], "state", "expired")
                    tx.emit(run, "approval.expired", {"approval_id": aid}, source="signer")
                    expired.append(aid)
            for key, run in self.log.runs.items():
                if key == SIGNER_RUN or run["final"]:
                    continue
                if run["closed"] and t - run["closing_at"] >= self.grace_s:
                    expire(run, live.get(key, ()))   # nothing can consume them once the run is final
                    tx.set(run, "final", True)
                    tx.emit(run, "run.final", {"head_run_seq": run["run_seq"] - 1, "head_hash": run["head"]},
                            source="signer")
                    finals.append(key)
                    continue
                expire(run, [aid for aid in live.get(key, ()) if self.log.approvals[aid]["expires_at"] <= deadline])
                if run["closed"]:
                    continue
                if any(self.log.approvals[aid]["state"] == "requested" for aid in live.get(key, ())):
                    tx.set(run, "active", run["active"] + paused)   # the idle clock pauses while an approval is pending
                elif t - run["active"] >= self.idle_s:
                    tx.closing(run, "idle_timeout", source="signer")
            return expired
        expired = self.log.write(fn)
        if finals:
            self._nudged.set()
        for aid in expired:
            self._drop_args(aid)
        if expired:
            with self._cond:
                self._cond.notify_all()

    def flush_refusals(self):
        """Write the refusals counted since the last flush as `refusal.summary` records, one per identity and code."""
        with self._refusals_lock:
            counted, self._refusals = self._refusals, {}
        if not counted:
            return

        def write(tx):
            run = self.log.signer_run(tx)
            for (scheme, subj, code), (first, last, n) in counted.items():
                tx.emit(run, "refusal.summary", {"code": code, "count": n, "from_ts": _iso(first), "to_ts": _iso(last),
                                                 "identity": f"{scheme}:{subj}"[:256]}, source="signer")
        try:
            self.log.write(write)
        except RPCError:   # storage down: keep the counts for the next flush
            with self._refusals_lock:
                for k, (first, last, n) in counted.items():
                    f2, l2, n2 = self._refusals.get(k, (first, last, 0))
                    self._refusals[k] = (min(first, f2), max(last, l2), n + n2)

    def close(self):
        if self._stop.is_set():
            return
        self._stop.set()
        self._nudged.set()
        self._ticker.join()
        self._checkpointer.join()
        self.flush_refusals()
        try:
            self.checkpoint()
        except (RPCError, StorageUnavailable, OSError):   # storage down: the next start's notes cover these records
            pass
        self.log.close()

    # --- helpers ---

    def _authorize(self, identity, req):
        """The (tenant, run_id) of a per-run call, after checking its capability token."""
        tenant = self.tokens.claims(req["run_token"])["tenant"]
        key = (tenant, req["run_id"])
        if key not in self.log.runs:
            raise RPCError("unknown_run", req["run_id"])
        self.tokens.verify(req["run_token"], tenant, req["run_id"], identity)
        return key

    def _approval(self, key, approval_id):
        a = self.log.approvals.get(approval_id)
        if a is None or a["run_key"] != key:
            raise RPCError("unknown_approval", approval_id)
        return a

    def _may_see(self, identity, a):
        """Whether `identity` may see and answer approval `a`: the run's owner, or an identity of the run's tenant."""
        sub = subject(identity)
        return sub == self.log.runs[a["run_key"]]["owner"] or a["run_key"][0] == lookup(self.tenants, sub, self.tenant)

    def _visible(self, identity, approval_id):
        a = self.log.approvals.get(approval_id)
        if a is None or not self._may_see(identity, a):
            raise RPCError("unknown_approval", approval_id)
        return a

    @staticmethod
    def _summary(approval_id, a):
        return {"approval_id": approval_id, "state": a["state"], "run_id": a["run_key"][1],
                **{k: a[k] for k in ("tool_call_id", "attempt", "tool", "rule_ids", "policy_hash", "requester",
                                     "expires_at")}}

    def _seal(self, approval_id, value):
        nonce = os.urandom(12)
        return nonce + self._args_key.encrypt(nonce, canonical(value), approval_id.encode())

    def _unseal(self, approval_id):
        """The signer's copy of an approval's arguments ({"args_source", "args", "reason"?}), None once deleted."""
        try:
            with open(os.path.join(self._args_dir, approval_id), "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return None
        try:
            return loads_strict(self._args_key.decrypt(blob[:12], blob[12:], approval_id.encode()))
        except InvalidTag:
            raise RPCError("unavailable", f"the stored arguments of {approval_id} do not decrypt") from None

    def _drop_args(self, approval_id):
        try:
            os.unlink(os.path.join(self._args_dir, approval_id))
        except FileNotFoundError:
            pass

    @staticmethod
    def _args(req):
        """(the arguments, their digest sha256(JCS({tool, args}))), or (None, None) when they are not canonical JSON."""
        try:
            args = loads_strict(req["args"]) if req["args_source"] == "raw" else req["args"]
            return args, event_hash({"tool": req["tool"], "args": args})
        except (StrictJSONError, rfc8785.CanonicalizationError):
            return None, None

    def _commit(self, label, digest):
        """A published commitment: HMAC of `digest` under the salt of `label` (a record's salt_label), which the signer
        can reveal to an auditor for that one record."""
        return "hmac-sha256:" + hmac.new(_salt(self._salt_key, label), digest.encode(), "sha256").hexdigest()

    def _same(self, call, digest):
        """Whether `digest` is the args digest the decision (or approval) `call` was made for."""
        return bool(call["commitment"] and digest) and hmac.compare_digest(call["commitment"],
                                                                            self._commit(call["decision_id"], digest))

    def _evaluate(self, tool, args, hint):
        """(policy decision, hint disagreed). A class hint that disagrees with the policy's class gets the stricter of
        the two decisions."""
        d = self.policy.decide(tool, args)
        if hint is None or hint == self.policy.tool_class(tool):
            return d, False
        h = self.policy.decide(tool, args, hint if hint in policy_compile.CLASSES else "unknown")
        return max(d, h, key=lambda x: STRICTNESS.index(x["verdict"])), True

    @staticmethod
    def _isolation(identity):
        if identity.scheme == "uid" and hasattr(os, "getuid"):
            return "same-user" if identity.subject == str(os.getuid()) else "separate-user"
        return "unknown"

    # --- methods ---

    def _register_run(self, identity, req):
        sub = subject(identity)
        for field, allowed in (("tenant", self.multi_tenant_apps), ("source", self.migrators),
                               ("analyzes", self.analyzers)):
            if field in req and sub not in allowed:
                raise RPCError("forbidden", f"{sub[:256]} is not configured to register runs with `{field}`")
        tenant = req.get("tenant") or lookup(self.tenants, sub, self.tenant)
        run_id = req.get("run_id") or secrets.token_hex(16)

        def fn(tx, _):
            if (tenant, run_id) in self.log.runs:
                raise RPCError("run_exists", run_id)
            if "analyzes" in req and (tenant, req["analyzes"]) not in self.log.runs:
                raise RPCError("unknown_run", req["analyzes"])
            # lean: counts by scanning every run, O(runs); keep a per-owner counter when runs reach the thousands
            self.quotas.check_count("open_runs", sum(r["owner"] == sub and not r["closed"]
                                                     for r in self.log.runs.values()))
            run = tx.new_run(tenant, run_id)
            tx.set(run, "owner", sub)
            tx.set(run, "source", req.get("source", "sdk"))
            out = {"run_id": run_id, "run_token": self.tokens.issue(tenant, run_id, identity), "tenant": tenant,
                   "tenant_attested": "tenant" not in req, "principal_attested": False, "fail_modes": self.fail_modes}
            top = {"tenant_attested": out["tenant_attested"], "principal_attested": False}
            if "principal" in req:
                out["principal"] = top["principal"] = req["principal"]
            data = {"agent": req["agent"], "signer_isolation": self.isolation or self._isolation(identity), "fail_modes": self.fail_modes,
                    "identity": {"scheme": identity.scheme, "subject": identity.subject[:256],
                                 "attested": identity.attested}}
            if "analyzes" in req:
                data["analyzes"] = req["analyzes"]
            tx.emit(run, "run.registered", data, request_id=req["request_id"], **top)
            return out
        return self.log.submit(identity, "register_run", req, fn)

    def _decide(self, identity, req):
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)
        tool, tcid, attempt, hint = req["tool"], req["tool_call_id"], req.get("attempt", 0), req.get("tool_class_hint")
        args, digest = self._args(req)
        # matched here, off the writer thread; the writer picks a memoised deny/ask or this result
        ruled = self._evaluate(tool, args, hint) if digest else None
        did = "dec-" + secrets.token_hex(16)
        commitment = self._commit(did, digest) if digest else None
        # lean: expires_at is signed but `complete` does not enforce it; enforce once executors check it before running
        expires_at = _iso(time.time() + DECISION_TTL_S)

        def fn(tx, run):
            memo, gaps = run["calls"].get(tcid), []
            data = {"tool_use_id": tcid, "tool": tool, "decision_id": did, "policy_hash": self.policy.policy_hash,
                    "engine": self.policy.engine, "nonce": secrets.token_hex(16), "expires_at": expires_at}
            if digest is None:
                verdict, rule_ids = "deny", ["TK-ARGS-INVALID"]
            elif memo and memo["attempt"] == attempt and memo["decision"] in ("deny", "ask") and self._same(memo, digest):
                verdict, rule_ids = memo["decision"], memo["rule_ids"]
            else:
                d, mismatch = ruled
                verdict, rule_ids = d["verdict"], d["rule_ids"]
                if d.get("nondeterministic"):
                    data["nondeterministic"] = True
                if mismatch:
                    gaps.append(("class_mismatch", f"class hint {hint!r} disagrees with the policy's class "
                                                   f"{self.policy.tool_class(tool)!r}; the stricter decision applies"))
                # lean: the deny set lives in memory, so a flip across a signer restart goes unflagged
                if verdict == "deny":
                    tx.set(run["denied"], digest, True)
                elif verdict != "ask" and digest in run["denied"]:
                    gaps.append(("decision_flip", f"{verdict} after a deny for the same arguments in this run"))
            if commitment:
                data["args_commitment"] = commitment
            call = {"tool_call_id": tcid, "attempt": attempt, "decision": verdict, "rule_ids": rule_ids,
                    "decision_id": did, "commitment": commitment, "dotenv": _dotenv(args)}
            if verdict == "ask":   # the signer's copy, for the approval request (memory only: decide again after a restart)
                call["pending"] = {"tool": tool, "args_source": req["args_source"], "args": req["args"]}
            tx.set(run["calls"], tcid, call)
            tx.set(run["decisions"], did, call)
            seq = tx.event(run, req, "policy.decision", dict(data, decision=verdict, rule_ids=rule_ids),
                           tool_call_id=tcid, attempt=attempt, args_source=req["args_source"])
            for kind, reason in gaps:
                tx.emit(run, "capture.gap", {"kind": kind, "reason": reason, "tool_use_id": tcid}, source="signer",
                        tool_call_id=tcid)
            return {"decision": "allow" if verdict == "flag" else verdict, "decision_id": did, "rule_ids": rule_ids,
                    "run_seq": seq, "expires_at": expires_at}
        return self.log.submit(identity, "decide", req, fn, key)

    def _event(self, identity, method, req, typ, data, need_call=False, **top):
        """`data(commit)`: the event's data, given `commit(digest)`, the commitment under this record's salt."""
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)
        label = salt_label({"type": typ, "data": None, "tenant": key[0], "run_id": key[1],
                            "request_id": req["request_id"]})
        data = data(lambda digest: self._commit(label, digest))

        def fn(tx, run):
            if need_call and req["tool_call_id"] not in run["calls"]:
                raise RPCError("unknown_tool_call", req["tool_call_id"])
            return {"run_seq": tx.event(run, req, typ, data, **top)}
        return self.log.submit(identity, method, req, fn, key, late=True)

    def _complete(self, identity, req):
        key, tcid, attempt, did = self._authorize(identity, req), req["tool_call_id"], req.get("attempt", 0), req["decision_id"]
        # read off the writer thread, which checks the decision again; unknown after a restart (arguments are never
        # logged), so a replayed decision redacts as if the call touched a .env file
        dotenv = (self.log.runs[key]["decisions"].get(did) or {}).get("dotenv", True)
        try:
            value, manifest = _redact({k: req[k] for k in ("result", "error") if k in req}, dotenv,
                                      req.get("redaction", {}) if req.get("redacted") else None)
            c = canonical(value)
        except rfc8785.CanonicalizationError as e:
            raise RPCError("invalid_request", f"result is not canonical JSON: {e}") from None
        output = {"hash": self._commit("result:" + did, "sha256:" + hashlib.sha256(c).hexdigest()), "size": len(c),
                  "redacted": manifest["count"] > 0 or manifest["client_claimed"]}
        self.quotas.take_event(identity)

        def fn(tx, run):
            call = run["decisions"].get(did)
            if call is None or (call["tool_call_id"], call["attempt"]) != (tcid, attempt):
                raise RPCError("unknown_decision", f"{did} is not an open decision for {tcid} attempt {attempt}")
            if not self._same(call, req["args_digest"]):
                raise RPCError("args_mismatch", f"{tcid} ran with other arguments than decision {did}")
            tx.set(run["decisions"], did, None)
            return {"run_seq": tx.event(run, req, "tool.result", {"tool_use_id": tcid, "ok": req["status"] == "ok",
                                                                  "output": output, "decision_id": did,
                                                                  "redaction": manifest},
                                        tool_call_id=tcid, attempt=attempt)}
        return self.log.submit(identity, "complete", req, fn, key, late=True)

    def _state_write(self, identity, req):
        return self._event(identity, "state_write", req, "state.write",
                           lambda commit: {"store": "default", "key": req["key"], "digest": commit(req["value_digest"])})

    def _model_event(self, identity, req):
        def data(commit):
            d = {"exchange_id": req.get("exchange_id", req["request_id"]), "phase": req["phase"],
                 "streamed": req.get("streamed", False), "model": req["model"], "upstream": req["provider"]}
            for k in ("stop_reason", "error", "tool_results_sent"):
                if k in req:
                    d[k] = req[k]
            if "content_digest" in req:
                d["content_digest"] = commit(req["content_digest"])
            if {"input_tokens", "output_tokens"} <= req.get("usage", {}).keys():   # the event schema needs both counts
                d["usage"] = req["usage"]
            if "tool_uses" in req:
                d["tool_uses"] = [{k: v for k, v in t.items() if k != "args_digest"} for t in req["tool_uses"]]
                for t, u in zip(req["tool_uses"], d["tool_uses"]):
                    if "args_digest" in t:
                        u["args_commitment"] = commit(t["args_digest"])
            return d
        return self._event(identity, "model_event", req, "model.exchange", data)

    def _approval_request(self, identity, req):
        key, tcid, sub = self._authorize(identity, req), req["tool_call_id"], subject(identity)
        attempt = req.get("attempt", 0)

        def fn(tx, run):
            aid = self.log.approval_index.get((*key, tcid, attempt))
            if aid:   # one approval per call attempt: asking again returns it, whatever its state
                a = self.log.approvals[aid]
                return {"approval_id": aid, "state": a["state"], "expires_at": a["expires_at"]}
            call = run["calls"].get(tcid)
            if call is None or call["attempt"] != attempt or "pending" not in call:
                raise RPCError("unknown_tool_call", f"{tcid} attempt {attempt} has no pending `ask` decision")
            self.quotas.check_count("pending_approvals", sum(a["requester"] == sub and a["state"] == "requested"
                                                             for a in self.log.approvals.values()))
            p = call["pending"]
            aid, expires_at = "apr-" + secrets.token_hex(16), _iso(time.time() + APPROVAL_TTL_S)
            binding = {"v": 1, "approval_id": aid, "tenant": key[0], "run_id": key[1], "tool_call_id": tcid,
                       "attempt": attempt, "tool": p["tool"], "args_commitment": call["commitment"],
                       "args_source": p["args_source"],
                       "policy_hash": self.policy.policy_hash, "nonce": secrets.token_hex(16), "expires_at": expires_at}
            data = {"approval_id": aid, "decision_id": call["decision_id"], "policy_hash": self.policy.policy_hash,
                    "rule_ids": call["rule_ids"], "expires_at": expires_at, "requester": sub, "binding": binding,
                    "binding_digest": "sha256:" + hashlib.sha256(canonical(binding)).hexdigest()}
            copy = {"args_source": p["args_source"], "args": privacy.redact(p["args"], call["dotenv"])[0]}
            if "reason" in req:
                copy["reason"] = privacy.redact(req["reason"], call["dotenv"])[0]
            _write_new(os.path.join(self._args_dir, aid), self._seal(aid, copy))
            tx.set(self.log.approvals, aid, approval(*key, data))
            tx.set(self.log.approval_index, (*key, tcid, attempt), aid)
            tx.emit(run, "approval.request", data, request_id=req["request_id"], tool_call_id=tcid, attempt=attempt)
            return {"approval_id": aid, "state": "requested", "expires_at": expires_at}
        return self.log.submit(identity, "approval_request", req, fn, key)

    def _approval_decide(self, identity, req):
        aid, sub = req["approval_id"], subject(identity)
        run_key = self._visible(identity, aid)["run_key"]

        def fn(tx, run):
            a = self.log.approvals[aid]
            if a["state"] != "requested":
                raise RPCError("approval_not_pending", a["state"])
            if a["expires_at"] <= _iso(time.time()):
                raise RPCError("approval_not_pending", "expired")
            tx.set(a, "state", "approved" if req["decision"] == "approve" else "rejected")
            same = a["requester"] == sub
            data = {"tool_use_id": a["tool_call_id"], "approval_id": aid, "decision": req["decision"], "approver": sub,
                    "channel": "rpc", "self_approved": same}
            if "reason" in req:
                data["reason"] = req["reason"]
            tx.emit(run, "approval", data, request_id=req["request_id"], tool_call_id=a["tool_call_id"])
            return {"approval_id": aid, "state": a["state"], "self_approved": same}
        out = self.log.submit(identity, "approval_decide", req, fn, run_key)
        if out["state"] == "rejected":
            self._drop_args(aid)
        with self._cond:
            self._cond.notify_all()
        return out

    def _approval_wait(self, identity, req):
        aid = req["approval_id"]
        self._approval(self._authorize(identity, req), aid)
        with self._cond:
            self._cond.wait_for(lambda: self.log.approvals[aid]["state"] != "requested", req.get("timeout_ms", 0) / 1000)
        return {"approval_id": aid, "state": self.log.approvals[aid]["state"]}

    def _approval_consume(self, identity, req):
        key, tcid, attempt, hint = self._authorize(identity, req), req["tool_call_id"], req.get("attempt", 0), \
            req.get("approval_id_hint")
        self.quotas.take_event(identity)
        _, digest = self._args(req)

        def fn(tx, run):
            aid = self.log.approval_index.get((*key, tcid, attempt))
            a, call, top = self.log.approvals.get(aid), run["calls"].get(tcid), {"tool_call_id": tcid, "attempt": attempt}
            if hint is not None and hint != aid:
                why = "TK-APPROVAL-UNBOUND", "approval_id not bound to this call"
            elif digest is None:
                why = "TK-ARGS-INVALID", "the arguments are not canonical JSON"
            elif a is None:
                if (call and call["attempt"] == attempt and call["decision"] in ("allow", "flag")
                        and self._same(call, digest)):
                    return {"ok": True, "rule_ids": []}   # needed no approval
                why = "TK-APPROVAL-REQUIRED", "approval required but none was requested for this call"
            elif not self._same(a, digest):
                tx.emit(run, "approval.binding_mismatch", {
                    "approval_id": aid, "decision_id": a["decision_id"], "tool_use_id": tcid,
                    "approved_commitment": a["commitment"],
                    "args_commitment": self._commit(a["decision_id"], digest)}, source="signer", **top)
                return {"ok": False, "rule_ids": ["TK-APPROVAL-MISMATCH"], "approval_id": aid,
                        "reason": "the arguments differ from the approved ones"}
            elif a["state"] != "approved":
                why = "TK-APPROVAL-" + a["state"].upper(), f"not approved (state={a['state']})"
            elif a["expires_at"] <= _iso(time.time()):
                why = "TK-APPROVAL-EXPIRED", "the approval expired"
            else:
                tx.set(a, "state", "consumed")
                tx.emit(run, "approval.consumed", {"approval_id": aid}, source="signer", **top)
                return {"ok": True, "rule_ids": ["TK-APPROVED"], "approval_id": aid}
            data = {"tool_use_id": tcid, "rule_ids": [why[0]], "reason": why[1]}
            if a is not None:
                data["approval_id"] = aid
            tx.emit(run, "approval.refused", data, source="signer", **top)
            return {"ok": False, **{k: v for k, v in data.items() if k != "tool_use_id"}}
        out = self.log.submit(identity, "approval_consume", req, fn, key)
        if out["ok"] and "approval_id" in out:
            self._drop_args(out["approval_id"])
        return out

    def _approval_get(self, identity, req):
        aid = req["approval_id"]
        a = self._visible(identity, aid)
        return {**self._summary(aid, a), "binding_digest": a["binding_digest"],
                **(self._unseal(aid) or {"args_source": a["args_source"], "args": None})}

    def _approval_list(self, identity, req):
        mine = [(aid, a) for aid, a in list(self.log.approvals.items())
                if req.get("run_id") in (None, a["run_key"][1]) and self._may_see(identity, a)]
        recent = [x for x in mine if x[1]["state"] in LIVE] + [x for x in reversed(mine) if x[1]["state"] not in LIVE]
        return {"approvals": [self._summary(aid, a) for aid, a in recent[:LIST_MAX]]}

    def _close_run(self, identity, req):
        key = self._authorize(identity, req)

        def fn(tx, run):
            return {"run_id": req["run_id"], "state": "closing",
                    "run_seq": tx.closing(run, "close_run", request_id=req["request_id"])}
        return self.log.submit(identity, "close_run", req, fn, key)

    def _status(self, identity, req):
        return {"rpc_version": rpc_schema.RPC_VERSION, "signer": {"name": "tracekit-signer", "version": __version__},
                "identity": {"scheme": identity.scheme, "subject": identity.subject[:256], "attested": identity.attested}}

    def _read(self, identity, req):
        key = self._authorize(identity, req)
        start, limit = req.get("from_seq", 0), req.get("limit", 100)
        events, next_seq = [], None
        try:
            # lean: reads the run from its first record for every page; index by run_seq if runs grow long
            for r in self.log.storage.iter_run(*key):
                e = r["event"]
                if e["run_seq"] < start:
                    continue
                if len(events) == limit:
                    next_seq = e["run_seq"]
                    break
                p = {"run_seq": e["run_seq"], "type": e["type"], "data": e["data"]}
                p["event_hash"] = event_hash(p)
                events.append(p)
        except (OSError, StorageUnavailable) as e:
            raise RPCError("unavailable", f"storage read failed: {e}") from None
        return {"events": events, "next_seq": next_seq}

    def _checkpoint_nudge(self, identity, req):
        self._nudged.set()
        return {"scheduled": True}


# the SignerAPI methods, answered for the in-process identity
for _m in REQUESTS:
    setattr(SignerService, _m, lambda self, req, _m=_m: self.call(self.identity, _m, req))


# --- tracekit signer serve | fsck ---

def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    unknown = set(cfg) - CONFIG_KEYS
    if unknown or "data_dir" not in cfg:
        raise ValueError(f"{path}: needs data_dir; unknown keys {sorted(unknown)}")
    base = os.path.dirname(os.path.abspath(path))
    for k in ("data_dir", "socket", "tcp_endpoint", "policy"):
        if cfg.get(k):
            cfg[k] = os.path.join(base, cfg[k])
    h = cfg.get("http")
    if h is not None:
        from tracekit.transport import http
        for section in (h, h.get("k8s_sa")) if isinstance(h, dict) else ():
            for k in ("cert", "key", "client_ca", "token_file", "ca"):
                if isinstance(section, dict) and section.get(k):
                    section[k] = os.path.join(base, section[k])
        http.configure(h)   # validates the section now; serve() builds it again
    return cfg


def signer_config(path=None):
    """The config at `path`, or the same-user dev signer's (data_dir and socket)."""
    if path:
        return load_config(path)
    from tracekit.sdk.autospawn import SOCK, runtime_dir
    return {"data_dir": dev_data_dir(), "socket": os.path.join(runtime_dir(), SOCK)}


def read_vkey(data_dir):
    """The log key's vkey the signer of `data_dir` wrote on start."""
    d = files.open_dir(data_dir)
    try:
        data = files.read(d, "log.vkey")
    finally:
        files.close(d)
    if data is None:
        raise ValueError(f"{data_dir} has no log.vkey yet: start the signer once")
    vkey = data.decode("ascii").strip()
    checkpoint.parse_vkey(vkey)
    return vkey


def open_service(cfg, **kw):
    if cfg.get("policy"):
        kw.setdefault("policy", load_policy(cfg["policy"]))
    # lean: no witness client until the checkpointer exists (04-design §2.9); pass witnesses= in process meanwhile
    return SignerService(cfg["data_dir"], durability=cfg.get("durability", ACK_ON_WRITE),
                         tenant=cfg.get("tenant", "default"), tenants=cfg.get("tenants"),
                         limits=Limits(**cfg.get("limits", {})),
                         acknowledge_rollback=bool(cfg.get("acknowledge_rollback")),
                         multi_tenant_apps=cfg.get("multi_tenant_apps", ()), migrators=cfg.get("migrators", ()),
                         analyzers=cfg.get("analyzers", ()), fail_modes=cfg.get("fail_modes"),
                         grace_s=float(cfg.get("grace_s", GRACE_S)), idle_s=float(cfg.get("idle_s", IDLE_S)),
                         origin=cfg.get("origin"),
                         authorize={**(DEV_GRANT if cfg.get("tcp_endpoint") else {}), **(cfg.get("authorize") or {})}, **kw)


def serve(cfg, service):
    """Bind the configured transports for `service` (whose storage lock is already held) and start answering.
    Returns the servers; stop each with shutdown() and server_close()."""
    if not (cfg.get("socket") or cfg.get("tcp_endpoint") or cfg.get("http")):
        raise ValueError("configure socket, tcp_endpoint and/or http")
    servers = [metrics.server(cfg["metrics"], service.metrics)] if "metrics" in cfg else []
    handle = answering_hello(service.handle_frame, hello())
    if cfg.get("socket"):
        from tracekit.transport.unix import UnixServer
        try:
            os.unlink(cfg["socket"])   # a dead signer's socket: safe to remove, this process holds the storage lock
        except FileNotFoundError:
            pass
        servers.append(UnixServer(cfg["socket"], handle))
    if cfg.get("tcp_endpoint"):
        from tracekit.transport.tcp_dev import TcpDevServer
        servers.append(TcpDevServer(cfg["tcp_endpoint"], _dev_token(), handle))
    if cfg.get("http"):
        from tracekit.transport import http
        servers.append(http.HttpServer(*http.configure(cfg["http"]), handle))
    for s in servers:
        threading.Thread(target=s.serve_forever, args=(0.2,), daemon=True).start()
    return servers


def _dev_token():
    from tracekit.identity.token import DevToken
    return DevToken("dev", [*REQUESTS, "hello"], ttl_s=365 * 86400)


def dev_data_dir():
    """The dev signer's per-user data dir (keys and store), created 0700."""
    if os.name == "nt":
        d = os.path.join(os.environ["LOCALAPPDATA"], "tracekit")
    elif sys.platform == "darwin":
        d = os.path.expanduser("~/Library/Application Support/tracekit/data")
    else:
        d = os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "tracekit")
    os.makedirs(d, 0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def serve_dev(runtime_dir, open_handler, proto=(rpc_schema.RPC_VERSION, rpc_schema.RPC_VERSION), version=__version__,
              idle_s=900):
    """Serve as the dev signer of `runtime_dir` (decision S3) until SIGTERM, or until `idle_s` seconds (0: never) pass
    with no connection open. Takes signer.lock before anything else (gives up after 1 s) and holds it for life; then
    `open_handler()` -> (handle_frame, close); then binds the socket (loopback TCP without Unix sockets) and publishes
    endpoint.json; before returning, unpublishes both, then calls close(). Call it from the main thread; returns an
    exit code."""
    from tracekit.deploy import files
    from tracekit.sdk import autospawn

    lock = open(os.path.join(runtime_dir, autospawn.LOCK), "a")
    deadline = time.monotonic() + 1
    while True:
        try:
            lock_file(lock, blocking=False)
            break
        except OSError:
            if time.monotonic() > deadline:
                print("LOST: another dev signer holds signer.lock", file=sys.stderr)
                return 1
            time.sleep(0.05)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    sock, endpoint = os.path.join(runtime_dir, autospawn.SOCK), os.path.join(runtime_dir, autospawn.ENDPOINT)
    for p in (sock, endpoint):
        pathlib.Path(p).unlink(missing_ok=True)
    handle_frame, close = open_handler()
    info = hello(proto, version)
    handle = answering_hello(handle_frame, info)
    if hasattr(socket, "AF_UNIX"):
        from tracekit.transport.unix import UnixServer
        server = UnixServer(sock, handle)
        files.write_json(endpoint, info)
    else:
        from tracekit.transport.tcp_dev import TcpDevServer
        server = TcpDevServer(endpoint, _dev_token(), handle, publish=info)
    active, last, mutex = [0], [time.monotonic()], threading.Lock()

    def finish_request(request, address, inner=server.finish_request):   # counts the open connections
        with mutex:
            active[0] += 1
        try:
            inner(request, address)
        finally:
            with mutex:
                active[0] -= 1
                last[0] = time.monotonic()
    server.finish_request = finish_request
    threading.Thread(target=server.serve_forever, args=(0.2,), daemon=True).start()
    print(f"SERVING pid {os.getpid()}", file=sys.stderr, flush=True)
    try:
        while not stop.wait(0.1):
            with mutex:
                if idle_s and not active[0] and time.monotonic() - last[0] > idle_s:
                    break
    except KeyboardInterrupt:
        pass
    for p in (endpoint, sock):
        pathlib.Path(p).unlink(missing_ok=True)
    server.shutdown()
    server.server_close()
    close()
    return 0


def _serve_dev():
    from tracekit.sdk.autospawn import runtime_dir

    def open_handler():
        service = SignerService(dev_data_dir(), isolation="same-user", authorize=DEV_GRANT)
        return service.handle_frame, service.close
    try:
        return serve_dev(runtime_dir(), open_handler, idle_s=float(os.environ.get("TRACEKIT_DEV_IDLE", 900)))
    except BlockingIOError:
        print(f"tracekit signer: another signer holds {dev_data_dir()}", file=sys.stderr)
    except Exception as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
    return 1


def fsck(data_dir):
    """Every problem in the store: the storage check (hashes, chains) plus every record's signature."""
    store = os.path.join(data_dir, "store")
    problems = fsck_store(store)
    with open(os.path.join(data_dir, "keys", "record.key"), "rb") as f:
        sign = RecordSigner(f.read())
    try:
        with open(os.path.join(store, "records.jsonl"), "rb") as f:
            for n, line in enumerate(f, 1):
                try:
                    verify_record(loads_strict(line), [sign.spki], {sign.alg})
                except RecordError as e:
                    problems.append(f"records.jsonl line {n}: {e}")
                except ValueError:
                    pass   # unreadable: reported by the storage check
    except FileNotFoundError:
        pass
    return problems


def reveal(data_dir, seq):
    """{"seq", "type", "salt"}: the salt of record `seq`'s commitments, for an auditor who holds that record's content.
    Only the owner of the signer's keys may ask."""
    keys = os.path.join(data_dir, "keys")
    if hasattr(os, "getuid") and os.stat(keys).st_uid != os.getuid():
        raise PermissionError(f"{keys} belongs to another user: only the signer's owner reveals salts")
    with open(os.path.join(data_dir, "store", "records.jsonl"), "rb") as f:
        # lean: scans the store from the start; seek by an offset index once stores reach gigabytes
        e = next((e for e in (loads_strict(line)["event"] for line in f) if e["seq"] == seq), None)
    label = e and salt_label(e)
    if label is None:
        raise ValueError(f"record {seq} " + ("does not exist" if e is None else f"({e['type']}) has no commitments"))
    with open(os.path.join(keys, "args_salt.key"), "rb") as f:
        return {"seq": seq, "type": e["type"], "salt": _salt(f.read(), label).hex()}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit signer", description="the v2 signer service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    mode = sub.add_parser("serve", help="run the signer in the foreground").add_mutually_exclusive_group(required=True)
    mode.add_argument("--config")
    mode.add_argument("--dev", action="store_true",
                      help="the same-user dev signer of the runtime dir ($TRACEKIT_RUNTIME_DIR); clients start it")
    sub.add_parser("fsck", help="check every record of the store").add_argument("--config", required=True)
    for name, text in (("vkey", "print the log key's verifier key (C2SP vkey)"),
                       ("trust", "write a v2 trust config that pins the log key, with no witnesses")):
        q = sub.add_parser(name, help=text)
        g = q.add_mutually_exclusive_group()
        g.add_argument("--config")
        g.add_argument("--dev", action="store_true", help="the same-user dev signer (the default)")
        if name == "trust":
            q.add_argument("-o", "--out", required=True)
    q = sub.add_parser("reveal", help="print the salt of one record's commitments (the signer's owner only)")
    q.add_argument("--record", type=int, required=True, metavar="SEQ")
    g = q.add_mutually_exclusive_group()
    g.add_argument("--config")
    g.add_argument("--dev", action="store_true", help="the same-user dev signer (the default)")
    p = sub.add_parser("bridge", help="continue a v1 ledger in this signer's log and destroy the v1 key")
    p.add_argument("--v1-home", required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--config")
    g.add_argument("--dev", action="store_true", help="the same-user dev signer's data dir")
    a = ap.parse_args(argv)
    if a.cmd == "serve" and a.dev:
        return _serve_dev()
    if a.cmd == "reveal":
        try:
            print(json.dumps(reveal(signer_config(a.config)["data_dir"], a.record)))
        except (OSError, ValueError) as e:
            print(f"tracekit signer: {e}", file=sys.stderr)
            return 2
        return 0
    if a.cmd in ("vkey", "trust"):
        from tracekit.sdk.client import SignerUnavailable
        try:
            vkey = read_vkey(signer_config(a.config)["data_dir"])
            if a.cmd == "trust":
                files.write_json(a.out, {"logs": [vkey], "witnesses": [], "algs": [RecordSigner.alg],
                                         "witnesses_required": 0}, 0o644)
        except (OSError, ValueError, SignerUnavailable) as e:
            print(f"tracekit signer: {e}", file=sys.stderr)
            return 2
        print(vkey if a.cmd == "vkey" else f"wrote {a.out}: pins log {vkey.split('+')[0]}, no witnesses")
        return 0
    from tracekit.signer import format_bridge
    try:
        cfg = {"data_dir": dev_data_dir()} if getattr(a, "dev", False) else load_config(a.config)
    except (OSError, ValueError) as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 2
    if a.cmd == "bridge":
        # lean: run by hand while v1 hooks still sign with the v1 key; run the bridge on first v2 start once the hook
        # speaks the RPC (M1a-14)
        try:
            print(json.dumps(format_bridge.bridge(a.v1_home, cfg["data_dir"])))
        except (OSError, format_bridge.BridgeError) as e:
            print(f"tracekit signer bridge: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "fsck":
        problems = fsck(cfg["data_dir"])
        for p in problems:
            print(p)
        print("ok" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    try:
        service = open_service(cfg)
    except BlockingIOError:
        print(f"tracekit signer: another signer holds {cfg['data_dir']}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 1
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        servers = serve(cfg, service)
    except Exception as e:
        service.close()
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 1
    print(f"tracekit signer {__version__} serving", flush=True)
    try:
        while not stop.wait(1):
            pass
    except KeyboardInterrupt:
        pass
    for s in servers:
        s.shutdown()
        s.server_close()
    if cfg.get("socket"):
        try:
            os.unlink(cfg["socket"])
        except FileNotFoundError:
            pass
    service.close()
    return 0
