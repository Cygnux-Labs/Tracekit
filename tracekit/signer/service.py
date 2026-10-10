"""The v2 signer service: `SignerService` implements `SignerAPI` over the record log's single writer (pipeline.py).

    tracekit signer serve --config signer.yaml
    tracekit signer serve --dev               # the same-user dev signer clients auto-spawn (decision S3)
    tracekit signer fsck  --config signer.yaml
    tracekit signer migrate --config signer.yaml     # create the Postgres store's tables (as the migration role)
    tracekit signer close-log --config signer.yaml   # shut the log down for good (log.closed), signer stopped
    tracekit signer vkey  [--dev | --config signer.yaml]               # the log's verifier key
    tracekit signer trust [--dev | --config signer.yaml] -o trust.json  # a v2 trust config pinning it and the witnesses
    tracekit signer reveal --record SEQ [--dev | --config signer.yaml]  # the salt of one record's commitments

signer.yaml:
    data_dir: /var/lib/tracekit-signer      # keys/ and store/; relative paths are from the config file
    socket: /run/tracekit/signer.sock        # Unix socket transport (peer uid, per frame on Linux)
    socket_mode: "0666"                      # chmod the socket after bind (default: as the umask leaves it)
    tcp_endpoint: /run/tracekit/endpoint.json   # loopback TCP dev transport (token, mutual HMAC)
    http: {listen: 0.0.0.0:8443, ...}        # HTTPS with k8s_sa, mtls or token identity (tracekit/transport/http.py)
    durability: ack-on-write                 # or ack-on-fsync
    log_key: {aws_kms: {key_id: alias/tracekit-log, region: eu-west-1}}   # the log key in AWS KMS
                                             # (tracekit.signer.logkey); default keys/log.key
    storage: {postgres: {dsn_file: pg.dsn}}  # a Postgres store (tracekit.storage.postgres): the DSN is read from the
                                             # file, never inline (no dsn_file: the libpq PG* variables); default the
                                             # file store in data_dir/store
    tenant: default                          # tenant of callers not in `tenants`
    tenants: {"uid:1001": acme, "k8s_sa:system:serviceaccount:acme:*": acme}   # identity or prefix:* -> tenant (attested)
    authorize: {"mtls:spiffe://acme/agent": [register_run, decide, complete, close_run]}   # identity or prefix:* ->
                                             # methods; uid and token:dev default to all, the rest to none
    multi_tenant_apps: ["uid:1002"]          # may assert a tenant per run (recorded as not attested)
    migrators: ["uid:1003"]                  # may register `migrated` runs
    analyzers: ["uid:1004"]                  # may register findings runs, each bound to the run it analyses
    fail_modes: {default: closed, read: open}   # tool class -> fail mode, recorded and returned by register_run
    grace_s: 5                               # reconciliation window between run.closing and run.final
    idle_s: 3600                             # a run without calls for this long is closed
    limits: {events_per_s: 200, burst: 400}  # tracekit.signer.quotas.Limits
    policy: /etc/tracekit/policy.yaml        # policy v2 (YAML or JSON); default tracekit/policy2/packs/dev.yaml
    origin: tracekit.example.org/log/1       # checkpoint origin, the log key's name; default tracekit.local/<log_id>
    metrics: {listen: 127.0.0.1:9464}        # Prometheus GET /metrics on its own port (tracekit.signer.metrics),
                                             # and GET /logs/v0: this signer's logs, for witnesses to poll, and
                                             # the logs' tiles and anchors, for monitors (SignerService.tlog);
                                             # serve_records: true adds the record entries a monitor of the record
                                             # log reads (every tenant's records: keep that port private)
    witnesses:                               # C2SP tlog-witnesses that cosign every new note (tracekit.tlog_witness)
      - {url: https://witness.example.org, vkey: "witness.example.org/w1+1234abcd+BA...", class: customer}
    contact: ops@example.org                 # the logs list's contact line; default the origin
    anchors: {rekor: {signing_config: sigstage-signing_config.json, trusted_root: sigstage-trusted_root.json,
                      every_s: 3600}}        # Rekor v2 + RFC 3161 anchors of the record note (tracekit.anchor.rekor2)
    approvals: {self_approval: deny, approvers: ["uid:1001", "mtls:spiffe://acme/ops/*"],   # identity or prefix/*
                break_glass: ["uid:0"]}      # may answer any approval, with a reason; recorded break_glass
    acknowledge_rollback: false
    lock_timeout_s: 10                       # wait this long for the storage lock, then exit naming its holder's pid
    fsck_every_s: 86400                      # full-chain check in the background (0: off; the dev signer's is off)
    clock_skew_s: 300                        # a witness cosignature this far from the signer's clock: clock_skew gap
    otlp: {max_spans: 512}                   # OTLP/HTTP POST /v1/traces on the `http` listener, for identities
                                             # `authorize` grants otlp_import (tracekit.signer.otel; docs/otel.md)
    otel_out: {endpoint: https://otel.example.org/v1/traces, headers: {x-api-key: "..."}}   # each final run's spans

Startup (04-design §2.6): the storage lock is taken before any socket is touched; the log is replayed, its chain
checked and its tail signatures verified; then the configured witnesses are asked for their latest cosigned checkpoint.
A witness is a `tlog_witness.TlogWitness` (or an object with its `name`, `vkey`, `add_checkpoint` and `latest`), and
`latest` raises when it is unreachable. A local log behind the witnessed one is a rollback: a signed `trace.tamper{rollback}`, then client writes are refused until it is
acknowledged. No witness reachable: a signed `degraded_unanchored` gap, and the signer runs. The store opens from its
latest snapshot (written every SNAPSHOT_RECORDS records and on close) and replays only the records after it.
Every `fsck_every_s` a background thread checks the whole store as `tracekit signer fsck` does; new problems are one
signed `trace.tamper{edited}` and refuse client writes (acknowledge_rollback does not cover them). Snapshots carry an
HMAC under keys/snapshot.key; one that fails it is ignored and the logs are replayed in full.

Tenant-level gaps (04-design §2.7): witness_failed, witness_late, clock_skew, degraded_unanchored gaps and rollback
tamper records are signer-level records with a leaf in every tenant's registry, so a run-set over the window shows them.

Run lifecycle (04-design §2.7): run.registered → events → close_run or the idle timeout (paused while an approval is
pending) → run.closing → grace window, where only late records (complete, state_write, model_event, tailer_lost) are
accepted → the run's reconcile.* records (tracekit.signer.reconcile) → run.final{head, coverage}. run.registered and
run.final also get a leaf in the tenant's registry log (tracekit.format.registry), log.closed and key.retire one in
every tenant's. Gap and tamper records are written by the signer only: no request can carry an event type, source,
isolation or fail mode.

Checkpoints (04-design §1.6, §2.9): a C2SP note of the record tree, signed by the log key (keys/log.key or AWS KMS,
Ed25519, named after the origin, signs notes only) and stored through the storage, after a run.final, on
`checkpoint_nudge` (at most one note per CHECKPOINT_MIN_S), every CHECKPOINT_S while the tree grows, and on close; then,
signed by the same key, a note of each tenant registry that grew, under origin `<origin>/registry/<id of the tenant's
salt>`. The log key's vkey is written to <data_dir>/log.vkey on start, which is refused when the stored notes were
signed by another key. Notes are signed off the writer thread; the writer only reads the heads. A note the log key
fails to sign waits for the next round; an outage of LOG_KEY_GAP_S gets one signed `capture.gap{degraded_unanchored}`.

Publishing (04-design §2.9, §8): one worker per configured witness sends each tree's latest note to it (add-checkpoint,
off the writer: the writer only computes consistency proofs) and merges the verified cosignature lines into the stored
note, whose body never changes. Per witness and tree, the store keeps the size the witness last cosigned and the retry
state (witness-queue.json), so a restart resumes where it left off; retries back off from BACKOFF_S[0] to BACKOFF_S[1]
(a refusal waits the longest). A log a witness has failed to cosign for WITNESS_GAP_S gets one signed
`capture.gap{witness_failed}` per outage. A cosignature whose timestamp is more than `clock_skew_s` from the signer's
clock starts a clock skew episode: one signed `capture.gap{clock_skew}` until a cosignature within it ends the episode.

Anchoring (04-design §2.9, decision S2): with `anchors.rekor`, one more worker of the same kind, named `rekor`, anchors
the latest record tree note in Rekor v2 with an RFC 3161 timestamp, at most once per `every_s` (>= 3600), signed with
keys/rekor.key (P-256, its public key written to <data_dir>/rekor.pub on start), and stores the anchor through the
storage (anchors.jsonl). It shares the retry queue, backoff and `witness_failed` gap.

Monitoring (04-design §2.9): the metrics port also serves each log read-only as C2SP tlog-tiles, for
`tracekit monitor` (SignerService.tlog).

Policy (04-design §4): the signer classifies the tool and decides with policy2; every decide gets a fresh decision_id
that one `complete` with the same arguments consumes. Only deny and ask are memoised, per (tool_call_id, attempt).

Approvals (04-design §5, decision S6): one per (tenant, run, tool_call_id, attempt), under a random id. The
approval.request record binds it to the call (binding_digest); `approval_consume` lets the call run once, only with the
approved arguments, and records every refusal. Approvals and the index are rebuilt from the log on start; the
signer's copy of a pending call's arguments (what the approver is shown) is kept encrypted under keys/approval_args.key
and deleted once the approval is consumed, rejected or expired. An approval expires after APPROVAL_TTL_S, when its
run ends, or at once when the adapter abandons it (`approval.abandoned`). An ask rule with `approval: {executor: t2}`
makes the consume return the approved arguments from that copy: its caller runs exactly those.
Who answers (design §5): with a config (`approvals`), only an approver of the run's tenant or a break-glass identity
(any tenant, a reason required, recorded `break_glass`), never the requester or the run's owner unless
`self_approval: allow`. Without one (the dev signer), any identity of the run's tenant, a self-approval labelled
(`self_approved`). The `approval` record carries the approver's identity as the transport established it. Approvals
are listed and shown only to the run's owner and to those who may answer them.

Privacy (04-design §1.2, §2.4; docs/privacy.md): a result and the approver's copy of the arguments go through
privacy.redact before they are committed or stored; a result's record carries a `redaction` manifest (the rules that
fired, never the values). A client may say it redacted already; the signer redacts again regardless and flags a secret
it still finds. Every published digest of agent content is an HMAC under a per-record salt derived from
keys/args_salt.key (`salt_label`), which `reveal` prints for one record. Policy decides on the unredacted arguments.
"""
import argparse
import base64
import collections
import datetime
import functools
import hashlib
import hmac
import itertools
import json
import logging
import os
import pathlib
import re
import secrets
import signal
import socket
import sys
import threading
import time
import types

import rfc8785
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tracekit import __version__, crypto, merkle, otlp, privacy, yamlmini
from tracekit.client import remote_url_error
from tracekit.anchor import rekor2
from tracekit.anchor.rekor2 import RekorAnchor
from tracekit.deploy import files
from tracekit.format import checkpoint, registry
from tracekit.format.canon import StrictJSONError, canonical, event_hash, loads_strict
from tracekit.format.records import RecordSigner, verify_record
from tracekit.identity.base import CallerIdentity
from tracekit.locking import lock_file
from tracekit.policy2 import compile as policy_compile
from tracekit.policy2.engine import Engine
from tracekit.signer import logkey, metrics, reconcile, rpc_schema
from tracekit.signer import otel as signer_otel
from tracekit.signer.pipeline import SIGNER_RUN, RecordLog, approval, final_run, owner, salt_label, subject
from tracekit.signer.quotas import Limits, Quotas
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.signer.runtoken import RunTokens
from tracekit.storage.base import ACK_ON_WRITE, RECORDS, StorageUnavailable, registry_tree
from tracekit.storage.file import FileStorage, _mkdir, _sync_dir, _write_all
from tracekit.storage.file import fsck as fsck_store
from tracekit.tlog_witness import TlogWitness, WitnessError, log_signed, signed_by
from tracekit.transport import answering_hello, hello

DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy2", "packs", "dev.yaml")
APPROVAL_TTL_S = 3600
DECISION_TTL_S = 300
REFUSAL_WINDOW_S = 60
STRICTNESS = ("allow", "flag", "ask", "deny")
LIVE = ("requested", "approved")   # approval states that may still lead to a consume
LIST_PAGE = 100
TICK_S = 1.0
CHECKPOINT_S, CHECKPOINT_MIN_S = 10.0, 1.0
WITNESS_GAP_S, LOG_KEY_GAP_S, BACKOFF_S = 300.0, 300.0, (1.0, 300.0)
FSCK_S, CLOCK_SKEW_S, LOCK_TIMEOUT_S = 86400.0, 300.0, 10.0
SNAPSHOT_RECORDS = 100_000
CLASSES = ("public", "customer", "tracekit", "operator")
GRACE_S, IDLE_S = 5.0, 3600.0
FAIL_MODES = {"default": "closed"}
TLOG_PATH = re.compile(r"/(?:registry/([0-9a-f]{32})/)?(?:(checkpoint)|tile/(entries|[0-9]|[1-5][0-9]|6[0-3])/"
                       r"((?:x[0-9]{3}/)*[0-9]{3})(?:\.p/([1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))?)")
CONFIG_KEYS = {"data_dir", "socket", "socket_mode", "tcp_endpoint", "http", "durability", "tenant", "tenants",
               "authorize", "limits", "acknowledge_rollback", "policy", "multi_tenant_apps", "migrators", "analyzers",
               "fail_modes", "grace_s", "idle_s", "origin", "metrics", "witnesses", "contact", "approvals",
               "lock_timeout_s", "fsck_every_s", "clock_skew_s", "anchors", "otlp", "otel_out", "storage", "log_key"}
APPROVAL_KEYS = {"self_approval", "approvers", "break_glass"}
OTLP_IMPORT = "otlp_import"   # an `authorize` grant, never a default: OTLP/HTTP import (otlp config section)
OTLP_MAX_SPANS = 512


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


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _shown(args, dotenv):
    """The approver's copy of parsed `args`: privacy.redact, and each digest under `typed_secrets` (a secret the
    Browser Use adapter typed) hidden, since an approver could test guesses of a weak secret against it."""
    shown = privacy.redact(args, dotenv)[0]
    if isinstance(shown, dict) and isinstance(shown.get("typed_secrets"), dict):
        shown = {**shown, "typed_secrets": {n: [d if not (isinstance(d, str) and _DIGEST.fullmatch(d))
                                                else "[REDACTED:typed_secret]" for d in v] if isinstance(v, list) else v
                                            for n, v in shown["typed_secrets"].items()}}
    return shown


def _write_new(path, data):
    """Create `path` (0600) holding all of `data`, or leave nothing there; FileExistsError when it exists."""
    tmp = f"{path}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(tmp, path)
    finally:
        os.unlink(tmp)
    _sync_dir(os.path.dirname(path))


def _snapshot_key(keys):
    """The key of the store's snapshots, or None before it exists (then the store replays its logs in full). Read
    before the storage lock is taken: a key cut short is ignored, and _secret then stops the start."""
    try:
        with open(os.path.join(keys, "snapshot.key"), "rb") as f:
            key = f.read()
    except FileNotFoundError:
        return None
    return key if len(key) == 32 else None


def _secret(path, make, size=32):
    """The `size`-byte secret in `path`, created (0600) on first use. Called under the storage lock, so never by two
    signers. A file of another size stops the start: a key is never used cut short."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = make()
        _write_new(path, data)
    if len(data) != size:
        raise ValueError(f"{path} holds {len(data)} bytes, not a {size}-byte key: restore it from a backup")
    logkey.mlock(data)
    return data


PREFIX_ENDS = (":*", "/*")


def lookup(table, sub, default=None):
    """table[sub], else the entry of the longest prefix key (ending in `:*` or `/*`) that `sub` starts with, else
    `default`."""
    if sub in table:
        return table[sub]
    # lean: scans every key per call; a prefix trie if maps grow past a few hundred entries
    best = max((k for k in table if k.endswith(PREFIX_ENDS) and sub.startswith(k[:-1])), key=len, default=None)
    return default if best is None else table[best]


def _process_identity():
    return CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)


class SignerService:
    def __init__(self, data_dir, policy=None, identity=None, tenant="default", tenants=None, limits=Limits(),
                 durability=ACK_ON_WRITE, witnesses=(), acknowledge_rollback=False, open_storage=None, isolation=None,
                 multi_tenant_apps=(), migrators=(), analyzers=(), fail_modes=None, grace_s=GRACE_S, idle_s=IDLE_S,
                 bridge=None, origin=None, authorize=None, contact=None, approvals=None, lock_timeout_s=0,
                 fsck_every_s=FSCK_S, clock_skew_s=CLOCK_SKEW_S, rekor=None, otlp=None, otel_out=None,
                 storage_config=None, log_key=None):
        """`identity` answers the in-process SignerAPI calls (default: this process's uid); transports call
        handle_frame with the identity they established. `policy` is a policy2 Engine (default: load_policy()).
        `open_storage()` defaults to the store `storage_config` (the `storage` config section) names, else file storage
        in data_dir/store. `origin` names the log in its checkpoints, `contact` its operator in the logs list.
        `witnesses` cosign its notes (see the module docstring).
        `multi_tenant_apps`, `migrators` and `analyzers` are identities ("scheme:subject"); `tenants` and `authorize`
        map identities or prefixes (`...:*`, `.../*`) to a tenant and to the methods they may call.
        `isolation` fixes the signer_isolation label of every run (a dev signer: same-user). `bridge`: see RecordLog.
        `approvals`: who answers approvals (the `approvals` config section); None for the dev signer's rules.
        `lock_timeout_s`, `fsck_every_s` (0: no background check) and `clock_skew_s`: see the config keys.
        `rekor`: the `anchors.rekor` config section ({signing_config, trusted_root, every_s}), or None.
        `otlp` ({max_spans}) and `otel_out` ({endpoint, headers}): the config sections, or None.
        `log_key`: a signer.logkey key (default: the file key in keys/log.key); it must be the key of the log's notes."""
        fail_modes = dict(fail_modes or FAIL_MODES)
        if not all(isinstance(k, str) and v in ("open", "closed") for k, v in fail_modes.items()):
            raise ValueError("fail_modes maps tool classes to open or closed")
        if approvals is not None and not (
                isinstance(approvals, dict) and set(approvals) <= APPROVAL_KEYS
                and approvals.get("self_approval", "deny") in ("allow", "deny")
                and all(isinstance(approvals.get(k, []), list) for k in ("approvers", "break_glass"))):
            raise ValueError("approvals takes self_approval (allow|deny), approvers and break_glass (identity lists)")
        otlp = {} if otlp is None else otlp
        if not (isinstance(otlp, dict) and set(otlp) <= {"max_spans"} and isinstance(
                otlp.get("max_spans", 1), int) and otlp.get("max_spans", 1) > 0):
            raise ValueError("otlp takes max_spans (a positive integer)")
        if otel_out is not None and not (
                isinstance(otel_out, dict) and set(otel_out) <= {"endpoint", "headers"}
                and isinstance(otel_out.get("endpoint"), str) and not remote_url_error(otel_out["endpoint"])
                and isinstance(otel_out.get("headers", {}), dict)
                and all(isinstance(v, str) for v in otel_out.get("headers", {}).values())):
            raise ValueError("otel_out takes endpoint (https, or http to loopback) and headers (a string mapping)")
        self.metrics = metrics.SignerMetrics()
        authorize = dict(authorize or {})
        if not all(isinstance(m, list) and set(m) <= {*REQUESTS, OTLP_IMPORT} for m in authorize.values()):
            raise ValueError(f"authorize maps identities to lists of methods out of {sorted({*REQUESTS, OTLP_IMPORT})}")
        keys = os.path.join(data_dir, "keys")
        if open_storage is None and storage_config:
            from tracekit.storage import postgres
            section = storage_config["postgres"]
            open_storage = lambda: postgres.PostgresStorage(postgres.read_dsn(section), durability,  # noqa: E731
                                                            lock_timeout_s, _snapshot_key(keys))
        open_storage = open_storage or (lambda: FileStorage(os.path.join(data_dir, "store"), durability,
                                                            self.metrics.fsync_seconds.observe, lock_timeout_s,
                                                            _snapshot_key(keys)))
        storage = open_storage()   # takes the storage lock before anything else
        try:
            _mkdir(keys)
            os.chmod(keys, 0o700)
            storage.snapshot_key = _secret(os.path.join(keys, "snapshot.key"), lambda: os.urandom(32))
            sign = RecordSigner(_secret(os.path.join(keys, "record.key"), lambda: crypto.generate()[0]))
            self.tokens = RunTokens(_secret(os.path.join(keys, "run_token.key"), lambda: os.urandom(32)))
            self._salt_key = _secret(os.path.join(keys, "args_salt.key"), lambda: os.urandom(32))
            self._args_key = AESGCM(_secret(os.path.join(keys, "approval_args.key"), lambda: os.urandom(32)))
            self.quotas = Quotas(limits)
            salt = _secret(os.path.join(keys, "registry_salt.key"), lambda: os.urandom(32))
            self._log_key = log_key or logkey.FileKey(_secret(os.path.join(keys, "log.key"),
                                                              lambda: crypto.generate()[0]))
            self.anchors = [] if rekor is None else [RekorAnchor(
                rekor["signing_config"], rekor["trusted_root"],
                _secret(os.path.join(keys, "rekor.key"), rekor2.new_key), rekor.get("every_s", rekor2.MIN_EVERY_S))]
            self.log = RecordLog(storage, open_storage, sign, self.quotas, salt, self.metrics, bridge)
        except BaseException:
            storage.close()
            raise
        self.policy, self.isolation = policy or load_policy(), isolation
        self.identity = identity or _process_identity()
        self.tenant, self.tenants, self.authorize = tenant, dict(tenants or {}), authorize
        self.multi_tenant_apps, self.migrators, self.analyzers = set(multi_tenant_apps), set(migrators), set(analyzers)
        self.fail_modes, self.grace_s, self.idle_s = fail_modes, grace_s, idle_s
        self.otlp_max_spans = otlp.get("max_spans", OTLP_MAX_SPANS)
        self.approvals, self.data_dir, self.storage_config = approvals, data_dir, storage_config
        self.fsck_every_s, self.clock_skew_s, self._skewed, self._fsck_seen = fsck_every_s, clock_skew_s, set(), set()
        self._snapped = storage.tail_state()["tree_size"]
        self._approvers, self._break_glass = ({k: True for k in (approvals or {}).get(name, ())}
                                              for name in ("approvers", "break_glass"))
        self._swept = self._noted = time.monotonic()
        self._args_dir = os.path.join(data_dir, "approvals")   # approval_id -> the encrypted args of a live approval
        self._cond = threading.Condition()
        self._refusals, self._refusals_lock = {}, threading.Lock()
        self._stop, self._nudged, self._checkpointing = threading.Event(), threading.Event(), threading.Lock()
        self.origin = origin or f"tracekit.local/{self.log.log_id}"
        self.contact, self.witnesses = contact or self.origin, list(witnesses)
        self._queue, self._queue_lock = storage.witness_queue(), threading.Lock()
        self._anchor = next(((a.pop("size"), a) for a in storage.anchors()[-1:]), None)   # (size, the latest anchor)
        self._wake = {w.name: threading.Event() for w in self.witnesses + self.anchors}
        self._key_down = None   # (since, gapped) while the log key fails to sign
        try:
            self.vkey = checkpoint.vkey(self.origin, checkpoint.ED25519, self._log_key.public)
            latest = storage.checkpoint_latest()
            if latest:   # the log key is stable: another key (a backend switch, a replaced log.key) never takes over
                origin = latest[1].split("\n", 1)[0]   # signature checks of the note are the rollback check's job
                if (origin, checkpoint.key_id(origin, checkpoint.ED25519, self._log_key.public)) \
                        not in checkpoint.signers(latest[1]):
                    raise ValueError("the configured log key did not sign this log's notes: a log keeps its log key, "
                                     "so switch backends only to a key with the same public key")
            d = files.open_dir(data_dir)
            try:
                files.write(d, "log.vkey", (self.vkey + "\n").encode("ascii"), 0o644)
                files.write(d, "hygiene.json", json.dumps(logkey.HYGIENE).encode("ascii"), 0o644)
                for a in self.anchors:
                    files.write(d, "rekor.pub", (base64.b64encode(a.spki).decode("ascii") + "\n").encode("ascii"), 0o644)
            finally:
                files.close(d)
            _mkdir(self._args_dir)
            os.chmod(self._args_dir, 0o700)
            for aid in os.listdir(self._args_dir):   # left by a crash, or by an approval_request that was rolled back
                if self.log.approvals.get(aid, {}).get("state") not in LIVE:
                    self._drop_args(aid)
            self._check_notes(acknowledge_rollback)
            self._check_witnesses(witnesses, acknowledge_rollback)
        except BaseException:
            self.log.close()
            raise
        for name, help, fn in (
                ("tracekit_signer_queue_depth", "Items waiting for the writer.", self.log.queue_depth),
                ("tracekit_signer_fsync_lag_seconds", "Seconds the oldest written but unsynced record has waited.",
                 lambda: self.log.storage.unsynced_s()),
                ("tracekit_signer_open_runs", "Runs registered and not yet closing.",
                 lambda: sum(list(self.log.open_runs.values()))),
                ("tracekit_signer_pending_approvals", "Approvals requested and not yet answered.",
                 lambda: sum(a["state"] == "requested" for a in list(self.log.approvals.values()))),
                ("tracekit_signer_checkpoint_age_seconds", "Seconds since this signer last wrote a checkpoint note "
                 "(since start when it has written none).", lambda: time.monotonic() - self._noted)):
            self.metrics.add(metrics.Gauge(name, help, fn))
        self.metrics.add(metrics.Gauge(
            "tracekit_signer_witness_lag_records", "Records in the latest record tree note that the witness has not "
            "cosigned yet.", lambda: self._lag(self.witnesses), "witness"))
        self.metrics.add(metrics.Gauge(
            "tracekit_signer_anchor_lag_records", "Records in the latest record tree note not anchored yet.",
            lambda: self._lag(self.anchors), "anchor"))
        self._exporter = otel_out and signer_otel.Exporter(
            otel_out["endpoint"], otel_out.get("headers", {}), lambda key: list(self.log.storage.iter_run(*key)),
            self.metrics.otel_dropped)
        self._ticker = threading.Thread(target=self._tick_loop, name="tracekit-signer-ticker", daemon=True)
        self._ticker.start()
        self._checkpointer = threading.Thread(target=self._checkpoint_loop, name="tracekit-signer-checkpointer",
                                              daemon=True)
        self._checkpointer.start()
        if fsck_every_s:
            self._fsck = threading.Thread(target=self._fsck_loop, name="tracekit-signer-fsck", daemon=True)
            self._fsck.start()
        self._publishers = [threading.Thread(target=self._publish_loop, args=(w,), name=f"tracekit-witness-{i}",
                                             daemon=True) for i, w in enumerate(self.witnesses + self.anchors)]
        for t in self._publishers:
            t.start()

    def _tamper(self, kind, path, before, after, acknowledged, why):
        """A signed trace.tamper (a rollback is tenant-level); unless acknowledged, client writes are refused."""
        data = {"path": path, "kind": kind, "before": before, "after": after,
                **({"tenant_level": True} if kind == "rollback" else {})}
        self.log.write(lambda tx: tx.emit(self.log.signer_run(tx), "trace.tamper", data, source="signer"))
        if not acknowledged:
            self.log.refuse_writes = why + ("; restart with acknowledge_rollback once investigated" if kind == "rollback"
                                            else "; repair the store (tracekit signer fsck) and restart")

    def _check_notes(self, acknowledged):
        """The latest stored note of each tree (the record tree, every registry tree) against the tree: a note of more
        leaves, or of another root at its size, means the log was rolled back or forked."""
        s = self.log.storage
        trees = [(RECORDS, s.tree)] + [(registry_tree(t), s.registry_merkle(t))
                                       for t in sorted(self.log.tenants | set(s.tail_state()["registry"]))]
        for name, tree in trees:
            latest = s.checkpoint_latest(name)
            if latest is None:
                continue
            size, note = latest
            origin, _, root = note.split("\n", 3)[:3]
            path, root = "records" if name == RECORDS else origin, base64.b64decode(root)   # no tenant name in clear
            local = tree.size if tree else 0
            if size > local or tree.root_at(size) != root:
                self._tamper("rollback", path, {"length": size, "hash": "sha256:" + root.hex()},
                               {"length": local, "hash": "sha256:" + (tree.root() if tree else merkle.root([])).hex()},
                               acknowledged, f"the local {path} log ({local} leaves) does not extend its stored "
                                             f"checkpoint ({size}): rolled back")

    def _check_witnesses(self, witnesses, acknowledged):
        if not witnesses:
            return
        text = checkpoint.body(self.origin, 0, merkle.root([]))
        empty, heads = self._note(text, self.origin), []
        for w in witnesses:
            try:
                heads.append(w.latest(empty, self.vkey))
            except Exception:   # unreachable or unreadable: counted as no answer
                pass
        if not heads:
            self.log.write(lambda tx: tx.gap("degraded_unanchored", "no configured witness answered at startup"))
            return
        size, root = max(heads, key=lambda h: h[0])
        local = self.log.storage.tail_state()
        if local["tree_size"] >= size:
            return
        self._tamper("rollback", "records", {"length": size, **({"hash": "sha256:" + root.hex()} if root else {})},
                       {"length": local["tree_size"], "hash": "sha256:" + local["tree_root"].hex()}, acknowledged,
                       f"the local log ({local['tree_size']} records) is behind the witnessed checkpoint ({size}): "
                       "rolled back")

    # --- dispatch ---

    def handle_frame(self, identity, frame):
        req = dict(frame)
        return self.call(identity, req.pop("method", None), req)

    def call(self, identity, method, req):
        try:
            if not isinstance(method, str) or method not in REQUESTS:
                raise RPCError("invalid_request", f"unknown method {str(method)[:64]}")
            self._grant(identity, method)
            errs = rpc_schema.validate(REQUESTS[method], req)
            if errs:
                raise RPCError("invalid_request", "; ".join(errs))
            self.quotas.check_strings(req)
            return getattr(self, "_" + method)(identity, req)
        except RPCError as e:
            self._refused(identity, e)
            raise

    def _grant(self, identity, method):
        granted = lookup(self.authorize, subject(identity))
        if granted is None:   # unconfigured: a uid or the dev token (scoped by DevToken) keeps every RPC method
            granted = REQUESTS if identity.scheme == "uid" or subject(identity) == "token:dev" else ()
        if method not in granted:
            raise RPCError("forbidden", f"{subject(identity)[:256]} is not authorized for {method}")

    def _refused(self, identity, e):
        """Count refusal `e` for the metrics and the next refusal.summary."""
        self.metrics.refusals.inc(e.code)
        now, k = time.time(), (identity.scheme, identity.subject, e.code)
        with self._refusals_lock:
            first, _, n = self._refusals.get(k, (now, now, 0))
            self._refusals[k] = (first, now, n + 1)

    def _loop_error(self, loop):
        """Count and log an unexpected error of a background loop, which carries on with its next round."""
        self.metrics.loop_errors.inc(loop)
        logging.getLogger(__name__).exception("tracekit signer: the %s loop failed; retrying", loop)

    def _tick_loop(self):
        flushed = time.monotonic()
        while not self._stop.wait(TICK_S):
            try:
                self.sweep()
            except RPCError:   # storage down: the next tick retries
                pass
            except Exception:
                self._loop_error("ticker")
            if time.monotonic() - flushed >= REFUSAL_WINDOW_S:
                flushed = time.monotonic()
                try:
                    self.flush_refusals()
                except Exception:
                    self._loop_error("ticker")

    def _checkpoint_loop(self):
        """A note after each nudge (a run.final nudges too), at most one per CHECKPOINT_MIN_S, and every CHECKPOINT_S."""
        while True:
            self._nudged.wait(CHECKPOINT_S)
            if self._stop.is_set():   # close() writes the last note
                return
            self._nudged.clear()
            try:
                self.checkpoint()
                if self.log.storage.tree.size - self._snapped >= SNAPSHOT_RECORDS:
                    self.snapshot()
            except (RPCError, StorageUnavailable, OSError):   # storage down: the next round retries
                pass
            except Exception:
                self._loop_error("checkpointer")
            self._stop.wait(CHECKPOINT_MIN_S)

    def snapshot(self):
        """Snapshot the store and the run state, so the next start replays only the records after it."""
        with self._checkpointing:   # no note is stored while the storage snapshots its note index
            size = self.log.storage.tree.size
            self.log.snapshot()
            self._snapped = size

    def _fsck_loop(self):
        while not self._stop.wait(self.fsck_every_s):
            try:
                self.check_store()
            except Exception:
                self._loop_error("fsck")

    def check_store(self):
        """Check the store as `tracekit signer fsck` does, up to the records and registry leaves written so far; new
        problems get one signed trace.tamper{edited} and refuse client writes until a restart."""
        def written(tx):
            t = self.log.storage.tail_state()
            return {"records.jsonl": t["tree_size"], "registry.jsonl": sum(n for n, _ in t["registry"].values())}
        problems = fsck(self.data_dir, self.log.write(written), self.storage_config)
        new = [p for p in problems if p not in self._fsck_seen]
        if new:   # acknowledge_rollback covers the rollback found at start, never a later finding
            self._fsck_seen.update(new)
            self._tamper("edited", new[0].split(": ")[0][:256], {}, {}, False,
                         f"the background fsck found {len(new)} new problem(s), first: {new[0][:512]}")
        return problems

    def checkpoint(self):
        """Sign and store a note of the record tree when it grew since the latest stored one, then one of each
        tenant's registry tree that grew (its leaves point to records the record note covers). A log key that fails to
        sign leaves the rest unsigned until the next call. Returns whether every tree that grew got its note."""
        def heads(tx):
            s = self.log.storage
            return [(RECORDS, self.origin, s.tree.size, s.tree.root())] + [
                (registry_tree(t), registry.origin(self.origin, self.log.tenant_salt(t)), m.size, m.root())
                for t in sorted(self.log.tenants) if (m := s.registry_merkle(t))]
        with self._checkpointing:   # the checkpointer thread, close_log and close may all call this
            for tree, origin, size, root in self.log.write(heads):
                latest = self.log.storage.checkpoint_latest(tree)
                if size and (latest is None or size > latest[0]):
                    text = checkpoint.body(origin, size, root)
                    try:
                        note = self._note(text, origin)
                    except logkey.KeyUnavailable as e:
                        self._key_failed(e)
                        return False
                    self.log.storage.checkpoint_put(size, note, tree)
                    if tree == RECORDS:
                        self.metrics.checkpoints.inc()
                        self._noted = time.monotonic()
            self._key_down = None
        for wake in self._wake.values():
            wake.set()
        return True

    def _note(self, text, origin):
        return text + "\n" + checkpoint.log_line(origin, self._log_key.public, self._log_key.sign(text.encode("utf-8")))

    def _key_failed(self, e):
        """Count a failed signature of the log key; an outage of LOG_KEY_GAP_S gets one signed degraded_unanchored gap
        (the records since the latest note are in no note)."""
        self.metrics.log_key_failures.inc()
        now = time.time()
        since, gapped = self._key_down or (now, False)
        if not gapped and now - since >= LOG_KEY_GAP_S:
            self.log.write(lambda tx: tx.gap("degraded_unanchored", f"the log key has signed no note since "
                                                                    f"{_iso(since)}: {e}"))
            gapped = True
        self._key_down = since, gapped

    # --- witness publishing ---

    def _publish_loop(self, w):
        wake = self._wake[w.name]
        while True:
            wake.wait(TICK_S)
            if self._stop.is_set():
                return
            wake.clear()
            try:
                trees = self.log.write(lambda tx: [(RECORDS, self.log.storage.tree)] + [
                    (registry_tree(t), self.log.storage.registry_merkle(t)) for t in sorted(self.log.tenants)])
                for tree, merkle_tree in trees[:1] if w in self.anchors else trees:   # anchors: the record tree only
                    self._publish(w, tree, merkle_tree)
            except (RPCError, StorageUnavailable, OSError):   # storage down: the next round retries
                pass
            except Exception:
                self._loop_error("publisher")

    def _check_skew(self, w, ts):
        now = time.time()
        if abs(ts - now) <= self.clock_skew_s:
            self._skewed.discard(w.name)
        elif w.name not in self._skewed:   # one gap per episode, however many notes it spans
            self.log.write(lambda tx: tx.gap("clock_skew", f"witness {w.name} cosigned at {_iso(ts)}, "
                                                           f"{abs(ts - now):.0f} s from the signer's clock ({_iso(now)})"))
            self._skewed.add(w.name)

    def _publish(self, w, tree, merkle_tree):
        latest = self.log.storage.checkpoint_latest(tree)
        with self._queue_lock:
            st = self._queue.setdefault(w.name, {}).setdefault(tree, {"size": 0, "attempts": 0, "next": 0,
                                                                      "since": None, "gapped": False})
            if latest is None or latest[0] <= st["size"] or time.time() < st["next"]:
                return
            old = st["size"]
        size, note = latest
        origin = note.split("\n", 1)[0]
        log_vkey = checkpoint.vkey(origin, checkpoint.ED25519, self._log_key.public)
        try:
            lines = w.add_checkpoint(note, log_vkey, old,
                                     lambda n: self.log.write(lambda tx: merkle_tree.consistency_proof(n, size)))
        except (RPCError, StorageUnavailable):   # storage down: the publish loop retries
            raise
        except Exception as e:   # any other failure is the witness's, and not worth a quick retry
            if not isinstance(e, WitnessError):
                e = WitnessError(f"{w.name}: {type(e).__name__}: {e}", False)
            self.metrics.witness_failures.inc(w.name)
            with self._queue_lock:
                st["attempts"] += 1
                st["since"] = st["since"] or time.time()
                st["next"] = time.time() + (w.every_s if getattr(e, "written", False)   # an anchor Rekor may hold
                                            else BACKOFF_S[1] if not e.retryable
                                            else min(BACKOFF_S[1], BACKOFF_S[0] * 2 ** (st["attempts"] - 1)))
                gap = not st["gapped"] and time.time() - st["since"] >= WITNESS_GAP_S
                reason = f"witness {w.name} has not cosigned {origin} since {_iso(st['since'])}: {str(e)[:512]}"
                self.log.storage.witness_queue_put(self._queue)
            if gap:
                self.log.write(lambda tx: tx.gap("witness_failed", reason))
                with self._queue_lock:
                    st["gapped"] = True
                    self.log.storage.witness_queue_put(self._queue)
            return
        with self._checkpointing:   # merged into the stored note unless a newer note replaced it meanwhile
            stored = self.log.storage.checkpoint_latest(tree)
            if w in self.anchors:   # the stored copy, with the cosignatures merged since
                self._anchor = size, {"note": stored[1] if stored and stored[0] == size else note, **lines}
                self.log.storage.anchor_put(*self._anchor)
            else:
                if stored and stored[0] == size and not signed_by(stored[1].split("\n\n", 1)[1], w.vkey):
                    self.log.storage.checkpoint_put(size, stored[1] + lines, tree)
                a = self._anchor   # and into the anchored copy, which exports use once a newer note replaces it
                if tree == RECORDS and a and a[0] == size and not signed_by(a[1]["note"].split("\n\n", 1)[1], w.vkey):
                    self._anchor = size, dict(a[1], note=a[1]["note"] + lines)
                    self.log.storage.anchor_put(*self._anchor)
        with self._queue_lock:
            st.update(size=size, attempts=0, next=time.time() + getattr(w, "every_s", 0), since=None, gapped=False)
            self.log.storage.witness_queue_put(self._queue)
        if w not in self.anchors:   # a Rekor anchor's time is its TSA's, checked by the verifier
            self._check_skew(w, checkpoint.open_note(log_signed(note, log_vkey) + lines, [log_vkey], [w.vkey])[3][0][1])
        self._wake[w.name].set()   # a newer note may be waiting

    def _lag(self, publishers):
        latest = self.log.storage.checkpoint_latest()
        with self._queue_lock:
            return {w.name: max(0, (latest[0] if latest else 0) - self._queue.get(w.name, {}).get(RECORDS, {}).get(
                "size", 0)) for w in publishers}

    def logs_list(self):
        """This signer's logs (the record log and each tenant's registry log) in the witness network's `logs/v0`
        format, for a witness to register them from."""
        tenants = sorted(self.log.tenants)   # a set of str: copied under the GIL, no writer needed
        public = self._log_key.public
        out = ["logs/v0", ""]
        for origin in [self.origin] + [registry.origin(self.origin, self.log.tenant_salt(t)) for t in tenants]:
            out += [f"vkey {checkpoint.vkey(origin, checkpoint.ED25519, public)}",
                    f"qpd {int(86400 / CHECKPOINT_MIN_S)}", f"contact {self.contact}", ""]
        return "".join(line + "\n" for line in out)

    def tlog(self, path, records=False):
        """The bytes at `path` of the logs' read-only C2SP tlog-tiles API, or None: the record log at /, each tenant's
        registry log at /registry/<id>/ (its origin's suffix), each with `checkpoint` (the latest note), hash tiles
        `tile/<L>/<N>[.p/<W>]` and entry bundles `tile/entries/<N>[.p/<W>]`; and /anchors, the stored Rekor anchors
        as JSON lines. A registry bundle is C2SP's (uint16 length ‖ leaf, per leaf); a record log bundle is JSON lines,
        one record per line, as a record can be longer than a uint16 length. The record log's entry bundles (every
        tenant's records: run ids, tool names, commitments) only with `records` (metrics.serve_records: true); its
        checkpoint and hash tiles, and the registry logs (salted leaves), always."""
        if path == "/anchors":
            return "".join(json.dumps(a) + "\n" for a in self.log.storage.anchors()).encode("utf-8")
        m = TLOG_PATH.fullmatch(path)
        if not m:
            return None
        reg, note, kind, index, width = m.groups()
        tenant = reg and next((t for t in sorted(self.log.tenants)
                               if registry.origin(self.origin, self.log.tenant_salt(t)).endswith("/" + reg)), None)
        if reg and tenant is None:
            return None
        if note:
            latest = self.log.storage.checkpoint_latest(RECORDS if tenant is None else registry_tree(tenant))
            return latest and latest[1].encode("utf-8")
        n, w = int(index.replace("x", "").replace("/", "")), int(width or 256)

        def read(tx):   # lean: on the writer thread, which owns the trees' edges; read tiles off it if monitors poll often
            s = self.log.storage
            tree, lo = s.tree if tenant is None else s.registry_merkle(tenant), n * 256
            level = 0 if kind == "entries" else int(kind)
            count = tree.size >> (8 * level)
            if count < lo + w:
                return None
            if kind == "entries" and tenant is None:
                if not records:
                    return None
                return "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in s.iter_range(lo, lo + w)).encode()
            if kind == "entries":
                return b"".join(len(x).to_bytes(2, "big") + x for x in itertools.islice(s.registry_iter(tenant, lo), w))
            return (b"".join(tree.edge[level]) if n == count // 256 else tree.store.get(level, n, 256))[:32 * w]
        return self.log.write(read)

    def close_log(self):
        """Close the log for good: a signed log.closed{final_seq: its own seq} (a leaf in every tenant's registry),
        then the final notes. Every later write is refused, after a restart too."""
        self.log.write(lambda tx: tx.emit(self.log.signer_run(tx), "log.closed", {"final_seq": self.log.head["seq"]},
                                          source="signer"))
        if not self.checkpoint():
            raise RPCError("unavailable", "the log is closed but the log key signed no final note: start the signer once "
                                          "the log key is reachable, and it writes the note")

    def sweep(self, now=None, wall=None):
        """Close idle runs, write run.final for runs whose grace window has passed and expire approvals.
        `now`: a monotonic time; `wall`: a time.time() for approval expiry."""
        finals = []

        def fn(tx):
            t = time.monotonic() if now is None else now
            paused = max(0.0, t - self._swept)
            self._swept = max(self._swept, t)
            expired, live, mine, deadline = [], {}, {}, _iso(time.time() if wall is None else wall)
            # lean: visits every approval and run on each tick; keep deadline heaps once a signer holds ~100k of them
            for aid, a in self.log.approvals.items():
                mine.setdefault(a["run_key"], []).append(aid)
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
                    coverage = reconcile.finish(tx, run)
                    tx.set(run, "final", True)
                    tx.emit(run, "run.final", {"head_run_seq": run["run_seq"] - 1, "head_hash": run["head"],
                                               **({"coverage": coverage} if coverage else {})}, source="signer")
                    tx.set(self.log.runs, key, final_run(run))   # its calls, decisions and arguments go
                    for aid in mine.get(key, ()):   # all ended now: nothing can use them
                        a = self.log.approvals[aid]
                        tx.pop(self.log.approval_index, (*key, a["tool_call_id"], a["attempt"]))
                        tx.pop(self.log.approvals, aid)
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
        for key in finals if self._exporter else ():
            self._exporter.put(key)
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
        for wake in self._wake.values():
            wake.set()
        self._ticker.join()
        if self._exporter:
            self._exporter.close()
        self._checkpointer.join()
        if self.fsck_every_s:
            self._fsck.join()
        for t in self._publishers:
            t.join()
        self.flush_refusals()
        try:
            self.checkpoint()
            self.snapshot()
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
        """Whether `identity` may see approval `a`: the run's owner, a break-glass identity, or an identity of the
        run's tenant (with a config, only an approver of it)."""
        sub = subject(identity)
        if owner(identity) == self.log.runs[a["run_key"]]["owner"] or lookup(self._break_glass, sub, False):
            return True
        return (self.approvals is None or lookup(self._approvers, sub, False)) and \
            a["run_key"][0] == lookup(self.tenants, sub, self.tenant)

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
        except OSError:   # gone already, or left for the next start's cleanup
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
        """Whether `digest` is the args digest the decision `call` was made for."""
        return self._opens(call["commitment"], call["decision_id"], digest)

    def _opens(self, commitment, label, digest):
        return bool(commitment and digest) and hmac.compare_digest(commitment, self._commit(label, digest))

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
        own = owner(identity)
        self.quotas.take_event(identity)

        def fn(tx, _):
            if (tenant, run_id) in self.log.runs:
                raise RPCError("run_exists", run_id)
            if "analyzes" in req and (tenant, req["analyzes"]) not in self.log.runs:
                raise RPCError("unknown_run", req["analyzes"])
            n = self.log.open_runs.get(own, 0)
            self.quotas.check_count("open_runs", n)
            run = tx.new_run(tenant, run_id)
            tx.set(run, "owner", own)
            tx.set(self.log.open_runs, own, n + 1)
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
                           digests={tcid: digest}, tool_call_id=tcid, attempt=attempt, args_source=req["args_source"])
            for kind, reason in gaps:
                tx.emit(run, "capture.gap", {"kind": kind, "reason": reason, "tool_use_id": tcid}, source="signer",
                        tool_call_id=tcid)
            return {"decision": "allow" if verdict == "flag" else verdict, "decision_id": did, "rule_ids": rule_ids,
                    "run_seq": seq, "expires_at": expires_at}
        return self.log.submit(identity, "decide", req, fn, key)

    def _event(self, identity, method, req, typ, data, need_call=False, digests=None, **top):
        """`data(commit)`: the event's data, given `commit(digest)`, the commitment under this record's salt."""
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)
        sid = secrets.token_hex(16)
        label = salt_label({"type": typ, "data": {"salt_id": sid}})
        data = {**data(lambda digest: self._commit(label, digest)), "salt_id": sid}

        def fn(tx, run):
            if need_call and req["tool_call_id"] not in run["calls"]:
                raise RPCError("unknown_tool_call", req["tool_call_id"])
            return {"run_seq": tx.event(run, req, typ, data, digests, **top)}
        return self.log.submit(identity, method, req, fn, key, late=True)

    def _complete(self, identity, req):
        key, tcid, attempt, did = self._authorize(identity, req), req["tool_call_id"], req.get("attempt", 0), req["decision_id"]
        # read off the writer thread, which checks the decision again; unknown after a restart (arguments are never
        # logged), so a replayed decision redacts as if the call touched a .env file
        dotenv = (self.log.runs[key].get("decisions", {}).get(did) or {}).get("dotenv", True)
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
            seq = tx.event(run, req, "tool.result", {"tool_use_id": tcid, "ok": req["status"] == "ok", "output": output,
                                                     "decision_id": did, "redaction": manifest},
                           tool_call_id=tcid, attempt=attempt)
            approved = self.log.approvals.get(self.log.approval_index.get((*key, tcid, attempt)), {}).get("state")
            if call["decision"] == "deny" or (call["decision"] == "ask" and approved != "consumed"):
                tx.emit(run, "capture.gap", {"kind": "executed_against_policy", "tool_use_id": tcid,
                                             "reason": f"{tcid} ran after a {call['decision']} decision"
                                                       + (" with no consumed approval" if call["decision"] == "ask" else "")},
                        source="signer", tool_call_id=tcid)
            return {"run_seq": seq}
        return self.log.submit(identity, "complete", req, fn, key, late=True)

    def _state_write(self, identity, req):
        key, sk = self._authorize(identity, req), req["key"]
        self.quotas.take_event(identity)
        sid = secrets.token_hex(16)
        label = salt_label({"type": "state.write", "data": {"salt_id": sid}})
        digest = self._commit(label, req["value_digest"])

        def fn(tx, run):
            data = {"store": "default", "key": sk, "digest": digest, "salt_id": sid}
            prev = req.get("prev_digest", ...)
            if prev is not ...:
                data["prev_digest"] = prev and self._commit(label, prev)
            seq = tx.event(run, req, "state.write", data)
            last = run["states"].get(sk)   # (salt label, commitment) of the last write of this key
            if prev is not ... and last and self._commit(last[0], prev or "") != last[1]:
                # the agent's own earlier write says the state was something else: it changed outside its writes
                tx.emit(run, "capture.gap", {"kind": "state_tamper", "reason": f"state {sk[:200]} changed between "
                                             "writes: the write starts from another state than the last one written"},
                        source="signer")
            tx.set(run["states"], sk, (label, digest))
            return {"run_seq": seq}
        return self.log.submit(identity, "state_write", req, fn, key, late=True)

    def _model_event(self, identity, req):
        def data(commit):
            d = {"exchange_id": req.get("exchange_id", req["request_id"]), "phase": req["phase"],
                 "streamed": req.get("streamed", False), "model": req["model"], "upstream": req["provider"]}
            for k in ("stop_reason", "tool_results_sent"):
                if k in req:
                    d[k] = req[k]
            if "error" in req:
                d["error"] = privacy.redact_text(req["error"])[0]
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
        return self._event(identity, "model_event", req, "model.exchange", data,
                           digests={t["id"]: t.get("args_digest") for t in req.get("tool_uses", ())})

    def _approval_request(self, identity, req):
        key, tcid, sub = self._authorize(identity, req), req["tool_call_id"], subject(identity)
        attempt = req.get("attempt", 0)
        self.quotas.take_event(identity)

        def fn(tx, run):
            aid = self.log.approval_index.get((*key, tcid, attempt))
            if aid:   # one approval per call attempt: asking again returns it, whatever its state
                a = self.log.approvals[aid]
                return {"approval_id": aid, "state": a["state"], "expires_at": a["expires_at"]}
            call = run["calls"].get(tcid)
            if call is None or call["attempt"] != attempt or not call.get("pending"):
                raise RPCError("unknown_tool_call", f"{tcid} attempt {attempt} has no pending `ask` decision")
            self.quotas.check_count("pending_approvals", sum(a["requester"] == sub and a["state"] == "requested"
                                                             for a in self.log.approvals.values()))
            p = call["pending"]
            aid, expires_at, sid = "apr-" + secrets.token_hex(16), _iso(time.time() + APPROVAL_TTL_S), secrets.token_hex(16)
            args, digest = self._args(p)
            binding = {"v": 1, "approval_id": aid, "tenant": key[0], "run_id": key[1], "tool_call_id": tcid,
                       "attempt": attempt, "tool": p["tool"], "args_commitment": self._commit("approval.request:" + sid, digest),
                       "args_source": p["args_source"],
                       "policy_hash": self.policy.policy_hash, "nonce": secrets.token_hex(16), "expires_at": expires_at}
            data = {"approval_id": aid, "decision_id": call["decision_id"], "policy_hash": self.policy.policy_hash,
                    "rule_ids": call["rule_ids"], "expires_at": expires_at, "requester": sub, "binding": binding,
                    "binding_digest": "sha256:" + hashlib.sha256(canonical(binding)).hexdigest(), "salt_id": sid}
            if any(r.get("approval") == {"executor": "t2"} for _, r, *_ in self.policy.rules
                   if r["id"] in call["rule_ids"]):
                data["executor"] = "t2"
            shown = _shown(args, call["dotenv"])   # redact the parsed args, so a raw copy stays valid JSON
            if p["args_source"] == "raw":
                shown = p["args"] if shown == args else canonical(shown).decode()
            copy = {"args_source": p["args_source"], "args": shown}
            if data.get("executor") == "t2":   # what the executor runs: the real arguments, never shown to approvers
                copy["exec_args"] = p["args"]
            if "reason" in req:
                copy["reason"] = privacy.redact(req["reason"], call["dotenv"])[0]
            _write_new(os.path.join(self._args_dir, aid), self._seal(aid, copy))
            tx.set(self.log.approvals, aid, approval(*key, data))
            tx.set(self.log.approval_index, (*key, tcid, attempt), aid)
            tx.set(call, "pending", None)   # the sealed copy on disk is what the approver sees from now on
            tx.emit(run, "approval.request", data, request_id=req["request_id"], tool_call_id=tcid, attempt=attempt)
            return {"approval_id": aid, "state": "requested", "expires_at": expires_at}
        return self.log.submit(identity, "approval_request", req, fn, key)

    def _approval_decide(self, identity, req):
        aid, sub = req["approval_id"], subject(identity)
        a = self._visible(identity, aid)
        run_key = a["run_key"]
        same = sub == a["requester"] or owner(identity) == self.log.runs[run_key]["owner"]
        glass = False
        if self.approvals is not None:
            if same:
                if self.approvals.get("self_approval") != "allow":
                    raise RPCError("forbidden", f"{sub[:256]} may not answer its own run's approval")
            elif not lookup(self._approvers, sub, False):
                glass = bool(lookup(self._break_glass, sub, False))
                if not glass:
                    raise RPCError("forbidden", f"{sub[:256]} is not an approver")
                if "reason" not in req:
                    raise RPCError("forbidden", "a break-glass answer needs a reason")
        self.quotas.take_event(identity)

        def fn(tx, run):
            a = self.log.approvals[aid]
            if a["state"] != "requested":
                raise RPCError("approval_not_pending", a["state"])
            if a["expires_at"] <= _iso(time.time()):
                raise RPCError("approval_not_pending", "expired")
            tx.set(a, "state", "approved" if req["decision"] == "approve" else "rejected")
            data = {"tool_use_id": a["tool_call_id"], "approval_id": aid, "decision": req["decision"], "approver": sub,
                    "approver_identity": {"scheme": identity.scheme, "subject": identity.subject[:256],
                                          "attested": identity.attested},
                    "channel": "rpc", "self_approved": same}
            if glass:
                data["break_glass"] = True
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
        with self.quotas.wait_slot(identity), self._cond:
            self._cond.wait_for(lambda: self.log.approvals.get(aid, {}).get("state") != "requested",
                                req.get("timeout_ms", 0) / 1000)
        # read on the writer, so only a committed state is answered; gone: its run went final, which expired it
        return {"approval_id": aid, "state": self.log.write(
            lambda tx: self.log.approvals.get(aid, {"state": "expired"})["state"])}

    def _approval_consume(self, identity, req):
        key, tcid, attempt, hint = self._authorize(identity, req), req["tool_call_id"], req.get("attempt", 0), \
            req.get("approval_id_hint")
        self.quotas.take_event(identity)
        _, digest = self._args(req)
        bound = self.log.approval_index.get((*key, tcid, attempt))
        # read before the writer runs: the copy is deleted once the approval is consumed
        copy = self._unseal(bound) if bound and self.log.approvals[bound]["executor"] == "t2" else None

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
            elif not self._opens(a["commitment"], a["label"], digest):
                sid = secrets.token_hex(16)
                tx.emit(run, "approval.binding_mismatch", {
                    "approval_id": aid, "decision_id": a["decision_id"], "tool_use_id": tcid,
                    "approved_commitment": a["commitment"],
                    "args_commitment": self._commit("approval.binding_mismatch:" + sid, digest), "salt_id": sid},
                        source="signer", **top)
                return {"ok": False, "rule_ids": ["TK-APPROVAL-MISMATCH"], "approval_id": aid,
                        "reason": "the arguments differ from the approved ones"}
            elif a["state"] != "approved":
                why = "TK-APPROVAL-" + a["state"].upper(), f"not approved (state={a['state']})"
            elif a["expires_at"] <= _iso(time.time()):
                why = "TK-APPROVAL-EXPIRED", "the approval expired"
            else:
                out = {"ok": True, "rule_ids": ["TK-APPROVED"], "approval_id": aid}
                if a["executor"] == "t2":
                    if copy is None:
                        raise RPCError("unavailable", f"the stored arguments of {aid} are gone")
                    out["args"] = loads_strict(copy["exec_args"]) if copy["args_source"] == "raw" else copy["exec_args"]
                tx.set(a, "state", "consumed")
                tx.emit(run, "approval.consumed", {"approval_id": aid}, source="signer", **top)
                return out
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
        a = self.log.write(lambda tx: dict(self._visible(identity, aid)))   # committed state only
        copy = self._unseal(aid) or {"args_source": a["args_source"], "args": None}
        copy.pop("exec_args", None)   # the approver sees the redacted copy only
        return {**self._summary(aid, a), "binding_digest": a["binding_digest"], **copy}

    def _approval_list(self, identity, req):
        # copied on the writer, so only committed states are listed
        items = iter(self.log.write(lambda tx: [(aid, dict(a)) for aid, a in self.log.approvals.items()]))
        page, cursor = [], req.get("cursor")
        # lean: every page scans the approvals from the first; index them by tenant once a signer holds ~100k
        if cursor is not None:
            for aid, _ in items:
                if aid == cursor:
                    break
        for aid, a in items:
            if req.get("run_id") in (None, a["run_key"][1]) and self._may_see(identity, a):
                if len(page) == req.get("limit", LIST_PAGE):
                    return {"approvals": page, "next_cursor": page[-1]["approval_id"]}
                page.append(self._summary(aid, a))
        return {"approvals": page, "next_cursor": None}

    def _approval_abandon(self, identity, req):
        key, aid = self._authorize(identity, req), req["approval_id"]
        self._approval(key, aid)

        def fn(tx, run):
            a = self.log.approvals[aid]
            if a["state"] not in LIVE:
                raise RPCError("approval_not_pending", a["state"])
            tx.set(a, "state", "expired")
            data = {"approval_id": aid, **({"reason": privacy.redact_text(req["reason"])[0]} if "reason" in req else {})}
            tx.emit(run, "approval.abandoned", data, request_id=req["request_id"], tool_call_id=a["tool_call_id"],
                    attempt=a["attempt"])
            return {"approval_id": aid, "state": "expired"}
        out = self.log.submit(identity, "approval_abandon", req, fn, key)
        self._drop_args(aid)
        with self._cond:
            self._cond.notify_all()
        return out

    def _close_run(self, identity, req):
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)

        def fn(tx, run):
            return {"run_id": req["run_id"], "state": "closing",
                    "run_seq": tx.closing(run, "close_run", request_id=req["request_id"])}
        return self.log.submit(identity, "close_run", req, fn, key)

    def _delegate_run(self, identity, req):
        tenant, run_id = self._authorize(identity, req)
        if lookup(self.authorize, req["identity"]) is None:   # unconfigured, it would keep every method of the run
            raise RPCError("forbidden", f"{req['identity'][:256]} has no authorize entry to delegate the run to")
        scheme, sub = req["identity"].split(":", 1)
        return {"run_token": self.tokens.issue(tenant, run_id, CallerIdentity(scheme, sub, True))}

    def _tailer_lost(self, identity, req):
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)

        def fn(tx, run):
            return {"run_seq": tx.emit(run, "capture.gap", {
                "kind": "tailer_lost",
                "reason": f"{privacy.redact_text(req['reason'])[0]} (at transcript offset {req['offset']}; "
                          f"reported by {subject(identity)[:256]})"},
                source="signer", request_id=req["request_id"])}
        return self.log.submit(identity, "tailer_lost", req, fn, key, late=True)

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

    # --- OTLP import (tracekit.signer.otel) ---

    def otlp(self, identity, body, content_type, content_encoding):
        """(status, headers, body) of an OTLP/HTTP `POST /v1/traces` from `identity`, which the transport established;
        RPCError forbidden unless `authorize` grants it otlp_import."""
        try:
            self._grant(identity, OTLP_IMPORT)
        except RPCError as e:
            self._refused(identity, e)
            raise
        return otlp.handle_traces(types.SimpleNamespace(export=lambda spans: self._import(identity, spans)), body,
                                  content_type, content_encoding)

    def _content(self, value, label, dotenv):
        value, manifest = _redact(value, dotenv)
        c = canonical(value)
        return {"hash": self._commit(label, "sha256:" + hashlib.sha256(c).hexdigest()), "size": len(c),
                "redacted": manifest["count"] > 0}, manifest

    def _import(self, identity, spans):
        """Write decoded spans as the records of their imported runs, all in one writer item (nothing on a refusal):
        a dict of counts for otlp.handle_traces."""
        res = {"accepted": 0, "duplicate": 0, "skipped": 0, "rejected": 0, "errors": [], "retryable": False}
        if len(spans) > self.otlp_max_spans:
            return dict(res, rejected=len(spans), errors=[f"more than {self.otlp_max_spans} spans in one request"])
        traces, agents = {}, {}   # trace id -> [[(type, data, span id)] per span]; trace id -> agent name
        for sp in sorted(spans, key=lambda x: (x["start_ns"], x["end_ns"])):
            kind = otlp.classify(sp)
            if kind not in ("tool", "llm"):
                res["skipped"] += 1
                continue
            try:
                recs = [(typ, data, sp["span_id"]) for typ, data in signer_otel.records(kind, sp, self._content)]
            except Exception as e:   # values no record can hold (nesting past the recursion limit, say)
                res["rejected"] += 1
                res["errors"].append(f"span {sp['span_id']}: {type(e).__name__}")
                continue
            traces.setdefault(sp["trace_id"], []).append(recs)
            agents.setdefault(sp["trace_id"], str(sp["attrs"].get("gen_ai.agent.name") or
                                                  sp["resource"].get("service.name") or "otel")[:128] or "otel")
        sub, own = subject(identity), owner(identity)
        tenant = lookup(self.tenants, sub, self.tenant)

        def fn(tx, _):
            out = dict(res, errors=list(res["errors"]))
            for tid, per_span in traces.items():
                key = (tenant, signer_otel.run_id(tid))
                run = self.log.runs.get(key)
                if run is None:
                    n = self.log.open_runs.get(own, 0)
                    self.quotas.check_count("open_runs", n)
                    run = tx.new_run(*key)
                    for k, v in (("owner", own), ("source", "import"), ("rec", None), ("spans", {})):
                        tx.set(run, k, v)
                    tx.set(self.log.open_runs, own, n + 1)
                    tx.emit(run, "run.registered", {
                        "agent": {"name": agents[tid]}, "signer_isolation": "unknown", "fidelity": "none",
                        "identity": {"scheme": identity.scheme, "subject": identity.subject[:256],
                                     "attested": identity.attested}}, tier=signer_otel.TIER)
                elif run["source"] != "import" or run["final"]:
                    out["rejected"] += len(per_span)
                    out["errors"].append(f"trace {tid}: " + ("its run is final" if run["final"] else
                                                             "a run of that id was registered over RPC"))
                    continue
                tx.set(run, "active", time.monotonic())
                for recs in per_span:
                    new = [(typ, data, sid) for typ, data, sid in recs if f"{sid}:{typ}" not in run["spans"]]
                    out["accepted" if new else "duplicate"] += 1
                    for typ, data, sid in new:
                        tx.emit(run, typ, data, tier=signer_otel.TIER, span_id=sid)
                        tx.set(run["spans"], f"{sid}:{typ}", True)
            return out
        try:
            # lean: one event-rate token per request (at most max_spans spans); a token per span if imports need a
            # finer rate limit than events_per_s * max_spans
            self.quotas.take_event(identity)
            return self.log.submit(identity, OTLP_IMPORT, {}, fn)
        except RPCError as e:   # a quota or the storage: the exporter keeps the batch and retries
            self._refused(identity, e)
            return dict(res, retryable=True, errors=[e.message])


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
    if "socket_mode" in cfg and not re.fullmatch(r"0?[0-7]{3}", str(cfg["socket_mode"])):
        raise ValueError(f'{path}: socket_mode is an octal mode such as "0666"')
    base = os.path.dirname(os.path.abspath(path))
    for k in ("data_dir", "socket", "tcp_endpoint", "policy"):
        if cfg.get(k):
            cfg[k] = os.path.join(base, cfg[k])
    h = cfg.get("http")
    if h is not None:
        from tracekit.transport import http
        for section in (h, h.get("k8s_sa")) if isinstance(h, dict) else ():
            for k in ("cert", "key", "token_file", "ca"):
                if isinstance(section, dict) and isinstance(section.get(k), str) and section[k]:
                    section[k] = os.path.join(base, section[k])
        if isinstance(h, dict) and isinstance(h.get("client_ca"), dict):
            h["client_ca"] = {td: os.path.join(base, p) if isinstance(p, str) else p for td, p in h["client_ca"].items()}
        http.configure(h)   # validates the section now; serve() builds it again
    if "storage" in cfg:
        pg = cfg["storage"].get("postgres") if isinstance(cfg["storage"], dict) and set(cfg["storage"]) == {"postgres"} else None
        if not (isinstance(pg, dict) and set(pg) <= {"dsn_file"} and isinstance(pg.get("dsn_file", ""), str)):
            raise ValueError(f"{path}: storage is {{postgres: {{dsn_file}}}} (the DSN in a file, never inline)")
        if pg.get("dsn_file"):
            pg["dsn_file"] = os.path.join(base, pg["dsn_file"])
    if "log_key" in cfg:
        # lean: AWS KMS only; GCP Cloud KMS (EC_SIGN_ED25519, software-protected) through its REST API once a
        # deployment asks for it
        lk = cfg["log_key"]
        kms = lk.get("aws_kms") if isinstance(lk, dict) and set(lk) == {"aws_kms"} else None
        if not (isinstance(kms, dict) and set(kms) == {"key_id", "region"}
                and all(isinstance(v, str) and v for v in kms.values())):
            raise ValueError(f"{path}: log_key is {{aws_kms: {{key_id, region}}}} (default: keys/log.key)")
    approvals = cfg.get("approvals") if isinstance(cfg.get("approvals"), dict) else {}
    for table in (cfg.get("tenants"), cfg.get("authorize"), approvals.get("approvers"), approvals.get("break_glass")):
        for k in table or ():
            if "*" in str(k) and not (str(k).endswith(PREFIX_ENDS) and str(k).count("*") == 1):
                raise ValueError(f"{path}: {k!r}: a prefix key must end in :* or /*")
    names = set()
    for w in cfg.get("witnesses") or ():
        if not (isinstance(w, dict) and set(w) == {"url", "vkey", "class"} and w["class"] in CLASSES):
            raise ValueError(f"{path}: each witness is {{url, vkey, class}}, class one of {', '.join(CLASSES)}")
        name = TlogWitness(w["url"], w["vkey"]).name   # a cosignature vkey
        if name in names:
            raise ValueError(f"{path}: two witnesses named {name}")
        names.add(name)
    if "anchors" in cfg:
        r = cfg["anchors"].get("rekor") if isinstance(cfg["anchors"], dict) and set(cfg["anchors"]) == {"rekor"} else None
        if not (isinstance(r, dict) and {"signing_config", "trusted_root"} <= set(r) <= {"signing_config", "trusted_root",
                                                                                      "every_s"}
                and all(isinstance(r[k], str) and r[k] for k in ("signing_config", "trusted_root"))
                and isinstance(r.get("every_s", rekor2.MIN_EVERY_S), (int, float))
                and r.get("every_s", rekor2.MIN_EVERY_S) >= rekor2.MIN_EVERY_S):
            raise ValueError(f"{path}: anchors is {{rekor: {{signing_config, trusted_root, every_s}}}}, every_s at least "
                             f"{rekor2.MIN_EVERY_S:g}")
        r.update({k: os.path.join(base, r[k]) for k in ("signing_config", "trusted_root")})
    return cfg


def signer_config(path=None):
    """The config at `path`, or the same-user dev signer's (data_dir and socket)."""
    if path:
        return load_config(path)
    from tracekit.sdk.autospawn import SOCK, runtime_dir
    return {"data_dir": dev_data_dir(), "socket": os.path.join(runtime_dir(), SOCK)}


def file_store(cfg, cmd):
    """data_dir/store, for `cmd`, which reads the file store without the signer; refuses a config with a storage section."""
    # lean: reveal, export --v2 and view read the file store only; read through PostgresStorage once central signers
    # need them
    if cfg.get("storage"):
        raise ValueError(f"{cmd} reads the file store only, and this config names a postgres store")
    return os.path.join(cfg["data_dir"], "store")


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


def read_rekor_pub(data_dir):
    """The Rekor publishing key (base64 SPKI) the signer of `data_dir` wrote on start."""
    d = files.open_dir(data_dir)
    try:
        data = files.read(d, "rekor.pub")
    finally:
        files.close(d)
    if data is None:
        raise ValueError(f"{data_dir} has no rekor.pub yet: start the signer with anchors once")
    return data.decode("ascii").strip()


def open_service(cfg, **kw):
    if cfg.get("policy"):
        kw.setdefault("policy", load_policy(cfg["policy"]))
    kw.setdefault("witnesses", [TlogWitness(w["url"], w["vkey"]) for w in cfg.get("witnesses", ())])
    if cfg.get("log_key") and "log_key" not in kw:
        kw["log_key"] = logkey.from_config(cfg["log_key"])
    return SignerService(cfg["data_dir"], durability=cfg.get("durability", ACK_ON_WRITE),
                         tenant=cfg.get("tenant", "default"), tenants=cfg.get("tenants"),
                         limits=Limits(**cfg.get("limits", {})),
                         acknowledge_rollback=bool(cfg.get("acknowledge_rollback")),
                         multi_tenant_apps=cfg.get("multi_tenant_apps", ()), migrators=cfg.get("migrators", ()),
                         analyzers=cfg.get("analyzers", ()), fail_modes=cfg.get("fail_modes"),
                         grace_s=float(cfg.get("grace_s", GRACE_S)), idle_s=float(cfg.get("idle_s", IDLE_S)),
                         origin=cfg.get("origin"), contact=cfg.get("contact"), approvals=cfg.get("approvals") or {},
                         authorize=cfg.get("authorize"), lock_timeout_s=float(cfg.get("lock_timeout_s", LOCK_TIMEOUT_S)),
                         fsck_every_s=float(cfg.get("fsck_every_s", FSCK_S)),
                         clock_skew_s=float(cfg.get("clock_skew_s", CLOCK_SKEW_S)),
                         rekor=(cfg.get("anchors") or {}).get("rekor"), otlp=cfg.get("otlp"),
                         otel_out=cfg.get("otel_out"), storage_config=cfg.get("storage"), **kw)


def serve(cfg, service):
    """Bind the configured transports for `service` (whose storage lock is already held) and start answering.
    Returns the servers; stop each with shutdown() and server_close()."""
    if not (cfg.get("socket") or cfg.get("tcp_endpoint") or cfg.get("http")):
        raise ValueError("configure socket, tcp_endpoint and/or http")
    if "otlp" in cfg and not cfg.get("http"):
        raise ValueError("otlp is served on the http listener: configure http")
    servers = [metrics.server(cfg["metrics"], service.metrics, service.logs_list,
                              lambda p: service.tlog(p, cfg["metrics"].get("serve_records") is True))
               ] if "metrics" in cfg else []
    handle = answering_hello(service.handle_frame, hello())
    if cfg.get("socket"):
        from tracekit.transport.unix import UnixServer
        try:
            os.unlink(cfg["socket"])   # a dead signer's socket: safe to remove, this process holds the storage lock
        except FileNotFoundError:
            pass
        servers.append(UnixServer(cfg["socket"], handle))
        if cfg.get("socket_mode"):
            os.chmod(cfg["socket"], int(str(cfg["socket_mode"]), 8))
    if cfg.get("tcp_endpoint"):
        from tracekit.transport.tcp_dev import TcpDevServer
        servers.append(TcpDevServer(cfg["tcp_endpoint"], _dev_token(), handle))
    if cfg.get("http"):
        from tracekit.transport import http
        servers.append(http.HttpServer(*http.configure(cfg["http"]), handle,
                                       otlp=service.otlp if "otlp" in cfg else None))
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

    logkey.harden()

    def open_handler():
        service = SignerService(dev_data_dir(), isolation="same-user", fsck_every_s=0)
        return service.handle_frame, service.close
    try:
        return serve_dev(runtime_dir(), open_handler, idle_s=float(os.environ.get("TRACEKIT_DEV_IDLE", 900)))
    except BlockingIOError:
        print(f"tracekit signer: another signer holds {dev_data_dir()}", file=sys.stderr)
    except Exception as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
    return 1


def fsck(data_dir, upto=None, storage=None):
    """Every problem in the store (the `storage` config section's, else data_dir/store): the storage check (hashes,
    chains) plus every record's signature. `upto`: see storage.file.fsck (a Postgres check reads one consistent
    snapshot instead)."""
    keys = os.path.join(data_dir, "keys")
    with open(os.path.join(keys, "record.key"), "rb") as f:
        sign = RecordSigner(f.read())
    verify = functools.partial(verify_record, keys=[sign.spki], algs={sign.alg})
    if storage:
        from tracekit.storage import postgres
        return postgres.fsck(postgres.read_dsn(storage["postgres"]), _snapshot_key(keys), verify)
    return fsck_store(os.path.join(data_dir, "store"), upto, _snapshot_key(keys), verify)


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
    sub.add_parser("migrate", help="create or check the Postgres store's tables").add_argument("--config", required=True)
    sub.add_parser("close-log", help="close the log for good: write log.closed and the final notes (signer stopped)"
                   ).add_argument("--config", required=True)
    for name, text in (("vkey", "print the log key's verifier key (C2SP vkey)"),
                       ("trust", "write a v2 trust config that pins the log key and the configured witnesses")):
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
            cfg = signer_config(a.config)
            file_store(cfg, "reveal")
            print(json.dumps(reveal(cfg["data_dir"], a.record)))
        except (OSError, ValueError) as e:
            print(f"tracekit signer: {e}", file=sys.stderr)
            return 2
        return 0
    if a.cmd in ("vkey", "trust"):
        from tracekit.sdk.client import SignerUnavailable
        try:
            cfg = signer_config(a.config)
            vkey = read_vkey(cfg["data_dir"])
            if a.cmd == "trust":
                witnesses = [{"vkey": w["vkey"], "class": w["class"]} for w in cfg.get("witnesses") or ()]
                rekor = (cfg.get("anchors") or {}).get("rekor")
                if rekor:
                    with open(rekor["trusted_root"], "rb") as f:
                        rekor = {"trusted_root": json.loads(f.read()), "publishing_key": read_rekor_pub(cfg["data_dir"]),
                                 "class": "public"}
                files.write_json(a.out, {"logs": [vkey], "witnesses": witnesses, "algs": [RecordSigner.alg],
                                         "witnesses_required": 0, **({"rekor": rekor} if rekor else {})}, 0o644)
        except (OSError, ValueError, SignerUnavailable) as e:
            print(f"tracekit signer: {e}", file=sys.stderr)
            return 2
        print(vkey if a.cmd == "vkey" else f"wrote {a.out}: pins log {vkey.split('+')[0]} and "
              f"{len(witnesses) or 'no'} witness(es)")
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
            print(json.dumps(format_bridge.bridge(a.v1_home, cfg["data_dir"], cfg.get("storage"))))
        except (OSError, ValueError, StorageUnavailable, format_bridge.BridgeError) as e:
            print(f"tracekit signer bridge: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "migrate":
        if not cfg.get("storage"):
            print("tracekit signer migrate: the config has no storage: {postgres: ...} section", file=sys.stderr)
            return 2
        from tracekit.storage import postgres
        try:
            print(f"schema version {postgres.migrate(postgres.read_dsn(cfg['storage']['postgres']))}")
        except (OSError, ValueError, StorageUnavailable) as e:
            print(f"tracekit signer migrate: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "fsck":
        try:
            problems = fsck(cfg["data_dir"], storage=cfg.get("storage"))
        except (OSError, ValueError, StorageUnavailable) as e:
            print(f"tracekit signer fsck: {e}", file=sys.stderr)
            return 2
        for p in problems:
            print(p)
        print("ok" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    if a.cmd == "serve":
        logkey.harden()   # before any key is read
    try:
        service = open_service(cfg)
    except BlockingIOError as e:
        print(f"tracekit signer: {e.strerror}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 1
    if a.cmd == "close-log":
        try:
            service.close_log()
        except (RPCError, StorageUnavailable, OSError) as e:
            print(f"tracekit signer close-log: {e}", file=sys.stderr)
            return 1
        finally:
            service.close()
        print(f"log closed at seq {service.log.head['seq'] - 1}")
        return 0
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
