"""The v2 signer service: `SignerService` implements `SignerAPI` over the record log's single writer (pipeline.py).

    tracekit signer serve --config signer.yaml
    tracekit signer serve --dev               # the same-user dev signer clients auto-spawn (decision S3)
    tracekit signer fsck  --config signer.yaml

signer.yaml:
    data_dir: /var/lib/tracekit-signer      # keys/ and store/; relative paths are from the config file
    socket: /run/tracekit/signer.sock        # Unix socket transport (peer uid, per frame on Linux)
    tcp_endpoint: /run/tracekit/endpoint.json   # loopback TCP dev transport (token, mutual HMAC)
    durability: ack-on-write                 # or ack-on-fsync
    tenant: default                          # tenant of callers not in `tenants`
    tenants: {"uid:1001": acme}              # identity -> tenant (recorded as attested)
    limits: {events_per_s: 200, burst: 400}  # tracekit.signer.quotas.Limits
    acknowledge_rollback: false

Startup (04-design §2.6): the storage lock is taken before any socket is touched; the log is replayed, its chain
checked and its tail signatures verified; then the configured witnesses are asked for their latest cosigned checkpoint.
A witness is any object with `latest() -> (tree_size, root_bytes)` that raises when unreachable. A local log behind the
witnessed one is a rollback: a signed `trace.tamper{rollback}`, then client writes are refused until it is
acknowledged. No witness reachable: a signed `degraded_unanchored` gap, and the signer runs.

Policy, approvals and checkpoints are stubs that keep the contract until M1a-09cef: `decide` allows, except one visible
demo deny rule; any identity may answer an approval and self-approval is labelled; `checkpoint_nudge` schedules nothing.
"""
import argparse
import datetime
import hashlib
import os
import pathlib
import secrets
import signal
import socket
import sys
import threading
import time

import rfc8785

from tracekit import __version__, crypto, yamlmini
from tracekit.format.canon import StrictJSONError, canonical, event_hash, loads_strict
from tracekit.format.records import RecordError, RecordSigner, verify_record
from tracekit.identity.base import CallerIdentity
from tracekit.locking import lock_file
from tracekit.signer import rpc_schema
from tracekit.signer.pipeline import RecordLog, subject
from tracekit.signer.quotas import Limits, Quotas
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.signer.runtoken import RunTokens
from tracekit.storage.base import ACK_ON_WRITE, StorageUnavailable
from tracekit.storage.file import FileStorage, _mkdir
from tracekit.storage.file import fsck as fsck_store
from tracekit.transport import answering_hello, hello

DEMO_DENY_TOOL = "tracekit_demo_denied"
STUB_POLICY_HASH = event_hash({"policy": "tracekit-stub", "deny_tools": [DEMO_DENY_TOOL]})
APPROVAL_TTL_S = 3600
REFUSAL_WINDOW_S = 60
CONFIG_KEYS = {"data_dir", "socket", "tcp_endpoint", "durability", "tenant", "tenants", "limits", "acknowledge_rollback"}


def demo_rule(tool, args):
    """The stub policy: allow everything except the tool `tracekit_demo_denied`, so a deny is easy to see."""
    return ("deny", ["TK-DEMO-DENY"]) if tool == DEMO_DENY_TOOL else ("allow", [])


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ref(value):
    c = canonical(value)
    return {"hash": "sha256:" + hashlib.sha256(c).hexdigest(), "size": len(c), "redacted": False}


def _secret(path, make):
    """The secret in `path`, created (0600) on first use. Called under the storage lock, so never by two signers."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        pass
    data = make()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return data


def _process_identity():
    return CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)


class SignerService:
    def __init__(self, data_dir, rule=demo_rule, identity=None, tenant="default", tenants=None, limits=Limits(),
                 durability=ACK_ON_WRITE, witnesses=(), acknowledge_rollback=False, open_storage=None, isolation=None):
        """`identity` answers the in-process SignerAPI calls (default: this process's uid); transports call
        handle_frame with the identity they established. `open_storage()` defaults to file storage in data_dir/store.
        `isolation` fixes the signer_isolation label of every run (a dev signer: same-user)."""
        open_storage = open_storage or (lambda: FileStorage(os.path.join(data_dir, "store"), durability))
        storage = open_storage()   # takes the storage lock before anything else
        try:
            keys = os.path.join(data_dir, "keys")
            _mkdir(keys)
            os.chmod(keys, 0o700)
            sign = RecordSigner(_secret(os.path.join(keys, "record.key"), lambda: crypto.generate()[0]))
            self.tokens = RunTokens(_secret(os.path.join(keys, "run_token.key"), lambda: os.urandom(32)))
            self.quotas = Quotas(limits)
            self.log = RecordLog(storage, open_storage, sign, self.quotas)
        except BaseException:
            storage.close()
            raise
        self.rule, self.identity, self.isolation = rule, identity or _process_identity(), isolation
        self.tenant, self.tenants = tenant, dict(tenants or {})
        self._approvals = {}   # approval_id -> {"run_key", "tool_call_id", "args_digest", "rule_ids", "state", ...}
        self._cond = threading.Condition()
        self._refusals, self._refusals_lock = {}, threading.Lock()
        self._stop = threading.Event()
        try:
            self._check_witnesses(witnesses, acknowledge_rollback)
        except BaseException:
            self.log.close()
            raise
        self._flusher = threading.Thread(target=self._flush_loop, name="tracekit-signer-refusals", daemon=True)
        self._flusher.start()

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
            errs = rpc_schema.validate(REQUESTS[method], req)
            if errs:
                raise RPCError("invalid_request", "; ".join(errs))
            self.quotas.check_strings(req)
            return getattr(self, "_" + method)(identity, req)
        except RPCError as e:
            now, k = time.time(), (identity.scheme, identity.subject, e.code)
            with self._refusals_lock:
                first, _, n = self._refusals.get(k, (now, now, 0))
                self._refusals[k] = (first, now, n + 1)
            raise

    def _flush_loop(self):
        while not self._stop.wait(REFUSAL_WINDOW_S):
            self.flush_refusals()

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
        self._stop.set()
        self._flusher.join()
        self.flush_refusals()
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
        a = self._approvals.get(approval_id)
        if a is None or a["run_key"] != key:
            raise RPCError("unknown_approval", approval_id)
        return a

    @staticmethod
    def _isolation(identity):
        if identity.scheme == "uid" and hasattr(os, "getuid"):
            return "same-user" if identity.subject == str(os.getuid()) else "separate-user"
        return "unknown"

    # --- methods ---

    def _register_run(self, identity, req):
        sub = subject(identity)
        tenant = req.get("tenant") or self.tenants.get(sub, self.tenant)
        run_id = req.get("run_id") or secrets.token_hex(16)

        def fn(tx, _):
            if (tenant, run_id) in self.log.runs:
                raise RPCError("run_exists", run_id)
            # lean: counts by scanning every run, O(runs); keep a per-owner counter when runs reach the thousands
            self.quotas.check_count("open_runs", sum(r["owner"] == sub and not r["closed"]
                                                     for r in self.log.runs.values()))
            run = tx.new_run(tenant, run_id)
            tx.set(run, "owner", sub)
            out = {"run_id": run_id, "run_token": self.tokens.issue(tenant, run_id, identity), "tenant": tenant,
                   "tenant_attested": "tenant" not in req, "principal_attested": False}
            top = {"tenant_attested": out["tenant_attested"], "principal_attested": False}
            if "principal" in req:
                out["principal"] = top["principal"] = req["principal"]
            tx.emit(run, "run.registered", {
                "agent": req["agent"], "signer_isolation": self.isolation or self._isolation(identity),
                "identity": {"scheme": identity.scheme, "subject": identity.subject[:256], "attested": identity.attested}},
                request_id=req["request_id"], **top)
            return out
        return self.log.submit(identity, "register_run", req, fn)

    def _decide(self, identity, req):
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)
        try:
            args = loads_strict(req["args"]) if req["args_source"] == "raw" else req["args"]
            digest = event_hash({"tool": req["tool"], "args": args})
        except (StrictJSONError, rfc8785.CanonicalizationError):
            digest = None
        ruled = self.rule(req["tool"], args) if digest and "approval_id" not in req else None
        tcid = req["tool_call_id"]

        def fn(tx, run):
            a = self._approval(key, req["approval_id"]) if "approval_id" in req else None
            if digest is None:
                decision, rule_ids = "deny", ["TK-ARGS-INVALID"]
            elif a is None:
                decision, rule_ids = ruled
            elif a["tool_call_id"] != tcid or a["args_digest"] != digest:
                decision, rule_ids = "deny", ["TK-APPROVAL-MISMATCH"]
            else:
                decision, rule_ids = {"approved": ("allow", ["TK-APPROVED"]), "requested": ("ask", a["rule_ids"])
                                      }.get(a["state"], ("deny", ["TK-APPROVAL-" + a["state"].upper()]))
            tx.set(run["calls"], tcid, {"args_digest": digest, "decision": decision, "rule_ids": rule_ids})
            seq = tx.event(run, req, "policy.decision", {"tool_use_id": tcid, "tool": req["tool"], "decision": decision,
                                                         "rule_ids": rule_ids, "policy_hash": STUB_POLICY_HASH},
                           tool_call_id=tcid, attempt=req.get("attempt", 0), args_source=req["args_source"])
            if decision == "allow" and a is not None:
                tx.set(a, "state", "consumed")
                tx.emit(run, "approval.consumed", {"approval_id": req["approval_id"]}, source="signer")
            return {"decision": decision, "rule_ids": rule_ids, "run_seq": seq}
        return self.log.submit(identity, "decide", req, fn, key)

    def _event(self, identity, method, req, typ, data, need_call=False, **top):
        key = self._authorize(identity, req)
        self.quotas.take_event(identity)

        def fn(tx, run):
            if need_call and req["tool_call_id"] not in run["calls"]:
                raise RPCError("unknown_tool_call", req["tool_call_id"])
            return {"run_seq": tx.event(run, req, typ, data, **top)}
        return self.log.submit(identity, method, req, fn, key)

    def _complete(self, identity, req):
        try:
            output = _ref({k: req[k] for k in ("result", "error") if k in req})
        except rfc8785.CanonicalizationError as e:
            raise RPCError("invalid_request", f"result is not canonical JSON: {e}") from None
        return self._event(identity, "complete", req, "tool.result",
                           {"tool_use_id": req["tool_call_id"], "ok": req["status"] == "ok", "output": output},
                           need_call=True, tool_call_id=req["tool_call_id"], attempt=req.get("attempt", 0))

    def _state_write(self, identity, req):
        return self._event(identity, "state_write", req, "state.write",
                           {"store": "default", "key": req["key"], "digest": req["value_digest"]})

    def _model_event(self, identity, req):
        data = {"exchange_id": req["request_id"], "phase": req["phase"], "streamed": False, "model": req["model"],
                "upstream": req["provider"]}
        if "content_digest" in req:
            data["content_digest"] = req["content_digest"]
        if len(req.get("usage", {})) == 2:   # the event schema needs both counts
            data["usage"] = req["usage"]
        return self._event(identity, "model_event", req, "model.exchange", data)

    def _approval_request(self, identity, req):
        key, tcid, sub = self._authorize(identity, req), req["tool_call_id"], subject(identity)

        def fn(tx, run):
            call = run["calls"].get(tcid)
            if call is None or call["decision"] != "ask":
                raise RPCError("unknown_tool_call", f"{tcid} has no pending `ask` decision")
            self.quotas.check_count("pending_approvals", sum(a["requester"] == sub and a["state"] == "requested"
                                                             for a in self._approvals.values()))
            aid, expires_at = "apr-" + secrets.token_hex(16), _iso(time.time() + APPROVAL_TTL_S)
            # lean: the stub records expires_at but never expires an approval; the approvals task enforces it
            tx.set(self._approvals, aid, {"run_key": key, "tool_call_id": tcid, "args_digest": call["args_digest"],
                                          "rule_ids": call["rule_ids"], "state": "requested", "requester": sub})
            tx.emit(run, "approval.request", {"approval_id": aid, "policy_hash": STUB_POLICY_HASH,
                                              "rule_ids": call["rule_ids"], "expires_at": expires_at, "requester": sub},
                    request_id=req["request_id"], tool_call_id=tcid)
            return {"approval_id": aid, "state": "requested", "expires_at": expires_at}
        return self.log.submit(identity, "approval_request", req, fn, key)

    def _approval_decide(self, identity, req):
        a = self._approvals.get(req["approval_id"])
        if a is None:
            raise RPCError("unknown_approval", req["approval_id"])
        sub = subject(identity)

        def fn(tx, run):
            if a["state"] != "requested":
                raise RPCError("approval_not_pending", a["state"])
            tx.set(a, "state", "approved" if req["decision"] == "approve" else "rejected")
            same = a["requester"] == sub
            tx.emit(run, "approval", {"tool_use_id": a["tool_call_id"], "decision": req["decision"], "approver": sub,
                                      "channel": "rpc", "same_user": same},
                    request_id=req["request_id"], tool_call_id=a["tool_call_id"])
            return {"approval_id": req["approval_id"], "state": a["state"], "self_approved": same}
        out = self.log.submit(identity, "approval_decide", req, fn, a["run_key"])
        with self._cond:
            self._cond.notify_all()
        return out

    def _approval_wait(self, identity, req):
        a = self._approval(self._authorize(identity, req), req["approval_id"])
        with self._cond:
            self._cond.wait_for(lambda: a["state"] != "requested", req.get("timeout_ms", 0) / 1000)
        return {"approval_id": req["approval_id"], "state": a["state"]}

    def _close_run(self, identity, req):
        key = self._authorize(identity, req)

        def fn(tx, run):
            tx.set(run, "closed", True)
            return {"run_id": req["run_id"], "state": "closing",
                    "run_seq": tx.emit(run, "run.closing", {"reason": "close_run"}, request_id=req["request_id"])}
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
        return {"scheduled": False}   # no checkpointer yet (04-design §2.9)


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
    for k in ("data_dir", "socket", "tcp_endpoint"):
        if cfg.get(k):
            cfg[k] = os.path.join(base, cfg[k])
    return cfg


def open_service(cfg, **kw):
    # lean: no witness client until the checkpointer exists (04-design §2.9); pass witnesses= in process meanwhile
    return SignerService(cfg["data_dir"], durability=cfg.get("durability", ACK_ON_WRITE),
                         tenant=cfg.get("tenant", "default"), tenants=cfg.get("tenants"),
                         limits=Limits(**cfg.get("limits", {})),
                         acknowledge_rollback=bool(cfg.get("acknowledge_rollback")), **kw)


def serve(cfg, service):
    """Bind the configured transports for `service` (whose storage lock is already held) and start answering.
    Returns the servers; stop each with shutdown() and server_close()."""
    servers, handle = [], answering_hello(service.handle_frame, hello())
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
    if not servers:
        raise ValueError("configure socket and/or tcp_endpoint")
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
        # lean: the Windows transport follows S3 but no client speaks it yet (sdk/client.py connect); test it with one
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
    # lean: no v2 checkpointer yet (04-design §2.9), so there is no final checkpoint to write; write it here first
    for p in (endpoint, sock):
        pathlib.Path(p).unlink(missing_ok=True)
    server.shutdown()
    server.server_close()
    close()
    return 0


def _serve_dev():
    from tracekit.sdk.autospawn import runtime_dir

    def open_handler():
        service = SignerService(dev_data_dir(), isolation="same-user")
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


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit signer", description="the v2 signer service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    mode = sub.add_parser("serve", help="run the signer in the foreground").add_mutually_exclusive_group(required=True)
    mode.add_argument("--config")
    mode.add_argument("--dev", action="store_true",
                      help="the same-user dev signer of the runtime dir ($TRACEKIT_RUNTIME_DIR); clients start it")
    sub.add_parser("fsck", help="check every record of the store").add_argument("--config", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "serve" and a.dev:
        return _serve_dev()
    try:
        cfg = load_config(a.config)
    except (OSError, ValueError) as e:
        print(f"tracekit signer: {e}", file=sys.stderr)
        return 2
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
