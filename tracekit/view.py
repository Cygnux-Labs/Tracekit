"""`tracekit view`: the laptop viewer for the v2 signer's runs (04-design §10).

Reads the signer's store without its lock (signer.service.reader: FileReader, or PostgresReader for a Postgres store),
exports each run with bundle_v2 and checks it with verify.v2, the code `tracekit verify` runs, against a trust config
that pins --log-vkey, else the store's own log key (data_dir/log.vkey, or on Postgres the vkey the signer stored there,
so the viewer needs no access to the signer's data dir). The page, server
and security are the observer's (observe.py): each run's verifier report is an alert on the run's lane, followed by its
events only when it verifies; a run that fails is shown only as the failure report. A run whose last record no
checkpoint covers yet waits for the signer's next note (at most CHECKPOINT_S). The viewer never opens a signing key.
Every request needs the token in the printed URL ($TRACEKIT_VIEW_TOKEN, else a random one), exchanged once for a
session cookie, also on loopback, where any local user or process could otherwise connect. With the config's
`view.oidc` section, /login also signs people in with an issuer of its `http.oidc` section (OidcLogin; docs/identity.md):
a session of the auditor or approver role sees, read-only, the runs of its tenant (the issuer's tenant claim) only, and
one of the operator-admin role every tenant's. With `view.logs` (the DSN file of each log of a central deployment, for
a SELECT-only role) the viewer serves the run pages of every log instead (Runs; docs/viewer.md).
With `view.signer` (the signer's address, as `tracekit approvals --signer` takes it), an approver's session also gets
the approval pages (/approvals; ApprovalDesk): the viewer answers for that person over the signer RPC as a bridge
identity (`authorize` grants it approval_decide_on_behalf), and the signer decides who may answer, verifies the passkey of a
`passkey: required` rule and records both the person and the viewer.

Dev assurance: the pinned log key is read from the directory being checked, so a run that verifies matches the key of
whoever can write that directory, the same user as the dev signer and this viewer.

    tracekit view [--dev | --config signer.yaml | --data-dir DIR] [--log-vkey VKEY] [--host H] [--port N]
                  [--tls-cert FILE --tls-key FILE | --insecure-http]
"""
import argparse
import atexit
import base64
import collections
import hashlib
import hmac
import io
import itertools
import logging
import json
import os
import secrets
import shutil
import ssl
import sys
import tempfile
import threading
import time
from http.client import HTTPException
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode, urlsplit

from . import observe
from .bundle_v2 import export
from .format import checkpoint
from .format.records import RecordSigner
from .identity import oidc, webauthn
from .identity.k8s_sa import _https
from .sdk.client import Client, Incompatible, SignerUnavailable
from .signer.rpc_schema import RPCError
from .signer.service import dev_data_dir, load_config, lookup, read_vkeys, reader
from .storage.base import StorageCorrupt, StorageUnavailable
from .storage.file import NOTE
from .verify import v2

POLL_S = 1.0
HANDSHAKE_S = 30
DEV_NOTE = ("trust pins this store's own log.vkey: dev assurance, the viewer runs as the same user as the dev signer "
            "and proves only that the records match that key")
STORED_NOTE = ("trust pins the log vkey this store holds and proves only that the records match that key; pin the "
               "signer's with --log-vkey")
OPERATOR_SIDE = "operator-side view — re-verify with the signed release for evidence"
LOGIN_KEYS = {"issuer", "client_id", "client_secret_file", "redirect_uri", "roles"}
ROLES = ("auditor", "approver", "operator-admin")
RUNS_PAGE, RECORDS_PAGE, VERDICTS_MAX = 50, 500, 4096
SEARCH_KEYS = {"tenant", "run", "agent", "since", "until", "verdict", "gaps", "denies", "approvals", "after", "limit"}
VERDICTS = ("verified", "failed", "pending")
LOGIN_S, SESSION_S, PENDING_MAX, SESSIONS_MAX = 600, 8 * 3600, 1024, 4096
log = logging.getLogger(__name__)


class OidcLogin:
    """Authorization code + PKCE (S256) login with the issuer `section["issuer"]` names in `issuers` (the signer's
    http.oidc section), its ID token's audience the client_id. A person whose identity keys (oidc.keys) are in
    roles.auditor or roles.approver and whose token carries the issuer's tenant claim gets a session of that tenant;
    an approver's session also answers approvals (ApprovalDesk), with the session's CSRF token. One in
    roles.operator-admin gets a read-only session of every tenant."""

    def __init__(self, section, issuers, clock=time.time):
        if not isinstance(section, dict) or set(section) - LOGIN_KEYS or not {"issuer", "client_id", "redirect_uri",
                                                                                "roles"} <= set(section):
            raise ValueError("view.oidc: {issuer, client_id, redirect_uri, roles, client_secret_file?}")
        alias, roles = section["issuer"], section["roles"]
        if not isinstance(issuers, dict) or not isinstance(issuers.get(alias), dict):
            raise ValueError(f"view.oidc.issuer: {alias!r} is not an issuer alias of http.oidc")
        if not (isinstance(roles, dict) and roles and set(roles) <= set(ROLES)
                and all(isinstance(v, list) for v in roles.values())):
            raise ValueError(f"view.oidc.roles: {{{', '.join(ROLES)}: [identity, person:<id>, group:<alias>/<name>]}}")
        if not str(section["redirect_uri"]).startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError("view.oidc.redirect_uri: an https:// URL (http:// on loopback only)")
        self.issuer = oidc.Issuer(alias, clock=clock, **dict(issuers[alias], audience=section["client_id"]))
        self.client_id, self.redirect_uri, self.clock = section["client_id"], section["redirect_uri"], clock
        self.roles = {r: {k: True for k in v} for r, v in roles.items()}
        self.secret = None
        if section.get("client_secret_file"):
            with open(section["client_secret_file"], encoding="utf-8") as f:
                self.secret = f.read().strip()
        self._lock = threading.Lock()
        # lean: sessions live in this process (a restart signs everyone out); a shared store once viewers are replicated
        self._pending, self._sessions = collections.OrderedDict(), collections.OrderedDict()

    def _endpoint(self, name):
        url = self.issuer.document().get(name)
        if not (isinstance(url, str) and url.startswith("https://")):
            raise ValueError(f"the issuer's {name} is not an https:// URL")
        return url

    def start(self):
        """(the issuer's authorization URL, state) for a new login."""
        url = self._endpoint("authorization_endpoint")
        state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        with self._lock:
            self._pending[state] = (verifier, nonce, self.clock() + LOGIN_S)
            while len(self._pending) > PENDING_MAX:
                self._pending.popitem(last=False)
        return url + ("&" if "?" in url else "?") + urlencode({
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
            "scope": "openid", "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256"}), state

    def finish(self, state, code, browser_state):
        """The session id of a login that `state` (also the browser's login cookie) and `code` complete, else None."""
        if not (state and code and hmac.compare_digest(state.encode(), browser_state.encode())):
            return None
        with self._lock:
            verifier, nonce, until = self._pending.pop(state, (None, None, 0))
        if self.clock() >= until:
            return None
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                "client_id": self.client_id, "code_verifier": verifier}
        if self.secret:
            form["client_secret"] = self.secret
        try:
            answer = _https("POST", self._endpoint("token_endpoint"), self.issuer.ctx, urlencode(form),
                            {"Content-Type": "application/x-www-form-urlencoded"})
            identity = self.issuer.verify(answer["id_token"], nonce)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, HTTPException, RPCError) as e:
            log.warning("viewer login refused: %s", e)
            return None
        keys = oidc.keys(identity)
        role = next((r for r in ("approver", "operator-admin", "auditor")
                     if any(lookup(self.roles.get(r, {}), k, False) for k in keys)), None)
        tenant = identity.claims.get("tenant")
        if role is None or tenant is None and role != "operator-admin":
            log.warning("viewer login refused: %s has %s", identity.subject[:256],
                        "no tenant claim" if role else "no viewer role")
            return None
        sid = secrets.token_urlsafe(32)
        person = {"subject": identity.subject[:256], "person": identity.claims["person"],
                  "groups": identity.claims["groups"], "tenant": tenant}
        with self._lock:
            self._sessions[sid] = {"tenant": observe.ALL if role == "operator-admin" else tenant, "role": role,
                                   "person": person, "csrf": secrets.token_urlsafe(32), "until": self.clock() + SESSION_S}
            while len(self._sessions) > SESSIONS_MAX:
                self._sessions.popitem(last=False)
        return sid

    def session(self, sid):
        """Session `sid` ({tenant, role, person, csrf, until}), else None."""
        with self._lock:
            s = self._sessions.get(sid)
            if s and self.clock() < s["until"]:
                return s
            self._sessions.pop(sid, None)
            return None

    def tenant(self, sid):
        """The tenant of session `sid` (observe.ALL for an operator-admin), else None."""
        s = self.session(sid)
        return s and s["tenant"]


class ApprovalDesk:
    """The approval pages' API, for an approver's session: the signer's approvals for that person (`on_behalf`), shown
    from the signer's copy, and their answers. `signer` has `call(method, req)` (sdk.client.Client); `webauthn` is the
    signer's approvals.webauthn section ({rp_id, origin}), or None."""
    ERRORS = {"invalid_request": 400, "forbidden": 403, "unknown_approval": 404, "approval_not_pending": 409}

    def __init__(self, signer, webauthn=None):
        self.signer, self.webauthn = signer, webauthn

    def _call(self, method, req):
        try:
            return 200, self.signer.call(method, req)
        except RPCError as e:
            return self.ERRORS.get(e.code, 502), {"error": e.message}
        except (OSError, SignerUnavailable, Incompatible):
            return 502, {"error": "signer unavailable"}

    def get(self, session, path):
        """(status, body) of GET `path`."""
        who = {"on_behalf": session["person"]}
        if path == "/api/session":
            return 200, {"csrf": session["csrf"], "person": session["person"]["person"],
                         "rp_id": self.webauthn and self.webauthn["rp_id"]}
        if path == "/api/approvals":
            return self._call("approval_list", who)
        if not path.startswith("/api/approvals/"):
            return 404, {"error": "not found"}
        aid = path[len("/api/approvals/"):]
        code, out = self._call("approval_get", {"approval_id": aid, **who})
        if code == 200 and out.get("passkey"):
            out["challenge"] = webauthn.b64url(webauthn.challenge(aid, out["binding_digest"], "approve"))
        return code, out

    def post(self, session, path, body):
        """(status, body) of POST `path` with JSON `body`: a passkey registration, or an answer to an approval."""
        who = {"on_behalf": session["person"]}
        if path == "/api/passkey":
            return self._call("passkey_register", {**who, **{k: body[k] for k in ("credential_id", "public_key")
                                                            if k in body}})
        if not path.startswith("/api/approvals/"):
            return 404, {"error": "not found"}
        return self._call("approval_decide", {"request_id": secrets.token_hex(16),
                                              "approval_id": path[len("/api/approvals/"):], **who,
                                              **{k: body[k] for k in ("decision", "reason", "passkey") if k in body}})


class Translator(observe.Translator):
    """v2 records -> the observer's record shape. A v2 policy.decision names its tool (there is no tool.call), and a
    type the observer has no row for is shown as an info alert, so every record of the run appears in order."""

    def feed(self, rec):
        e = rec["event"]
        t, d = e["type"], e.get("data") or {}
        if t == "run.registered":
            self.agent_names[e["run_id"]] = (d.get("agent") or {}).get("name") or "agent"
            return [{**self._base(e, rec, "SessionStart"), "source": f"{d.get('signer_isolation')} signer"}]
        if t in ("run.closing", "run.final"):
            return [{**self._base(e, rec, "SessionEnd"), "reason": d.get("reason") or t}]
        if t == "policy.decision":
            self.pending[d.get("tool_use_id")] = ({**e, "data": {"name": d.get("tool"), "tool_use_id": d.get("tool_use_id")}},
                                                  rec)
        return super().feed(rec) or [self.alert(e, rec, "info", t, json.dumps(d, ensure_ascii=False)[:200])]


class StoreFeed:
    """What observe.make_handler serves (records, base, lock, verify()), from the store of a v2 signer's config."""

    def __init__(self, cfg, log_vkey=None):
        self.cfg, self.pg = cfg, bool(cfg.get("storage"))
        self.store = "the Postgres store" if self.pg else os.path.join(cfg["data_dir"], "store")
        self.note = "trust pins --log-vkey" if log_vkey else STORED_NOTE if self.pg else DEV_NOTE
        if not log_vkey and self.pg:
            r = reader(cfg)
            try:
                log_vkey = r.meta("log_vkey")
            finally:
                r.close()
            if log_vkey is None:
                raise ValueError("the store holds no log vkey yet: start the signer once, or pass --log-vkey")
        vkeys = [log_vkey] if log_vkey else read_vkeys(cfg["data_dir"])   # a file store: the hybrid key's too
        for k in vkeys:
            checkpoint.parse_vkey(k)
        self.records, self.base, self.lock = [], 0, threading.Condition()
        self.runs = {}   # (tenant, run_id) -> {"count": records verified, "shown": records translated, "failed": report}
        self.tr = Translator()
        self.tmp = tempfile.mkdtemp(prefix="tk-view-")
        atexit.register(shutil.rmtree, self.tmp, True)
        self.trust = write_trust(os.path.join(self.tmp, "trust.json"), vkeys)
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self):
        seen = None
        while True:
            stamp = []
            for name in () if self.pg else ("records.jsonl", NOTE):
                try:
                    st = os.stat(os.path.join(self.store, name))
                    stamp.append((st.st_size, st.st_mtime_ns))
                except FileNotFoundError:
                    stamp.append(None)
            # lean: a Postgres store is read again every POLL_S; compare its latest note first if that loads the server
            if stamp != seen or self.pg:
                seen = stamp
                try:
                    self.refresh()
                except (OSError, ValueError, StorageCorrupt, StorageUnavailable) as e:
                    print(f"tracekit view: cannot read {self.store}: {e}", file=sys.stderr, flush=True)
            time.sleep(POLL_S)

    def refresh(self):
        """Verify every run that grew since it was last verified and a checkpoint now covers."""
        r = reader(self.cfg)
        try:
            note = r.checkpoint_latest()
            if note and note[0] > r.tree.size:
                r.close()
                r = reader(self.cfg)   # opened after the note: holds every record it covers
            for key, run in list(r.runs.items()):
                if note and run["seqs"][-1] < note[0] and len(run["seqs"]) != self.runs.get(key, {}).get("count"):
                    self._verify(r, note[1], key, len(run["seqs"]))
        finally:
            r.close()

    def _verify(self, reader, note, key, count):
        tenant, run_id = key
        rep, code, text = check(reader, tenant, run_id, note, self.trust, os.path.join(self.tmp, "run.tkb"))
        state = self.runs.get(key) or {"count": 0, "shown": 0, "failed": None}
        e = {"run_id": run_id}
        if code:
            new = [self.tr.alert(e, {}, "high", f"RUN {run_id} · Integrity {rep.integrity}",
                                 f"{OPERATOR_SIDE}\n\n{text}")]
            state = dict(state, count=count, failed=rep.integrity)
        else:
            records = list(reader.iter_run(tenant, run_id))
            new = [x for r in records[state["shown"]:] for x in self.tr.feed(r)]
            types = collections.Counter(r["event"]["type"] for r in records)
            verdicts = collections.Counter(r["event"]["data"].get("decision") for r in records
                                           if r["event"]["type"] == "policy.decision")
            summary = (f"tenant {tenant} · agent {self.tr.agent_names.get(run_id, '?')} · "
                       f"{'final' if types['run.final'] else 'closing' if types['run.closing'] else 'open'} · decisions "
                       + (", ".join(f"{v} {n}" for v, n in sorted(verdicts.items())) or "none")
                       + f" · approvals {types['approval']} · gaps {types['capture.gap']}")
            new.append(self.tr.alert(e, records[-1], "info", f"RUN {run_id} · Integrity {rep.integrity} · Assurance "
                                     f"{rep.assurance.split(';')[0]}", f"{summary}\n{self.note}\n{OPERATOR_SIDE}\n\n{text}"))
            state = dict(state, count=count, shown=len(records), failed=None)
        with self.lock:
            self.runs[key] = state
            # lean: keeps every translated record in memory; bound it like observe.Feed once stores hold millions
            self.records.extend(dict(x, tenant=tenant) for x in new)
            self.lock.notify_all()

    def verify(self, tenant=None):
        """For the page's chain badge: records verified, and the runs that failed (of `tenant`, else of all)."""
        with self.lock:
            runs = {k: s for k, s in self.runs.items() if tenant is None or k[0] == tenant}
            return (sum(s["shown"] for s in runs.values() if not s["failed"]),
                    [f"run {k[1]} of tenant {k[0]}: {s['failed']}" for k, s in runs.items() if s["failed"]], None)


def write_trust(path, vkeys):
    """A verify.v2 trust config at `path` that pins the log vkeys `vkeys` and no witness; returns `path`."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"logs": vkeys, "witnesses": [], "algs": [RecordSigner.alg], "witnesses_required": 0}, f)
    return path


def check(reader, tenant, run_id, note, trust, out):
    """(report, exit code, printed report) of verify.v2 on the run's bundle, exported from `reader` with `note` to
    `out`."""
    try:
        export(reader, tenant, run_id, note, out)
        rep, code = v2.verify(out, trust)
    except ValueError as e:   # the store does not match its own checkpoint
        rep, code = v2.Report(), v2.EXIT_FAIL
        rep.integrity, rep.assurance = "FAILED", "none"
        rep.check("export", False, str(e))
    text = io.StringIO()
    v2.print_report(rep, code, text)
    return rep, code, text.getvalue()


class Runs:
    """The runs of every log of a central deployment (view.logs: the DSN file of each log's schema, for a role holding
    postgres.READ_GRANTS only), for observe.make_handler's run pages. Each method takes the caller's scope (observe.ALL,
    or one tenant) and reads that tenant's rows only, in its queries. A run's verdict is verify.v2's report on the bundle
    exported from the store, against the log vkey the store holds (or --log-vkey), labelled OPERATOR_SIDE; the bundle is
    served too, to re-verify with the signed release."""

    def __init__(self, dsn_files, log_vkey=None):
        from tracekit.storage import postgres
        self.pg, self.logs, self.tmp = postgres, [], tempfile.mkdtemp(prefix="tk-view-")
        atexit.register(shutil.rmtree, self.tmp, True)
        for i, path in enumerate(dsn_files):
            dsn, vkey = postgres.read_dsn({"dsn_file": path}), log_vkey
            if not vkey:
                r = postgres.PostgresReader(dsn)
                try:
                    vkey = r.meta("log_vkey")
                finally:
                    r.close()
                if vkey is None:
                    raise ValueError(f"log {i} holds no log vkey yet: start its signer once, or pass --log-vkey")
            checkpoint.parse_vkey(vkey)
            self.logs.append((dsn, write_trust(os.path.join(self.tmp, f"trust-{i}.json"), [vkey])))
        self._lock, self._verdicts = threading.Lock(), collections.OrderedDict()

    def _open(self, i):
        """A reader of log `i` and its latest record note (size, note), or None: the reader holds what the note
        covers."""
        r = self.pg.PostgresReader(self.logs[i][0])
        try:
            return r, r.checkpoint_latest()
        except BaseException:
            r.close()
            raise

    def _key(self, scope, q):
        """(log, tenant, run id) that query `q` names, or None when `scope` may not read its tenant."""
        if not (q.get("log", "").isdecimal() and int(q["log"]) < len(self.logs) and q.get("tenant") and q.get("run")):
            raise ValueError("needs log (a log number), tenant and run")
        return (int(q["log"]), q["tenant"], q["run"]) if scope is observe.ALL or q["tenant"] == scope else None

    def _verdict(self, r, i, note, tenant, run_id, cached=True):
        """{verdict (VERDICTS), integrity, assurance, label, report} of the run in reader `r` of log `i`, or None when it
        holds no such run; with `cached` False, checked on `r` whatever the cache holds."""
        run = r.runs.get((tenant, run_id))
        if run is None:
            return None
        if not note or run["seqs"][-1] >= note[0]:
            return {"verdict": "pending", "integrity": "PENDING", "assurance": "none", "label": OPERATOR_SIDE,
                    "report": "No checkpoint covers the run's last record yet."}
        key = (i, tenant, run_id, len(run["seqs"]))
        with self._lock:
            v = self._verdicts.get(key) if cached else None
        if v is None:
            fd, out = tempfile.mkstemp(suffix=".tkb", dir=self.tmp)   # requests run concurrently: a file each
            os.close(fd)
            try:
                rep, code, text = check(r, tenant, run_id, note[1], self.logs[i][1], out)
            finally:
                os.unlink(out)
            v = {"verdict": "failed" if code else "verified", "integrity": rep.integrity,
                 "assurance": rep.assurance.split(";")[0], "label": OPERATOR_SIDE, "report": text}
            with self._lock:
                self._verdicts[key] = v
                while len(self._verdicts) > VERDICTS_MAX:
                    self._verdicts.popitem(last=False)
        return v

    def search(self, scope, q):
        """GET /api/runs: {runs, next}: at most `limit` (RUNS_PAGE) runs that `scope` may read and query `q` (SEARCH_KEYS)
        matches, log by log, newest first, and the `after` of the next page or None. One search query per log, plus a
        reader of each log with matching runs."""
        if set(q) - SEARCH_KEYS or q.get("verdict", "verified") not in VERDICTS:
            raise ValueError(f"the query takes {', '.join(sorted(SEARCH_KEYS))}; verdict is one of {', '.join(VERDICTS)}")
        try:
            limit = int(q.get("limit", RUNS_PAGE))
            start, before = (int(x) for x in q["after"].split(":")) if "after" in q else (0, None)
        except ValueError:
            raise ValueError("limit is a number, after a cursor from `next`") from None
        if not (0 < limit <= RUNS_PAGE and start >= 0):
            raise ValueError(f"limit is 1 to {RUNS_PAGE}")
        tenant = (q.get("tenant") or None) if scope is observe.ALL else scope
        filters = {**{k: q[k] for k in ("run", "agent", "since", "until") if q.get(k)},
                   **{k: True for k in ("gaps", "denies", "approvals") if k in q}}
        if any(q[k] != "1" for k in ("gaps", "denies", "approvals") if k in q):
            raise ValueError("gaps, denies and approvals take 1")
        out = []
        for i in range(start, len(self.logs)):
            want = limit - len(out)
            rows = self.pg.search_runs(self.logs[i][0], tenant, want, before, **filters)
            before = None
            if rows:
                r, note = self._open(i)
                try:
                    for row in rows:
                        v = self._verdict(r, i, note, row["tenant"], row["run_id"])
                        if v and q.get("verdict", v["verdict"]) == v["verdict"]:
                            out.append({"log": i, **row, "verdict": {k: v[k] for k in v if k != "report"}})
                finally:
                    r.close()
            if len(rows) == want:
                return {"runs": out, "next": f"{i}:{rows[-1]['first']}"}
        return {"runs": out, "next": None}

    def run(self, scope, q):
        """GET /api/run?log&tenant&run&from: the run's verdict with its report and, only when it verified, RECORDS_PAGE
        of its records from the `from`th, and the `from` of the next page or None; None when `scope` may not read the
        run or there is no such run."""
        key = self._key(scope, q)
        start = q.get("from", "0")
        if not start.isdecimal():
            raise ValueError("from is a number")
        if key is None:
            return None
        i, tenant, run_id = key
        start = int(start)
        r, note = self._open(i)
        try:
            v = self._verdict(r, i, note, tenant, run_id, cached=False)   # the records served are the ones checked
            if v is None:
                return None
            records = list(itertools.islice(r.iter_run(tenant, run_id), start, start + RECORDS_PAGE)) \
                if v["verdict"] == "verified" else []
        finally:
            r.close()
        return {"log": i, "tenant": tenant, "run_id": run_id, "verdict": v, "records": records,
                "next": start + RECORDS_PAGE if len(records) == RECORDS_PAGE else None}

    def bundle(self, scope, q):
        """GET /api/bundle?log&tenant&run: the run's bundle (.tkb bytes); None when `scope` may not read the run, there is
        no such run or no checkpoint covers its last record yet."""
        key = self._key(scope, q)
        if key is None:
            return None
        i, tenant, run_id = key
        r, note = self._open(i)
        fd, out = tempfile.mkstemp(suffix=".tkb", dir=self.tmp)
        os.close(fd)
        try:
            run = r.runs.get((tenant, run_id))
            if run is None or not note or run["seqs"][-1] >= note[0]:
                return None
            export(r, tenant, run_id, note[1], out)
            with open(out, "rb") as f:
                return f.read()
        finally:
            r.close()
            os.unlink(out)


class _TLSServer(ThreadingHTTPServer):
    """HTTPS, with each handshake on the request's own thread so a silent client never stalls the others."""
    tls = None

    def finish_request(self, request, client_address):
        request.settimeout(HANDSHAKE_S)   # a client that connects and stays silent frees its thread
        try:
            s = self.tls.wrap_socket(request, server_side=True)
        except OSError:   # the timeout, or not TLS
            return
        with s:
            super().finish_request(s, client_address)


def server(feed, host, port, token, tls=None, login=None, desk=None, runs=None):
    """The viewer's HTTP server (HTTPS with `tls`, an ssl.SSLContext), open to requests that present `token` (or the
    session cookie it is exchanged for), or with `login` (an OidcLogin) a session of its own, whose approver sessions
    get the approval pages of `desk` (an ApprovalDesk); with `runs` (a Runs, and no `feed`), the run pages of a central
    deployment's logs; call serve_forever()."""
    if not token:
        raise ValueError("the viewer needs a token")
    hosts = [host] + ([urlsplit(login.redirect_uri).hostname] if login else [])
    srv = (_TLSServer if tls else ThreadingHTTPServer)((host, port), observe.make_handler(
        feed, token, hosts, secure=bool(tls), login=login, approvals=desk, runs=runs))
    srv.tls, srv.daemon_threads = tls, True
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit view", description="laptop viewer for the v2 signer's runs (read-only)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dev", action="store_true", help="the same-user dev signer's data dir (the default)")
    g.add_argument("--config", help="signer.yaml: view its data_dir")
    g.add_argument("--data-dir", help="a signer data dir (holds store/ and log.vkey)")
    ap.add_argument("--log-vkey", help="pin this log vkey (`tracekit signer vkey`) instead of the one the store names")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7778)
    ap.add_argument("--tls-cert", help="PEM certificate: serve HTTPS (required beyond loopback)")
    ap.add_argument("--tls-key", help="PEM private key of --tls-cert")
    ap.add_argument("--insecure-http", action="store_true", help="serve plain HTTP beyond loopback anyway")
    a = ap.parse_args(argv)
    loopback = a.host in observe.LOOPBACK_HOSTS
    if bool(a.tls_cert) != bool(a.tls_key):
        print("tracekit view: --tls-cert and --tls-key go together", file=sys.stderr)
        return 2
    if not loopback and not a.tls_cert:
        if not a.insecure_http:
            print("tracekit view: refusing plain HTTP beyond loopback; pass --tls-cert and --tls-key "
                  "(or --insecure-http)", file=sys.stderr)
            return 2
        print("tracekit view: WARNING: plain HTTP beyond loopback; the token and every record cross the network "
              "unencrypted", file=sys.stderr)
    token = os.environ.get("TRACEKIT_VIEW_TOKEN") or secrets.token_urlsafe(24)
    try:
        tls = None
        if a.tls_cert:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(a.tls_cert, a.tls_key)
        cfg = load_config(a.config) if a.config else {"data_dir": a.data_dir or dev_data_dir()}
        view = cfg.get("view") or {}
        login = view.get("oidc") and OidcLogin(view["oidc"], (cfg.get("http") or {}).get("oidc"))
        desk = login and view.get("signer") and ApprovalDesk(Client(view["signer"]),
                                                             (cfg.get("approvals") or {}).get("webauthn"))
        runs = view.get("logs") and Runs(view["logs"], a.log_vkey)
        feed = None if runs else StoreFeed(cfg, a.log_vkey)
        srv = server(feed, a.host, a.port, token, tls, login, desk, runs)
    except (OSError, ValueError, StorageUnavailable) as e:
        print(f"tracekit view: {e}", file=sys.stderr)
        return 1
    scheme = "https" if tls else "http"
    print(f"tracekit view on {scheme}://{a.host}:{srv.server_address[1]}/"
          + ("" if os.environ.get("TRACEKIT_VIEW_TOKEN") else f"?token={token}")
          + (f"  ({len(runs.logs)} Postgres logs, read-only)" if runs else
             f"  (store: {feed.store}, read-only; {feed.note})"), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
