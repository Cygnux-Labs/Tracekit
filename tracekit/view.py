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
a session of the auditor or approver role sees, read-only, the runs of its tenant (the issuer's tenant claim) only.

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
from .identity import oidc
from .identity.k8s_sa import _https
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
ROLES = ("auditor", "approver")
LOGIN_S, SESSION_S, PENDING_MAX, SESSIONS_MAX = 600, 8 * 3600, 1024, 4096
log = logging.getLogger(__name__)


class OidcLogin:
    """Authorization code + PKCE (S256) login with the issuer `section["issuer"]` names in `issuers` (the signer's
    http.oidc section), its ID token's audience the client_id. A person whose identity keys (oidc.keys) are in
    roles.auditor or roles.approver and whose token carries the issuer's tenant claim gets a session of that tenant;
    both roles are read-only here (approvals are answered over the signer RPC)."""

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
        role = next((r for r in ROLES if any(lookup(self.roles.get(r, {}), k, False) for k in keys)), None)
        tenant = identity.claims.get("tenant")
        if role is None or tenant is None:
            log.warning("viewer login refused: %s has %s", identity.subject[:256],
                        "no tenant claim" if role else "no viewer role")
            return None
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[sid] = (tenant, self.clock() + SESSION_S)
            while len(self._sessions) > SESSIONS_MAX:
                self._sessions.popitem(last=False)
        return sid

    def tenant(self, sid):
        """The tenant of session `sid`, else None."""
        with self._lock:
            tenant, until = self._sessions.get(sid, (None, 0))
            if self.clock() < until:
                return tenant
            self._sessions.pop(sid, None)
            return None


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
        self.trust = os.path.join(self.tmp, "trust.json")
        with open(self.trust, "w", encoding="utf-8") as f:
            json.dump({"logs": vkeys, "witnesses": [], "algs": [RecordSigner.alg],
                       "witnesses_required": 0}, f)
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
        out = os.path.join(self.tmp, "run.tkb")
        try:
            export(reader, tenant, run_id, note, out)
            rep, code = v2.verify(out, self.trust)
        except ValueError as e:   # the store does not match its own checkpoint
            rep, code = v2.Report(), v2.EXIT_FAIL
            rep.integrity, rep.assurance = "FAILED", "none"
            rep.check("export", False, str(e))
        text = io.StringIO()
        v2.print_report(rep, code, text)
        state = self.runs.get(key) or {"count": 0, "shown": 0, "failed": None}
        e = {"run_id": run_id}
        if code:
            new = [self.tr.alert(e, {}, "high", f"RUN {run_id} · Integrity {rep.integrity}",
                                 f"{OPERATOR_SIDE}\n\n{text.getvalue()}")]
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
                                     f"{rep.assurance.split(';')[0]}", f"{summary}\n{self.note}\n{OPERATOR_SIDE}\n\n{text.getvalue()}"))
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


def server(feed, host, port, token, tls=None, login=None):
    """The viewer's HTTP server (HTTPS with `tls`, an ssl.SSLContext), open to requests that present `token` (or the
    session cookie it is exchanged for), or with `login` (an OidcLogin) a session of its own; call serve_forever()."""
    if not token:
        raise ValueError("the viewer needs a token")
    hosts = [host] + ([urlsplit(login.redirect_uri).hostname] if login else [])
    srv = (_TLSServer if tls else ThreadingHTTPServer)((host, port), observe.make_handler(
        feed, token, hosts, secure=bool(tls), login=login))
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
        section = (cfg.get("view") or {}).get("oidc")
        login = section and OidcLogin(section, (cfg.get("http") or {}).get("oidc"))
        feed = StoreFeed(cfg, a.log_vkey)
        srv = server(feed, a.host, a.port, token, tls, login)
    except (OSError, ValueError, StorageUnavailable) as e:
        print(f"tracekit view: {e}", file=sys.stderr)
        return 1
    scheme = "https" if tls else "http"
    print(f"tracekit view on {scheme}://{a.host}:{srv.server_address[1]}/"
          + ("" if os.environ.get("TRACEKIT_VIEW_TOKEN") else f"?token={token}")
          + f"  (store: {feed.store}, read-only; {feed.note})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
