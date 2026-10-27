"""`tracekit view`: the laptop viewer for the v2 signer's runs (04-design §10).

Reads the signer's store without its lock (signer.service.reader: FileReader, or PostgresReader for a Postgres store),
exports each run with bundle_v2 and checks it with verify.v2, the code `tracekit verify` runs, against a trust config
that pins --log-vkey, else the store's own log key (data_dir/log.vkey, or on Postgres the vkey the signer stored there,
so the viewer needs no access to the signer's data dir). The page, server
and security are the observer's (observe.py): each run's verifier report is an alert on the run's lane, followed by its
events only when it verifies; a run that fails is shown only as the failure report. A run is shown up to the newest
checkpoint note that covers its records (a run still being written grows with each note). The viewer never opens a
signing key.
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

With the dev signer's content (dev_content_source) a model exchange shows what was asked (a person's prompt) and what
the model said before each call (parsers.said: its reasoning, labelled full, summary or withheld, and its text),
self-reported, never proof; without it, that something was said and committed. Once a run is final its intent,
reasoning and action checks (tracekit analyze --v2, dev_analysis) add a FINDING alert each and the run review's
findings and monitorability lines, beside its integrity, never in it.

With why logs (`--why DIR`, else WHY_DIR in the data dir when present) the page also investigates them
(why.server.Store, docs/viewer.md#why): their alerts, the why provenance of each call's arguments, the WHY, GRAPH,
AGENTS and INFLUENCE views; FIND THE CAUSE and RUN TEST replay only the programs passed with --allow-program.
`--why DIR` with no store option (--dev, --config, --data-dir, --ledger, --bundle) shows the why logs alone, each run's
events on the tape (what `tracekit why serve` runs). `--ledger [HOME]` and `--bundle FILE` show the v1 ledger, or a v1
bundle once it verifies (what `tracekit observe` runs), on this server, token and nav, on loopback only.

    tracekit view [--dev | --config signer.yaml | --data-dir DIR | --ledger [HOME] | --bundle FILE] [--log-vkey VKEY]
                  [--host H] [--port N] [--tls-cert FILE --tls-key FILE | --insecure-http] [--why DIR]
                  [--allow-program SPEC] [--ingest-token TOKEN] [--webhook URL]
"""
import argparse
import atexit
import base64
import bisect
import collections
import functools
import glob
import hashlib
import hmac
import io
import itertools
import logging
import json
import os
import secrets
import shutil
import signal
import ssl
import sys
import tempfile
import threading
import time
from http.client import HTTPException
from urllib.parse import urlencode, urlsplit

from . import observe
from . import findings_v2, parsers
from .bundle_v2 import export
from .format import checkpoint
from .format.records import RecordSigner
from .identity import oidc, webauthn
from .identity.k8s_sa import _https
from .netserver import Server
from .policy2 import compile as policy_compile
from .sdk.client import Client, Incompatible, SignerUnavailable
from .signer.pipeline import SIGNER_RUN
from .signer.rpc_schema import RPCError
from .signer.service import dev_data_dir, load_config, lookup, read_vkeys, reader
from .storage.base import StorageCorrupt, StorageUnavailable
from .storage.file import NOTE
from .verify import v2
from .why.server import Store

POLL_S = 1.0
BACKOFF = 4   # a run being written is verified again no sooner than BACKOFF x its last check's time after that check
RECHECK_S = 300   # a run that did not grow is verified again this long after its last check, one run a pass
MEMO_MAX = 500_000   # records whose signature and schema the viewer remembers holding (verify.v2's memo)
KEPT_MAX = 10_000   # runs whose latest verdict stays in the run list after its row left the live view
WHY_DIR = "why"   # where the signer-backed why runtime writes its logs, in the signer's data dir
THREADS, PER_IP = 256, 32   # requests; each open page's event stream counts against STREAMS instead
STREAMS, STREAMS_PER_IP = 256, 64   # a team may share one address
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
LOGIN_S, SESSION_S, SESSIONS_MAX = 600, 8 * 3600, 4096
PASSKEY_LOGIN_S = 300   # a passkey is registered only this soon after the sign-in
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
        self._sessions = collections.OrderedDict()
        self._key = secrets.token_bytes(32)   # seals login states; a pending login is held by its browser, not here

    def _endpoint(self, name):
        url = self.issuer.document().get(name)
        if not (isinstance(url, str) and url.startswith("https://")):
            raise ValueError(f"the issuer's {name} is not an https:// URL")
        return url

    def _derive(self, label, state):
        return base64.urlsafe_b64encode(hmac.new(self._key, f"{label}:{state}".encode(), hashlib.sha256).digest()) \
            .rstrip(b"=").decode()

    def start(self):
        """(the issuer's authorization URL, state) for a new login. The state carries its expiry under this viewer's
        MAC, and the PKCE verifier and nonce are derived from it, so nothing is kept until the browser comes back."""
        url = self._endpoint("authorization_endpoint")
        body = f"{int(self.clock()) + LOGIN_S}.{secrets.token_urlsafe(24)}"
        state = f"{body}.{self._derive('state', body)}"
        verifier, nonce = self._derive("verifier", state), self._derive("nonce", state)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        return url + ("&" if "?" in url else "?") + urlencode({
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
            "scope": "openid", "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256"}), state

    def finish(self, state, code, browser_state):
        """The session id of a login that `state` (also the browser's login cookie) and `code` complete, else None."""
        if not (state and code and hmac.compare_digest(state.encode(), browser_state.encode())):
            return None
        body, _, mac = state.rpartition(".")
        until = body.partition(".")[0]
        if not (hmac.compare_digest(mac.encode(), self._derive("state", body).encode()) and until.isdigit()
                and self.clock() < int(until)):
            return None
        verifier, nonce = self._derive("verifier", state), self._derive("nonce", state)
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
        self._keep(sid, {"tenant": observe.ALL if role == "operator-admin" else tenant, "role": role,
                         "person": person, "csrf": secrets.token_urlsafe(32), "at": self.clock(),
                         "until": self.clock() + SESSION_S})
        return sid

    def _keep(self, sid, session):
        """Store a new session; past SESSIONS_MAX, expired sessions go first, then the oldest live ones."""
        with self._lock:
            self._sessions[sid] = session
            if len(self._sessions) > SESSIONS_MAX:
                now = self.clock()
                for k in [k for k, v in self._sessions.items() if v["until"] <= now]:
                    del self._sessions[k]
            while len(self._sessions) > SESSIONS_MAX:
                self._sessions.popitem(last=False)

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
    signer's approvals.webauthn section ({rp_id, origin}), or None. A passkey is registered only within
    PASSKEY_LOGIN_S of the session's sign-in: the signer keeps a person's first passkey, on this viewer's word."""
    ERRORS = {"invalid_request": 400, "forbidden": 403, "unknown_approval": 404, "approval_not_pending": 409}

    def __init__(self, signer, webauthn=None, clock=time.time):
        self.signer, self.webauthn, self.clock = signer, webauthn, clock

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
        """(status, body) of POST `path` with JSON `body`: a passkey registration, an answer to an approval, or
        (`/api/approvals/<id>/revoke`) the revocation of an agent's approval."""
        who = {"on_behalf": session["person"]}
        if path == "/api/passkey":
            if self.clock() - session["at"] > PASSKEY_LOGIN_S:
                return 403, {"error": f"sign in again (/login): a passkey is registered within "
                                      f"{PASSKEY_LOGIN_S // 60} minutes of signing in"}
            return self._call("passkey_register", {**who, **{k: body[k] for k in ("credential_id", "public_key")
                                                            if k in body}})
        if not path.startswith("/api/approvals/"):
            return 404, {"error": "not found"}
        if path.endswith("/revoke"):   # a person vetoes an agent's approval that is not consumed yet
            return self._call("approval_revoke", {"request_id": secrets.token_hex(16),
                                                  "approval_id": path[len("/api/approvals/"):-len("/revoke")], **who,
                                                  **{k: body[k] for k in ("reason",) if k in body}})
        return self._call("approval_decide", {"request_id": secrets.token_hex(16),
                                              "approval_id": path[len("/api/approvals/"):], **who,
                                              **{k: body[k] for k in ("decision", "reason", "passkey") if k in body}})


ENGINE_RULES = {"TK-UNKNOWN-TOOL": "a tool the policy does not map", "TK-SQL-PARSE": "SQL no dialect reads",
                "TK-OVERSIZE": "arguments too large to check", "TK-SHELL-PARSE": "a shell command that does not parse",
                "TK-ENGINE-ERROR": "the policy engine failed on these arguments, so the call was denied",
                "TK-LIMIT-SUM": "a sum limit counts this call: send the amount as a non-negative integer in minor "
                                "units, with its three-letter currency code",
                "TK-CONSTRAINT": "the person's request in this run said not to do this, so a person must approve it",
                "TK-HOLD": "the run is held by an incident: every call waits for a person",
                "TK-QUARANTINE": "the run is quarantined by an incident: its calls are refused",
                "TK-ARGS-INVALID": "arguments the signer could not read, so it refused the call",
                "TK-A2A-NAME": policy_compile.ENGINE_REASONS["TK-A2A-NAME"]["reason"]}
# a signed gap's kind in words (the kind itself stays on the row, for its tooltip and DETAIL)
GAP_WORDS = {
    "signer_unavailable": "the signer was unreachable: calls may be missing",
    "client_counter_gap": "events the client sent never arrived",
    "retry_conflict": "a retried event differed from the first one",
    "run_abandoned": "the run stopped without closing",
    "witness_late": "a witness countersigned late", "witness_failed": "a witness did not countersign",
    "degraded_unanchored": "checkpoints no witness countersigned",
    "format_upgrade": "the record format was upgraded during the run",
    "policy_timeout": "the policy ran out of time to decide",
    "decision_flip": "the same call got a different decision",
    "class_mismatch": "a tool's class differs from the one the run declared",
    "args_coerced": "arguments were converted before they were checked",
    "reconcile.hook_missing": "a call the model asked for was never decided",
    "reconcile.fabricated": "a decided call that no model message asked for",
    "reconcile.args_mismatch": "a call's arguments differ between what was asked and what was decided",
    "reconcile.result_without_call": "a result for a call that was never decided",
    "reconcile.unexplained_effect": "the run reached a host that no call explains",
    "state_tamper": "the agent's saved state was changed outside the run",
    "tailer_lost": "the transcript reader stopped: model messages may be missing",
    "rollback": "the store went back to an earlier state",
    "clock_skew": "a clock disagreed with the signer's",
    "key_retired": "a signing key was retired", "key_revoked": "a signing key was revoked",
    "log_closed": "the log was closed", "quota_refused": "events refused over the rate limit",
    "identity_refused": "events refused from an identity that may not write them",
    "approval_expired": "an approval expired",
    "executed_against_policy": "a call ran that the policy refused",
    "decision_mismatch": "a call ran under a different decision than the one recorded",
    "decided_not_completed": "a call was allowed but its result never came back",
    "late_activity": "writes came in after the run was final",
    "concurrent_run": "another run of the same agent process was open",
    "tailer_redelegated": "a second transcript reader took over",
    "reask_after_reject": "a rejected call was asked again",
    "held_call_unresolved": "a held call was never resolved",
    "observer_lost": "the network or process observer stopped reporting",
    "effect_outside_run": "an effect that no open run holds",
    "result_unchecked": "a tool result nothing compared",
    "constraint_refused": "a constraint from the person's request the run had no room for"}
SEVERE_GAPS = {"hook_missing", "proxy_missing", "policy_unrecorded", "state_tamper", "rollback", "key_revoked",
               "decision_flip", "executed_against_denial", "concurrent_run"}


def policy_reasons(paths=()):
    """policy_hash -> {rule id: {reason[, remedy]}} of the shipped packs and the policy files `paths`: a decision's
    rule reasons are shown only from the policy whose hash it records."""
    out = {}
    for p in sorted(glob.glob(os.path.join(os.path.dirname(policy_compile.__file__), "packs", "*.yaml"))) + list(paths):
        pol, errors = policy_compile.build(p)
        if not errors:
            out[policy_compile.policy_hash(pol)] = {
                r["id"]: {"reason": r.get("reason") or r.get("label") or "", **{k: r[k] for k in ("remedy",) if k in r}}
                for sec in policy_compile.SECTIONS for r in pol.get(sec, [])}
    return out


def _who(i):
    """An identity record ({scheme, subject, attested, person?}) as text."""
    if not isinstance(i, dict):
        return "?"
    return (f"{i.get('scheme')}:{i.get('subject')} ({'attested' if i.get('attested') else 'not attested'})"
            + (f" · person {i['person']}" if i.get("person") else ""))


def _hms(ts):
    return ts[11:19] + " UTC" if ts else "?"


class Translator(observe.Translator):
    """v2 records -> the observer's record shape. A v2 policy.decision names its tool (there is no tool.call), and
    every other type is an alert with a line of text, so every record of the run appears in order. Each record carries
    `v2` (type, run_seq and what the page's detail and run review need); the signer's own run is `signer`, no agent.
    Arguments are only a salted commitment: a decision's target is its rules' reasons, from `reasons` (policy_reasons)."""

    def __init__(self, reasons=None):
        super().__init__()
        self.reasons = reasons or {}
        # approval_id -> (tool, rule ids, tool call id), and shadow suggestions: the newest MAX_RUNS_KEPT each, like agent_names
        self.requests, self.suggested = (observe._Bounded(observe.MAX_RUNS_KEPT),
                                         observe._Bounded(observe.MAX_RUNS_KEPT))
        self.shadow = collections.defaultdict(lambda: [0, 0])   # rule id -> [person answers agreeing, compared]
        self.content = {}   # (run_id, run_seq) -> a decision's retained arguments, from StoreFeed's content source
        # a findings run -> (the run its findings are about, its author: the identity the signer measured)
        self.analyzes = observe._Bounded(observe.MAX_RUNS_KEPT)

    def _base(self, e, rec, event):
        return {**super()._base(e, rec, event), "agent": self.agent_names.get(e["run_id"], "agent")}

    def rules(self, d):
        known = self.reasons.get(d.get("policy_hash"), {})
        return [{"id": i, "reason": known.get(i, {}).get("reason") or ENGINE_RULES.get(i, ""),
                 **{k: v for k, v in known.get(i, {}).items() if k == "remedy"}} for i in d.get("rule_ids") or []]

    def feed(self, rec):
        e = rec["event"]
        t, d = e["type"], e.get("data") or {}
        out = self._v2(e, rec, t, d)
        # an approval's later records (one that expired at run.final names no call) are its request's call's
        info = {"type": t, "run_seq": e.get("run_seq"), "tool_use_id": d.get("tool_use_id")
                or (d.get("binding") or {}).get("tool_call_id") or e.get("tool_call_id")
                or self.requests.get(d.get("approval_id"), ("", [], None))[2]}
        for x in out:
            x["v2"] = {**info, **x.get("v2", {})}
            if e["run_id"] == SIGNER_RUN[1]:
                x.update(signer=True, agent="signer")
        return out

    def _v2(self, e, rec, t, d):
        def alert(sev, title, text, tape, **v2):
            return [{**self.alert(e, rec, sev, title, text, tape), "v2": v2}]

        def note(title, text, tape, **v2):   # a signed record that is a row of the tape, not an alert
            return [{**self._base(e, rec, "tk_note"), "title": title, "text": text, "tape": tape, "v2": v2}]
        if t == "run.registered":
            self.agent_names[e["run_id"]] = (d.get("agent") or {}).get("name") or "agent"
            if d.get("analyzes"):
                self.analyzes[e["run_id"]] = d["analyzes"], _who(d.get("identity"))
            return [{**self._base(e, rec, "SessionStart"),
                     "source": f"{d.get('signer_isolation')} signer · {_who(d.get('identity'))}"
                               + (f" · findings about run {d['analyzes']}" if d.get("analyzes") else "")}]
        if t == "input.observed":
            return note(f"INPUT · {d.get('source')}", f"{d.get('trust')} content the run read; the record holds "
                                                       "only its commitment", "INPUT", trust=d.get("trust"))
        if t == "content.accessed":
            seqs = d.get("seqs") or []
            return note("CONTENT READ", f"{d.get('principal')} read the kept content of {len(seqs)} record"
                                        f"{'s' * (len(seqs) != 1)} of run {d.get('run_id')} · “{d.get('purpose')}”",
                        "SIGNER")
        if t == "review":   # a signed finding of a findings run, about the run it analyzes
            v, (about, author) = d.get("verdict") or {}, self.analyzes.get(e["run_id"], (None, "?"))
            rule = v.get("rule", "")
            if v.get("kind") == "coverage":
                checks = v.get("checks") or {}
                return alert("info", f"FINDINGS COVERAGE · {sum(c.get('checked', 0) for c in checks.values())} "
                             f"checks ran", "what the analyzer could and could not check"
                             + "".join(f"\n{r}: not checkable for {g.get('n')}: "
                                       + findings_v2.REASONS.get(g.get("reason"), (g.get("reason"),))[0]
                                       for r, c in sorted(checks.items()) for g in c.get("not_checkable") or ()),
                             "FINDING", finding=v, about=about)
            why, todo = findings_v2.WHY.get(rule, ("", ""))
            return alert({"critical": "high", "high": "high", "medium": "med"}.get(v.get("severity"), "low"),
                         f"FINDING {rule} · {v.get('title') or findings_v2.TITLES.get(rule, '')}",
                         (f"Why it matters: {why}\nWhat to do: {todo}\n" if why else "")
                         + f"Written by {author}, reviewer {d.get('reviewer')} (its own claim), about run "
                         f"{about or '?'}", "FINDING",
                         finding=v, cites=d.get("cites") or [], about=about)
        if t == "run.closing":
            return [{**self._base(e, rec, "SessionEnd"), "reason": {"close_run": "closed by the agent",
                                                                    "idle_timeout": "closed after the idle timeout"}
                     .get(d.get("reason"), d.get("reason"))}]
        if t == "model.exchange":
            return self._exchange(e, rec, d)
        if t == "run.final":
            cov = d.get("coverage") or {}
            line = (f"final · head run_seq {d.get('head_run_seq')} · coverage {'+'.join(cov.get('layers') or []) or 'none'}"
                    f" · reconciled {cov.get('reconciled', 0)}"
                    + "".join(f" · unreconciled {k} {v}" for k, v in sorted((cov.get("unreconciled") or {}).items()))
                    + (f" · provider-run tools {d['provider_executed']}" if d.get("provider_executed") else ""))
            return [{**self._base(e, rec, "SessionEnd"), "reason": line, "v2": {"coverage": line}}]
        if t == "policy.decision":
            dec, rules = d.get("decision"), self.rules(d)
            shown = self.content.pop((e["run_id"], e.get("run_seq")), None)
            r = self._base(e, rec, "PreToolUse")
            # with its retained arguments the page names the call by them (a command, a path), then its rules
            r.update(tool_name=d.get("tool"), tool_use_id=d.get("tool_use_id"),
                     tool_input={} if shown is None else shown if isinstance(shown, dict) else {"args": shown},
                     target=None if shown is not None else
                     "; ".join(f"{x['id']} {x['reason']}".strip() for x in rules) or "no rule matched",
                     policy={"decision": "deny" if dec == "deny" else "allow", "reasons": [x["id"] for x in rules],
                             "flags": {"flag": ["flagged"], "ask": ["held_for_approval"]}.get(dec, [])},
                     v2={"decision": dec, "rules": rules, "args_commitment": d.get("args_commitment"),
                         "policy_hash": d.get("policy_hash"), "decision_id": d.get("decision_id"),
                         **{k: d[k] for k in ("provenance", "provenance_state") if k in d}})
            return [r]
        aid = d.get("approval_id")
        tool, rule_ids, _ = self.requests.get(aid, ("", [], None))
        if t == "approval.request":
            tool = (d.get("binding") or {}).get("tool", "")
            self.requests[aid] = (tool, d.get("rule_ids") or [], (d.get("binding") or {}).get("tool_call_id"))
            rules = self.rules(d)
            return alert("med", f"APPROVAL REQUESTED · {tool}",
                         f"requested by {d.get('requester')} · rules "
                         + ", ".join(f"{x['id']} {x['reason']}".strip() for x in rules)
                         + f" · expires {_hms(d.get('expires_at'))}"
                         + (" · signer executes (t2)" if d.get("executor") == "t2" else ""), "HOLD",
                         approval="requested", rules=rules, binding_digest=d.get("binding_digest"))
        agent = d.get("approver_kind") == "agent"
        model = " (model output" + (f", {d['asserted'].get('model')}" if (d.get("asserted") or {}).get("model") else "")\
            + ")" if agent else ""
        if t == "approval.suggested":   # shadow mode: recorded, changes nothing
            self.suggested[aid] = d.get("decision")
            return alert("low", f"AGENT SUGGESTED {str(d.get('decision')).upper()} · {tool}",
                         f"shadow mode, changes nothing · by agent {d.get('approver')}{model}"
                         + (f" · “{d['reason']}”" if d.get("reason") else ""), "HOLD", approval="suggested")
        if t == "approval.escalated":
            by = f"agent {_who(d.get('approver_identity'))} (model output, over arguments the requesting agent " \
                 "supplied)" if d.get("by") == "agent" else "the signer"
            return alert("med", f"ESCALATED TO PEOPLE · {tool}", f"by {by}"
                         + (f" · “{d['reason']}”" if d.get("reason") else ""), "HOLD", approval="escalated")
        if t == "approval.revoked":
            return alert("med", f"AGENT APPROVAL REVOKED · {tool}", f"by {d.get('by')}"
                         + (f" · “{d['reason']}”" if d.get("reason") else "") + " · the call never runs", "REJECT",
                         approval="revoked")
        if t == "approval.agents":
            return alert("high" if not d.get("enabled") else "info",
                         f"AGENT APPROVALS {'ON' if d.get('enabled') else 'OFF'}", f"by {d.get('by')}"
                         + (f" · “{d['reason']}”" if d.get("reason") else ""), "SIGNER")
        if t == "approval":
            dec, who = d.get("decision"), d.get("approver_identity")
            shadow = ""
            if aid in self.suggested and not agent:   # a person's answer to a call an agent answered in shadow mode
                hit = self.suggested.pop(aid) == dec
                for r in rule_ids:
                    self.shadow[r][0] += hit
                    self.shadow[r][1] += 1
                shadow = " · shadow agent " + ("agreed" if hit else "disagreed") + " · agreement " + ", ".join(
                    f"{r} {self.shadow[r][0]}/{self.shadow[r][1]}" for r in rule_ids)
            text = (f"by {'agent ' if agent else ''}{_who(who) if who else d.get('approver')}{model}"
                    + (f" · vouched for by {_who(d['via'])} via {d.get('channel')}" if d.get("via") else "")
                    + (f" · “{d['reason']}”" if d.get("reason") else "")
                    # only an approval can be a self-approval: the requester rejecting their own call is no risk
                    + ((" · SELF-APPROVED" if d.get("self_approved") else " · not self-approved") if dec == "approve"
                       else " · by the requester" if d.get("self_approved") else "")
                    + (" · BREAK-GLASS" if d.get("break_glass") else "") + (" · passkey" if d.get("passkey") else "")
                    + shadow)
            sev = "high" if dec == "self_approval_refused" or d.get("break_glass") else \
                "med" if d.get("self_approved") and dec == "approve" or agent else "info"
            word = {"approve": "APPROVED", "reject": "REJECTED", "timeout": "TIMED OUT",
                    "self_approval_refused": "SELF-APPROVAL REFUSED"}.get(dec, str(dec).upper())
            return alert(sev, f"{'AGENT ' if agent else ''}{word} · {tool or d.get('tool_use_id')}", text,
                         "APPROVE" if dec == "approve" else "REJECT", approval=dec, approver=_who(who) if who else
                         d.get("approver"), via=d.get("via") and _who(d["via"]), self_approved=d.get("self_approved"),
                         break_glass=bool(d.get("break_glass")), reason=d.get("reason"))
        if t in ("approval.consumed", "approval.expired", "approval.abandoned", "approval.refused",
                 "approval.binding_mismatch"):
            word = t.split(".")[1]
            text = {"approval.consumed": "the approved call ran with the approved arguments",
                    "approval.expired": "expired before anyone answered",
                    "approval.binding_mismatch": "the call's arguments differ from the approved ones: refused"}.get(
                t, d.get("reason") or "")
            sev = {"approval.consumed": "info", "approval.expired": "med", "approval.abandoned": "low"}.get(t, "high")
            return alert(sev, f"APPROVAL {word.replace('_', ' ').upper()} · {tool}", text,
                         "APPROVE" if word == "consumed" else "HOLD" if sev != "high" else "ALERT", approval=word)
        if t == "capture.gap" or t.startswith("reconcile."):
            kind = d.get("kind") or t
            text = (d.get("reason") or d.get("detail") or "")
            text += f" · {d['missed_events']} events missed" if d.get("missed_events") else ""
            text += f" · {_hms(d.get('from_ts'))}–{_hms(d.get('to_ts'))}" if d.get("from_ts") else ""
            sev = "high" if t.startswith("reconcile.") or kind in SEVERE_GAPS else "med"
            return alert(sev, f"GAP · {GAP_WORDS.get(kind, kind)}", text.strip(" ·") or "signed gap: records may be "
                         "missing", "GAP", kind=kind)
        if t == "signer.epoch":
            keys = d.get("keys") or []
            return alert("info", "SIGNER EPOCH", f"{len(keys)} signing key(s): " + ", ".join(
                f"{k.get('alg')} {str(k.get('kid'))[7:19]}" for k in keys)
                + (f" · bridges v1 ledger at seq {d['bridge'].get('v1_last_seq')}" if d.get("bridge") else ""), "SIGNER")
        if t == "key.retire":
            return alert("med", "KEY RETIRED", f"{str(d.get('kid'))[7:19]} signs nothing after seq {d.get('last_seq')}",
                         "SIGNER")
        if t == "log.closed":
            return alert("med", "LOG CLOSED", f"final seq {d.get('final_seq')}", "SIGNER")
        if t == "refusal.summary":
            return alert("med", f"SIGNER REFUSED {d.get('count')} · {d.get('code')}",
                         f"from {d.get('identity')} · {_hms(d.get('from_ts'))}–{_hms(d.get('to_ts'))}", "SIGNER")
        if t == "policy.external":
            return alert("high" if d.get("decision") == "deny" else "info",
                         f"EXTERNAL DECISION · {d.get('system')} · {d.get('decision')} · {d.get('tool')}",
                         f"{', '.join(d.get('rule_ids') or [])} {d.get('reason', '')} · signature {d.get('signature')}",
                         "ALERT")
        if t == "state.write":
            return alert("info", f"STATE WRITE · {d.get('store')}", f"key {d.get('key')}", "STATE")
        if t == "incident.opened":   # containment (docs/incidents.md): read-only marks on the timeline
            acts = "+".join(d.get("actions") or []) or ("would " + "+".join(d.get("would") or []) if d.get("would")
                                                         else "recorded")
            return alert("high" if d.get("actions") else "med",
                         f"INCIDENT · {d.get('trigger')} {' '.join(d.get('rule_ids') or [])}".strip(),
                         f"{d.get('incident_id')} · {d.get('mode')} · {acts}"
                         + (f" · {d['reason']}" if d.get("reason") else ""), "ALERT", incident=d.get("incident_id"))
        if t in ("run.held", "run.quarantined", "run.resumed"):
            word = {"run.held": "RUN HELD", "run.quarantined": "RUN QUARANTINED", "run.resumed": "RUN RESUMED"}[t]
            return alert("info" if t == "run.resumed" else "high", f"{word} · {d.get('incident_id')}",
                         f"by {d.get('person') or d.get('by')}" + (f" · {d['reason']}" if d.get("reason") else "")
                         + (" · inherited" if d.get("inherited") else ""), "HOLD", incident=d.get("incident_id"))
        if t in ("incident.updated", "incident.capped", "incident.resolved", "incident.response",
                 "identity.suspension"):
            text = {"incident.updated": f"{d.get('incident_id')} matched again",
                    "incident.capped": str(d.get("reason")),
                    "incident.resolved": f"{d.get('incident_id')} by {d.get('person')}",
                    "incident.response": f"response engine {'on' if d.get('enabled') else 'paused'} by {d.get('by')}",
                    "identity.suspension": f"{d.get('identity')} {d.get('state')} by {d.get('by')}"}[t]
            return alert("med", t.upper().replace(".", " · "), text, "ALERT", incident=d.get("incident_id"))
        if t == "constraint.added":   # a live constraint (#309): the person's request said not to do this
            return alert("info", f"CONSTRAINT · {CONSTRAINTS.get(d.get('kind'), d.get('kind'))}",
                         "a later call that breaks it waits for a person's approval (TK-CONSTRAINT)"
                         + (": the file is committed, not named" if d.get("object_commitment") else ""), "HOLD",
                         constraint=d.get("kind"))
        if t == "run.child":
            return alert("info", "CHILD RUN", f"run {d.get('run_id')} registered from this run's harness process with "
                                              "this run as its parent", "SIGNER")
        if t == "effect.observed" and d.get("sensor") == "openshell":   # what OpenShell reported of its sandbox
            k, who, by = d.get("kind"), f"{d.get('binary')} (pid {d.get('pid')})", f" · OpenShell's report, via " \
                                                                                  f"{d.get('observer')}"
            target = f"{d.get('host')}:{d.get('port')}" if k == "connect" else d.get("binary")
            if d.get("denied"):
                return alert("med", f"BLOCKED BY OPENSHELL · {k} {target}", f"OpenShell's policy blocked {who} from "
                             + (f"connecting to {target}" if k == "connect" else "starting") + by, "BLOCK")
            return alert("info", f"OPENSHELL · {k} {target}", (
                f"{who} connected to {target}; OpenShell's policy allowed it" if k == "connect" else
                f"OpenShell started {who} in the sandbox" if k == "exec" else
                f"{who} ended" + (f" with status {d['status']}" if "status" in d else "")) + by, "EFFECT")
        if t == "ext" and d.get("name") == "openshell.policy":   # OpenShell changed the sandbox's policy
            return alert("med", f"OPENSHELL POLICY · {d.get('change')}",
                         "OpenShell reported a change of the sandbox's policy or configuration"
                         + (f" by {d['by']}" if d.get("by") else "")
                         + (f" · policy {str(d['policy_hash'])[:16]}" if d.get("policy_hash") else "")
                         + f" · via {d.get('observer')}; its message is committed, not shown", "STATE")
        if t == "effect.observed" and d.get("sensor"):   # what a kernel sensor saw; the run's analysis joins it to a call
            k = d.get("kind")
            target = (f"{d.get('host')}:{d.get('port')}" if k == "connect" else d.get("path") if k == "file" else
                      f"{d.get('binary')} status {d.get('status')}" if k == "exit" else d.get("binary"))
            claim = d.get("tool_call_id")
            return alert("info", f"EFFECT · {k} {target}",
                         f"{d.get('binary')} pid {d.get('pid')} · {d.get('sensor')} via {d.get('observer')}"
                         + (f" · names call {claim} (the process's claim, which the run's analysis checks)"
                            if claim else ""), "EFFECT", effect={"kind": k, "target": target, "claim": claim})
        return super().feed(rec) or alert("info", t, json.dumps(d, ensure_ascii=False)[:200], "ALERT")


    def _exchange(self, e, rec, d):
        """A model exchange: a person's prompt (UserPromptSubmit), what the model said (a model_turn whose blocks name
        their form), a response's tool uses (observe's model line); without retained content, what is committed."""
        body = self.content.pop((e["run_id"], e.get("run_seq")), None)
        out = super().feed(rec) if d.get("tool_uses") or d.get("usage") else []   # a transcript line has neither
        x = {"exchange_id": d.get("exchange_id"), "tool_ids": [u["id"] for u in d.get("tool_uses") or ()]}
        for r in out:
            r["v2"] = x
        if d.get("phase") == "request":
            prompt = findings_v2._tailer(body) and findings_v2._prompt(body)
            return [{**self._base(e, rec, "UserPromptSubmit"), "prompt": prompt[0], "v2": x}] if prompt else []
        calls = []   # the message's tool uses in order; each block says how many came before it (`after`)
        if body is None:
            blocks = [] if d.get("tool_uses") else [{"kind": "committed", "text": "said something here; it is "
                                                     "committed, and this viewer reads no content"}]
        else:
            blocks = []
            for s in parsers.said(*findings_v2._message(body, d)):
                if s["text"] or s["kind"] == "reasoning":
                    blocks.append({"kind": ("thinking" if s["text"] else "thinking_redacted") if s["kind"] ==
                                   "reasoning" else "text", "text": s["text"], "form": s["form"], "after": len(calls)})
                calls += s["tools"]
        turn = [{**self._base(e, rec, "model_turn"), "blocks": blocks, "calls": calls,
                 "message_id": d.get("exchange_id"), "v2": x}]
        return (turn if blocks else []) + out


CONSTRAINTS = {"keep_away": "keep a file unchanged", "only_change": "change only certain files",
               "read_only": "read-only", "no_push": "don't push", "no_network": "no network"}


def review(records, rep, verdict):
    """The run review of a verified run's records: what the page's run list and review show. `rep` is verify.v2's
    report and `verdict` one of VERDICTS; `first` maps each line to the seq of its first record."""
    out = {"verdict": verdict, "integrity": rep.integrity, "assurance": rep.assurance.split(";")[0],
           "label": OPERATOR_SIDE, "agent": None, "records": len(records), "first_ts": None, "last_ts": None,
           "decisions": collections.Counter(), "approvals": [], "gaps": collections.Counter(), "coverage": None,
           "incidents": [], "constraints": [], "constraint_holds": 0,
           "state": "open", "first": {}}
    for rec in records:
        e = rec["event"]
        t, d = e["type"], e.get("data") or {}
        out["first_ts"] = out["first_ts"] or e.get("ts")
        out["last_ts"] = e.get("ts")
        key = None
        if t == "run.registered":
            out["agent"] = (d.get("agent") or {}).get("name") or "agent"
            if d.get("analyzes"):
                out["analyzes"] = d["analyzes"]
        elif t == "policy.decision":
            out["decisions"][d.get("decision")] += 1
            out["constraint_holds"] += "TK-CONSTRAINT" in (d.get("rule_ids") or ())
            key = d.get("decision")
        elif t == "constraint.added":
            out["constraints"].append({"kind": CONSTRAINTS.get(d.get("kind"), d.get("kind")), "seq": e.get("seq")})
        elif t == "approval":
            who = _who(d["approver_identity"]) if d.get("approver_identity") else d.get("approver")
            out["approvals"].append({"decision": d.get("decision"), "tool_use_id": d.get("tool_use_id"),
                                     "approver": f"agent {who} (model output)" if d.get("approver_kind") == "agent"
                                     else who, "via": d.get("via") and _who(d["via"]),
                                     "self_approved": bool(d.get("self_approved")),
                                     "break_glass": bool(d.get("break_glass")), "seq": e.get("seq")})
            key = "approval"
        elif t == "capture.gap" or t.startswith("reconcile."):
            key = "gap:" + (d.get("kind") or t)
            out["gaps"][key[4:]] += 1
            out.setdefault("gap_words", {})[key[4:]] = GAP_WORDS.get(key[4:], key[4:])
        elif t == "incident.opened":
            out["incidents"].append({"incident_id": d.get("incident_id"), "trigger": d.get("trigger"), "seq": e.get("seq"),
                                     "rule_ids": d.get("rule_ids") or [], "mode": d.get("mode"),
                                     "actions": d.get("actions") or [], "state": "open"})
        elif t in ("run.held", "run.quarantined", "run.resumed"):
            mine = [x for x in out["incidents"] if x["incident_id"] == d.get("incident_id")]
            if not mine:   # the pointer of an incident opened in another run
                mine = [{"incident_id": d.get("incident_id"), "trigger": "(another run)", "seq": e.get("seq"),
                         "rule_ids": [], "mode": "enforce", "actions": [], "state": "open"}]
                out["incidents"] += mine
            mine[0]["state"] = t.split(".")[1]
        elif t == "run.final":
            cov = d.get("coverage") or {}
            out["coverage"] = {"layers": cov.get("layers") or [], "reconciled": cov.get("reconciled", 0),
                               "unreconciled": cov.get("unreconciled") or {},
                               "provider_executed": d.get("provider_executed", 0)}
            out["state"] = "final"
        elif t == "run.closing" and out["state"] == "open":
            out["state"] = "closing"
        if key and key not in out["first"]:
            out["first"][key] = e.get("seq")
    return out


def dev_content_source():
    """StoreFeed's `content` for the dev signer's store: the retained arguments of a run's decisions and content of its
    model exchanges, read with `content_get` (the dev signer keeps them and grants this user content_read:
    service.dev_content), each item opening its record's commitment (why.signed.vault_content: EvidenceAlert when one
    doesn't, and nothing is shown; content redaction changed is left out). Each read is one signed content.accessed
    record. A refusal (TRACEKIT_DEV_CONTENT=0, or a signer from before 1.2.2) stops it for good, said once; while the
    signer is down it reads nothing."""
    from .why.signed import vault_content
    state = {"client": None, "off": False}

    def read(run_id, records):
        if state["off"]:
            return {}
        out = {}
        try:
            state["client"] = state["client"] or Client()
            # content redaction changed opens no commitment: not shown as what the record holds
            out = {seq: content for seq, content, opened in vault_content(state["client"], records, "tracekit view")
                   if opened}
        except RPCError as e:
            state["off"] = True
            print(f"tracekit view: calls show their rules, not their arguments: the dev signer keeps none for this "
                  f"viewer ({e.code}: {e})", file=sys.stderr, flush=True)
        except (SignerUnavailable, OSError):
            state["client"] = None
        return out
    return read


def dev_analysis():
    """StoreFeed's `analyze` for the dev signer's store: tracekit analyze --v2 over a final run, its content read with
    content_get and each item opening its record's commitment (why.signed.vault_content). A signer that gives no
    content leaves the checks that read it not checkable; one whose content does not open its record is an alert."""
    from .why.signed import vault_content

    def run(records):
        client = Client()
        try:
            def content(recs):
                try:
                    yield from vault_content(client, recs, "tracekit view")
                except (RPCError, SignerUnavailable, OSError):
                    return
            return findings_v2.analyze(records, content)
        finally:
            client.close()
    return run


class StoreFeed:
    """What observe.make_handler serves (records, base, lock, verify()), from the store of a v2 signer's config.
    `on_run(tenant, run_id, records, reasons)`: called once a client run's records are on the tape, each time it grows
    and verifies (records), and when it fails verification (None): mirror_run. `content(run_id, records)`: the
    retained arguments of those decisions and content of those model exchanges ({run_seq: content}), for the tape to
    show (dev_content_source; EvidenceAlert when the content does not open its record: a CONTENT NOT SHOWN alert).
    `analyze(records)`: a final run's findings (dev_analysis), once per run."""

    def __init__(self, cfg, log_vkey=None, on_run=None, content=None, analyze=None):
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
        # past it the oldest records leave the live view (base counts them), as observe.Feed's
        self.max_records = int(os.environ.get("TRACEKIT_OBSERVE_MAX_RECORDS", "50000") or 50000)
        # (tenant, run_id) -> {"count": records verified, "shown": records translated, "failed": report, "checked": when
        # its last check ended, "took": the CPU time it took}
        self.runs = {}
        self.memo = set()   # verify.v2's memo: a run is checked again at each checkpoint, its new records only in full
        self.due = 0   # when a run put off (BACKOFF, RECHECK_S) is due, so _watch refreshes with no store change
        # (tenant, run_id) -> its latest review row while on the live view, else (it left the view) in kept, which the
        # snapshot serves before the records so the run list keeps every run's verdict, failed ones longest
        self.latest, self.kept = {}, collections.OrderedDict()
        self.tr = Translator(policy_reasons([cfg["policy"]] if cfg.get("policy") else []))
        self.stopped = None   # why the watch thread ended, when it did: the page then says verification stopped
        self.on_run, self.content, self.analyze = on_run, content, analyze
        # (tenant, run_id) -> the newest records of a run to mirror (on_run), off the watch thread: the tape never
        # waits for a graph, and a run that grew twice meanwhile is mirrored once
        self._mirror, self._mlock = {}, threading.Condition()
        self._stop, self.threads = threading.Event(), []   # close()
        if on_run:
            self.threads.append(threading.Thread(target=self._mirrors, daemon=True))
        self.tmp = tempfile.mkdtemp(prefix="tk-view-")
        atexit.register(shutil.rmtree, self.tmp, True)
        self.trust = write_trust(os.path.join(self.tmp, "trust.json"), vkeys)
        self.threads.append(threading.Thread(target=self._watch, daemon=True))
        for t in self.threads:
            t.start()

    def close(self):
        """Stop the watch and mirror threads, once a refresh or mirror under way ends: a feed over a store that goes
        away (a test's) then never reports it."""
        self._stop.set()
        with self._mlock:
            self._mlock.notify_all()
        for t in self.threads:
            t.join()

    def _watch(self):
        seen = None
        try:
            while not self._stop.is_set():
                stamp = []
                for name in () if self.pg else ("records.jsonl", NOTE):
                    try:
                        st = os.stat(os.path.join(self.store, name))
                        stamp.append((st.st_size, st.st_mtime_ns))
                    except FileNotFoundError:
                        stamp.append(None)
                # lean: a Postgres store is read again every POLL_S; compare its latest note first if that loads it
                if stamp != seen or self.pg or time.time() >= self.due:
                    seen = stamp
                    try:
                        self.refresh()
                    except Exception as e:   # the store unreadable, or a bug: said, and tried again
                        print(f"tracekit view: cannot check {self.store}: {e!r}", file=sys.stderr, flush=True)
                self._stop.wait(POLL_S)
        except BaseException as e:   # whatever ends the watch but close(): the page stops saying LIVE
            self.stopped = f"verification stopped ({type(e).__name__}: {e}): no run is checked until tracekit view " \
                           "restarts"
            raise

    def refresh(self):
        """Verify every run with records a checkpoint covers that were not verified yet: a run still being written is
        shown up to the newest checkpoint, not only once it stops, and checked again no sooner than BACKOFF times its
        last check's time after it. A run that did not grow is checked again RECHECK_S after its last check (the run
        checked longest ago, one a pass), so a later edit of its records shows."""
        now, stale = time.time(), None
        due = [now + RECHECK_S]
        self.due = due[0]   # a store that cannot be read is tried again when it changes, not every POLL_S
        r = reader(self.cfg)
        try:
            note = r.checkpoint_latest()
            if note and note[0] > r.tree.size:
                r.close()
                r = reader(self.cfg)   # opened after the note: holds every record it covers
            for key, run in list(r.runs.items()):
                covered = bisect.bisect_left(run["seqs"], note[0]) if note else 0   # its records the note covers
                state = self.runs.get(key, {})
                if covered and covered != state.get("count"):
                    at = state.get("checked", 0) + BACKOFF * state.get("took", 0)
                    if at > now:
                        due.append(at)
                    else:
                        self._check(r, note[1], key, covered)
                elif covered:
                    due.append(state["checked"] + RECHECK_S)
                    if state["checked"] + RECHECK_S <= now and (stale is None or state["checked"] < stale[1]):
                        stale = key, state["checked"], covered
                elif key not in self.runs and key[1] != SIGNER_RUN[1]:   # no checkpoint covers it yet: listed as pending
                    # its first record, unverified: the agent's name only if it is one
                    name = parsers._get(next(iter(r.iter_run(*key)), None), "event", "data", "agent", "name")
                    name = name if isinstance(name, str) else None
                    with self.lock:
                        self.runs[key] = {"count": 0, "shown": 0, "failed": None}
                        self._append([{**self.tr._base({"run_id": key[1]}, {}, "tk_run"), "tenant": key[0],
                                       "analysis": True, "review": {"verdict": "pending", "agent": name,
                                                                    "label": OPERATOR_SIDE}}], key)
            if stale:
                self._check(r, note[1], stale[0], stale[2])
        finally:
            r.close()
        self.due = min(due)

    def _check(self, reader, note, key, count):
        """_verify, where an error gives the run a "not checked" row and is tried again as a run that did not grow
        is: one run never stops the others being checked."""
        try:
            self._verify(reader, note, key, count)
        except Exception as x:
            why = f"{type(x).__name__}: {x}"[:1024]
            print(f"tracekit view: run {key[1]} not checked: {why}", file=sys.stderr, flush=True)
            row = self._own({"run_id": key[1]}, "high", f"RUN {key[1]} · NOT CHECKED: error",
                            f"{OPERATOR_SIDE}\n\nThe viewer could not check this run ({why}); it tries again in "
                            f"{RECHECK_S // 60} minutes or when the run grows.", "VERIFY")
            row["review"] = {"verdict": "error", "integrity": "NOT CHECKED", "assurance": "none",
                             "label": OPERATOR_SIDE, "agent": None}
            with self.lock:
                self.runs[key] = dict(self.runs.get(key) or {"count": 0, "shown": 0}, count=count,
                                      failed="NOT CHECKED (error)", checked=time.time())
                self._append([dict(row, tenant=key[0])], key)

    def _verify(self, reader, note, key, count):
        tenant, run_id = key
        t = time.thread_time()   # its own CPU time: not the time it waited for the mirror thread
        rep, code, text = check(reader, tenant, run_id, note, self.trust, os.path.join(self.tmp, "run.tkb"), self.memo)
        if len(self.memo) > MEMO_MAX:   # lean: forgets every run's records at once; an LRU if big stores re-check often
            self.memo.clear()
        state = dict(self.runs.get(key) or {"count": 0, "shown": 0, "failed": None}, checked=time.time(),
                     took=time.thread_time() - t)
        if not code and count == state["count"] and not state["failed"]:   # checked again, unchanged: nothing new
            with self.lock:
                self.runs[key] = state
            return
        e = {"run_id": run_id}
        if code:
            rv = {"verdict": "failed", "integrity": rep.integrity, "assurance": rep.assurance.split(";")[0],
                  "label": OPERATOR_SIDE, "agent": None}
            try:   # placed at its run's last record's time, as a run that verifies is; only the time is read
                e["ts"] = collections.deque(reader.iter_run(tenant, run_id), 1)[0]["event"]["ts"]
            except (ValueError, KeyError, IndexError, TypeError, StorageCorrupt):
                pass
            new = [self._own(e, "high", f"RUN {run_id} · Integrity {rep.integrity}", f"{OPERATOR_SIDE}\n\n{text}",
                             "VERIFY")]
            # its rows of when it verified leave the tape (shown again from the start, findings too, if it verifies
            # again)
            state = dict(state, count=count, shown=0, failed=rep.integrity, analyzed=False)
            records = None   # a mirror of it, from when it verified, goes
        else:
            records = list(itertools.islice(reader.iter_run(tenant, run_id), count))   # what the checkpoint covers
            e["ts"] = records[-1]["event"]["ts"]   # the report sits at the end of what it covers
            want = [r for r in records[state["shown"]:] if self.content and (
                r["event"]["type"] == "policy.decision" and (r["event"].get("data") or {}).get("args_commitment")
                or r["event"]["type"] == "model.exchange" and (r["event"].get("data") or {}).get("content_digest"))]
            from .why.signed import EvidenceAlert
            new = []
            if want:   # content_get per run and refresh, each a content.accessed record
                try:
                    self.tr.content.update({(run_id, s): c for s, c in self.content(run_id, want).items()})
                except EvidenceAlert as x:   # the vault's content does not open its record: none of it shown
                    new = [self._own(e, "high", "CONTENT NOT SHOWN", str(x)[:1024], "ALERT")]
            new += [x for r in records[state["shown"]:] for x in self.tr.feed(r)]
            rv = review(records, rep, "verified")
            summary = (f"tenant {tenant} · the signer's own records" if run_id == SIGNER_RUN[1] else
                       f"tenant {tenant} · agent {rv['agent'] or '?'} · {rv['state']} · decisions "
                       + (", ".join(f"{v} {n}" for v, n in sorted(rv["decisions"].items())) or "none")
                       + f" · approvals {len(rv['approvals'])} · gaps {sum(rv['gaps'].values())}")
            # the verifier's report is a row when the run is first shown and when it is final; as a run still being
            # written grows to each checkpoint, only its review (the run list's verdict and counts) is updated
            new.append(self._own(e, "info", f"RUN {run_id} · Integrity {rep.integrity} · Assurance {rv['assurance']}",
                                 f"{summary}\n{self.note}\n{OPERATOR_SIDE}\n\n{text}", "VERIFY")
                       if not state["shown"] or rv["state"] == "final" or state.get("failed") else
                       {**self.tr._base(e, {}, "tk_run"), "analysis": True})
            # a findings run is the analysis of another run: its signed findings are shown, never analysed again
            analyze = bool(self.analyze) and rv["state"] == "final" and not rv.get("analyzes") \
                and not state.get("analyzed")
            state = dict(state, count=count, shown=len(records), failed=None,
                         analyzed=state.get("analyzed") or analyze)
        new[-1]["review"] = rv
        if key[1] == SIGNER_RUN[1]:
            new[-1].update(signer=True, agent="signer")
        with self.lock:
            self.runs[key] = state
            if code:   # its records, and the reports and findings of when it verified
                for i, x in enumerate(self.records):
                    if x is not observe.RETRACTED and (x.get("tenant"), x.get("session_id")) == key:
                        self.records[i] = observe.RETRACTED
            self._append([dict(x, tenant=tenant) for x in new], key)
        if self.on_run and key[1] != SIGNER_RUN[1]:   # after the tape has the records: the graph waits, not the tape
            with self._mlock:
                self._mirror[key] = records
                self._mlock.notify()
        if not code and analyze:   # after its rows too: the analysis reads the run's content, which takes a while
            found = self._findings(e, records)
            row = {**self.tr._base(e, {}, "tk_run"), "analysis": True,
                   "review": dict(rv, findings=found[-1].pop("summary"))}
            with self.lock:
                self._append([dict(x, tenant=tenant) for x in found + [row]], key)

    def _mirrors(self):
        """The mirror thread: on_run for each run that changed, with its newest records. A run is imported whole each
        time, so a growing run is mirrored again no sooner than BACKOFF times its last mirror's time after it; a run
        that failed or left the live view (records None) loses its mirror at once."""
        # lean: BACKOFF counts the import, not the why server's analysis of it on its own thread (about as long again);
        # count both if a growing run's graph costs too much CPU
        due = {}   # (tenant, run_id) -> when it may be mirrored again
        while True:
            with self._mlock:
                while True:
                    if self._stop.is_set():
                        return
                    now = time.time()
                    ready = next((k for k, v in self._mirror.items() if v is None or due.get(k, 0) <= now), None)
                    if ready:
                        break
                    self._mlock.wait(min(due[k] for k in self._mirror) - now if self._mirror else None)
                records = self._mirror.pop(ready)
            t, cpu = time.time(), time.thread_time()
            try:
                self.on_run(*ready, records, self.tr.reasons)
            except Exception as e:   # the run's own view does not depend on its graph
                print(f"tracekit view: no graph for run {ready[1]}: {e}", file=sys.stderr, flush=True)
            due = {k: v for k, v in due.items() if v > t}   # only runs still put off
            due[ready] = time.time() + BACKOFF * (time.thread_time() - cpu)

    def _own(self, e, sev, title, text, tape):
        """A row the viewer makes (a verifier report, a finding of its analysis): no record of the log, so no seq and
        no hash, and labelled as the viewer's analysis."""
        return {**self.tr.alert(e, {}, sev, title, text, tape), "analysis": True}

    def _findings(self, e, records):
        """A final run's findings as FINDING alerts, each with its cited records; the last carries the run review's
        findings and monitorability lines (`summary`)."""
        try:
            out = self.analyze(records)
        except Exception as x:   # an EvidenceAlert: the vault's content does not open its record
            return [{**self._own(e, "high", "FINDINGS NOT RUN", str(x)[:1024], "ALERT"),
                     "summary": {"line": f"not run: {str(x)[:256]}"}}]
        alerts = []
        for f, d in zip(out["findings"], out["shown"]["details"]):
            v = f["verdict"]
            why, todo = findings_v2.WHY[v["rule"]]
            alerts.append({**self._own(
                e, {"critical": "high", "high": "high", "medium": "med"}.get(v["severity"], v["severity"]),
                f"FINDING {v['rule']} · {findings_v2.TITLES[v['rule']]}",
                f"{d['what']}\nWhy it matters: {why}\nWhat to do: {todo}\nRelied on: {', '.join(d['tiers'])}",
                "FINDING"), "v2": {"finding": v, "cites": f["cites"]}})
        actions, readable = findings_v2.monitorability(out["coverage"]["verdict"])
        cov = out["coverage"]["verdict"]
        # each check that could not run, in words (its reason code is the tooltip)
        gaps = [{"rule": r, "code": g["reason"], "n": g["n"],
                 "text": findings_v2.REASONS.get(g["reason"], (g["reason"],))[0]}
                for r, c in cov["checks"].items() for g in c["not_checkable"]]
        said = out["summary"].split(": ", 1)[1]
        if gaps:   # "no problems found" only when every check could run
            said = said.replace("no problems found", "nothing found in what could be checked")
        line = {"line": said, "not_checkable": gaps, "monitorability": (
            f"reasoning readable before {readable} of {actions} actions · "
            + ", ".join(f"{k} {n}" for k, n in cov["reasoning"].items()))}
        alerts.append({**self._own(e, "info", "FINDINGS · " + said,
                                   f"{line['monitorability']}\nnot checkable: "
                                   + ("".join(f"\n  {g['rule']} for {g['n']}: {g['text']}" for g in gaps) or "none")
                                   + "\nfindings are the analyzer's opinion of the run, not part of its integrity",
                                   "FINDING"), "summary": line,
                       "v2": {"effects": out["shown"].get("effects", {})}})   # each sensor effect's call (TK-X206)
        return alerts

    def _append(self, rows, key):
        """Under self.lock: add `rows`, the last of them run `key`'s review, and wake the event streams."""
        self.records.extend(rows)
        self.latest[key] = rows[-1]
        self.kept.pop(key, None)
        self._trim()
        self.lock.notify_all()

    def _trim(self):
        """Under self.lock: drop the oldest records past max_records, counted in base (what /api/snapshot calls dropped);
        a run's latest review among them goes to kept, which keeps KEPT_MAX runs' and drops a failed run's last, and
        the run's graph goes (on_run), so the graphs too are of the runs on the live view only."""
        over = len(self.records) - self.max_records
        if over > 0:
            for x in self.records[:over]:
                key = x is not observe.RETRACTED and x.get("review") and (x.get("tenant"), x["session_id"])
                if key and self.latest.get(key) is x:
                    del self.latest[key]
                    self.kept[key] = x
                    if self.on_run and key[1] != SIGNER_RUN[1]:
                        with self._mlock:
                            self._mirror[key] = None
                            self._mlock.notify()
            while len(self.kept) > KEPT_MAX:
                self.kept.pop(next((k for k, x in self.kept.items() if x["review"]["verdict"] != "failed"),
                                   next(iter(self.kept))))
            del self.records[:over]
            self.base += over

    def verify(self, tenant=None):
        """For the page's chain badge: records verified, and the runs that failed (of `tenant`, else of all)."""
        with self.lock:
            runs = {k: s for k, s in self.runs.items() if tenant is None or k[0] == tenant}
            return (sum(s["shown"] for s in runs.values() if not s["failed"]),
                    [f"run {k[1]} of tenant {k[0]}: {s['failed']}" for k, s in runs.items() if s["failed"]]
                    + [self.stopped] * bool(self.stopped), None)


def mirror_run(why_dir, tenant, run_id, records, reasons=None):
    """Import one verified v2 run as a why run under `why_dir` (why.import_v2, from the records only), replacing an
    earlier import of it, so GRAPH, WHY, AGENTS and INFLUENCE work on a store with no why logs; with `records` None (the
    run failed verification), remove its import. A reader sees the old import, the new one or, between the two
    renames, neither: never part of one."""
    # lean: the whole run is imported again each time it grows; import only the new records if long runs make it slow
    from .why.import_v2 import _target, import_records
    target = _target(why_dir, run_id, tenant)
    stage = tempfile.mkdtemp(prefix=".import-", dir=why_dir)
    try:
        if records is not None:
            path = import_records({run_id: records}, stage, reasons)[0]
        if os.path.exists(target):
            _rename(target, os.path.join(stage, "old"))
        if records is not None:
            _rename(path, target)
    finally:
        shutil.rmtree(stage, True)


def _rename(src, dst):
    """os.rename, tried again while Windows denies it: a reader with a file of the folder open (the why server reading
    the run, a virus scanner) denies a folder's rename for as long as it reads."""
    # lean: a reader holding a file over 5 s still fails the mirror (the run keeps its old graph); queue it again then
    for _ in range(100):
        try:
            return os.rename(src, dst)
        except PermissionError as e:
            if getattr(e, "winerror", None) not in (5, 32):   # access denied, sharing violation
                raise
            time.sleep(0.05)
    os.rename(src, dst)


def write_trust(path, vkeys):
    """A verify.v2 trust config at `path` that pins the log vkeys `vkeys` and no witness; returns `path`."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"logs": vkeys, "witnesses": [], "algs": [RecordSigner.alg], "witnesses_required": 0}, f)
    return path


def check(reader, tenant, run_id, note, trust, out, memo=None):
    """(report, exit code, printed report) of verify.v2 on the run's bundle, exported from `reader` with `note` to
    `out`; `memo`: verify.v2's, kept across checks."""
    try:
        export(reader, tenant, run_id, note, out)
        rep, code = v2.verify(out, trust, memo=memo)
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


def server(feed, host, port, token, tls=None, login=None, desk=None, runs=None, why=None):
    """The viewer's HTTP server (HTTPS with `tls`, an ssl.SSLContext), open to requests that present `token` (or the
    session cookie it is exchanged for), or with `login` (an OidcLogin) a session of its own, whose approver sessions
    get the approval pages of `desk` (an ApprovalDesk); with `runs` (a Runs, and no `feed`), the run pages of a central
    deployment's logs; with `why` (a why.server.Store publishing into `feed`), the why views' API; call
    serve_forever()."""
    if not token:
        raise ValueError("the viewer needs a token")
    hosts = [host] + ([urlsplit(login.redirect_uri).hostname] if login else [])

    class Handler(observe.make_handler(feed, token, hosts, secure=bool(tls), login=login, approvals=desk, runs=runs,
                                       why=why)):
        def long_request(self):
            self.server.stop_deadline()   # an event stream lasts as long as the page is open, a replay its trials

        def stream_slot(self):
            return self.server.to_stream(self.client_address[0])
    return Server((host, port), Handler, tls, max_threads=THREADS, max_per_ip=PER_IP, max_streams=STREAMS,
                  max_streams_per_ip=STREAMS_PER_IP)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit view", description="the viewer: the v2 signer's runs, why logs, the v1 ledger or a bundle (read-only)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dev", action="store_true", help="the same-user dev signer's data dir (the default)")
    g.add_argument("--config", help="signer.yaml: view its data_dir")
    g.add_argument("--data-dir", help="a signer data dir (holds store/ and log.vkey)")
    g.add_argument("--ledger", nargs="?", const="", metavar="HOME",
                   help="the v1 signer's ledger (tracekitd; HOME default: the client config's signer home)")
    g.add_argument("--bundle", help="a v1 .tkb bundle, verified first (refused when it fails)")
    ap.add_argument("--log-vkey", help="pin this log vkey (`tracekit signer vkey`) instead of the one the store names")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7778)
    ap.add_argument("--tls-cert", help="PEM certificate: serve HTTPS (required beyond loopback)")
    ap.add_argument("--tls-key", help="PEM private key of --tls-cert")
    ap.add_argument("--insecure-http", action="store_true", help="serve plain HTTP beyond loopback anyway")
    ap.add_argument("--why", metavar="DIR", help=f"why logs to investigate (default: {WHY_DIR}/ in the data dir, if "
                                                 "present)")
    ap.add_argument("--allow-program", action="append", default=[], metavar="SPEC",
                    help="a why System (module:ATTR) FIND THE CAUSE and RUN TEST may replay (repeatable)")
    ap.add_argument("--ingest-token", action="append", default=[], metavar="TOKEN",
                    help="a bearer token /v1/ingest takes for why logs, and nothing else (repeatable; default: the "
                         "viewer's token)")
    ap.add_argument("--webhook", help="POST each new high why alert here as JSON (Slack-compatible)")
    a = ap.parse_args(argv)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # a stop runs atexit too: the temp dirs go
    from .cli import experimental
    if a.why:
        experimental("tracekit why (tracekit view --why)")
    if a.ledger is not None or a.bundle:
        experimental("the v1 ledger (tracekit view --ledger, --bundle)")
    loopback = a.host in observe.LOOPBACK_HOSTS
    if (a.ledger is not None or a.bundle) and not loopback:
        print("tracekit view: --ledger and --bundle serve on loopback only, as `tracekit observe` did; reach the page "
              "from another machine through an SSH tunnel", file=sys.stderr)
        return 2
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
        v1 = a.ledger is not None or a.bundle
        alone = a.why and not (v1 or a.dev or a.config or a.data_dir)   # why logs alone, as `tracekit why serve`
        cfg = {} if v1 or alone else load_config(a.config) if a.config else {"data_dir": a.data_dir or dev_data_dir()}
        view = cfg.get("view") or {}
        login = view.get("oidc") and OidcLogin(view["oidc"], (cfg.get("http") or {}).get("oidc"))
        desk = login and view.get("signer") and ApprovalDesk(Client(view["signer"]),
                                                             (cfg.get("approvals") or {}).get("webauthn"))
        runs = view.get("logs") and Runs(view["logs"], a.log_vkey)
        why_dir = a.why or (cfg.get("data_dir") and os.path.join(cfg["data_dir"], WHY_DIR))
        mirror = None
        if not (v1 or alone or runs or a.why or (why_dir and os.path.isdir(why_dir))):   # no why logs: the store's own
            why_dir = tempfile.mkdtemp(prefix="tk-view-why-")
            atexit.register(shutil.rmtree, why_dir, True)
            mirror = functools.partial(mirror_run, why_dir)
        if v1:
            ledger, code = observe.ledger_path(a.ledger, a.bundle, "tracekit view")
            if ledger is None:
                return code
            feed = observe.Feed(ledger, source="bundle" if a.bundle else None)
        else:
            dev = not (a.config or a.data_dir)
            feed = None if runs or alone else StoreFeed(cfg, a.log_vkey, mirror, dev_content_source() if dev else None,
                                                        dev_analysis() if dev else None)
        why = Store(why_dir, a.allow_program, a.webhook, out=feed, tape=bool(alone), ingest_tokens=a.ingest_token,
                    ingest=not mirror) \
            if (feed or alone) and why_dir and (a.why or os.path.isdir(why_dir)) else None
        feed = why.out if alone else feed
        srv = server(feed, a.host, a.port, token, tls, login, desk, runs, why)
    except (OSError, ValueError, StorageUnavailable) as e:
        print(f"tracekit view: {e}", file=sys.stderr)
        return 1
    scheme = "https" if tls else "http"
    print(f"tracekit view on {scheme}://{a.host}:{srv.server_address[1]}/"
          + ("" if os.environ.get("TRACEKIT_VIEW_TOKEN") else f"?token={token}")
          + (f"  ({len(runs.logs)} Postgres logs, read-only)" if runs else
             f"  (bundle: {a.bundle}, verified, read-only)" if a.bundle else
             f"  (ledger: {feed.path}, read-only)" if v1 else f"  (why logs alone: {why.root})" if alone else
             f"  (store: {feed.store}, read-only; {feed.note})"), flush=True)
    if why and mirror:
        why.watch()
        print("  graphs: each verified run, imported from the store (read-only) into a temp dir", flush=True)
    elif why:
        why.watch()
        print(f"  why logs: {why.root}; FIND THE CAUSE and RUN TEST "
              + (f"replay {', '.join(a.allow_program)}" if a.allow_program else
                 "show the command to run (start with --allow-program module:SYSTEM to run them here)"), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        if why:
            why.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
