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
import ssl
import sys
import tempfile
import threading
import time
from http.client import HTTPException
from urllib.parse import urlencode, urlsplit

from . import observe
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

POLL_S = 1.0
THREADS, PER_IP = 512, 128   # each open page holds a connection for its event stream; a team may share one address
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
        with self._lock:
            self._sessions[sid] = {"tenant": observe.ALL if role == "operator-admin" else tenant, "role": role,
                                   "person": person, "csrf": secrets.token_urlsafe(32), "at": self.clock(),
                                   "until": self.clock() + SESSION_S}
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
        """(status, body) of POST `path` with JSON `body`: a passkey registration, or an answer to an approval."""
        who = {"on_behalf": session["person"]}
        if path == "/api/passkey":
            if self.clock() - session["at"] > PASSKEY_LOGIN_S:
                return 403, {"error": f"sign in again (/login): a passkey is registered within "
                                      f"{PASSKEY_LOGIN_S // 60} minutes of signing in"}
            return self._call("passkey_register", {**who, **{k: body[k] for k in ("credential_id", "public_key")
                                                            if k in body}})
        if not path.startswith("/api/approvals/"):
            return 404, {"error": "not found"}
        return self._call("approval_decide", {"request_id": secrets.token_hex(16),
                                              "approval_id": path[len("/api/approvals/"):], **who,
                                              **{k: body[k] for k in ("decision", "reason", "passkey") if k in body}})


ENGINE_RULES = {"TK-UNKNOWN-TOOL": "a tool the policy does not map", "TK-SQL-PARSE": "SQL no dialect reads",
                "TK-OVERSIZE": "arguments too large to check", "TK-SHELL-PARSE": "a shell command that does not parse"}
SEVERE_GAPS = {"hook_missing", "proxy_missing", "policy_unrecorded", "state_tamper", "rollback", "key_revoked",
               "decision_flip", "executed_against_denial"}


def policy_reasons(paths=()):
    """policy_hash -> {rule id: reason} of the shipped packs and the policy files `paths`: a decision's rule reasons
    are shown only from the policy whose hash it records."""
    out = {}
    for p in sorted(glob.glob(os.path.join(os.path.dirname(policy_compile.__file__), "packs", "*.yaml"))) + list(paths):
        pol, errors = policy_compile.build(p)
        if not errors:
            out[policy_compile.policy_hash(pol)] = {r["id"]: r.get("reason") or r.get("label") or ""
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
        # lean: approval_id -> tool for the viewer's life, like agent_names; bound both once stores hold millions
        self.requests = {}

    def _base(self, e, rec, event):
        return {**super()._base(e, rec, event), "agent": self.agent_names.get(e["run_id"], "agent")}

    def rules(self, d):
        known = self.reasons.get(d.get("policy_hash"), {})
        return [{"id": i, "reason": known.get(i) or ENGINE_RULES.get(i, "")} for i in d.get("rule_ids") or []]

    def feed(self, rec):
        e = rec["event"]
        t, d = e["type"], e.get("data") or {}
        out = self._v2(e, rec, t, d)
        info = {"type": t, "run_seq": e.get("run_seq"), "tool_use_id": d.get("tool_use_id")
                or (d.get("binding") or {}).get("tool_call_id") or e.get("tool_call_id")}
        for x in out:
            x["v2"] = {**info, **x.get("v2", {})}
            if e["run_id"] == SIGNER_RUN[1]:
                x.update(signer=True, agent="signer")
        return out

    def _v2(self, e, rec, t, d):
        def alert(sev, title, text, tape, **v2):
            return [{**self.alert(e, rec, sev, title, text, tape), "v2": v2}]
        if t == "run.registered":
            self.agent_names[e["run_id"]] = (d.get("agent") or {}).get("name") or "agent"
            return [{**self._base(e, rec, "SessionStart"),
                     "source": f"{d.get('signer_isolation')} signer · {_who(d.get('identity'))}"}]
        if t == "run.closing":
            return [{**self._base(e, rec, "SessionEnd"), "reason": {"close_run": "closed by the agent",
                                                                    "idle_timeout": "closed after the idle timeout"}
                     .get(d.get("reason"), d.get("reason"))}]
        if t == "run.final":
            cov = d.get("coverage") or {}
            line = (f"final · head run_seq {d.get('head_run_seq')} · coverage {'+'.join(cov.get('layers') or []) or 'none'}"
                    f" · reconciled {cov.get('reconciled', 0)}"
                    + "".join(f" · unreconciled {k} {v}" for k, v in sorted((cov.get("unreconciled") or {}).items())))
            return [{**self._base(e, rec, "SessionEnd"), "reason": line, "v2": {"coverage": line}}]
        if t == "policy.decision":
            dec, rules = d.get("decision"), self.rules(d)
            r = self._base(e, rec, "PreToolUse")
            r.update(tool_name=d.get("tool"), tool_use_id=d.get("tool_use_id"), tool_input={},
                     target="; ".join(f"{x['id']} {x['reason']}".strip() for x in rules) or "no rule matched",
                     policy={"decision": "deny" if dec == "deny" else "allow", "reasons": [x["id"] for x in rules],
                             "flags": {"flag": ["flagged"], "ask": ["held_for_approval"]}.get(dec, [])},
                     v2={"decision": dec, "rules": rules, "args_commitment": d.get("args_commitment"),
                         "policy_hash": d.get("policy_hash"), "decision_id": d.get("decision_id")})
            return [r]
        tool = self.requests.get(d.get("approval_id"), "")
        if t == "approval.request":
            self.requests[d.get("approval_id")] = tool = (d.get("binding") or {}).get("tool", "")
            rules = self.rules(d)
            return alert("med", f"APPROVAL REQUESTED · {tool}",
                         f"requested by {d.get('requester')} · rules "
                         + ", ".join(f"{x['id']} {x['reason']}".strip() for x in rules)
                         + f" · expires {_hms(d.get('expires_at'))}"
                         + (" · signer executes (t2)" if d.get("executor") == "t2" else ""), "HOLD",
                         approval="requested", rules=rules, binding_digest=d.get("binding_digest"))
        if t == "approval":
            dec, who = d.get("decision"), d.get("approver_identity")
            text = (f"by {_who(who) if who else d.get('approver')}"
                    + (f" · vouched for by {_who(d['via'])} via {d.get('channel')}" if d.get("via") else "")
                    + (f" · “{d['reason']}”" if d.get("reason") else "")
                    + (" · SELF-APPROVED" if d.get("self_approved") else " · not self-approved")
                    + (" · BREAK-GLASS" if d.get("break_glass") else "") + (" · passkey" if d.get("passkey") else ""))
            sev = "high" if dec == "self_approval_refused" or d.get("break_glass") else \
                "med" if d.get("self_approved") else "info"
            word = {"approve": "APPROVED", "reject": "REJECTED", "timeout": "TIMED OUT",
                    "self_approval_refused": "SELF-APPROVAL REFUSED"}.get(dec, str(dec).upper())
            return alert(sev, f"{word} · {tool or d.get('tool_use_id')}", text,
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
            return alert(sev, f"GAP · {kind}", text.strip(" ·") or "signed gap: records may be missing", "GAP",
                         kind=kind)
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
        return super().feed(rec) or alert("info", t, json.dumps(d, ensure_ascii=False)[:200], "ALERT")


def review(records, rep, verdict):
    """The run review of a verified run's records: what the page's run list and review show. `rep` is verify.v2's
    report and `verdict` one of VERDICTS; `first` maps each line to the seq of its first record."""
    out = {"verdict": verdict, "integrity": rep.integrity, "assurance": rep.assurance.split(";")[0],
           "label": OPERATOR_SIDE, "agent": None, "records": len(records), "first_ts": None, "last_ts": None,
           "decisions": collections.Counter(), "approvals": [], "gaps": collections.Counter(), "coverage": None,
           "state": "open", "first": {}}
    for rec in records:
        e = rec["event"]
        t, d = e["type"], e.get("data") or {}
        out["first_ts"] = out["first_ts"] or e.get("ts")
        out["last_ts"] = e.get("ts")
        key = None
        if t == "run.registered":
            out["agent"] = (d.get("agent") or {}).get("name") or "agent"
        elif t == "policy.decision":
            out["decisions"][d.get("decision")] += 1
            key = d.get("decision")
        elif t == "approval":
            out["approvals"].append({"decision": d.get("decision"), "tool_use_id": d.get("tool_use_id"),
                                     "approver": _who(d["approver_identity"]) if d.get("approver_identity")
                                     else d.get("approver"), "via": d.get("via") and _who(d["via"]),
                                     "self_approved": bool(d.get("self_approved")),
                                     "break_glass": bool(d.get("break_glass")), "seq": e.get("seq")})
            key = "approval"
        elif t == "capture.gap" or t.startswith("reconcile."):
            key = "gap:" + (d.get("kind") or t)
            out["gaps"][key[4:]] += 1
        elif t == "run.final":
            cov = d.get("coverage") or {}
            out["coverage"] = {"layers": cov.get("layers") or [], "reconciled": cov.get("reconciled", 0),
                               "unreconciled": cov.get("unreconciled") or {}}
            out["state"] = "final"
        elif t == "run.closing" and out["state"] == "open":
            out["state"] = "closing"
        if key and key not in out["first"]:
            out["first"][key] = e.get("seq")
    return out


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
        self.tr = Translator(policy_reasons([cfg["policy"]] if cfg.get("policy") else []))
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
                elif key not in self.runs and key != SIGNER_RUN:   # no checkpoint covers it yet: listed as pending
                    first = next(iter(r.iter_run(*key)), None)
                    name = first and ((first["event"].get("data") or {}).get("agent") or {}).get("name")
                    with self.lock:
                        self.runs[key] = {"count": 0, "shown": 0, "failed": None}
                        self.records.append({**self.tr._base({"run_id": key[1]}, {}, "tk_run"), "tenant": key[0],
                                             "review": {"verdict": "pending", "agent": name, "label": OPERATOR_SIDE}})
                        self.lock.notify_all()
        finally:
            r.close()

    def _verify(self, reader, note, key, count):
        tenant, run_id = key
        rep, code, text = check(reader, tenant, run_id, note, self.trust, os.path.join(self.tmp, "run.tkb"))
        state = self.runs.get(key) or {"count": 0, "shown": 0, "failed": None}
        e = {"run_id": run_id}
        if code:
            rv = {"verdict": "failed", "integrity": rep.integrity, "assurance": rep.assurance.split(";")[0],
                  "label": OPERATOR_SIDE, "agent": None}
            try:   # placed at its run's last record's time, as a run that verifies is; only the time is read
                e["ts"] = collections.deque(reader.iter_run(tenant, run_id), 1)[0]["event"]["ts"]
            except (ValueError, KeyError, IndexError, TypeError, StorageCorrupt):
                pass
            new = [self.tr.alert(e, {}, "high", f"RUN {run_id} · Integrity {rep.integrity}",
                                 f"{OPERATOR_SIDE}\n\n{text}", "VERIFY")]
            state = dict(state, count=count, failed=rep.integrity)
        else:
            records = list(reader.iter_run(tenant, run_id))
            e["ts"] = records[-1]["event"]["ts"]   # the report sits at the end of what it covers
            new = [x for r in records[state["shown"]:] for x in self.tr.feed(r)]
            rv = review(records, rep, "verified")
            summary = (f"tenant {tenant} · agent {rv['agent'] or '?'} · {rv['state']} · decisions "
                       + (", ".join(f"{v} {n}" for v, n in sorted(rv["decisions"].items())) or "none")
                       + f" · approvals {len(rv['approvals'])} · gaps {sum(rv['gaps'].values())}")
            new.append(self.tr.alert(e, records[-1], "info", f"RUN {run_id} · Integrity {rep.integrity} · Assurance "
                                     f"{rv['assurance']}", f"{summary}\n{self.note}\n{OPERATOR_SIDE}\n\n{text}", "VERIFY"))
            state = dict(state, count=count, shown=len(records), failed=None)
        new[-1]["review"] = rv
        if key == SIGNER_RUN:
            new[-1].update(signer=True, agent="signer")
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


def server(feed, host, port, token, tls=None, login=None, desk=None, runs=None):
    """The viewer's HTTP server (HTTPS with `tls`, an ssl.SSLContext), open to requests that present `token` (or the
    session cookie it is exchanged for), or with `login` (an OidcLogin) a session of its own, whose approver sessions
    get the approval pages of `desk` (an ApprovalDesk); with `runs` (a Runs, and no `feed`), the run pages of a central
    deployment's logs; call serve_forever()."""
    if not token:
        raise ValueError("the viewer needs a token")
    hosts = [host] + ([urlsplit(login.redirect_uri).hostname] if login else [])

    class Handler(observe.make_handler(feed, token, hosts, secure=bool(tls), login=login, approvals=desk, runs=runs)):
        def stream(self, *a):
            self.server.stop_deadline()   # an event stream lasts as long as the page is open
            return super().stream(*a)
    return Server((host, port), Handler, tls, max_threads=THREADS, max_per_ip=PER_IP)


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
