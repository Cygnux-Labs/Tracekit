"""`tracekit observe`: the live terminal (the Bloomberg-style observer) for v0.2 ledgers; part of `tracekit view` now
(`tracekit view --ledger [HOME]`, `--bundle FILE`), whose server this handler is.

Reads the signer's ledger (world-readable, never written here), translates each signed v0.2
event into the record shape the terminal UI understands, and serves the same endpoints as the
v0.1 observer: `/`, `/api/snapshot`, `/api/stream` (Server-Sent Events) and `/api/verify`
(hash chain + Ed25519 signatures of the whole ledger). It is read-only: there is no ingest
endpoint, because in v0.2 only tracekitd writes the ledger.

v0.2 extras are shown as alerts: blocked or held calls, capture gaps, trace tampering,
proxy/hook mismatches and approvals. Content that the ledger holds only as a hash is shown as
`[hashed · N bytes]`; the hash itself is in the record's DETAIL view.

    tracekit observe [--home /var/lib/tracekit] [--port 7777]
"""
import argparse
import collections
import hashlib
import hmac
import itertools
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote, urlparse

from .core import event_hash, read_text
from .ledger import read_records, verify_record_sig
from .netserver import MAX_STREAMS, MAX_THREADS, Lines, Server, body_length, drain, read_body
from .replay import CSP_META
from .storage.base import StorageCorrupt, StorageUnavailable
from .why.core import ts_seconds

HERE = os.path.dirname(os.path.abspath(__file__))
UI = os.path.join(HERE, "ui", "terminal.html")
APPROVALS_UI = os.path.join(HERE, "ui", "approvals.html")
RUNS_UI = os.path.join(HERE, "ui", "runs.html")
MAX_POST = 64 * 1024
MAX_INGEST = 20 * 1024 * 1024   # a why log batch (POST /v1/ingest)


def _epoch(ts):
    try:
        return ts_seconds(ts)
    except ValueError:
        return time.time()


def _show(c):
    """A content field as the UI should show it."""
    if not isinstance(c, dict):
        return c
    if "value" in c:
        return c["value"]
    if "hash" in c:
        return f"[hashed · {c.get('size', '?')} bytes{' · redacted' if c.get('redacted') else ''}]"  # the hash is in DETAIL
    return c


MAX_RUNS_KEPT = 50_000   # runs whose names, cwd and subagents the translator remembers


class _Bounded(collections.OrderedDict):
    """A dict that keeps its newest `cap` keys: per-run state of a long-running viewer can't grow with every run."""

    def __init__(self, cap):
        super().__init__()
        self.cap = cap

    def __setitem__(self, k, v):
        super().__setitem__(k, v)
        self.move_to_end(k)
        while len(self) > self.cap:
            self.popitem(last=False)


class Translator:
    """v0.2 events -> v0.1-shaped records for terminal.html. Stateful: joins tool.call with its
    policy.decision, which v0.2 records as two events."""

    def __init__(self, prices=None):
        self.prices = prices  # usage.Prices from --prices: adds cost to model calls (Tracekit ships no prices)
        self.pending = {}   # tool_use_id -> (tool.call event, record meta)
        # per run, the newest MAX_RUNS_KEPT kept (as many as the feed keeps records): a run past that shows defaults
        self.cwd = _Bounded(MAX_RUNS_KEPT)          # run_id -> cwd
        self.agent_names = _Bounded(MAX_RUNS_KEPT)  # run_id -> agent name
        self.child_meta = _Bounded(MAX_RUNS_KEPT)   # (run_id, child agent id) -> its spawn's meta
        self.spawn_calls = _Bounded(MAX_RUNS_KEPT)  # (run_id, tool_use_id) -> child agent id
        self.seen_agents = _Bounded(MAX_RUNS_KEPT)  # (run_id, agent id) -> True
        self.n = 0
        self.max_pending = 10000  # calls that never got a result must not accumulate forever

    def _base(self, e, rec, event):
        self.n += 1
        r = {"seq": self.n - 1, "ts": _epoch(e.get("ts")), "event": event, "session_id": e["run_id"],
             "cwd": self.cwd.get(e["run_id"], ""), "agent": self.agent_names.get(e["run_id"], "claude-code"),
             "parent_id": e.get("parent_id"), "hash": rec.get("hash"),
             "prev": e.get("prev_hash"), "tk_seq": e.get("seq"), "tk_source": e.get("source"),
             **({"ts_signed": _epoch(e["ts_signed"])} if "ts_signed" in e else {})}   # v1: ts is the client's
        if e.get("agent_id") and e["agent_id"] not in ("main", "tracekitd"):
            r["agent_id"] = e["agent_id"]
            meta = self.child_meta.get((e["run_id"], e["agent_id"]), {})
            r["agent_type"] = meta.get("agent_type") or "subagent"
        return r

    def alert(self, e, rec, severity, title, text, tape="ALERT"):
        return {**self._base(e, rec, "tk_alert"), "severity": severity, "title": title, "text": text, "tape": tape}

    def feed(self, rec):
        if not rec or rec.get("elided"):
            return []
        e = rec["event"]
        d = e.get("data") or {}
        t = e["type"]
        out = []
        if e["run_id"] == "_signer":
            if t in ("capture.gap", "trace.tamper"):
                out.append(self.alert(e, rec, "med", "SIGNER · " + t, d.get("reason") or json.dumps(d)[:200], "GAP"))
            return out
        if e["run_id"].startswith("findings:"):
            v = d.get("verdict") or {}
            if t == "review" and v.get("kind") == "finding":
                sev = {"critical": "high", "high": "high", "medium": "med"}.get(v.get("severity"), "low")
                a = self.alert(e, rec, sev, f"FINDING {v.get('rule', '')} · {v.get('title', '')}",
                               f"{v.get('detail', '')} [evidence seq {', '.join(str(x.get('seq')) for x in (v.get('evidence') or [])[:6])}]", "FINDING")
                a["evidence"] = [{"seq": x.get("seq"), "hash": x.get("hash")} for x in (v.get("evidence") or [])[:50] if isinstance(x, dict)]
                a.pop("agent_id", None)  # the analyzer is not an agent lane of the run
                a.pop("agent_type", None)
                a["session_id"] = v.get("run_id") or a["session_id"]
                a["agent"] = self.agent_names.get(a["session_id"], a["agent"])
                out.append(a)
            return out
        if t == "run.start":
            self.agent_names[e["run_id"]] = (d.get("agent") or {}).get("name") or "custom-agent"
        agent_id = e.get("agent_id")
        agent_key = (e["run_id"], agent_id)
        if agent_id not in (None, "main", "tracekitd") and agent_key not in self.seen_agents:
            self.seen_agents[agent_key] = True
            out.append(self._base(e, rec, "SubagentStart"))
        if t == "run.start":
            self.cwd[e["run_id"]] = d.get("cwd") or ""
            r = self._base(e, rec, "SessionStart")
            r.update(source=f"{d.get('signer_isolation')} signer · fail_mode={d.get('fail_mode')} · "
                            f"policy {(d.get('policy') or {}).get('version')} · sources {'+'.join(d.get('capture_sources') or [])}",
                     model=d.get("model"))
            out.append(r)
            if d.get("signer_isolation") == "same-user":
                out.append(self.alert(e, rec, "low", "DEV MODE", "signer runs as the agent's own user: not tamper-proof", "GAP"))
        elif t == "user.prompt":
            out.append({**self._base(e, rec, "UserPromptSubmit"), "prompt": _show(d.get("content"))})
        elif t == "tool.call":
            if len(self.pending) >= self.max_pending:
                self.pending.pop(next(iter(self.pending)))
            self.pending[d["tool_use_id"]] = (e, rec)
        elif t == "policy.decision":
            call = self.pending.pop(d.get("tool_use_id"), None)
            if call:
                ce, crec = call
                cd = ce["data"]
                r = self._base(ce, crec, "PreToolUse")
                reasons = d.get("reasons") or []
                known_flags = [x for x in reasons if x.replace("_", "").isalpha() and x == x.lower()]
                r.update(tool_name=cd["name"], tool_use_id=cd["tool_use_id"],
                         tool_input={k: _show(v) for k, v in (cd.get("input") or {}).items()},
                         policy={"decision": "deny" if d["decision"] == "deny" else "allow",
                                 "reasons": [f"{i}" for i in d.get("rule_ids") or []] + [x for x in reasons if x not in known_flags],
                                 "flags": known_flags + (["held_for_approval"] if d["decision"] == "ask" else [])})
                out.append(r)
                if cd["name"] in ("Agent", "Task"):
                    child_id = (cd.get("input") or {}).get("child_agent_id")
                    if isinstance(child_id, dict):
                        child_id = _show(child_id)
                    if isinstance(child_id, str) and child_id:
                        self.child_meta[(ce["run_id"], child_id)] = {
                            "agent_type": _show((cd.get("input") or {}).get("subagent_type")) or "subagent",
                            "parent_id": ce.get("agent_id"),
                        }
                        self.spawn_calls[(ce["run_id"], cd["tool_use_id"])] = child_id
                if d["decision"] == "ask":
                    out.append(self.alert(e, rec, "med", f"HELD FOR APPROVAL · {cd['name']}",
                                          f"{', '.join(d.get('rule_ids') or [])}: tracekit pending / tracekit approve <id>", "GAP"))
        elif t == "tool.result":
            r = self._base(e, rec, "PostToolUse")
            r.update(tool_use_id=d.get("tool_use_id"), failed=not d.get("ok", True), duration_ms=d.get("duration_ms"),
                     tool_response={"output": _show(d.get("output"))})
            out.append(r)
            child_id = self.spawn_calls.pop((e["run_id"], d.get("tool_use_id")), None)
            if child_id:
                child_key = (e["run_id"], child_id)
                if child_key not in self.seen_agents:
                    self.seen_agents[child_key] = True
                    start = {**self._base(e, rec, "SubagentStart"), "agent_id": child_id,
                             "parent_id": (self.child_meta.get(child_key) or {}).get("parent_id")}
                    start["agent_type"] = (self.child_meta.get(child_key) or {}).get("agent_type", "subagent")
                    out.append(start)
                final = _show(d.get("output"))
                if isinstance(final, dict):
                    final = final.get("final", "")
                out.append({**self._base(e, rec, "SubagentStop"), "agent_id": child_id,
                            "parent_id": (self.child_meta.get(child_key) or {}).get("parent_id"),
                            "last_assistant_message": str(final or "")})
        elif t == "run.end":
            out.append({**self._base(e, rec, "SessionEnd"), "reason": d.get("reason")})
        elif t == "model.exchange":
            if d.get("phase") == "response":
                tools = ", ".join(f"{x['name']}" for x in d.get("tool_uses") or []) or "no tool calls"
                u = d.get("usage") or {}
                usage_txt = (f" · {(u.get('input_tokens') or 0) + (u.get('cache_read_tokens') or 0) + (u.get('cache_write_tokens') or 0)} in"
                             f" / {u.get('output_tokens') or 0} out tok") if u else ""
                cost = self.prices.cost(d.get("model"), u) if (self.prices and u) else None
                out.append({**self._base(e, rec, "tk_model"), "model": d.get("model"),
                            **({"cost": cost, "currency": self.prices.currency} if cost is not None else {}),
                            "usage": {"input_tokens": u.get("input_tokens") or 0, "output_tokens": u.get("output_tokens") or 0,
                                      "cache_read_input_tokens": u.get("cache_read_tokens") or 0,
                                      "cache_creation_input_tokens": u.get("cache_write_tokens") or 0} if u else None,
                            # a v2 exchange records no status or duration: only what was recorded is shown
                            "text": f"model {d.get('model') or '?'}"
                                    + "".join(f" → {d[k]}" if k == "status" else f" {d[k]}" for k in ("status", "stop_reason")
                                              if d.get(k) not in (None, "")) + f" · {tools}"
                                    + (f" · {d['duration_ms']} ms" if d.get("duration_ms") is not None else "")
                                    + (f" (+{d.get('added_latency_ms')} ms proxy)" if d.get("added_latency_ms") is not None else "") + usage_txt})
        elif t == "model.message":
            kind = {"thinking": "thinking", "thinking_withheld": "thinking_redacted"}.get(d.get("kind"), "text")
            out.append({**self._base(e, rec, "model_turn"), "blocks": [{"kind": kind, "text": str(_show(d.get("content")))}]})
        elif t == "capture.gap":
            sev = "high" if d.get("kind") in ("hook_missing", "proxy_missing", "policy_unrecorded") else "med"
            out.append(self.alert(e, rec, sev, "CAPTURE GAP" + (f" · {d['kind']}" if d.get("kind") else ""), d.get("reason", ""), "GAP"))
        elif t == "trace.tamper":
            out.append(self.alert(e, rec, "high", f"TRACE TAMPERING · {d.get('kind', 'changed')}",
                                  f"{d.get('path')} length {(d.get('before') or {}).get('length')} → {(d.get('after') or {}).get('length')}"))
        elif t == "approval":
            dec = d.get("decision")
            sev = "high" if dec == "self_approval_refused" else ("med" if d.get("same_user") else "info")
            out.append(self.alert(e, rec, sev, f"APPROVAL · {dec}", f"{d.get('approver')} via {d.get('channel')}",
                                  "APPROVE" if dec == "approve" else "ALERT"))
        elif t == "error":
            out.append(self.alert(e, rec, "med", "SIGNER REJECTED EVENT", d.get("message", "")))
        return out


def _script_json(obj):
    """JSON safe to embed inside an HTML <script>: no </script>, no <!--, no line-separator surprises."""
    return (json.dumps(obj, ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def verify_ledger(path):
    """Chain + signature check of the whole ledger (the signer's public key sits next to it)."""
    pub_path = os.path.join(os.path.dirname(path), "signer.pub")
    try:
        with open(pub_path, "rb") as f:
            pub = f.read()
    except OSError:
        pub = None
    prev, n, problems, head = "0" * 64, 0, [], None
    for _, rec, _raw in read_records(path):
        if rec is None:
            problems.append("torn or invalid line"); continue
        e = rec.get("event") or {}
        seq = rec["seq"] if rec.get("elided") else e.get("seq")
        ph = rec.get("prev_hash") if rec.get("elided") else e.get("prev_hash")
        if not rec.get("elided") and event_hash(e) != rec.get("hash"):
            problems.append(f"seq {seq}: content edited")
        if ph != prev:
            problems.append(f"seq {seq}: chain broken")
        if pub and not verify_record_sig(rec, pub):
            problems.append(f"seq {seq}: signature invalid")
        prev, head, n = rec.get("hash"), rec.get("hash"), n + 1
    if pub is None:
        problems.append("signer.pub not found next to the ledger: signatures not checked")
    return n, problems[:50], head


_VERIFY_CACHE = {}


def verify_ledger_cached(path):
    """verify_ledger, remembered until the file changes: every open browser tab polls /api/verify,
    and re-checking every signature of a large ledger on each poll is wasted work."""
    try:
        st = os.stat(path)
        key = (st.st_size, st.st_mtime_ns)
    except OSError:
        return verify_ledger(path)
    hit = _VERIFY_CACHE.get(path)
    if hit and hit[0] == key:
        return hit[1]
    result = verify_ledger(path)
    _VERIFY_CACHE[path] = (key, result)
    return result


class Feed:
    """Tails the ledger once and keeps the most recent translated records for every client.

    Memory is bounded: past `max_records` the oldest are dropped from the live view (the ledger on
    disk is untouched, and `tracekit export` / `observe --export` still cover all of it). Stream
    positions are absolute (`base` + index) so a client never loses its place when records drop."""

    def __init__(self, path, max_records=None, prices=None, source=None):
        self.path, self.records, self.lock, self.source = path, [], threading.Condition(), source   # "bundle": a file
        self.max_records = max_records or int(os.environ.get("TRACEKIT_OBSERVE_MAX_RECORDS", "50000") or 50000)
        self.base = 0  # absolute index of records[0]
        self.tr = Translator(prices)
        self.errors = 0
        threading.Thread(target=self._tail, daemon=True).start()

    def _tail(self):
        while not os.path.exists(self.path):
            time.sleep(0.5)
        with open(self.path, encoding="utf-8") as f:
            buf = ""
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                buf += line
                if not buf.endswith("\n"):
                    continue
                raw, buf = buf.strip(), ""
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                    new = self.tr.feed(rec)
                except Exception as e:  # one malformed record must not stop the live view for good
                    self.errors += 1
                    print(f"tracekit observe: skipped an unreadable ledger record ({type(e).__name__}: {e})",
                          file=sys.stderr, flush=True)
                    continue
                if new:
                    with self.lock:
                        self.records.extend(new)
                        over = len(self.records) - self.max_records
                        if over > 0:
                            del self.records[:over]
                            self.base += over
                        self.lock.notify_all()

    def verify(self):
        return verify_ledger_cached(self.path)


def _page(trace="null", raw="null", nonce=None, nav=""):
    """terminal.html with its data slots filled in one pass (so record content that happens to contain a slot name is
    never substituted again) and, when served, the per-response script nonce and the viewer's nav."""
    slots = {"/*__TRACE_DATA__*/null": trace, "/*__RAW_DATA__*/null": raw, NAV: nav}
    if nonce:
        slots["<script>"] = f'<script nonce="{nonce}">'
    return re.sub("|".join(re.escape(k) for k in slots), lambda m: slots[m.group(0)], read_text(UI))


NAV = "<!--__NAV__-->"   # where a served page gets the viewer's nav
NOTICE = ("tracekit observe is now part of tracekit view: `tracekit view --ledger [HOME]` or `tracekit view --bundle "
          "FILE`; this command keeps working")


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
WILDCARD_HOSTS = {"0.0.0.0", "::", ""}
COOKIE = "tracekit_observe"
LOGIN_COOKIE = "tracekit_login"
SESSION_S = 8 * 3600   # how long a session cookie the token was exchanged for lasts
ALL = object()   # a session's scope: every tenant
class Busy(Exception):
    """A feed at its limit of a costly request (view.StoreFeed.rows): answered 503 with Retry-After."""


RETRACTED = {}   # a feed's row taken back (view.StoreFeed: a run that failed verification): kept for its position only
CSP = ("default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; img-src data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _host_only(value):
    """'localhost:7777' -> 'localhost'; '[::1]:7777' -> '::1'."""
    value = (value or "").strip().lower()
    if value.startswith("["):
        return value[1:value.find("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def _session(key, until):
    """The cookie value a browser gets in exchange for the token: when it expires (`until`) and its MAC under `key`, a
    server's own random key, so it holds nothing of the token and is void once that server stops or `until` passes."""
    return f"{until}.{hmac.new(key, str(until).encode(), hashlib.sha256).hexdigest()}"


def _session_ok(key, cookie):
    until = cookie.partition(".")[0]
    return until.isdigit() and int(until) > time.time() and hmac.compare_digest(cookie.encode(),
                                                                              _session(key, int(until)).encode())


def make_handler(feed, token, allowed_hosts=None, secure=False, login=None, approvals=None, runs=None, why=None):
    """`feed`: records, base, lock and verify() -> (records, problems, head), as Feed has, and optionally `kept` (rows
    that left records but stay in each snapshot, before them; view.StoreFeed: each run's latest verdict); a row that is
    RETRACTED is never sent. `secure`: served over HTTPS,
    so the session cookie is Secure. `login`: a view.OidcLogin; its sessions see the records of their tenant only
    (`feed.verify(tenant)` and each record's `tenant`). `approvals`: a view.ApprovalDesk; an approver's session gets
    /approvals, its GET API and, with the session's CSRF token in X-CSRF-Token, its JSON POSTs (the only requests that
    change state, and only on this handler). `runs`: a view.Runs; /runs and its GET API, for the token and every
    session, each read scoped to the session's tenant by Runs itself; `feed` may then be None (`/` goes to /runs).
    `why`: a why.server.Store; its read API (/api/why/...) for the token only (why logs belong to no tenant, so never to
    an OIDC session), its replay POSTs for the token with a same-origin JSON body, and /v1/ingest for a bearer token
    only: one of the Store's ingest tokens, else (none set) the token."""
    allowed = set(LOOPBACK_HOSTS) | {h.lower() for h in (allowed_hosts or ()) if h.lower() not in WILDCARD_HOSTS}
    pages = [p for p, on in (("/", feed is not None), ("/runs", runs), ("/approvals", approvals)) if on]

    def nav(here):
        """One nav for every page this server has: the live terminal (its why views are its header buttons), the run
        pages, the approval pages."""
        names = {"/": "LIVE", "/runs": "RUNS", "/approvals": "APPROVALS"}
        return '<nav class="nav">' + "".join(f'<a href="{p}" class="{"on" if p == here else ""}">{names[p]}</a>'
                                             for p in pages) + "</nav>"

    class Handler(Lines, BaseHTTPRequestHandler):
        server_version = "tracekit-observe"
        session_key = secrets.token_bytes(32)   # this server's: its session cookies die with it

        def log_message(self, *a):
            pass

        def end_headers(self):   # every answer, the default error pages and the stream too
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            super().end_headers()

        def _send(self, code, body, ctype="application/json", nonce=None, headers=()):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if ctype == "text/html":
                self.send_header("Content-Security-Policy", CSP.format(nonce=nonce or secrets.token_urlsafe(18)))
            self.end_headers()
            self.wfile.write(data)

        def _cookie(self, name=COOKIE):
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == name:
                    return v
            return ""

        def _token_ok(self):
            """The token's request (or no token): its bearer header or the cookie it was exchanged for, never an OIDC
            session, whatever its role."""
            if not token:
                return True
            bearer = self.headers.get("Authorization", "")
            return hmac.compare_digest(bearer.encode(), f"Bearer {token}".encode()) or \
                _session_ok(self.session_key, self._cookie())

        def _scope(self):
            """ALL for the token (or no token), a tenant for an OIDC session (ALL for an operator-admin's), else None."""
            return ALL if self._token_ok() else login and login.tenant(self._cookie())

        def _cookie_attrs(self):
            return "; HttpOnly; Path=/" + ("; Secure" if secure else "")

        def _login(self, u):
            """GET /login: to the issuer, a login cookie holding the state; GET /callback: back with a session cookie,
            through a page of our own so the SameSite=Strict cookie is sent on the next request."""
            if u.path == "/login":
                try:
                    location, state = login.start()
                except (OSError, ValueError, KeyError, TypeError):
                    return self._send(502, '{"error":"login unavailable"}')
                return self._send(303, "", "text/plain", headers=[
                    ("Location", location),
                    ("Set-Cookie", f"{LOGIN_COOKIE}={state}; SameSite=Lax; Max-Age=600{self._cookie_attrs()}")])
            q = parse_qs(u.query)
            sid = login.finish(q.get("state", [""])[0], q.get("code", [""])[0], self._cookie(LOGIN_COOKIE))
            if sid is None:
                return self._send(403, '{"error":"login refused"}')
            return self._send(200, '<!doctype html><meta http-equiv="refresh" content="0;url=/">', "text/html", headers=[
                ("Set-Cookie", f"{LOGIN_COOKIE}=; Max-Age=0{self._cookie_attrs()}"),
                ("Set-Cookie", f"{COOKIE}={sid}; SameSite=Strict{self._cookie_attrs()}")])

        def _exchange(self, u):
            """`/?token=…` (or `/runs?token=…`) once: the token becomes an HttpOnly cookie and the browser is sent to the
            same page without it."""
            supplied = parse_qs(u.query).get("token", [""])[0]
            return bool(token and supplied and u.path in ("/", "/index.html", "/runs")
                        and hmac.compare_digest(supplied.encode(), token.encode()))

        def do_GET(self):
            u = urlparse(self.path)
            exchange = self._exchange(u)
            scope = ALL if exchange else self._scope()
            authorized = scope is not None
            # DNS-rebinding guard: a web page the user visits can make a browser send requests to
            # 127.0.0.1 under an attacker-controlled name; only names we expect are served, and any
            # other name (a wildcard bind reached by its LAN address) only with the token
            if _host_only(self.headers.get("Host")) not in allowed and not (token and authorized):
                return self._send(403, '{"error":"unexpected Host header"}')
            if login and u.path in ("/login", "/callback"):
                return self._login(u)
            if approvals and (u.path == "/approvals" or u.path.startswith(("/api/approvals", "/api/session"))):
                return self._desk(u.path)
            if not authorized:
                if u.path in ("/", "/index.html", "/runs"):   # a person at a page: words, not JSON
                    return self._send(401, "<!doctype html><title>Tracekit view</title><p>This viewer needs its token: "
                                           "open the URL <code>tracekit view</code> printed (it ends in "
                                           "<code>?token=…</code>).", "text/html")
                return self._send(401, '{"error":"missing or wrong token"}')
            if exchange:
                return self._send(303, "", "text/plain", headers=[
                    ("Location", "/runs" if u.path == "/runs" else "/"),
                    ("Set-Cookie", f"{COOKIE}={_session(self.session_key, int(time.time()) + SESSION_S)}; HttpOnly; "
                                   f"SameSite=Strict; Path=/; Max-Age={SESSION_S}" + ("; Secure" if secure else ""))])
            if runs and u.path in ("/runs", "/api/runs", "/api/run", "/api/bundle"):
                return self._runs(u, scope)
            if why and u.path.startswith("/api/why/"):
                if not self._token_ok():
                    return self._send(403, '{"error":"why logs need the viewer token, not a sign-in"}')
                m = re.match(r"^/api/why/runs/([^/]+)$", u.path)
                if u.path != "/api/why/workspace" and not m:
                    return self._send(404, '{"error":"not found"}')
                return self._why(lambda: why.detail(unquote(m.group(1))) if m else why.workspace())
            if u.path == "/api/why/workspace":   # no why logs here: nothing to load, not a missing page
                return self._send(204, "")
            if feed is None:
                if u.path in ("/", "/index.html"):
                    return self._send(303, "", "text/plain", headers=[("Location", "/runs")])
                return self._send(404, '{"error":"not found"}')
            if u.path in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(18)
                return self._send(200, _page(nonce=nonce, nav=nav("/")), "text/html", nonce=nonce)
            if u.path == "/api/snapshot":
                with feed.lock:   # copied under the lock, written after it: a client that stops reading holds nothing
                    body = {"next": feed.base + len(feed.records), "dropped": feed.base,
                            "max": getattr(feed, "max_records", None),
                            "records": [r for r in itertools.chain(getattr(feed, "kept", {}).values(), feed.records)
                                        if r is not RETRACTED and (scope is ALL or r.get("tenant") == scope)],
                            **({"source": feed.source} if getattr(feed, "source", None) else {})}
                return self._send(200, json.dumps(body, ensure_ascii=False))
            if u.path == "/api/rows" and hasattr(feed, "rows"):   # a run of the store, verified again, in full
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                if not (q.get("tenant") and q.get("run")):
                    return self._send(400, '{"error":"needs tenant and run"}')
                try:
                    body = feed.rows(scope, q["tenant"], q["run"])
                except Busy:
                    return self._send(503, '{"error":"checking other runs: try again shortly"}',
                                      headers=[("Retry-After", "5")])
                except (OSError, StorageUnavailable, StorageCorrupt):
                    return self._send(502, '{"error":"store unavailable"}')
                if body is None:
                    return self._send(404, '{"error":"no such verified run"}')
                return self._send(200, body)
            if u.path == "/api/verify":
                n, problems, head = feed.verify() if scope is ALL else feed.verify(scope)
                return self._send(200, json.dumps({"records": n, "ok": not problems, "problems": problems, "head": head,
                                                   "stopped": getattr(feed, "stopped", None)}))
            if u.path == "/api/stream":
                try:
                    start = max(0, int(parse_qs(u.query).get("from", ["0"])[0]))
                except ValueError:
                    return self._send(400, '{"error":"from must be an integer"}')
                return self.stream(start, scope)
            self._send(404, '{"error":"not found"}')

        def _runs(self, u, scope):
            """The run pages of a central deployment's logs (view.Runs), read-only."""
            if u.path == "/runs":
                nonce = secrets.token_urlsafe(18)
                return self._send(200, read_text(RUNS_UI).replace("<script>", f'<script nonce="{nonce}">')
                                  .replace(NAV, nav("/runs")), "text/html", nonce=nonce)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                out = {"/api/runs": runs.search, "/api/run": runs.run, "/api/bundle": runs.bundle}[u.path](scope, q)
            except Busy:
                return self._send(503, '{"error":"checking other runs: try again shortly"}',
                                  headers=[("Retry-After", "5")])
            except ValueError as e:
                return self._send(400, json.dumps({"error": str(e)}))
            except (OSError, StorageUnavailable, StorageCorrupt):
                return self._send(502, '{"error":"store unavailable"}')
            if out is None:
                return self._send(404, '{"error":"no such run"}')
            if u.path == "/api/bundle":
                name = re.sub(r"[^A-Za-z0-9._-]", "_", q["run"])[:120]   # the run's own name, safe in a header
                return self._send(200, out, "application/octet-stream",
                                  headers=[("Content-Disposition", f'attachment; filename="{name}.tkb"')])
            return self._send(200, json.dumps(out, ensure_ascii=False))

        def _desk(self, path, post=False):
            """The approval pages, for an approver's OIDC session only."""
            s = login.session(self._cookie())
            if not s or s["role"] != "approver":
                return self._send(403, '{"error":"needs an approver session"}')
            if not post and path == "/approvals":
                nonce = secrets.token_urlsafe(18)
                return self._send(200, read_text(APPROVALS_UI).replace("<script>", f'<script nonce="{nonce}">')
                                  .replace(NAV, nav("/approvals")), "text/html", nonce=nonce)
            if not post:
                code, out = approvals.get(s, path)
                return self._send(code, json.dumps(out, ensure_ascii=False))
            # CSRF: the session's token in a header, which a cross-site request cannot set without a preflight we
            # never answer, on top of the SameSite=Strict cookie
            if not (hmac.compare_digest(self.headers.get("X-CSRF-Token", "").encode(), s["csrf"].encode())
                    and self.headers.get("Content-Type", "").split(";")[0].strip() == "application/json"):
                return self._send(403, '{"error":"missing or wrong CSRF token"}')
            body = self._body(MAX_POST)
            if body is None:
                return
            code, out = approvals.post(s, path, body)
            return self._send(code, json.dumps(out, ensure_ascii=False))

        def _body(self, limit):
            """The request's JSON object, else None once the refusal is sent (or the body was cut short)."""
            n, why = body_length(self.headers)
            if why or n is None:
                return self._send(411, '{"error":"needs a Content-Length"}')
            if n > limit:
                return self._send(413, '{"error":"body too large"}')
            body = read_body(self, n)
            if body is None:
                return None
            try:
                body = json.loads(body)
            except (UnicodeDecodeError, ValueError, RecursionError):   # RecursionError: nested too deep to parse
                body = None
            return body if isinstance(body, dict) else self._send(400, '{"error":"the body is not a JSON object"}')

        def _why(self, fn):
            """Answer with `fn()`, the why Store's JSON; its refusals (why.server.IngestError) with their status."""
            try:
                out = fn()
            except Exception as e:   # a broken run must not leave the request unanswered
                if isinstance(e, ValueError) and hasattr(e, "status"):
                    return self._send(e.status, json.dumps({"error": str(e), **getattr(e, "extra", {})},
                                                           ensure_ascii=False))
                traceback.print_exc()
                return self._send(500, '{"error":"internal error"}')
            return self._send(200, json.dumps(out, ensure_ascii=False, default=str))

        def _ingest_token(self):
            """The bearer token when /v1/ingest takes it: one of the Store's ingest tokens, else (none set) the token."""
            auth = self.headers.get("Authorization", "")
            supplied = auth[7:] if auth.startswith("Bearer ") else ""
            ok = supplied and any(hmac.compare_digest(supplied.encode(), t.encode())
                                  for t in (why.ingest_tokens or [token]) if t)
            return supplied if ok else None

        def _why_post(self, path, ingest):
            """POST /v1/ingest (an ingest token only) and the replay POSTs (the token, a same-origin JSON body)."""
            if path == "/v1/ingest":
                if ingest is None:
                    return self._send(401, '{"error":"ingest needs an ingest token as a Bearer token"}')
                body = self._body(MAX_INGEST)
                if body is not None:
                    self._why(lambda: why.ingest(body, ingest))
                return
            m = re.match(r"^/api/why/runs/([^/]+)/(tests|attribute)$", path)
            if not m:
                return self._send(404, '{"error":"not found"}')
            if not self._token_ok():
                return self._send(401, '{"error":"missing or wrong token"}')
            # CSRF: a JSON body needs a preflight a cross-site page never gets answered, on top of SameSite=Strict
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json" or (
                    self.headers.get("Origin") and urlparse(self.headers["Origin"]).netloc != self.headers.get("Host")):
                return self._send(403, '{"error":"cross-origin request refused"}')
            body = self._body(MAX_POST)
            if body is None:
                return
            self.long_request()   # a replay takes as long as its trials
            run_id = unquote(m.group(1))
            return self._why(lambda: why.test(run_id, body) if m.group(2) == "tests" else why.attribute(run_id, body))

        def long_request(self):
            """A request that outlives the server's deadline (an event stream, a replay): bounded() lifts it."""

        def finish(self):
            super().finish()
            drain(self.connection)

        if approvals or why:
            def do_POST(self):
                bearer = bool(token) and hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                                             f"Bearer {token}".encode())
                ingest = self._ingest_token() if why else None
                # remote agents ingest under the server's DNS name: a bearer token is enough, never the cookie
                if _host_only(self.headers.get("Host")) not in allowed and not (why and (bearer or ingest)):
                    return self._send(403, '{"error":"unexpected Host header"}')
                u = urlparse(self.path)
                if approvals and u.path.startswith(("/api/approvals/", "/api/passkey")):
                    return self._desk(u.path, post=True)
                if why:
                    return self._why_post(u.path, ingest)
                self._send(404, '{"error":"not found"}')

        def stream_slot(self):
            """Whether this connection may become an event stream: bounded() counts streams on their own."""
            return True

        def stream(self, i, scope=ALL):
            if not self.stream_slot():
                return self._send(503, '{"error":"too many open event streams"}')
            self.long_request()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            last_ping = time.time()
            try:
                while True:
                    with feed.lock:
                        i = max(i, feed.base)
                        if i >= feed.base + len(feed.records):
                            feed.lock.wait(timeout=1.0)
                        batch = feed.records[i - feed.base:]
                    for r in [r for r in batch if r is not RETRACTED and (scope is ALL or r.get("tenant") == scope)]:
                        self.wfile.write(b"data: " + json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n\n")
                    i += len(batch)
                    if batch:
                        self.wfile.flush()
                    elif time.time() - last_ping > 15:
                        self.wfile.write(b": ping\n\n"); self.wfile.flush(); last_ping = time.time()
            except OSError:  # client went away (broken pipe, reset, timeout)
                return
    return Handler


def bounded(handler):
    """`handler`, a make_handler class, for a netserver.Server: event streams count against its stream limits."""
    class Bounded(handler):
        def long_request(self):
            self.server.stop_deadline()   # an event stream lasts as long as the page is open, a replay its trials

        def stream_slot(self):
            return self.server.to_stream(self.client_address[0])
    return Bounded


def server(feed, host, port, token):
    """`tracekit observe`'s server, on loopback only: every client has the one address, so its limits are the overall
    ones."""
    return Server((host, port), bounded(make_handler(feed, token, [host])), max_per_ip=MAX_THREADS,
                  max_streams_per_ip=MAX_STREAMS)


def _open_bundle(bundle_path, prog="tracekit observe"):
    """Unpack a bundle's records and public key into a private temp dir laid out like a signer home, so the same
    feed and the same /api/verify (chain + signatures) run over it. Returns (ledger path, `tracekit verify` exit)."""
    import atexit
    import shutil
    import tempfile
    from . import bundle
    try:
        _rep, code = bundle.verify(bundle_path)
        _manifest, blobs = bundle.load_bundle(bundle_path)
    except Exception as e:
        print(f"{prog}: cannot read bundle {bundle_path}: {e}", file=sys.stderr)
        return None, 2
    d = tempfile.mkdtemp(prefix="tk-observe-")
    atexit.register(shutil.rmtree, d, True)
    os.makedirs(os.path.join(d, "ledger"))
    with open(os.path.join(d, "ledger", "ledger.jsonl"), "wb") as f:
        f.write(blobs.get("records.jsonl", b""))
    with open(os.path.join(d, "ledger", "signer.pub"), "wb") as f:
        f.write(blobs.get("signer.pub", b""))
    return os.path.join(d, "ledger", "ledger.jsonl"), code


def ledger_path(home=None, bundle=None, prog="tracekit observe"):
    """(the ledger to show, 0): `bundle`'s, verified first, else HOME's (default: the client config's signer home);
    (None, exit code) once the refusal is printed."""
    if not bundle:
        from . import client
        home = home or client.client_config().get("signer_home") or "/var/lib/tracekit"
        return os.path.join(home, "ledger", "ledger.jsonl"), 0
    path, code = _open_bundle(bundle, prog)
    if path is None:
        return None, code
    if code != 0:
        print(f"{prog}: bundle {bundle} FAILED verification (exit {code}); refusing to show it. "
              f"Run `tracekit verify {bundle}` for the details.", file=sys.stderr)
        return None, code
    print(f"{prog}: bundle {bundle} verified", file=sys.stderr)
    return path, 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit observe")
    ap.add_argument("--home", help="signer home (default: from the client config)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--export", help="write a self-contained replay HTML of the ledger so far and exit")
    ap.add_argument("--bundle", help="view an exported .tkb bundle instead of the live ledger (verified first)")
    ap.add_argument("--prices", help="JSON price table (see tracekit/usage.py): adds cost per model call, agent and session")
    a = ap.parse_args(argv)
    prices = None
    if a.prices:
        from .usage import Prices
        prices = Prices.load(a.prices)
    path, code = ledger_path(a.home, a.bundle)
    if path is None:
        return code
    if a.export:
        if not os.path.exists(path):
            print(f"tracekit observe: no ledger at {path} (is the signer running? pass --home)", file=sys.stderr)
            return 1
        tr, recs, raw_recs = Translator(prices), [], []
        for _, rec, _raw in read_records(path):
            if isinstance(rec, dict):
                raw_recs.append(rec)
                recs += tr.feed(rec)
        page = _page(_script_json(recs), _script_json(raw_recs)).replace("<head>", "<head>" + CSP_META, 1)
        tmp = f"{a.export}.tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(page)
        os.replace(tmp, a.export)
        print(f"Wrote {a.export} ({len(raw_recs)} ledger records)")
        return 0
    token = os.environ.get("TRACEKIT_OBSERVE_TOKEN")
    if a.host not in LOOPBACK_HOSTS:
        print("tracekit observe: serves plain HTTP, so only on loopback; reach it from another machine through an "
              "SSH tunnel", file=sys.stderr)
        return 1
    print(NOTICE, file=sys.stderr, flush=True)
    feed = Feed(path, prices=prices, source="bundle" if a.bundle else None)
    try:
        srv = server(feed, a.host, a.port, token)
    except OSError as e:
        print(f"tracekit observe: cannot listen on {a.host}:{a.port} ({e.strerror or e}); try --port", file=sys.stderr)
        return 1
    print(f"tracekit observe on http://{a.host}:{srv.server_address[1]}  (ledger: {path}, read-only)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
