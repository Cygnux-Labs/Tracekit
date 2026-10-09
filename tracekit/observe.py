"""`tracekit observe`: the live terminal (the Bloomberg-style observer) for v0.2 ledgers.

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
import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .core import event_hash, read_text
from .ledger import read_records, verify_record_sig
from .replay import CSP_META

HERE = os.path.dirname(os.path.abspath(__file__))
UI = os.path.join(HERE, "ui", "terminal.html")


def _epoch(ts):
    try:
        return _dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc).timestamp()
    except (TypeError, ValueError):
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


class Translator:
    """v0.2 events -> v0.1-shaped records for terminal.html. Stateful: joins tool.call with its
    policy.decision, which v0.2 records as two events."""

    def __init__(self, prices=None):
        self.prices = prices  # usage.Prices from --prices: adds cost to model calls (Tracekit ships no prices)
        self.pending = {}   # tool_use_id -> (tool.call event, record meta)
        self.cwd = {}       # run_id -> cwd
        self.agent_names = {}
        self.child_meta = {}
        self.spawn_calls = {}
        self.seen_agents = set()
        self.n = 0
        self.max_pending = 10000  # calls that never got a result must not accumulate forever

    def _base(self, e, rec, event):
        self.n += 1
        r = {"seq": self.n - 1, "ts": _epoch(e.get("ts")), "event": event, "session_id": e["run_id"],
             "cwd": self.cwd.get(e["run_id"], ""), "agent": self.agent_names.get(e["run_id"], "claude-code"),
             "parent_id": e.get("parent_id"), "hash": rec.get("hash"),
             "prev": e.get("prev_hash"), "tk_seq": e.get("seq"), "tk_source": e.get("source")}
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
            self.seen_agents.add(agent_key)
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
                    self.seen_agents.add(child_key)
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
                            "text": f"model {d.get('model') or ''} → {d.get('status')} {d.get('stop_reason') or ''} · {tools} · "
                                    f"{d.get('duration_ms')} ms" + (f" (+{d.get('added_latency_ms')} ms proxy)" if d.get("added_latency_ms") is not None else "") + usage_txt})
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

    def __init__(self, path, max_records=None, prices=None):
        self.path, self.records, self.lock = path, [], threading.Condition()
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


def _page(trace="null", raw="null", nonce=None):
    """terminal.html with its data slots filled in one pass (so record content that happens to contain a slot name is
    never substituted again) and, when served, the per-response script nonce."""
    slots = {"/*__TRACE_DATA__*/null": trace, "/*__RAW_DATA__*/null": raw}
    if nonce:
        slots["<script>"] = f'<script nonce="{nonce}">'
    return re.sub("|".join(re.escape(k) for k in slots), lambda m: slots[m.group(0)], read_text(UI))


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
WILDCARD_HOSTS = {"0.0.0.0", "::", ""}
COOKIE = "tracekit_observe"
CSP = ("default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; img-src data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _host_only(value):
    """'localhost:7777' -> 'localhost'; '[::1]:7777' -> '::1'."""
    value = (value or "").strip().lower()
    if value.startswith("["):
        return value[1:value.find("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def _session(token):
    """The cookie value a browser gets in exchange for the token: derived from it, so the token itself is never stored."""
    return hmac.new(token.encode(), b"tracekit-observe-session", hashlib.sha256).hexdigest()


def make_handler(feed, token, allowed_hosts=None):
    allowed = set(LOOPBACK_HOSTS) | {h.lower() for h in (allowed_hosts or ()) if h.lower() not in WILDCARD_HOSTS}

    class Handler(BaseHTTPRequestHandler):
        server_version = "tracekit-observe"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json", nonce=None, headers=()):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if ctype == "text/html":
                self.send_header("Content-Security-Policy", CSP.format(nonce=nonce or secrets.token_urlsafe(18)))
            self.end_headers()
            self.wfile.write(data)

        def _cookie(self):
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return v
            return ""

        def _authorized(self):
            if not token:
                return True
            bearer = self.headers.get("Authorization", "")
            return hmac.compare_digest(bearer.encode(), f"Bearer {token}".encode()) or \
                hmac.compare_digest(self._cookie().encode(), _session(token).encode())

        def _exchange(self, u):
            """`/?token=…` once: the token becomes an HttpOnly cookie and the browser is sent to a URL without it."""
            supplied = parse_qs(u.query).get("token", [""])[0]
            return bool(token and supplied and u.path in ("/", "/index.html")
                        and hmac.compare_digest(supplied.encode(), token.encode()))

        def do_GET(self):
            u = urlparse(self.path)
            exchange = self._exchange(u)
            authorized = exchange or self._authorized()
            # DNS-rebinding guard: a web page the user visits can make a browser send requests to
            # 127.0.0.1 under an attacker-controlled name; only names we expect are served, and any
            # other name (a wildcard bind reached by its LAN address) only with the token
            if _host_only(self.headers.get("Host")) not in allowed and not (token and authorized):
                return self._send(403, '{"error":"unexpected Host header"}')
            if not authorized:
                return self._send(401, '{"error":"missing or wrong token"}')
            if exchange:
                return self._send(303, "", "text/plain", headers=[
                    ("Location", u.path),
                    ("Set-Cookie", f"{COOKIE}={_session(token)}; HttpOnly; SameSite=Strict; Path=/")])
            if u.path in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(18)
                return self._send(200, _page(nonce=nonce), "text/html", nonce=nonce)
            if u.path == "/api/snapshot":
                with feed.lock:
                    body = {"next": feed.base + len(feed.records), "dropped": feed.base, "records": feed.records}
                    return self._send(200, json.dumps(body, ensure_ascii=False))
            if u.path == "/api/verify":
                n, problems, head = verify_ledger_cached(feed.path)
                return self._send(200, json.dumps({"records": n, "ok": not problems, "problems": problems, "head": head}))
            if u.path == "/api/stream":
                try:
                    start = max(0, int(parse_qs(u.query).get("from", ["0"])[0]))
                except ValueError:
                    return self._send(400, '{"error":"from must be an integer"}')
                return self.stream(start)
            self._send(404, '{"error":"not found"}')

        def stream(self, i):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            last_ping = time.time()
            try:
                while True:
                    with feed.lock:
                        i = max(i, feed.base)
                        if i >= feed.base + len(feed.records):
                            feed.lock.wait(timeout=1.0)
                        batch = feed.records[i - feed.base:]
                    for r in batch:
                        self.wfile.write(b"data: " + json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n\n")
                    i += len(batch)
                    if batch:
                        self.wfile.flush()
                    elif time.time() - last_ping > 15:
                        self.wfile.write(b": ping\n\n"); self.wfile.flush(); last_ping = time.time()
            except OSError:  # client went away (broken pipe, reset, timeout)
                return
    return Handler


def _open_bundle(bundle_path):
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
        print(f"tracekit observe: cannot read bundle {bundle_path}: {e}", file=sys.stderr)
        return None, 2
    d = tempfile.mkdtemp(prefix="tk-observe-")
    atexit.register(shutil.rmtree, d, True)
    os.makedirs(os.path.join(d, "ledger"))
    with open(os.path.join(d, "ledger", "ledger.jsonl"), "wb") as f:
        f.write(blobs.get("records.jsonl", b""))
    with open(os.path.join(d, "ledger", "signer.pub"), "wb") as f:
        f.write(blobs.get("signer.pub", b""))
    return os.path.join(d, "ledger", "ledger.jsonl"), code


def main(argv=None):
    from . import client
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
    if a.bundle:
        path, code = _open_bundle(a.bundle)
        if path is None:
            return 1
        if code != 0:
            print(f"tracekit observe: bundle {a.bundle} FAILED verification (exit {code}); refusing to show it. "
                  f"Run `tracekit verify {a.bundle}` for the details.", file=sys.stderr)
            return code
        print(f"tracekit observe: bundle {a.bundle} verified", file=sys.stderr)
    else:
        home = a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"
        path = os.path.join(home, "ledger", "ledger.jsonl")
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
    if a.host not in ("127.0.0.1", "localhost", "::1") and not token:
        print("Refusing to listen beyond localhost without TRACEKIT_OBSERVE_TOKEN set.", file=sys.stderr)
        return 1
    feed = Feed(path, prices=prices)
    try:
        srv = ThreadingHTTPServer((a.host, a.port), make_handler(feed, token, [a.host]))
    except OSError as e:
        print(f"tracekit observe: cannot listen on {a.host}:{a.port} ({e.strerror or e}); try --port", file=sys.stderr)
        return 1
    srv.daemon_threads = True
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
