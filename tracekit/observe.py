"""`tracekit observe`: the live terminal (the Bloomberg-style observer) for v0.2 ledgers.

Reads the signer's ledger (world-readable, never written here), translates each signed v0.2
event into the record shape the terminal UI understands, and serves the same endpoints as the
v0.1 observer: `/`, `/api/snapshot`, `/api/stream` (Server-Sent Events) and `/api/verify`
(hash chain + Ed25519 signatures of the whole ledger). It is read-only: there is no ingest
endpoint, because in v0.2 only tracekitd writes the ledger.

v0.2 extras are shown as alerts: blocked or held calls, capture gaps, trace tampering,
proxy/hook mismatches and approvals. Content that the ledger holds only as a hash is shown as
`[hashed sha256:...]`.

    tracekit observe [--home /var/lib/tracekit] [--port 7777]
"""
import argparse
import datetime as _dt
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .core import event_hash, read_text
from .ledger import read_records, verify_record_sig

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
        return f"[hashed {c['hash'][:19]}… {c.get('size', '?')} bytes{', redacted' if c.get('redacted') else ''}]"
    return c


class Translator:
    """v0.2 events -> v0.1-shaped records for terminal.html. Stateful: joins tool.call with its
    policy.decision, which v0.2 records as two events."""

    def __init__(self):
        self.pending = {}   # tool_use_id -> (tool.call event, record meta)
        self.cwd = {}       # run_id -> cwd
        self.n = 0

    def _base(self, e, rec, event):
        self.n += 1
        r = {"seq": self.n - 1, "ts": _epoch(e.get("ts")), "event": event, "session_id": e["run_id"],
             "cwd": self.cwd.get(e["run_id"], ""), "agent": "claude-code", "hash": rec.get("hash"),
             "prev": e.get("prev_hash"), "tk_seq": e.get("seq"), "tk_source": e.get("source")}
        if e.get("agent_id") and e["agent_id"] not in ("main", "tracekitd"):
            r["agent_id"] = e["agent_id"]
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
                if d["decision"] == "ask":
                    out.append(self.alert(e, rec, "med", f"HELD FOR APPROVAL · {cd['name']}",
                                          f"{', '.join(d.get('rule_ids') or [])}: tracekit pending / tracekit approve <id>", "GAP"))
        elif t == "tool.result":
            r = self._base(e, rec, "PostToolUse")
            r.update(tool_use_id=d.get("tool_use_id"), failed=not d.get("ok", True), duration_ms=d.get("duration_ms"),
                     tool_response={"output": _show(d.get("output"))})
            out.append(r)
        elif t == "run.end":
            out.append({**self._base(e, rec, "SessionEnd"), "reason": d.get("reason")})
        elif t == "model.exchange":
            if d.get("phase") == "response":
                tools = ", ".join(f"{x['name']}" for x in d.get("tool_uses") or []) or "no tool calls"
                out.append({**self._base(e, rec, "tk_model"),
                            "text": f"model {d.get('model') or ''} → {d.get('status')} {d.get('stop_reason') or ''} · {tools} · "
                                    f"{d.get('duration_ms')} ms (+{d.get('added_latency_ms')} ms proxy)"})
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


class Feed:
    """Tails the ledger once and keeps the translated records for every client."""

    def __init__(self, path):
        self.path, self.records, self.lock = path, [], threading.Condition()
        self.tr = Translator()
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
                except ValueError:
                    continue
                new = self.tr.feed(rec)
                if new:
                    with self.lock:
                        self.records.extend(new)
                        self.lock.notify_all()


def make_handler(feed, token):
    class Handler(BaseHTTPRequestHandler):
        server_version = "tracekit-observe"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            if token and self.headers.get("Authorization") != f"Bearer {token}" and parse_qs(u.query).get("token", [""])[0] != token:
                return self._send(401, '{"error":"missing or wrong token"}')
            if u.path in ("/", "/index.html"):
                return self._send(200, read_text(UI).replace("/*__TRACE_DATA__*/null", "null"), "text/html")
            if u.path == "/api/snapshot":
                with feed.lock:
                    return self._send(200, json.dumps(feed.records, ensure_ascii=False))
            if u.path == "/api/verify":
                n, problems, head = verify_ledger(feed.path)
                return self._send(200, json.dumps({"records": n, "ok": not problems, "problems": problems, "head": head}))
            if u.path == "/api/stream":
                return self.stream(int(parse_qs(u.query).get("from", ["0"])[0]))
            self._send(404, '{"error":"not found"}')

        def stream(self, i):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            last_ping = time.time()
            try:
                while True:
                    with feed.lock:
                        if i >= len(feed.records):
                            feed.lock.wait(timeout=1.0)
                        batch = feed.records[i:]
                    for r in batch:
                        self.wfile.write(b"data: " + json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n\n")
                    i += len(batch)
                    if batch:
                        self.wfile.flush()
                    elif time.time() - last_ping > 15:
                        self.wfile.write(b": ping\n\n"); self.wfile.flush(); last_ping = time.time()
            except (BrokenPipeError, ConnectionResetError):
                return
    return Handler


def main(argv=None):
    from . import client
    ap = argparse.ArgumentParser(prog="tracekit observe")
    ap.add_argument("--home", help="signer home (default: from the client config)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--export", help="write a self-contained replay HTML of the ledger so far and exit")
    a = ap.parse_args(argv)
    home = a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"
    path = os.path.join(home, "ledger", "ledger.jsonl")
    if a.export:
        tr, recs = Translator(), []
        for _, rec, _raw in read_records(path):
            recs += tr.feed(rec)
        boot = json.dumps(recs, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e")
        with open(a.export, "w", encoding="utf-8") as f:
            f.write(read_text(UI).replace("/*__TRACE_DATA__*/null", boot))
        print("Wrote", a.export)
        return 0
    token = os.environ.get("TRACEKIT_OBSERVE_TOKEN")
    if a.host not in ("127.0.0.1", "localhost", "::1") and not token:
        print("Refusing to listen beyond localhost without TRACEKIT_OBSERVE_TOKEN set.", file=sys.stderr)
        return 1
    feed = Feed(path)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(feed, token))
    srv.daemon_threads = True
    print(f"tracekit observe on http://{a.host}:{srv.server_address[1]}  (ledger: {path}, read-only)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0



if __name__ == "__main__":
    sys.exit(main())
