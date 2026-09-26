#!/usr/bin/env python3
"""tracekit observer: a live terminal for every agent writing to the ledger.

  python3 observer.py                  -> http://127.0.0.1:7777
  python3 observer.py --port 8080 --host 0.0.0.0   (LAN; set TRACEKIT_INGEST_TOKEN)
  python3 observer.py --export replay.html          one self-contained replay file

Endpoints
  GET  /                 the terminal UI
  GET  /api/snapshot     every ledger record (JSON array)
  GET  /api/stream?from=N  Server-Sent Events: each new record as it is written
  GET  /api/verify       hash-chain integrity
  POST /api/ingest       add events from ANY agent (JSON object or array):
                         {"event": "PreToolUse", "session_id": "...", "agent": "my-bot",
                          "agent_id": "worker-2", "tool_name": "search", "tool_input": {...}}
                         Header "Authorization: Bearer $TRACEKIT_INGEST_TOKEN" when that is set.
Standard library only.
"""
import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import verify as verifier  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
UI = os.path.join(HERE, "terminal.html")
TOKEN = os.environ.get("TRACEKIT_INGEST_TOKEN")
ALLOWED_EVENTS = {"UserPromptSubmit", "PreToolUse", "PostToolUse", "model_turn", "SessionStart",
                  "SessionEnd", "Stop", "SubagentStart", "SubagentStop", "Notification",
                  "judge_verdict", "log"}


def ui_html(records=None):
    with open(UI, encoding="utf-8") as f:
        page = f.read()
    boot = "null" if records is None else (json.dumps(records, ensure_ascii=False)
                                           .replace("<", "\\u003c").replace(">", "\\u003e"))
    return page.replace("/*__TRACE_DATA__*/null", boot)


class Handler(BaseHTTPRequestHandler):
    server_version = "tracekit-observer"

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
        if u.path in ("/", "/index.html"):
            return self._send(200, ui_html(), "text/html")
        if u.path == "/api/snapshot":
            return self._send(200, json.dumps(common.read_ledger(), ensure_ascii=False))
        if u.path == "/api/verify":
            n, problems, head = verifier.verify(common.LEDGER)
            problems += verifier.check_anchors(common.ANCHORS, common.LEDGER)
            return self._send(200, json.dumps({"records": n, "ok": not problems,
                                               "problems": problems, "head": head}))
        if u.path == "/api/stream":
            return self.stream(int(parse_qs(u.query).get("from", ["0"])[0]))
        self._send(404, '{"error":"not found"}')

    def stream(self, start):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        while not os.path.exists(common.LEDGER):
            time.sleep(0.5)
        seq, last_ping = 0, time.time()
        try:
            with open(common.LEDGER, encoding="utf-8") as f:
                buf = ""
                while True:
                    line = f.readline()
                    if not line:
                        if time.time() - last_ping > 15:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                            last_ping = time.time()
                        time.sleep(0.25)
                        continue
                    buf += line
                    if not buf.endswith("\n"):
                        continue
                    raw, buf = buf.strip(), ""
                    if not raw:
                        continue
                    if seq >= start:
                        self.wfile.write(b"data: " + raw.encode("utf-8") + b"\n\n")
                        self.wfile.flush()
                    seq += 1
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_POST(self):
        if urlparse(self.path).path != "/api/ingest":
            return self._send(404, '{"error":"not found"}')
        if TOKEN and self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, '{"error":"missing or wrong ingest token"}')
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"null")
        except Exception:
            return self._send(400, '{"error":"body must be JSON"}')
        items = body if isinstance(body, list) else [body]
        clean = []
        for ev in items:
            if not isinstance(ev, dict) or ev.get("event") not in ALLOWED_EVENTS or not ev.get("session_id"):
                return self._send(400, json.dumps({"error": "each event needs session_id and an event in "
                                                   + ", ".join(sorted(ALLOWED_EVENTS))}))
            ev = {k: v for k, v in ev.items() if k not in ("seq", "ts", "prev", "hash")}
            ev.setdefault("agent", "external")
            ev["source"] = "ingest"
            clean.append(ev)
        common.append(clean)
        self._send(200, json.dumps({"accepted": len(clean)}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--export", help="write a self-contained replay HTML file and exit")
    a = ap.parse_args()
    if a.export:
        with open(a.export, "w", encoding="utf-8") as f:
            f.write(ui_html(common.read_ledger()))
        print("Wrote", a.export)
        return
    if a.host not in ("127.0.0.1", "localhost", "::1") and not TOKEN:
        print("Refusing to listen beyond localhost without TRACEKIT_INGEST_TOKEN set.")
        sys.exit(1)
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    print(f"tracekit observer on http://{a.host}:{a.port}  (ledger: {common.LEDGER})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
