"""Authenticated remote ingestion: let SDK agents on other machines write to this signer's ledger.

    tracekit ingest token build-agent --home /var/lib/tracekit     # prints a token once; stores only its hash
    tracekit ingest serve --home /var/lib/tracekit --host 0.0.0.0 --port 8443 --cert c.pem --key k.pem
    # on the agent's machine:
    tracekit init --remote https://tracekit.example:8443 --token-file token.txt

What a remote client can and cannot be:
* Every remote event enters the ledger as source=sdk, in a run namespaced `remote:<client>:<run>`, so a
  remote client can neither write into another run nor forge hook, proxy or transcript evidence.
* Only the event types the SDK emits are accepted; checkpoints, gaps, tamper and approval events are the
  signer's own and are refused.
* The remote client is trusted only for what it chooses to send. Nothing proves its calls are complete or
  truthful, and the run's coverage says so. Approvals ("ask" rules) are not available remotely: held calls
  are refused.
* The gateway holds no key. It forwards to the signer, which signs, chains and checkpoints as usual.
* Traffic must be TLS unless bound to loopback (`--insecure-http` overrides, for a proxy that terminates TLS)."""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import client
from .core import now_ts

TOKENS_FILE = "ingest-tokens.json"
MAX_BODY = 1024 * 1024
ALLOWED_TYPES = {"run.start", "user.prompt", "tool.call", "policy.decision", "tool.result", "model.message", "model.exchange",
                 "review", "run.end"}  # review: guard verdicts (contrib/onchain); remote runs are namespaced, never findings:/anchors:  # model.exchange: SDK auto-instrumentation; source=sdk, never cross-checked as proxy evidence
ALLOWED_OPS = {"append", "status"}
OTLP_EXTRA_TYPES = {"model.exchange"}  # application-reported (source=sdk); never cross-checked as proxy evidence
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,120}$")
RATE_PER_S, BURST = 100.0, 300.0


def _tokens_path(home):
    return os.path.join(home, TOKENS_FILE)


def load_tokens(home):
    try:
        with open(_tokens_path(home), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def add_token(home, name):
    if not ID_RE.match(name or ""):
        raise ValueError("client name must be 1-120 characters of letters, digits, . _ : -")
    tokens = load_tokens(home)
    if name in tokens:
        raise ValueError(f"client {name!r} already has a token; remove it from {TOKENS_FILE} to rotate")
    token = "tk_" + secrets.token_urlsafe(32)
    tokens[name] = {"sha256": hashlib.sha256(token.encode()).hexdigest(), "created": now_ts()}
    path = _tokens_path(home)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(tokens, f, indent=2)
    os.replace(tmp, path)
    return token


def authenticate(tokens, bearer):
    """-> client name or None. Compares against every stored hash in constant time."""
    if not bearer.startswith("Bearer "):
        return None
    digest = hashlib.sha256(bearer[7:].strip().encode()).hexdigest()
    found = None
    for name, rec in tokens.items():
        if isinstance(rec, dict) and hmac.compare_digest(str(rec.get("sha256", "")), digest):
            found = name
    return found


def sanitize(req, cid, addr, isolation="same-user", extra_types=()):
    """Validate a remote request and rewrite it for the signer. -> (request, error).
    extra_types: event types allowed on this path beyond the SDK's (the OTLP path adds model.exchange)."""
    if not isinstance(req, dict) or req.get("op") not in ALLOWED_OPS:
        return None, f"op must be one of {sorted(ALLOWED_OPS)}"
    if req["op"] == "status":
        return {"op": "status"}, None
    ev = req.get("event")
    if not isinstance(ev, dict):
        return None, "event must be an object"
    if ev.get("source") != "sdk":
        return None, "remote clients may only send source=sdk events"
    if ev.get("type") not in ALLOWED_TYPES and ev.get("type") not in extra_types:
        return None, f"event type {ev.get('type')!r} is not accepted from remote clients"
    if "transcript" in ev:
        return None, "transcript evidence cannot be sent remotely"
    run = ev.get("run_id")
    if not isinstance(run, str) or not ID_RE.match(run):
        return None, "run_id must be 1-120 characters of letters, digits, . _ : -"
    ev = dict(ev, run_id=f"remote:{cid}:{run}", source="sdk")
    if ev["type"] == "run.start" and isinstance(ev.get("data"), dict):
        ev["data"] = dict(ev["data"], host=f"remote:{cid}@{addr}", signer_isolation=isolation)
    out = {"op": "append", "event": ev, "stream": "sdk"}
    if isinstance(req.get("cseq"), int):
        out["cseq"] = req["cseq"]
    if isinstance(req.get("attach"), dict):
        out["attach"] = {k: v for k, v in req["attach"].items() if k == "policy"}
    return out, None


class _Bucket:
    def __init__(self):
        self.t, self.tokens, self.lock = time.monotonic(), BURST, threading.Lock()

    def take(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(BURST, self.tokens + (now - self.t) * RATE_PER_S)
            self.t = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


_REQ = threading.local()  # the address of the request being handled, read by the OTLP sink on the same thread


def _otlp_receiver(cid, forward):
    """An OTLP receiver for one authenticated client: events are sanitised exactly like SDK events (namespaced
    run, source=sdk) and carry a per-run counter so the signer can see gaps."""
    from . import otlp
    counters = {}

    def sink(ev, attach):
        run = ev["run_id"]
        req = {"op": "append", "event": ev, "cseq": counters.get(run, -1) + 1}
        if attach:
            req["attach"] = attach
        safe, err = sanitize(req, cid, getattr(_REQ, "addr", "?"), client.client_config().get("signer_isolation", "same-user"),
                             extra_types=OTLP_EXTRA_TYPES)
        if err:
            return {"ok": False, "error": err}
        resp = forward(safe)
        if resp.get("ok"):
            counters[run] = req["cseq"]
        return resp
    return otlp.Receiver(sink)


def make_handler(home, forward=None):
    forward = forward or client.rpc
    buckets = {}
    receivers = {}
    receivers_lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        server_version = "tracekit-ingest"

        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _otlp(self, cid):
            from . import otlp
            from .otlp_wire import MAX_BODY as OTLP_MAX
            try:
                n = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                n = -1
            if not 0 <= n <= OTLP_MAX:
                self.close_connection = True
                return self._send(413, {"message": f"body must be 0..{OTLP_MAX} bytes with a Content-Length"})
            body = self.rfile.read(n)
            with receivers_lock:
                rcv = receivers.get(cid)
                if rcv is None:
                    rcv = receivers[cid] = _otlp_receiver(cid, forward)
            _REQ.addr = self.client_address[0]
            code, headers, data = otlp.handle_traces(rcv, body, self.headers.get("Content-Type"), self.headers.get("Content-Encoding"))
            self.send_response(code)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            path = self.path.split("?")[0].rstrip("/")
            if path not in ("/v1/rpc", "/v1/traces"):
                return self._send(404, {"ok": False, "error": "not found"})
            cid = authenticate(load_tokens(home), self.headers.get("Authorization", ""))
            if not cid:
                return self._send(401, {"ok": False, "error": "unauthorized"})
            if not buckets.setdefault(cid, _Bucket()).take():
                return self._send(429, {"ok": False, "error": "rate limited", "retryable": True})
            if path == "/v1/traces":
                return self._otlp(cid)
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if not 0 < n <= MAX_BODY:
                return self._send(413, {"ok": False, "error": f"body must be 1..{MAX_BODY} bytes"})
            try:
                req = json.loads(self.rfile.read(n))
            except ValueError:
                return self._send(400, {"ok": False, "error": "invalid JSON"})
            safe, err = sanitize(req, cid, self.client_address[0], client.client_config().get("signer_isolation", "same-user"))
            if err:
                return self._send(400, {"ok": False, "error": err})
            try:
                return self._send(200, forward(safe))
            except client.SignerUnavailable as e:
                return self._send(503, {"ok": False, "error": f"signer unavailable: {e}", "retryable": True})
    return H


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit ingest")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("token", help="create a client token (shown once; only its hash is stored)")
    t.add_argument("name")
    t.add_argument("--home", required=True)
    s = sub.add_parser("serve", help="run the ingest gateway")
    s.add_argument("--home", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--cert")
    s.add_argument("--key")
    s.add_argument("--insecure-http", action="store_true", help="plain HTTP on a non-loopback address (TLS terminated in front)")
    a = ap.parse_args(argv)
    if a.cmd == "token":
        try:
            token = add_token(a.home, a.name)
        except ValueError as e:
            print(f"tracekit ingest: {e}", file=sys.stderr)
            return 2
        print(token)
        print(f"(client {a.name!r}; this is the only time the token is shown)", file=sys.stderr)
        return 0
    loopback = a.host in ("127.0.0.1", "localhost", "::1")
    if bool(a.cert) != bool(a.key):
        print("tracekit ingest: --cert and --key go together", file=sys.stderr)
        return 2
    if not a.cert and not loopback and not a.insecure_http:
        print("tracekit ingest: refusing to serve plain HTTP on a non-loopback address; pass --cert/--key "
              "(or --insecure-http if TLS is terminated in front)", file=sys.stderr)
        return 2
    if not load_tokens(a.home):
        print("tracekit ingest: no client tokens yet: run `tracekit ingest token <name> --home ...` first", file=sys.stderr)
        return 2
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(a.home))
    srv.daemon_threads = True
    if a.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.cert, a.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"tracekit ingest: listening on {'https' if a.cert else 'http'}://{a.host}:{a.port}/v1/rpc "
          "(SDK) and /v1/traces (OTLP/HTTP)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
