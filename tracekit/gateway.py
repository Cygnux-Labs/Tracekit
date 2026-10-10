"""LLM gateway (04-design §6, tier T2): an HTTP(S) reverse proxy in front of an OpenAI-compatible upstream that records
every model exchange in the v2 signer as source `gateway`. docs/gateway.md.

    tracekit gateway serve --config gateway.yaml

gateway.yaml:
    http: {listen: 0.0.0.0:8080, cert: tls/gw.pem, key: tls/gw.key, client_ca: {acme.org: tls/acme-ca.pem},
           authenticators: [mtls, k8s_sa, token]}   # the signer's `http` section (tracekit/transport/http.py)
    upstream: https://api.openai.com      # POST /v1/chat/completions, /v1/responses and /v1/messages go here
    api_key_file: secrets/provider.key     # the provider credential: the gateway's own, never the client's
    api_key_header: authorization          # sent as `Bearer <key>`; or x-api-key (Anthropic), sent as is
    signer: https://signer.internal:8443   # the gateway's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client)
    max_body: 33554432                     # request and non-streamed response bodies; 413 / 502 beyond

Every request carries an identity the authenticators accept and its run, `X-Tracekit-Run: <run_id>.<run token>` or
that value as `Authorization: Bearer` (then the identity must come from a client certificate). No identity or run: 401.
The signer checks the run token against that identity (signer.yaml `gateways` lists this gateway): a token of another
run, identity or tenant: 403. Nothing is attributed by address or name. Relative paths are from the config file.

For each exchange: model_event phase request (with the tool results it sends back) before forwarding; the response
streams through, parsed by tracekit.parsers; model_event phase response (tool uses with args digests, usage, stop
reason, error) is recorded before the chunk with the stream's terminal event, or before any of a non-streamed
response. An upstream error, a broken stream or one that ends before its terminal event is recorded with an error and
ends, for the client, in an error (an SSE error event and a cut connection once the headers went out), never a clean
end. Signer unreachable: the run's fail mode for class `model`, as the signer last answered it for this run, token and
identity (closed when it has not): closed answers 503. A signer refusal is an error whatever the fail mode.
"""
import argparse
import collections
import hashlib
import http.client
import http.server
import json
import os
import sys
import threading
import types
import urllib.error
import urllib.request
import uuid

from tracekit import parsers, yamlmini
from tracekit.client import remote_url_error
from tracekit.identity.base import bearer
from tracekit.proxy import HOP, MAX_SSE_LINE
from tracekit.sdk.client import Client, SignerUnavailable, fail_open
from tracekit.signer.rpc_schema import MAX_RESULTS_SENT, RPCError
from tracekit.transport import http as transport

KINDS = {"/v1/chat/completions": "openai:chat", "/v1/responses": "openai:responses", "/v1/messages": "anthropic:messages"}
TERMINAL = {"response.completed", "response.incomplete", "message_stop"}   # chat completions: data: [DONE]
FAILED = {"error", "response.failed"}
DROP = HOP | {"authorization", "x-api-key", "x-tracekit-run", "cookie"}   # never forwarded: the client's credentials
KEYS = {"http", "upstream", "api_key_file", "api_key_header", "signer", "max_body"}
MAX_BODY = 32 * 1024 * 1024
MAX_RUNS = 10_000   # runs remembered (stream, counter, fail modes), least recently used dropped first
UPSTREAM_TIMEOUT_S = 600


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):   # a redirect would carry the provider credential to wherever it points
        return None


OPEN = urllib.request.build_opener(_NoRedirect).open


class Gateway:
    def __init__(self, upstream, api_key, api_key_header="authorization", client=None, max_body=MAX_BODY):
        self.upstream, self.max_body, self.client = upstream.rstrip("/"), max_body, client
        self.auth = (api_key_header, "Bearer " + api_key if api_key_header == "authorization" else api_key)
        self.runs, self.lock = collections.OrderedDict(), threading.Lock()

    def _run(self, key):
        with self.lock:
            run = self.runs.pop(key, None) or types.SimpleNamespace(
                stream="gx-" + uuid.uuid4().hex, seq=0, modes=None, lock=threading.Lock())
            self.runs[key] = run
            if len(self.runs) > MAX_RUNS:
                self.runs.popitem(last=False)
            return run

    def record(self, key, xid, **fields):
        """model_event for run `key` = (run_id, token, caller): True once recorded, False when the signer can't be
        reached; RPCError for a refusal. A run's records share one stream whose counter every attempt advances, so an
        exchange the signer never got shows as a client_counter_gap once a later one of the run reaches it."""
        # lean: no gap if no later exchange of the run reaches the signer; a gateway-side outbox if that matters
        run_id, token, caller = key
        run = self._run(key)
        with run.lock:   # counter order is arrival order
            seq, run.seq = run.seq, run.seq + 1
            try:
                out = self.client.model_event({"run_id": run_id, "run_token": token, "caller": caller,
                                               "exchange_id": xid, "stream": run.stream, "client_seq": seq, **fields})
            except SignerUnavailable:
                return False
            except RPCError as e:
                if e.code == "unavailable":
                    return False
                raise
            run.modes = out.get("fail_modes")
        return True

    def fail_open(self, key):
        return fail_open(self._run(key).modes, "model")


class _SSE:
    """Feeds each `data:` line of an SSE stream to a parsers.Stream: `done` once its terminal event came, `error` when
    the upstream sent an error event or a line over MAX_SSE_LINE."""

    def __init__(self, stream):
        self.stream, self.buf, self.done, self.error = stream, b"", False, None

    def feed(self, chunk):
        lines = (self.buf + chunk).split(b"\n")
        self.buf = lines.pop()
        if len(self.buf) > MAX_SSE_LINE:
            self.buf, self.error = b"", f"an SSE line over {MAX_SSE_LINE} bytes"
        for line in lines:
            data = line[5:].strip() if line.startswith(b"data:") else None
            if data == b"[DONE]":
                self.done = True
            if not data or data == b"[DONE]":
                continue
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            if not isinstance(ev, dict):
                continue
            if ev.get("type") in FAILED or ev.get("error"):
                self.error = "upstream error event: " + json.dumps(ev.get("error") or ev.get("type"))[:900]
            self.stream.add(ev)
            self.done = self.done or ev.get("type") in TERMINAL


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.timeout = self.server.read_timeout
        super().setup()

    def handle_one_request(self):
        self.server.restart_deadline()
        super().handle_one_request()

    def log_message(self, *a):
        pass

    def _error(self, status, msg, close=True):
        body = json.dumps({"error": {"type": "tracekit_gateway", "message": "tracekit gateway: " + msg}}).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        if close:
            self.send_header("connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        gw, kind = self.server.gateway, KINDS.get(self.path.split("?")[0])
        if kind is None:
            return self._error(404, f"POST one of {', '.join(KINDS)}")
        run, conn = self.headers.get("X-Tracekit-Run"), self
        if run is None:   # the run in the bearer: only a client certificate can say who is calling
            run, conn = bearer(self), types.SimpleNamespace(headers={}, connection=self.connection,
                                                             client_address=self.client_address)
        try:
            identity = self.server.authenticate(conn, {"method": "model_event"})
        except RPCError as e:
            return self._error(401, e.message)
        parts = (run or "").rsplit(".", 2)   # a run token is <payload>.<mac>
        if len(parts) != 3 or not all(parts):
            return self._error(401, "no run: send X-Tracekit-Run: <run_id>.<run token>")
        n = self.headers.get("content-length", "")
        if not (n.isascii() and n.isdigit()):
            return self._error(411, "Content-Length required")
        if int(n) > gw.max_body:
            return self._error(413, f"request body over {gw.max_body} bytes")
        if self.headers.get("content-encoding", "identity").lower() != "identity":
            return self._error(415, "send the request body uncompressed")
        body = self.rfile.read(int(n))
        if len(body) < int(n):
            self.close_connection = True
            return
        self.server.stop_deadline()   # the request is in; the upstream's answer may stream for minutes
        try:
            req = json.loads(body)
        except ValueError:
            req = None
        if not isinstance(req, dict):
            return self._error(400, "the request body is not a JSON object")
        key, xid = (parts[0], f"{parts[1]}.{parts[2]}", f"{identity.scheme}:{identity.subject}"), "gx-" + uuid.uuid4().hex
        base = {"provider": kind.split(":")[0], "model": str(req.get("model") or "")[:128],
                "streamed": req.get("stream") is True}
        sent = parsers.parse(kind, None, req)["tool_results_sent"][-MAX_RESULTS_SENT:]
        try:
            ok = gw.record(key, xid, phase="request", content_digest="sha256:" + hashlib.sha256(body).hexdigest(),
                           **base, **({"tool_results_sent": sent} if sent else {}))
        except RPCError as e:
            return self._error(429 if e.code == "quota_exceeded" else 403, f"the signer refused the run: {e.message}")
        if not ok and not gw.fail_open(key):
            return self._error(503, "the signer is unreachable and the run's fail mode is closed")
        self._forward(gw, kind, key, xid, base, req, body)

    def _forward(self, gw, kind, key, xid, base, req, body):
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP}
        headers.update({"Accept-Encoding": "identity", gw.auth[0]: gw.auth[1]})
        up = urllib.request.Request(gw.upstream + self.path, data=body, headers=headers, method="POST")
        stream, h = parsers.Stream(kind), hashlib.sha256()

        def done(err, parsed=None):
            """Record the response; whether the client may have it."""
            out = parsed or stream.parse(req)
            fields = {"stop_reason": out["finish"] and str(out["finish"])[:100], "usage": out["usage"],
                      "tool_uses": out["tool_uses"][:128],   # lean: the RPC's cap; split the record if models exceed it
                      "error": err and err[:1024]}
            try:
                ok = gw.record(key, xid, phase="response", content_digest="sha256:" + h.hexdigest(),
                               **dict(base, model=str(out["model"] or base["model"])[:128]),
                               **{k: v for k, v in fields.items() if v})
            except RPCError:
                return False
            return ok or gw.fail_open(key)

        try:
            try:
                resp = OPEN(up, timeout=UPSTREAM_TIMEOUT_S)
            except urllib.error.HTTPError as e:
                resp = e
        except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
            err = f"upstream unreachable: {e}"
            done(err)
            return self._error(502, err)
        try:
            status, ctype = resp.getcode(), resp.headers.get("content-type", "")
            if status < 300 and "event-stream" in ctype:
                self._stream(resp, status, stream, h, done)
            else:
                self._whole(gw, resp, status, kind, req, h, done)
        finally:
            resp.close()

    def _send_head(self, resp, status, extra):
        self.send_response(status)
        for k, v in resp.headers.items():
            if k.lower() not in HOP:
                self.send_header(k, v)
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()

    def _whole(self, gw, resp, status, kind, req, h, done):
        err, parsed = None if status < 300 else f"upstream status {status}", None
        try:
            data = resp.read(gw.max_body + 1)
        except (http.client.HTTPException, OSError) as e:
            data, err = b"", f"upstream response broke: {e}"
        h.update(data)
        if len(data) > gw.max_body:
            err = f"upstream response over {gw.max_body} bytes"
        elif err is None:
            try:
                parsed = parsers.parse(kind, json.loads(data), req)
            except ValueError:
                err = "upstream response is not JSON"
        ok = done(err, parsed)
        if not ok:
            return self._error(503, "the response could not be recorded and the run's fail mode is closed")
        if err and status < 400:
            return self._error(502, err)
        self._send_head(resp, status, {"content-length": str(len(data))})
        self.wfile.write(data)

    def _stream(self, resp, status, stream, h, done):
        self._send_head(resp, status, {"transfer-encoding": "chunked"})
        sse, err, last = _SSE(stream), None, b""
        try:
            while not sse.done:   # the chunk with the terminal event waits for the record; anything after it is dropped
                chunk = resp.read1(65536)
                if not chunk:
                    break
                h.update(chunk)
                sse.feed(chunk)
                if sse.done:
                    last = chunk
                else:
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
        except (http.client.HTTPException, OSError) as e:
            err = f"stream broke: {e}"
        err = err or sse.error or (None if sse.done else "upstream stream ended before its terminal event")
        if not done(err):
            err = "the response could not be recorded and the run's fail mode is closed"
        self.close_connection = bool(err)
        try:
            if err:   # an error the SDKs raise, then no last chunk: never a clean end
                ev = b"event: error\ndata: " + json.dumps({"type": "error", "error": {
                    "type": "tracekit_gateway", "message": "tracekit gateway: " + err}}).encode() + b"\n\n"
                self.wfile.write(b"%x\r\n%s\r\n" % (len(ev), ev))
            else:
                self.wfile.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(last), last))
            self.wfile.flush()
        except OSError:
            pass


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not {"http", "upstream", "api_key_file", "signer"} <= set(cfg):
        raise ValueError(f"{path}: needs http, upstream, api_key_file and signer; takes {sorted(KEYS)}")
    if remote_url_error(str(cfg["upstream"])):
        raise ValueError(f"{path}: upstream: {remote_url_error(str(cfg['upstream']))}")
    if cfg.get("api_key_header", "authorization") not in ("authorization", "x-api-key"):
        raise ValueError(f"{path}: api_key_header is authorization or x-api-key")
    if not (isinstance(cfg.get("max_body", MAX_BODY), int) and cfg.get("max_body", MAX_BODY) > 0):
        raise ValueError(f"{path}: max_body is a positive integer")
    base = os.path.dirname(os.path.abspath(path))
    cfg["api_key_file"] = os.path.join(base, cfg["api_key_file"])
    transport.resolve(cfg["http"], base)
    return cfg


def serve(cfg, client=None):
    """The gateway's server for a loaded config, not yet serving; stop it with shutdown() and server_close()."""
    with open(cfg["api_key_file"], encoding="utf-8") as f:
        key = f.read().strip()
    srv = transport.HttpServer(*transport.configure(cfg["http"]), None, handler=_Handler)
    srv.gateway = Gateway(cfg["upstream"], key, cfg.get("api_key_header", "authorization"),
                          client or Client(cfg["signer"]), cfg.get("max_body", MAX_BODY))
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the LLM gateway in the foreground").add_argument("--config", required=True)
    a = ap.parse_args(argv)
    try:
        srv = serve(load_config(a.config))
    except (OSError, ValueError) as e:
        print(f"tracekit gateway: {e}", file=sys.stderr)
        return 2
    host, port = srv.server_address[:2]
    print(f"tracekit gateway: {host}:{port} -> {srv.gateway.upstream}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
