"""Model proxy (C3, opt-in): records every model API exchange before forwarding it.

Runs as the `tracekit` user on 127.0.0.1. `tracekit init --proxy` points Claude Code at it
with ANTHROPIC_BASE_URL (settings.json `env`). For each request it:
  1. records a `model.exchange` (phase=request) with the request hashed per docs/privacy.md,
     *before* anything is forwarded; if that fails, fail_mode=open forwards anyway (the client
     library records a capture.gap once the signer is back) and fail_mode=closed answers 503;
  2. forwards the request unchanged except `Host` and `Accept-Encoding` (identity, so the stream
     can be read without buffering), streaming the response back chunk by chunk;
  3. records phase=response when the stream ends: status, tool_use ids and names the model
     asked for, stop reason, a hash of the full (redacted) response, timing and added latency.
Errors from upstream are passed through unchanged. Auth headers are forwarded, never recorded.

The tool_use ids are what the signer cross-checks against hook events (C4): a tool call the
model asked for with no hook event means hooks were disabled or bypassed; a hook event with no
model exchange (for a run that declared the proxy) means the proxy was bypassed.

    python -m tracekit.proxy --home /var/lib/tracekit [--port 8787] [--upstream https://api.anthropic.com]
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
import re
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib

from . import client, privacy
from .core import content_ref, new_id, now_ts

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding",
       "upgrade", "host", "content-length", "accept-encoding"}
MAX_KEEP = 64 * 1024 * 1024
MAX_REQUEST_SIZE = 64 * 1024 * 1024
MAX_SSE_LINE = 1024 * 1024
MAX_TOOL_USES = 200
MAX_CONCURRENT_REQUESTS = 16
SESSION_RE = re.compile(r'"session_id"\s*:\s*"([^"]+)"')
CFG = {"upstream": "https://api.anthropic.com", "fail_mode": "open", "content_capture": "hashed"}


def _decode(body, enc):
    enc = (enc or "").lower()
    try:
        if enc == "gzip":
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            decoder = zlib.decompressobj()
        else:
            return body if not enc or enc == "identity" else None
        out = bytearray()
        pending = body
        while pending:
            chunk = decoder.decompress(pending, MAX_REQUEST_SIZE + 1 - len(out))
            out.extend(chunk)
            if len(out) > MAX_REQUEST_SIZE:
                return None
            pending = decoder.unconsumed_tail
            if pending and not chunk:
                return None
        out.extend(decoder.flush(MAX_REQUEST_SIZE + 1 - len(out)))
        if len(out) > MAX_REQUEST_SIZE or not decoder.eof:
            return None
        return bytes(out)
    except (OSError, zlib.error):
        return None


def attribute(headers, req_json):
    sid = headers.get("X-Claude-Code-Session-Id")
    if sid:
        return sid[:200], "metadata"
    uid = ((req_json or {}).get("metadata") or {}).get("user_id")
    if isinstance(uid, str):
        m = SESSION_RE.search(uid) or re.search(r"session_([0-9a-f-]{36})", uid)
        if m:
            return m.group(1)[:200], "metadata"
    return "_proxy", "none"


def tool_results_sent(req_json):
    """tool_use ids whose results the harness sends back in the newest user turn."""
    if not isinstance(req_json, dict):
        return []
    msgs = (req_json or {}).get("messages") or []
    if not isinstance(msgs, list):
        return []
    out = []
    for m in reversed(msgs):
        if not isinstance(m, dict):
            break
        if m.get("role") != "user":
            break
        c = m.get("content")
        if isinstance(c, list):
            for block in c:
                if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id"):
                    out.append(str(block["tool_use_id"])[:500])
                    if len(out) >= 200:
                        return out
    return out[:200]


class SSEScan:
    """Incrementally pull tool_use blocks and the stop reason out of an SSE stream."""

    def __init__(self):
        self.buf = b""
        self.discarding_line = False
        self.tool_uses, self.stop_reason = [], None

    def feed(self, chunk):
        while chunk:
            if self.discarding_line:
                end = chunk.find(b"\n")
                if end < 0:
                    return
                chunk = chunk[end + 1:]
                self.discarding_line = False
            end = chunk.find(b"\n")
            if end < 0:
                if len(self.buf) + len(chunk) > MAX_SSE_LINE:
                    self.buf = b""
                    self.discarding_line = True
                else:
                    self.buf += chunk
                return
            line = self.buf + chunk[:end]
            self.buf = b""
            chunk = chunk[end + 1:]
            if len(line) > MAX_SSE_LINE:
                continue
            line = line.strip()
            if not line.startswith(b"data:"):
                continue
            try:
                ev = json.loads(line[5:].strip() or b"{}")
            except ValueError:
                continue
            self._event(ev)

    def _event(self, ev):
        if not isinstance(ev, dict):
            return
        t = ev.get("type")
        if t == "content_block_start":
            cb = ev.get("content_block") or {}
            if (isinstance(cb, dict) and len(self.tool_uses) < MAX_TOOL_USES
                    and cb.get("type") in ("tool_use", "server_tool_use") and cb.get("id")):
                self.tool_uses.append({"id": str(cb["id"])[:500], "name": str(cb.get("name") or "?")[:200]})
        elif t == "message_delta":
            delta = ev.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("stop_reason"), str):
                self.stop_reason = delta["stop_reason"] or self.stop_reason
        elif t == "message" or ev.get("content"):
            self.json_message(ev)

    def json_message(self, msg):
        if not isinstance(msg, dict):
            return
        content = msg.get("content") or []
        if not isinstance(content, list):
            return
        for cb in content:
            if len(self.tool_uses) >= MAX_TOOL_USES:
                break
            if isinstance(cb, dict) and cb.get("type") in ("tool_use", "server_tool_use") and cb.get("id"):
                self.tool_uses.append({"id": str(cb["id"])[:500], "name": str(cb.get("name") or "?")[:200]})
        if isinstance(msg.get("stop_reason"), str):
            self.stop_reason = msg["stop_reason"] or self.stop_reason


def record(ev, fail_closed):
    """Send one proxy event. Returns True if recorded."""
    try:
        r = client.send(ev, stream="proxy")
        return bool(r.get("ok"))
    except client.SignerUnavailable:
        return False


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "tracekit-proxy"

    def log_message(self, *a):
        pass

    def _error(self, status, msg):
        body = json.dumps({"type": "error", "error": {"type": "api_error", "message": msg}}).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def _proxy(self):
        if self.path == "/__tracekit_health":
            body = json.dumps({"ok": True, "upstream": CFG["upstream"], "fail_mode": CFG["fail_mode"]}).encode()
            self.send_response(200); self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        t0 = time.perf_counter()
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            self.close_connection = True
            return self._error(400, "tracekit proxy: invalid content-length")
        if n < 0:
            self.close_connection = True
            return self._error(400, "tracekit proxy: invalid content-length")
        if n > MAX_REQUEST_SIZE:
            self.close_connection = True
            return self._error(413, "tracekit proxy: request body exceeds the configured size limit")
        body = self.rfile.read(n) if n else b""
        if len(body) != n:
            self.close_connection = True
            return self._error(400, "tracekit proxy: incomplete request body")
        plain = _decode(body, self.headers.get("content-encoding"))
        try:
            decoded = json.loads(plain) if plain else None
            req_json = decoded if isinstance(decoded, dict) else None
        except ValueError:
            req_json = None
        run_id, how = attribute(self.headers, req_json)
        cc = CFG["content_capture"]
        xid = new_id()
        is_model = self.path.split("?")[0].rstrip("/").endswith("/v1/messages")
        base = {"run_id": run_id, "agent_id": "main", "parent_id": None, "source": "proxy", "type": "model.exchange"}
        streamed = bool((req_json or {}).get("stream"))
        if is_model:
            req_content = privacy.content(req_json if req_json is not None else "", cc) if plain is not None \
                else content_ref("<undecodable body sha256:" + hashlib.sha256(body).hexdigest() + ">")
            ok = record({**base, "ts": now_ts(), "data": {
                "exchange_id": xid, "phase": "request", "model": (req_json or {}).get("model"), "request": req_content,
                "streamed": streamed, "tool_results_sent": tool_results_sent(req_json), "upstream": CFG["upstream"],
                "attribution": how}}, CFG["fail_mode"] == "closed")
            if not ok and CFG["fail_mode"] == "closed":
                return self._error(503, "tracekit proxy: could not record the request (signer unavailable) and fail_mode=closed")
        added = (time.perf_counter() - t0) * 1000
        url = CFG["upstream"].rstrip("/") + self.path
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        headers["Accept-Encoding"] = "identity"
        req = urllib.request.Request(url, data=body if self.command in ("POST", "PUT") else None, headers=headers,
                                     method=self.command)
        t_up = time.perf_counter()
        status, scan, h, size, err = None, SSEScan(), hashlib.sha256(), 0, None
        first = None
        raw_tail = []
        resp = None
        chunked_response = False
        try:
            try:
                resp = urllib.request.urlopen(req, timeout=600)
            except urllib.error.HTTPError as e:
                resp = e
            status = resp.status if hasattr(resp, "status") else resp.code
            self.send_response(status)
            ctype = resp.headers.get("content-type", "")
            for k, v in resp.headers.items():
                if k.lower() not in HOP:
                    self.send_header(k, v)
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            chunked_response = True
            while True:
                chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
                if not chunk:
                    break
                if first is None:
                    first = (time.perf_counter() - t_up) * 1000
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                size += len(chunk)
                h.update(chunk)
                if "event-stream" in ctype:
                    scan.feed(chunk)
                if size <= MAX_KEEP:
                    raw_tail.append(chunk)
            if raw_tail and "json" in ctype:
                try:
                    scan.json_message(json.loads(b"".join(raw_tail)))
                except ValueError:
                    pass
        except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
            err = str(e)[:300]
            if status is None:
                try:
                    self._error(502, f"tracekit proxy: upstream error: {err}")
                except OSError:
                    pass
        finally:
            if resp is not None:
                try:
                    resp.close()
                except OSError:
                    pass
        if is_model:
            if size <= MAX_KEEP:
                # redact, then hash (or keep), exactly like hook content (docs/privacy.md)
                resp_content = privacy.content(b"".join(raw_tail).decode("utf-8", "replace"), cc)
            else:
                resp_content = {"hash": "sha256:" + h.hexdigest(), "size": size, "redacted": False}
            record({**base, "ts": now_ts(), "data": {
                "exchange_id": xid, "phase": "response", "model": (req_json or {}).get("model"), "response": resp_content,
                "status": status, "streamed": streamed, "duration_ms": int((time.perf_counter() - t0) * 1000),
                "first_byte_ms": int(first) if first is not None else None, "added_latency_ms": round(added, 3),
                "tool_uses": scan.tool_uses[:200], "stop_reason": scan.stop_reason, "upstream": CFG["upstream"],
                "error": err, "attribution": how}}, False)
        if chunked_response:
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except OSError:
                pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def serve(home, port=None, upstream=None, host="127.0.0.1"):
    from .daemon import load_config
    cfg = load_config(home) if home else {}
    pc = dict(cfg.get("proxy") or {})
    CFG.update({k: v for k, v in pc.items() if k in CFG})
    if upstream:
        CFG["upstream"] = upstream
    port = int(port or pc.get("port") or 8787)
    if home:
        os.environ.setdefault("TRACEKIT_CLIENT_HOME", os.path.join(home, "proxy-client"))
        os.environ.setdefault("TRACEKIT_SOCKET", cfg.get("socket", os.path.join(home, "tracekitd.sock")))
        if cfg.get("socket_token"):
            os.environ.setdefault("TRACEKIT_SOCKET_TOKEN", cfg["socket_token"])
    srv = Server((host, port), Handler)
    print(f"tracekit proxy: http://{host}:{srv.server_address[1]} -> {CFG['upstream']} (fail_mode={CFG['fail_mode']})", flush=True)
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit-proxy")
    ap.add_argument("--home", default=os.environ.get("TRACEKIT_SIGNER_HOME", "/var/lib/tracekit"))
    ap.add_argument("--port", type=int)
    ap.add_argument("--upstream")
    a = ap.parse_args(argv)
    srv = serve(a.home, a.port, a.upstream)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    sys.exit(main())
