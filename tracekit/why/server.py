"""`tracekit why serve`: the investigation app, its JSON API, and a token-protected ingestion endpoint.

GET  /                         the app
GET  /api/workspace            run summaries + cross-run influence graph
GET  /api/runs/<id>            everything the app shows for one run
GET  /api/stream               server-sent events: a run changed (with its new alerts), a test finished
POST /api/runs/<id>/tests      {"intervention","target","n"} -> counterfactual replay (allow-listed programs only)
POST /api/runs/<id>/attribute  {"target","n","n_max"} -> group test, then narrow down to the causes
POST /v1/ingest                Authorization: Bearer <token>; {"events":[...], "blobs":{ref: value}}

Live: a watcher polls the runs folder, so runs written to disk by a local Runtime show up as they are
recorded, the same as ingested ones. Each change recomputes that run's alerts; new ones are pushed to
the app over /api/stream and, with a webhook, POSTed out.

Security: the conventions of `tracekit view` (observe.py). Every request needs the token: the page's `?token=` is
exchanged once for an HttpOnly, SameSite=Strict cookie derived from it, the API also takes it as a bearer token, and
ingest takes the bearer token only. Requests to a Host name other than loopback or the bound address are refused
unless they carry the token (DNS rebinding); POSTs need an expected Host whatever they carry. The replay POSTs need a
JSON body, which a cross-site form cannot send. Ingest validates every event's hash, its link to the previous event
and every blob's content hash before anything is written. Replay imports the program a run names, so only programs
passed with --allow-program can be replayed. Served by netserver.Server: bounded threads, per-IP limits, deadlines.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from collections import deque
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from ..netserver import Server
from ..observe import CSP, LOOPBACK_HOSTS, WILDCARD_HOSTS, _host_only, _session
from .core import EVENT_TYPES, GENESIS, SCHEMA, content_hash, event_hash, load_run
from .evals import list_runs
from .graph import build_graph
from .replay import attribute, counterfactual, load_system
from .view import render_app, run_detail
from .analysis import alerts, workspace

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
MAX_BODY = 20 * 1024 * 1024
COOKIE = "tracekit_why"
# fields each event type must carry for the analysis to read it
REQUIRED = {"run.start": (), "agent.start": (), "run.end": (), "input": ("ref", "source", "trust"),
            "decision": ("model", "context", "output"), "action": ("tool", "args_ref", "result_ref"),
            "message": ("to", "ref")}


class IngestError(ValueError):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


def _int(val) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        raise IngestError(400, "n and n_max must be integers")


class Store:
    def __init__(self, root: str, token: Optional[str], allow_programs: Iterable[str] = (),
                 webhook: Optional[str] = None):
        self.root = root
        self.token = token
        self.allow = set(allow_programs)
        self.webhook = webhook
        self.lock = threading.Lock()
        os.makedirs(root, exist_ok=True)
        # live feed: a counter, recent messages, and a condition the stream handlers wait on
        self.cond = threading.Condition()
        self.counter = 0
        self.feed: deque = deque(maxlen=500)
        self._stat: Dict[str, Tuple[int, float]] = {}
        self._seen: Dict[str, set] = {}
        self._watching = False
        self._analyse = threading.Lock()  # ingest and the watcher may both see the same change

    # -- live
    def publish(self, msg: Dict[str, Any]) -> None:
        with self.cond:
            self.counter += 1
            self.feed.append((self.counter, msg))
            self.cond.notify_all()

    def since(self, n: int) -> List[Tuple[int, Dict[str, Any]]]:
        with self.cond:
            return [(i, m) for i, m in self.feed if i > n]

    def changed(self, path: str, announce: bool = True) -> None:
        """A run's log grew: recompute its alerts and announce the new ones (each one once)."""
        with self._analyse:
            self._changed(path, announce)

    def _changed(self, path: str, announce: bool) -> None:
        try:
            st = os.stat(os.path.join(path, "events.jsonl"))
            self._stat[path] = (st.st_size, st.st_mtime)
            run = load_run(path)
            al = alerts(run, build_graph(run, infer=False))
        except Exception as e:  # a half-written line or a broken run must not stop the feed
            print(f"tracekit why: could not analyse {path}: {e}", file=sys.stderr)
            return
        seen = self._seen.setdefault(path, set())
        new = []
        for a in al:
            key = (a["title"], a.get("node"))
            if key not in seen:
                seen.add(key)
                new.append({k: a.get(k) for k in ("severity", "title", "detail", "node", "tool", "agent", "seq")})
        if not announce:
            return
        finished = bool(run.events) and run.events[-1]["type"] == "run.end"
        self.publish({"type": "run", "run_id": run.run_id, "events": len(run.events), "finished": finished,
                      "alerts": new})
        if self.webhook:
            for a in new:
                if a["severity"] == "high":
                    self._post_webhook(run.run_id, a)

    def _post_webhook(self, run_id: str, a: Dict[str, Any]) -> None:
        import urllib.request
        body = json.dumps({"text": f"[tracekit why HIGH] {run_id} {a.get('agent')}.{a.get('tool')}: {a['title']}. "
                                   f"{a.get('detail') or ''}", "run_id": run_id, "alert": a}).encode()

        def post() -> None:
            try:
                req = urllib.request.Request(self.webhook, data=body, method="POST",
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as e:
                print(f"tracekit why: webhook failed: {e}", file=sys.stderr)

        threading.Thread(target=post, daemon=True).start()

    def scan(self, announce: bool = True) -> None:
        for p in list_runs(self.root) if os.path.isdir(self.root) else []:
            try:
                st = os.stat(os.path.join(p, "events.jsonl"))
            except OSError:
                continue
            if self._stat.get(p) != (st.st_size, st.st_mtime):
                with self._analyse:  # re-check: ingest may have just handled this change
                    if self._stat.get(p) == (st.st_size, st.st_mtime):
                        continue
                    self._changed(p, announce)

    def watch(self, interval: float = 0.5) -> None:
        """Poll the runs folder in a daemon thread. Existing runs are indexed silently first, so only
        alerts raised after the server started are announced."""
        if self._watching:
            return
        self._watching = True

        def loop() -> None:
            self.scan(announce=False)
            while self._watching:
                time.sleep(interval)
                try:
                    self.scan()
                except Exception as e:
                    print(f"tracekit why: watcher: {e}", file=sys.stderr)

        threading.Thread(target=loop, daemon=True).start()

    def paths(self) -> List[str]:
        return list_runs(self.root) if os.listdir(self.root) else []

    def run_path(self, run_id: str) -> str:
        if not RUN_ID.match(run_id):
            raise IngestError(400, "bad run id")
        return os.path.join(self.root, run_id)

    # -- ingest
    def ingest(self, body: Dict[str, Any]) -> Dict[str, Any]:
        events, blobs = body.get("events"), body.get("blobs") or {}
        if not isinstance(events, list) or not events or not isinstance(blobs, dict):
            raise IngestError(400, "expected {events: [...], blobs: {...}}")
        for ref, val in blobs.items():
            if content_hash(val) != ref:
                raise IngestError(422, f"blob {str(ref)[:20]} does not match its hash")
        run_id = events[0].get("run_id", "") if isinstance(events[0], dict) else ""
        if any(not isinstance(e, dict) or e.get("run_id") != run_id for e in events):
            raise IngestError(400, "one batch must belong to one run")
        for e in events:
            missing = [k for k in REQUIRED.get(e.get("type"), ("type",)) if k not in e]
            if e.get("type") not in EVENT_TYPES or missing or not isinstance(e.get("context", []), list) \
                    or not all(isinstance(c, dict) and "ref" in c for c in e.get("context", [])):
                raise IngestError(422, f"seq {e.get('seq')}: malformed {e.get('type')!r} event {missing or ''}")
        path = self.run_path(run_id)
        with self.lock:
            os.makedirs(os.path.join(path, "blobs"), exist_ok=True)
            ev_path = os.path.join(path, "events.jsonl")
            last_seq, last_hash = -1, GENESIS
            if os.path.exists(ev_path):
                with open(ev_path, "rb") as f:
                    lines = [l for l in f.read().splitlines() if l.strip()]
                if lines:
                    last = json.loads(lines[-1])
                    last_seq, last_hash = last["seq"], last["hash"]
            for ev in events:
                if ev.get("schema") != SCHEMA:
                    raise IngestError(422, "unknown schema")
                if ev.get("seq") != last_seq + 1:
                    raise IngestError(409, f"expected seq {last_seq + 1}, got {ev.get('seq')}")
                if ev.get("prev_hash") != last_hash:
                    raise IngestError(409, f"seq {ev['seq']}: does not link to the stored chain")
                if event_hash(ev) != ev.get("hash"):
                    raise IngestError(422, f"seq {ev['seq']}: hash mismatch")
                last_seq, last_hash = ev["seq"], ev["hash"]
            known = set()
            bdir = os.path.join(path, "blobs")
            known.update("sha256:" + n[:-5] for n in os.listdir(bdir))
            known.update(blobs)
            for ev in events:
                for k in ("ref", "output", "args_ref", "result_ref"):
                    if ev.get(k) and ev[k] not in known:
                        raise IngestError(422, f"seq {ev['seq']}: missing blob {ev[k][:20]}")
                for c in ev.get("context", []):
                    if c["ref"] not in known:
                        raise IngestError(422, f"seq {ev['seq']}: missing blob {c['ref'][:20]}")
            for ref, val in blobs.items():
                p = os.path.join(bdir, ref[7:] + ".json")
                if not os.path.exists(p):
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump({"v": val}, f, sort_keys=True, ensure_ascii=False, default=str)
            with open(ev_path, "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
        self.changed(path)
        return {"run_id": run_id, "accepted": len(events), "head_seq": last_seq}

    # -- tests
    def _replayable(self, run_id: str):
        path = self.run_path(run_id)
        if not os.path.exists(os.path.join(path, "events.jsonl")):
            raise IngestError(404, "no such run")
        run = load_run(path)
        prog = run.start.get("program")
        if not prog or prog not in self.allow:
            raise IngestError(403, f"replay of program {prog!r} is not allowed on this server (--allow-program)")
        return run, prog

    def attribute(self, run_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        run, prog = self._replayable(run_id)
        n, n_max = _int(body.get("n", 10)), _int(body.get("n_max", 80))
        target = str(body.get("target", ""))
        if not target or not 1 <= n <= n_max <= 400:
            raise IngestError(400, "target is required; 1 <= n <= n_max <= 400")
        try:
            result = attribute(run, target, body.get("suspects") or None, n=n, n_max=n_max, system=load_system(prog))
        except ValueError as e:
            raise IngestError(400, str(e))
        self.publish({"type": "test", "run_id": run.run_id, "verdict": result["summary"]})
        out = {k: v for k, v in result.items() if k != "tests"}
        out["tests"] = len(result["tests"])
        return out

    def test(self, run_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        run, prog = self._replayable(run_id)
        n = _int(body.get("n", 30))
        n_max = _int(body["n_max"]) if body.get("n_max") else None
        if not 1 <= n <= 200 or (n_max is not None and not n <= n_max <= 400):
            raise IngestError(400, "n must be 1..200 and n_max n..400")
        inter, target = str(body.get("intervention", "")), str(body.get("target", ""))
        if not inter or not target:
            raise IngestError(400, "intervention and target are required")
        try:
            result = counterfactual(run, inter, target, n=n, system=load_system(prog), n_max=n_max)
        except ValueError as e:
            raise IngestError(400, str(e))
        self.publish({"type": "test", "run_id": run.run_id, "verdict": result["verdict"]})
        return result


def make_handler(store: Store, token: str, allowed_hosts: Iterable[str] = (), secure: bool = False):
    allowed = set(LOOPBACK_HOSTS) | {h.lower() for h in allowed_hosts if h.lower() not in WILDCARD_HOSTS}
    cookie = _session(token)

    class H(BaseHTTPRequestHandler):
        server_version = "tracekit-why"

        def log_message(self, *a):
            pass

        def end_headers(self):  # every answer, the default error pages and the stream too
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            super().end_headers()

        def _send(self, status: int, body: Any, ctype: str = "application/json", headers=()) -> None:
            data = body if isinstance(body, (bytes, bytearray)) else (
                body.encode() if isinstance(body, str) else json.dumps(body, default=str).encode())
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()
            self.wfile.write(data)

        def _bearer(self) -> bool:
            return hmac.compare_digest(self.headers.get("Authorization", "").encode(), f"Bearer {token}".encode())

        def _authorized(self) -> bool:
            got = ""
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    got = v
            return self._bearer() or hmac.compare_digest(got.encode(), cookie.encode())

        def _guarded(self, fn) -> None:
            try:
                fn()
            except IngestError as e:
                self._send(e.status, {"error": str(e)})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                traceback.print_exc()
                try:
                    self._send(500, {"error": "internal error"})
                except OSError:
                    pass

        def _stream(self) -> None:
            self.server.stop_deadline()  # an event stream lasts as long as the page is open
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            last = store.counter
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while True:
                with store.cond:
                    store.cond.wait_for(lambda: store.counter > last, timeout=15)
                items = store.since(last)
                if not items:
                    self.wfile.write(b": ping\n\n")
                for i, msg in items:
                    self.wfile.write(("data: " + json.dumps(msg, default=str) + "\n\n").encode())
                    last = i
                self.wfile.flush()

        def _body(self) -> Dict[str, Any]:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise IngestError(400, "bad Content-Length")
            if not 0 <= n <= MAX_BODY:
                raise IngestError(413, "body too large")
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (UnicodeDecodeError, ValueError):
                raise IngestError(400, "invalid JSON")
            if not isinstance(body, dict):
                raise IngestError(400, "the body is not a JSON object")
            return body

        def do_GET(self):
            self._guarded(self._get)

        def do_POST(self):
            self._guarded(self._post)

        def _get(self):
            u = urlparse(self.path)
            supplied = parse_qs(u.query).get("token", [""])[0]
            exchange = bool(supplied and u.path in ("/", "/index.html")
                            and hmac.compare_digest(supplied.encode(), token.encode()))
            authorized = exchange or self._authorized()
            # DNS rebinding: other names (a wildcard bind reached by its LAN address) only with the token
            if _host_only(self.headers.get("Host")) not in allowed and not authorized:
                return self._send(403, {"error": "unexpected Host header"})
            if not authorized:
                return self._send(401, {"error": "missing or wrong token"})
            if exchange:
                return self._send(303, "", "text/plain", headers=[
                    ("Location", u.path), ("Set-Cookie", f"{COOKIE}={cookie}; HttpOnly; SameSite=Strict; Path=/"
                                           + ("; Secure" if secure else ""))])
            p = u.path
            if p in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(18)
                return self._send(200, render_app(None, server=True).replace("<script>", f'<script nonce="{nonce}">'),
                                  "text/html", headers=[("Content-Security-Policy", CSP.format(nonce=nonce))])
            if p == "/api/workspace":
                return self._send(200, workspace(store.paths()))
            m = re.match(r"^/api/runs/([^/]+)$", p)
            if m:
                path = store.run_path(unquote(m.group(1)))
                if not os.path.exists(os.path.join(path, "events.jsonl")):
                    return self._send(404, {"error": "no such run"})
                return self._send(200, run_detail(load_run(path)))
            if p == "/healthz":
                return self._send(200, {"ok": True})
            if p == "/api/stream":
                return self._stream()
            self._send(404, {"error": "not found"})

        def _post(self):
            if _host_only(self.headers.get("Host")) not in allowed and not self._bearer():
                return self._send(403, {"error": "unexpected Host header"})
            p = urlparse(self.path).path
            if p == "/v1/ingest":
                if not self._bearer():
                    return self._send(401, {"error": "unauthorized"})
                return self._send(200, store.ingest(self._body()))
            m = re.match(r"^/api/runs/([^/]+)/(tests|attribute)$", p)
            if not m:
                return self._send(404, {"error": "not found"})
            if not self._authorized():
                return self._send(401, {"error": "missing or wrong token"})
            # CSRF: a JSON body needs a preflight a cross-site page never gets answered, on top of SameSite=Strict
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json" or (
                    self.headers.get("Origin") and urlparse(self.headers["Origin"]).netloc != self.headers.get("Host")):
                return self._send(403, {"error": "cross-origin request refused"})
            body = self._body()
            self.server.stop_deadline()  # a replay takes as long as its trials
            run_id = unquote(m.group(1))
            self._send(200, store.test(run_id, body) if m.group(2) == "tests" else store.attribute(run_id, body))

    return H


def serve(root: str, host: str = "127.0.0.1", port: int = 7788, token: Optional[str] = None,
          allow_programs: Iterable[str] = (), webhook: Optional[str] = None, watch: bool = True,
          tls=None) -> Tuple[Server, Store]:
    """The server (HTTPS with `tls`, an ssl.SSLContext) and its Store; call serve_forever(). Without `token`, a random
    one: read it from store.token."""
    store = Store(root, token or secrets.token_urlsafe(24), allow_programs, webhook)
    httpd = Server((host, port), make_handler(store, store.token, [host], secure=bool(tls)), tls)
    if watch:
        store.watch()
    return httpd, store
