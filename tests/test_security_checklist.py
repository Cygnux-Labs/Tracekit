"""docs/security-checklist.md, enforced: every HTTP handler in tracekit/ is listed in SURFACES and probed with hostile
requests, and every test the checklist names exists.

    python3 -m pytest tests/test_security_checklist.py -v
"""
import ast
import contextlib
import http.client
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import types
import unittest
from http.server import ThreadingHTTPServer

from test_observe_render import XSS
from tracekit import gateway, ingest, observe, otlp, proxy, slack_approvals, witness_server
from tracekit.identity.token import BearerToken
from tracekit.ledger import Keys
from tracekit.signer import metrics
from tracekit.transport import http as transport

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "security-checklist.md")
UI = os.path.join(ROOT, "tracekit", "ui", "terminal.html")
SECRET = "tk-checklist-" + "s" * 40
HOSTILE = [XSS, "javascript:alert(1)", "rm\u202e/hs.exe", "a\u200bb", "tenant\u2066x\u2069", "\ufeffBash", "\u061cx"]
FORMAT_CHARS = "[\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
BIG = "9" * 8   # over every surface's limit, and within the 8 digits the signer parses

# every BaseHTTPRequestHandler in tracekit/ -> what serves it (the checklist's Surfaces table has the same keys)
SURFACES = {
    "tracekit/observe.py:Handler": "viewer (tracekit view) and observer (tracekit observe)",
    "tracekit/transport/http.py:_Handler": "signer HTTPS RPC and OTLP/HTTP; issuer",
    "tracekit/gateway.py:_Handler": "LLM gateway",
    "tracekit/signer/metrics.py:Handler": "signer metrics, logs list and tlog tiles",
    "tracekit/otlp.py:H": "local OTLP receiver (tracekit otel serve)",
    "tracekit/ingest.py:H": "remote ingest",
    "tracekit/witness_server.py:H": "checkpoint witness",
    "tracekit/proxy.py:Handler": "Anthropic proxy",
    "tracekit/slack_approvals.py:Handler": "Slack approvals bridge (interactivity callbacks)",
}


def handler_classes():
    """'path:Class' of every class in tracekit/ that derives, directly or through another, from BaseHTTPRequestHandler."""
    trees = {}
    for d, _, files in os.walk(os.path.join(ROOT, "tracekit")):
        for f in files:
            if f.endswith(".py"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    trees[os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/")] = ast.parse(fh.read())
    names, found = {"BaseHTTPRequestHandler"}, set()
    while True:
        before = len(found)
        for rel, tree in trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and any(
                        getattr(b, "attr", getattr(b, "id", None)) in names for b in node.bases):
                    found.add(f"{rel}:{node.name}")
                    names.add(node.name)
        if len(found) == before:
            return found


class Checklist(unittest.TestCase):
    def test_every_http_handler_is_listed(self):
        self.assertEqual(handler_classes(), set(SURFACES),
                         "a new HTTP handler goes into SURFACES, the probes below and docs/security-checklist.md")

    def test_checklist_lists_every_surface_and_names_tests_that_exist(self):
        with open(DOC, encoding="utf-8") as f:
            doc = f.read()
        for key in SURFACES:
            self.assertIn(f"`{key}`", doc)
        items = re.findall(r"^\| (\d+) \|.*$", doc, re.M)
        self.assertGreaterEqual(len(items), 15)
        for row in re.findall(r"^\| \d+ \|.*$", doc, re.M):
            self.assertRegex(row, r"tests/test_\w+\.py::", f"checklist item without a test: {row}")
        for path, cls, name in re.findall(r"tests/(test_\w+\.py)::(\w+)::(\w+)", doc):
            with open(os.path.join(ROOT, "tests", path), encoding="utf-8") as f:
                tree = ast.parse(f.read())
            methods = {m.name for c in tree.body if isinstance(c, ast.ClassDef) and c.name == cls
                       for m in c.body if isinstance(m, ast.FunctionDef)}
            self.assertIn(name, methods, f"the checklist names {path}::{cls}::{name}, which does not exist")


class Surfaces(unittest.TestCase):
    """Each surface, on loopback, gets requests it must refuse: the answer and the server's output never carry a
    traceback, a source path or the credential sent, and an oversized body is refused before it is read."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.bearer = os.path.join(self.d, "bearer")
        with open(self.bearer, "w", encoding="utf-8") as f:
            f.write(SECRET)

    def start(self, srv):
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def viewer(self):
        feed = types.SimpleNamespace(records=[{"tool_name": s} for s in HOSTILE], base=0, lock=threading.Condition(),
                                     verify=lambda: (0, [], None))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), observe.make_handler(feed, SECRET, ["127.0.0.1"]))
        auth = {"Authorization": f"Bearer {SECRET}"}
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", {}, 401), ("GET", "/nope", auth, 404),
                             ("GET", "/api/stream?from=x", auth, 400), ("POST", "/", auth, 501)]

    def signer_http(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, lambda identity, frame: {})
        auth = {"Authorization": f"Bearer {SECRET}"}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", auth, 404), ("GET", transport.PATH, auth, 501),
                             ("POST", transport.PATH, {**auth, "Content-Length": BIG}, 413)]

    def gateway(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, None, handler=gateway._Handler)
        srv.gateway = types.SimpleNamespace(max_body=1024)
        auth = {"Authorization": f"Bearer {SECRET}", "X-Tracekit-Run": f"run.{SECRET}.mac"}
        return srv, SECRET, [("POST", "/nope", auth, 404), ("POST", "/v1/chat/completions", {}, 401),
                             ("POST", "/v1/chat/completions", {**auth, "Content-Length": BIG}, 413)]

    def metrics(self):
        srv = metrics.server({"listen": "127.0.0.1:0"}, metrics.SignerMetrics())
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", {}, 404), ("POST", "/metrics", {}, 501)]

    def otlp(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), otlp.make_handler(otlp.Receiver(lambda event, attach: {})))
        auth = {"Authorization": f"Bearer {SECRET}"}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", auth, 404),
                             ("POST", "/v1/traces", {**auth, "Content-Length": BIG}, 413)]

    def ingest(self):
        token = ingest.add_token(self.d, "box")
        srv = ingest.serve(self.d, "127.0.0.1", 0, forward=lambda req: {"ok": True})
        auth = {"Authorization": f"Bearer {token}"}
        return srv, token, [("POST", f"/nope?token={token}", auth, 404), ("POST", "/v1/rpc", {}, 401),
                            ("POST", "/v1/rpc", {**auth, "Content-Length": BIG}, 413)]

    def witness(self):
        home = os.path.join(self.d, "w")
        witness_server.init(home)
        token = witness_server.add_token(home, "box", Keys.load_or_create(os.path.join(self.d, "keys")).public)
        srv = witness_server.serve(home, "127.0.0.1", 0)
        auth = {"Authorization": f"Bearer {token}"}
        return srv, token, [("GET", f"/nope?token={token}", auth, 404), ("GET", "/v1/checkpoints?after=x", auth, 400),
                            ("POST", "/v1/checkpoints", {**auth, "Content-Length": BIG}, 413)]

    def proxy(self):
        srv = proxy.Server(("127.0.0.1", 0), proxy.Handler)
        auth = {"x-api-key": SECRET}
        return srv, SECRET, [("POST", "/v1/messages", {**auth, "Content-Length": "abc"}, 400),
                             ("POST", "/v1/messages", {**auth, "Content-Length": BIG}, 413)]

    def slack(self):
        bridge = slack_approvals.Bridge({"signing_secret": b"slack-signing"}, None)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), slack_approvals.make_handler(bridge))
        signed = {"X-Slack-Signature": f"v0={SECRET}", "X-Slack-Request-Timestamp": str(int(time.time()))}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", signed, 404), ("POST", slack_approvals.PATH, signed, 401),
                             ("POST", slack_approvals.PATH, {**signed, "Content-Length": BIG}, 413),
                             ("GET", slack_approvals.PATH, {}, 501)]

    PROBES = {"tracekit/observe.py:Handler": viewer, "tracekit/transport/http.py:_Handler": signer_http,
              "tracekit/gateway.py:_Handler": gateway, "tracekit/signer/metrics.py:Handler": metrics,
              "tracekit/otlp.py:H": otlp, "tracekit/ingest.py:H": ingest, "tracekit/witness_server.py:H": witness,
              "tracekit/proxy.py:Handler": proxy, "tracekit/slack_approvals.py:Handler": slack}

    def request(self, port, method, path, headers):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            c.request(method, path, headers=headers)
            r = c.getresponse()
            return r.status, r.getheaders(), r.read()
        finally:
            c.close()

    def test_every_surface_has_probes(self):
        self.assertEqual(set(self.PROBES), set(SURFACES))

    def test_refusals_carry_no_internals_or_credentials(self):
        root = logging.getLogger()
        logs, level = io.StringIO(), root.level
        handler = logging.StreamHandler(logs)
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.setLevel, level)
        self.addCleanup(root.removeHandler, handler)
        for key, make in self.PROBES.items():
            srv, secret, probes = make(self)
            port = self.start(srv)
            for method, path, headers, status in probes:
                with self.subTest(surface=key, request=f"{method} {path.replace(secret, 'SECRET')}"), \
                        contextlib.redirect_stderr(io.StringIO()) as err:
                    code, h, body = self.request(port, method, path, headers)
                    self.assertEqual(code, status)
                    for leak in (b"Traceback", b'File "', ROOT.encode(), secret.encode()):
                        self.assertNotIn(leak, body)
                    self.assertNotIn(secret, json.dumps(h))
                    self.assertNotIn(secret, err.getvalue() + logs.getvalue())
                    if key == "tracekit/observe.py:Handler":   # the browser surface: every answer carries these
                        h = dict(h)
                        self.assertEqual((h.get("X-Content-Type-Options"), h.get("Referrer-Policy")),
                                         ("nosniff", "no-referrer"))


class Viewer(unittest.TestCase):
    def setUp(self):
        feed = types.SimpleNamespace(records=[{"tool_name": s, "input": {"q": s}} for s in HOSTILE], base=0,
                                     lock=threading.Condition(), verify=lambda: (0, [], None))
        self.handler = observe.make_handler(feed, SECRET, ["127.0.0.1"])
        srv = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.port = srv.server_address[1]
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", f"/?token={SECRET}")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 303)
        self.assertNotIn(SECRET, r.getheader("Location"))
        self.cookie = {"Cookie": r.getheader("Set-Cookie").split(";")[0]}
        self.conn = c
        self.addCleanup(c.close)

    def get(self, path):
        self.conn.request("GET", path, headers=self.cookie)
        r = self.conn.getresponse()
        return r, r.read()

    def test_page_headers(self):
        r, _ = self.get("/")
        csp = r.getheader("Content-Security-Policy")
        for directive in ("default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(directive, csp)
        self.assertRegex(csp, r"script-src 'nonce-[A-Za-z0-9_-]{16,}';")
        self.assertEqual((r.getheader("X-Content-Type-Options"), r.getheader("Referrer-Policy")),
                         ("nosniff", "no-referrer"))

    def test_hostile_run_data_is_served_as_json_data(self):
        r, body = self.get("/api/snapshot")
        self.assertTrue(r.getheader("Content-Type").startswith("application/json"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual([x["tool_name"] for x in json.loads(body)["records"]], HOSTILE)
        _, page = self.get("/")
        self.assertNotIn(b"<img", page)   # run data never reaches the served page itself

    def test_no_state_changing_request_is_served_to_a_session(self):
        self.assertEqual(sorted(m for m in dir(self.handler) if m.startswith("do_")), ["do_GET"])
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            self.conn.request(method, "/api/snapshot", body=b"{}", headers=self.cookie)
            r = self.conn.getresponse()
            r.read()
            self.assertEqual(r.status, 501, method)


class PlainHttp(unittest.TestCase):
    """The CLIs that serve HTTP refuse plain HTTP beyond loopback (view, the signer's http section and the issuer have
    their own tests); ingest and witness take --insecure-http for TLS terminated in front."""

    def test_plain_http_beyond_loopback_is_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for main, argv, code in ((observe.main, ["--host", "0.0.0.0", "--home", d], 1),
                                 (ingest.main, ["serve", "--experimental", "--home", d, "--host", "0.0.0.0"], 2),
                                 (witness_server.main, ["serve", "--home", d, "--host", "0.0.0.0"], 2),
                                 (otlp.main, ["serve", "--experimental", "--host", "0.0.0.0"], 2)):
            with self.subTest(main.__module__), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(argv), code)
                self.assertRegex(err.getvalue(), "loopback")


class Page(unittest.TestCase):
    """terminal.html's sinks: esc() is the one HTML/attribute escaper (test_observe_render checks every interpolation
    uses it); here it neutralises hostile strings, and no URL or code sink takes data."""

    @classmethod
    def setUpClass(cls):
        with open(UI, encoding="utf-8") as f:
            cls.page = f.read()

    @unittest.skipUnless(shutil.which("node"), "needs node to run the page's esc()")
    def test_esc_neutralises_markup_quotes_and_format_characters(self):
        esc = re.search(r"^\s*(const esc = .*;)$", self.page, re.M).group(1)
        out = json.loads(subprocess.run(["node", "-e", f"{esc} process.stdout.write(JSON.stringify("
                                         f"{json.dumps(HOSTILE)}.map(esc)))"],
                                        capture_output=True, text=True, check=True).stdout)
        for s in out:
            self.assertNotRegex(s, "[<>\"']|" + FORMAT_CHARS)
        self.assertEqual(out[2], "rm\\u202e/hs.exe")

    def test_no_url_or_code_sink_takes_data(self):
        self.assertEqual([v for v in re.findall(r'\b(?:href|src|action)="([^"]*)"', self.page) if "${" in v], [])
        self.assertNotRegex(self.page, r"\beval\(|new Function|\.href\s*=|window\.open|document\.write|location\.")


if __name__ == "__main__":
    unittest.main()
