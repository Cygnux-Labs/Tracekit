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

from test_e13_approvals import Sessions
from test_observe_render import XSS
from tracekit import gateway, ingest, observe, otlp, proxy, slack_approvals, witness_server
from tracekit.observe import _session
from tracekit.identity.token import BearerToken
from tracekit.ledger import Keys
from tracekit.signer import metrics
from tracekit.transport import http as transport
from tracekit.view import ApprovalDesk, OidcLogin, Runs
from tracekit.why import cli as why_cli, server as why_server

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "security-checklist.md")
UI = os.path.join(ROOT, "tracekit", "ui", "terminal.html")
APPROVALS_UI = os.path.join(ROOT, "tracekit", "ui", "approvals.html")
RUNS_UI = os.path.join(ROOT, "tracekit", "ui", "runs.html")
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
    "tracekit/why/server.py:H": "tracekit why serve (investigation app, its API and ingest)",
}


def no_logs():
    """A view.Runs of no log: its request checks without Postgres (tests/test_view_central.py reads real logs)."""
    runs = Runs.__new__(Runs)
    runs.logs = []
    return runs


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
        login = OidcLogin({"issuer": "corp", "client_id": "viewer", "redirect_uri": "https://127.0.0.1/callback",
                           "roles": {"auditor": ["group:corp/auditors"]}},
                          {"corp": {"issuer": "https://idp.invalid", "audience": "viewer"}})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), observe.make_handler(feed, SECRET, ["127.0.0.1"], login=login,
                                                                         runs=no_logs()))
        auth = {"Authorization": f"Bearer {SECRET}"}
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", {}, 401), ("GET", "/nope", auth, 404),
                             ("GET", "/runs", {}, 401), ("GET", f"/api/runs?run={SECRET}", {}, 401),
                             ("GET", f"/api/runs?limit={BIG}", auth, 400), ("GET", f"/api/runs?{SECRET}=1", auth, 400),
                             ("GET", f"/api/run?log=0&tenant=t&run={SECRET}", auth, 400),
                             ("GET", f"/api/bundle?log=0&tenant=t&run={SECRET}", {}, 401),
                             ("GET", "/api/stream?from=x", auth, 400), ("POST", "/", auth, 501),
                             ("GET", f"/callback?state=x&code={SECRET}", {"Cookie": "tracekit_login=x"}, 403),
                             ("GET", "/api/snapshot", {"Cookie": f"tracekit_observe={SECRET}"}, 401)]

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

    def why(self):
        srv, _ = why_server.serve(os.path.join(self.d, "why"), "127.0.0.1", 0, token=SECRET, watch=False)
        auth = {"Authorization": f"Bearer {SECRET}"}
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", {}, 401), ("GET", "/nope", auth, 404),
                             ("GET", f"/api/runs/{SECRET}", auth, 404), ("GET", "/api/runs/..%2f..", auth, 400),
                             ("GET", "/api/workspace", {"Cookie": f"tracekit_why={SECRET}"}, 401),
                             ("POST", "/v1/ingest", {"Cookie": f"tracekit_why={_session(SECRET)}"}, 401),
                             ("POST", "/v1/ingest", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/api/runs/x/tests", {"Content-Type": "application/json"}, 401),
                             ("POST", "/api/runs/x/tests", auth, 403), ("PUT", "/", auth, 501)]

    PROBES = {"tracekit/observe.py:Handler": viewer, "tracekit/transport/http.py:_Handler": signer_http,
              "tracekit/gateway.py:_Handler": gateway, "tracekit/signer/metrics.py:Handler": metrics,
              "tracekit/otlp.py:H": otlp, "tracekit/ingest.py:H": ingest, "tracekit/witness_server.py:H": witness,
              "tracekit/proxy.py:Handler": proxy, "tracekit/slack_approvals.py:Handler": slack,
              "tracekit/why/server.py:H": why}

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
                    if key in ("tracekit/observe.py:Handler", "tracekit/why/server.py:H"):   # browser surfaces
                        h = dict(h)
                        self.assertEqual((h.get("X-Content-Type-Options"), h.get("Referrer-Policy")),
                                         ("nosniff", "no-referrer"))


class Viewer(unittest.TestCase):
    def setUp(self):
        feed = types.SimpleNamespace(records=[{"tool_name": s, "input": {"q": s}} for s in HOSTILE], base=0,
                                     lock=threading.Condition(), verify=lambda: (0, [], None))
        self.handler = observe.make_handler(feed, SECRET, ["127.0.0.1"], runs=no_logs())
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
        for path in ("/", "/runs"):
            r, page = self.get(path)
            csp = r.getheader("Content-Security-Policy")
            for directive in ("default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
                self.assertIn(directive, csp)
            nonce = re.search(r"script-src 'nonce-([A-Za-z0-9_-]{16,})';", csp).group(1)
            if path == "/runs":
                self.assertEqual(re.findall(r"<script[^>]*>", page.decode()), [f'<script nonce="{nonce}">'])
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


class Approvals(unittest.TestCase):
    """The approval pages (view.ApprovalDesk): an approver's OIDC session only, and every POST with that session's CSRF
    token, as JSON, within the size cap, to an expected Host; nothing else reaches the signer."""

    def setUp(self):
        self.calls, self.sessions = [], Sessions()
        desk = ApprovalDesk(types.SimpleNamespace(call=lambda m, req: self.calls.append(m) or {"approval_id": "apr-1"}))
        feed = types.SimpleNamespace(records=[], base=0, lock=threading.Condition(), verify=lambda t=None: (0, [], None))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), observe.make_handler(feed, SECRET, ["127.0.0.1"],
                                                                         login=self.sessions, approvals=desk))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.port = srv.server_address[1]
        self.sid = self.sessions.add({"subject": "corp/u", "person": "corp/p", "groups": [], "tenant": "acme"},
                                     "approver")
        self.good = {"Cookie": f"{observe.COOKIE}={self.sid}", "Content-Type": "application/json",
                     "X-CSRF-Token": self.sessions.by_id[self.sid]["csrf"]}

    def request(self, method, path, headers, body=b""):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request(method, path, body=body or None, headers=headers)
            r = c.getresponse()
            return r, r.read()
        finally:
            c.close()

    def test_page_headers(self):
        r, page = self.request("GET", "/approvals", {"Cookie": f"{observe.COOKIE}={self.sid}"})
        self.assertEqual(r.status, 200)
        csp = r.getheader("Content-Security-Policy")
        for directive in ("default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(directive, csp)
        nonce = re.search(r"script-src 'nonce-([A-Za-z0-9_-]{16,})';", csp).group(1)
        self.assertEqual(re.findall(r"<script[^>]*>", page.decode()), [f'<script nonce="{nonce}">'])
        self.assertEqual((r.getheader("X-Content-Type-Options"), r.getheader("Referrer-Policy")),
                         ("nosniff", "no-referrer"))

    def test_posts_need_the_session_csrf_token(self):
        body = b'{"decision": "approve"}'
        auditor = self.sessions.add({"subject": "corp/a", "person": "corp/a", "groups": [], "tenant": "acme"}, "auditor")
        for headers, data, status in (
                ({k: v for k, v in self.good.items() if k != "X-CSRF-Token"}, body, 403),
                (dict(self.good, **{"X-CSRF-Token": "forged"}), body, 403),
                (dict(self.good, **{"Content-Type": "text/plain"}), body, 403),
                (dict(self.good, Cookie=f"{observe.COOKIE}={auditor}"), body, 403),
                (dict(self.good, Cookie=f"{observe.COOKIE}={_session(SECRET)}"), body, 403),   # the operator token
                (dict(self.good, Host="evil.example"), body, 403),
                (dict(self.good, **{"Content-Length": BIG}), b"", 413),
                (self.good, b"[1]", 400)):
            with self.subTest(headers=headers, body=data):
                self.assertEqual(self.request("POST", "/api/approvals/apr-1", headers, data)[0].status, status)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.request("POST", "/api/approvals/apr-1", self.good, body)[0].status, 200)
        self.assertEqual(self.calls, ["approval_decide"])


class PlainHttp(unittest.TestCase):
    """The CLIs that serve HTTP refuse plain HTTP beyond loopback (view, the signer's http section and the issuer have
    their own tests); ingest and witness take --insecure-http for TLS terminated in front."""

    def test_plain_http_beyond_loopback_is_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for main, argv, code in ((observe.main, ["--host", "0.0.0.0", "--home", d], 1),
                                 (ingest.main, ["serve", "--experimental", "--home", d, "--host", "0.0.0.0"], 2),
                                 (witness_server.main, ["serve", "--home", d, "--host", "0.0.0.0"], 2),
                                 (otlp.main, ["serve", "--experimental", "--host", "0.0.0.0"], 2),
                                 (why_cli.main, ["serve", d, "--host", "0.0.0.0"], 2)):
            with self.subTest(main.__module__), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(argv), code)
                self.assertRegex(err.getvalue(), "loopback")

    def test_loopback_receivers_answer_only_a_loopback_host(self):
        """A web page can point a name it controls at 127.0.0.1; the OTLP receiver and the proxy answer only
        requests addressed to a loopback name."""
        for srv, method, path in ((ThreadingHTTPServer(("127.0.0.1", 0), otlp.make_handler(
                otlp.Receiver(lambda event, attach: {}))), "POST", "/nope"),
                                  (proxy.Server(("127.0.0.1", 0), proxy.Handler), "GET", "/__tracekit_health")):
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
            port = srv.server_address[1]
            for host, refused in (("evil.example", True), (f"evil.example:{port}", True), ("", True),
                                  (f"127.0.0.1:{port}", False), (f"localhost:{port}", False), (f"[::1]:{port}", False)):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(method, path, headers={"Host": host})
                with self.subTest(path=path, host=host):
                    self.assertEqual(c.getresponse().status == 403, refused)
                c.close()


class Page(unittest.TestCase):
    """terminal.html's sinks: esc() is the one HTML/attribute escaper (test_observe_render checks every interpolation
    uses it); here it neutralises hostile strings, and no URL or code sink takes data."""

    @classmethod
    def setUpClass(cls):
        with open(UI, encoding="utf-8") as f:
            cls.page = f.read()
        with open(APPROVALS_UI, encoding="utf-8") as f:
            cls.approvals = f.read()
        with open(RUNS_UI, encoding="utf-8") as f:
            cls.runs = f.read()

    @unittest.skipUnless(shutil.which("node"), "needs node to run the page's esc()")
    def test_esc_neutralises_markup_quotes_and_format_characters(self):
        esc = re.search(r"^\s*(const esc = .*;)$", self.page, re.M).group(1)
        out = json.loads(subprocess.run(["node", "-e", f"{esc} process.stdout.write(JSON.stringify("
                                         f"{json.dumps(HOSTILE)}.map(esc)))"],
                                        capture_output=True, text=True, check=True).stdout)
        for s in out:
            self.assertNotRegex(s, "[<>\"']|" + FORMAT_CHARS)
        self.assertEqual(out[2], "rm\\u202e/hs.exe")

    @unittest.skipUnless(shutil.which("node"), "needs node to run the approval page's vis()")
    def test_approval_page_shows_data_as_text_with_format_characters_escaped(self):
        for page in (self.approvals, self.runs):
            self.assertNotRegex(page, r"innerHTML|outerHTML|insertAdjacentHTML")
            vis = re.search(r"^(const vis = .*?;)$", page, re.M | re.S).group(1)
            out = json.loads(subprocess.run(["node", "-e", f"{vis} process.stdout.write(JSON.stringify("
                                             f"{json.dumps(HOSTILE)}.map(vis)))"],
                                            capture_output=True, text=True, check=True).stdout)
            for s in out:
                self.assertNotRegex(s, FORMAT_CHARS)
            self.assertEqual(out[2], "rm\\u202e/hs.exe")

    def test_no_url_or_code_sink_takes_data(self):
        for page in (self.page, self.approvals, self.runs):
            self.assertEqual([v for v in re.findall(r'\b(?:href|src|action)="([^"]*)"', page) if "${" in v], [])
            # the one href set: the downloaded bundle's object URL, never data
            self.assertNotRegex(page, r"\beval\(|new Function|\.href\s*=(?! URL\.createObjectURL\(await r\.blob\(\)\);)"
                                      r"|window\.open|document\.write|location\.")


if __name__ == "__main__":
    unittest.main()
