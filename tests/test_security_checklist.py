"""docs/security-checklist.md, enforced: every HTTP handler in tracekit/ is listed in SURFACES and probed with hostile
requests, and every test the checklist names exists.

    python3 -m pytest tests/test_security_checklist.py -v
"""
import ast
import base64
import contextlib
import http.client
import io
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import types
import unittest
from http.server import ThreadingHTTPServer

from test_e13_approvals import Sessions
from test_observe_render import XSS
from tracekit import (a2a_gateway, egress, executor, gateway, ingest, mcp_gateway, observe, otlp, proxy,
                      public_witness_server, slack_approvals, witness_server)
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
    "tracekit/executor.py:_Executor": "tool executor",
    "tracekit/mcp_gateway.py:_McpGateway": "MCP gateway",
    "tracekit/a2a_gateway.py:_A2aGateway": "A2A gateway",
    "tracekit/egress.py:_Handler": "egress observer (forward and CONNECT proxy)",
    "tracekit/signer/metrics.py:Handler": "signer metrics, logs list and tlog tiles",
    "tracekit/otlp.py:H": "local OTLP receiver (tracekit otel serve)",
    "tracekit/ingest.py:H": "remote ingest",
    "tracekit/witness_server.py:H": "checkpoint witness",
    "tracekit/public_witness_server.py:H": "public tlog-witness",
    "tracekit/proxy.py:Handler": "Anthropic proxy",
    "tracekit/slack_approvals.py:Handler": "Slack approvals bridge (interactivity callbacks)",
}


def no_logs():
    """A view.Runs of no log: its request checks without Postgres (tests/test_view_central.py reads real logs)."""
    runs = Runs.__new__(Runs)
    runs.logs = []
    return runs


def source_trees():
    """{'tracekit/...py': its AST} for every module in tracekit/."""
    trees = {}
    for d, _, files in os.walk(os.path.join(ROOT, "tracekit")):
        for f in files:
            if f.endswith(".py"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    trees[os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/")] = ast.parse(fh.read())
    return trees


def has_lines(trees, rel, name):
    """Whether class `name` of module `rel` derives from netserver.Lines ahead of BaseHTTPRequestHandler, whose
    parse_request doesn't call on (so Lines' never runs): through a base class defined in the same module, or one
    imported by name from another module of tracekit/."""
    tree = trees[rel]
    classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    for base in (getattr(b, "attr", getattr(b, "id", None)) for b in classes[name].bases):
        if base == "BaseHTTPRequestHandler":
            return False
        if base == "Lines" or base in classes and base != name and has_lines(trees, rel, base):
            return True
        for imp in ast.walk(tree):
            if isinstance(imp, ast.ImportFrom) and base in {a.name for a in imp.names}:
                parts = (rel.split("/")[:-imp.level] if imp.level else []) + (imp.module or "").split(".")
                other = "/".join(parts) + ".py"
                if other in trees and has_lines(trees, other, base):
                    return True
    return False


def handler_classes():
    """'path:Class' of every class in tracekit/ that derives, directly or through another, from BaseHTTPRequestHandler."""
    trees = source_trees()
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


# a whole request sent as another's body; the proxy's health route, so one smuggled through the proxy stays local
NEXT = b"GET /__tracekit_health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
AUTH = [f"Authorization: Bearer {SECRET}", f"X-Tracekit-Run: run.{SECRET}.mac"]


def wire(request, lines, body=b""):
    """The bytes of `request` ("METHOD path") with header `lines` as given: repeated, or malformed."""
    method, path = request.split()
    return (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n" + "".join(f"{x}\r\n" for x in lines) +
            "\r\n").encode("latin-1") + body


def exchange(port, data, half_close=False):
    """(the statuses one connection answers `data` with, whether the server then closed it); `half_close`: the client
    sends nothing more."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(data)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        s.settimeout(1)   # an open connection with nothing more to answer
        out, closed = b"", True
        try:
            while chunk := s.recv(65536):
                out += chunk
        except socket.timeout:
            closed = False
        except ConnectionResetError:
            pass
    return [int(x) for x in re.findall(rb"HTTP/1\.[01] (\d{3}) ", out)], closed


class Checklist(unittest.TestCase):
    def test_every_http_handler_is_listed(self):
        self.assertEqual(handler_classes(), set(SURFACES),
                         "a new HTTP handler goes into SURFACES, the probes below and docs/security-checklist.md")

    def test_every_http_handler_reads_its_raw_header_lines(self):
        """netserver.Lines refuses a CR that doesn't end its header line, which Python's parser takes as a line end."""
        trees = source_trees()
        self.assertEqual({key for key in SURFACES if not has_lines(trees, *key.split(":"))}, set())
        order = {"m.py": ast.parse("class A(BaseHTTPRequestHandler, Lines): pass\n"
                                   "class B(Lines, http.server.BaseHTTPRequestHandler): pass\n")}
        self.assertEqual([has_lines(order, "m.py", c) for c in "AB"], [False, True])

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
                                     verify=lambda: (0, [], None), rows=lambda scope, tenant, run: None)
        login = OidcLogin({"issuer": "corp", "client_id": "viewer", "redirect_uri": "https://127.0.0.1/callback",
                           "roles": {"auditor": ["group:corp/auditors"]}},
                          {"corp": {"issuer": "https://idp.invalid", "audience": "viewer"}})
        why = why_server.Store(os.path.join(self.d, "why"), out=feed)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), observe.make_handler(feed, SECRET, ["127.0.0.1"], login=login,
                                                                         runs=no_logs(), why=why))
        auth = {"Authorization": f"Bearer {SECRET}"}
        operator = _session(srv.RequestHandlerClass.session_key, int(time.time()) + 60)   # the token's session
        login._keep("admin", {"tenant": observe.ALL, "role": "operator-admin", "person": {}, "csrf": "c",
                              "at": time.time(), "until": time.time() + 60})   # every tenant's records, no why logs
        admin = {"Cookie": f"{observe.COOKIE}=admin", "Content-Type": "application/json"}
        return srv, SECRET, [("GET", "/api/why/workspace", admin, 403), ("POST", "/api/why/runs/x/tests", admin, 401),("GET", f"/nope?token={SECRET}", {}, 401), ("GET", "/nope", auth, 404),
                             ("GET", "/runs", {}, 401), ("GET", f"/api/runs?run={SECRET}", {}, 401),
                             ("GET", f"/api/runs?limit={BIG}", auth, 400), ("GET", f"/api/runs?{SECRET}=1", auth, 400),
                             ("GET", f"/api/run?log=0&tenant=t&run={SECRET}", auth, 400),
                             ("GET", f"/api/bundle?log=0&tenant=t&run={SECRET}", {}, 401),
                             ("GET", "/api/stream?from=x", auth, 400),
                             ("GET", f"/api/rows?tenant=t&run={SECRET}", {}, 401), ("GET", "/api/rows?run=x", auth, 400),
                             ("GET", f"/api/rows?tenant=t&run={SECRET}", auth, 404),
                             ("GET", f"/callback?state=x&code={SECRET}", {"Cookie": "tracekit_login=x"}, 403),
                             ("GET", "/api/snapshot", {"Cookie": f"tracekit_observe={SECRET}"}, 401),
                             ("GET", f"/api/why/runs/{SECRET}", auth, 404), ("GET", "/api/why/runs/..%2f..", auth, 400),
                             ("GET", "/api/why/nope", auth, 404),
                             ("GET", "/api/why/workspace", {"Cookie": f"tracekit_observe={SECRET}"}, 401),
                             ("POST", "/v1/ingest", {"Cookie": f"tracekit_observe={operator}"}, 401),
                             ("POST", "/v1/ingest", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/api/why/runs/x/tests", {"Content-Type": "application/json"}, 401),
                             ("POST", "/api/why/runs/x/tests", auth, 403), ("POST", "/nope", auth, 404),
                             ("PUT", "/", auth, 501)]

    def signer_http(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, lambda identity, frame: {})
        auth = {"Authorization": f"Bearer {SECRET}"}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", auth, 404), ("GET", transport.PATH, auth, 501),
                             ("POST", transport.PATH, {**auth, "Content-Length": BIG}, 413),
                             ("POST", transport.PATH, {**auth, "Transfer-Encoding": "chunked", "Content-Length": "2"}, 400)]

    def gateway(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, None, handler=gateway._Handler)
        srv.gateway = types.SimpleNamespace(max_body=1024)
        auth = {"Authorization": f"Bearer {SECRET}", "X-Tracekit-Run": f"run.{SECRET}.mac"}
        return srv, SECRET, [("POST", "/nope", auth, 404), ("POST", "/v1/chat/completions", {}, 401),
                             ("POST", "/v1/chat/completions", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/v1/chat/completions", {**auth, "Transfer-Encoding": "chunked", "Content-Length": "2"}, 400)]

    def executor(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, None, handler=executor._Executor)
        srv.executor = {"actions": {"pay": {"name": "pay", "args": {}}}, "max_body": 1024, "custody": None}
        auth = {"Authorization": f"Bearer {SECRET}", "X-Tracekit-Run": f"run.{SECRET}.mac"}
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", auth, 404), ("GET", "/v1/actions", {}, 401),
                             ("POST", f"/v1/actions/{SECRET}", {}, 401), ("POST", "/v1/actions/pay", {}, 401),
                             ("POST", "/v1/actions/pay", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/v1/actions/pay", {**auth, "Transfer-Encoding": "chunked", "Content-Length": "2"}, 400),
                             ("PUT", "/v1/actions", auth, 501)]

    def mcp_gateway(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, None,
                                   handler=mcp_gateway._McpGateway)
        srv.mcp = {"max_body": 1024}
        auth = {"Authorization": f"Bearer {SECRET}", "X-Tracekit-Run": f"run.{SECRET}.mac"}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", auth, 404), ("GET", "/mcp", auth, 405),
                             ("POST", "/mcp", {}, 401), ("POST", "/mcp", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/mcp", {**auth, "Transfer-Encoding": "chunked", "Content-Length": "2"}, 400),
                             ("PUT", "/mcp", auth, 501)]

    def a2a_gateway(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, None,
                                   handler=a2a_gateway._A2aGateway)
        srv.a2a = {"max_body": 1024, "upstreams": {}}
        auth = {"Authorization": f"Bearer {SECRET}", "X-Tracekit-Run": f"run.{SECRET}.mac"}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", auth, 404), ("GET", "/a2a/up", auth, 405),
                             ("POST", f"/a2a/{SECRET}", {}, 401),
                             ("POST", "/a2a/up", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/a2a/up", {**auth, "Transfer-Encoding": "chunked", "Content-Length": "2"}, 400),
                             ("PUT", "/a2a/up", auth, 501)]

    def egress(self):
        srv = transport.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer)], None, None, handler=egress._Handler)
        srv.observer = egress.Observer(types.SimpleNamespace(observe_effect=lambda req: None))
        run = {"Proxy-Authorization": "Basic " + base64.b64encode(f"run-1:{SECRET}".encode()).decode()}
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", run, 400), ("CONNECT", "nohost", run, 400),
                             ("CONNECT", "x.example:443", {"Proxy-Authorization": f"Basic {SECRET}"}, 407),
                             ("CONNECT", "dns.google:443", run, 403), ("CONNECT", "10.0.0.1:443", run, 403),
                             ("POST", "http://x.example/", {**run, "Content-Length": BIG}, 413)]

    def metrics(self):
        srv = metrics.server({"listen": "127.0.0.1:0"}, metrics.SignerMetrics())
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", {}, 404), ("POST", "/metrics", {}, 501)]

    def otlp(self):
        srv = otlp.serve("127.0.0.1", 0, otlp.Receiver(lambda event, attach: {}))
        auth = {"Authorization": f"Bearer {SECRET}"}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", auth, 404),
                             ("POST", "/v1/traces", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/v1/traces", {**auth, "Transfer-Encoding": "chunked", "Content-Length": "2"}, 400)]

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

    def public_witness(self):
        home = os.path.join(self.d, "pw")
        public_witness_server.init(home, "witness.example.org/w1")
        srv = public_witness_server.serve(home, port=0)
        return srv, SECRET, [("GET", f"/nope?token={SECRET}", {}, 404), ("POST", f"/nope?token={SECRET}", {}, 404),
                             ("POST", "/add-checkpoint", {}, 413), ("POST", "/register", {"Content-Length": BIG}, 413),
                             ("PUT", "/register", {}, 501)]

    def proxy(self):
        srv = proxy.Server(("127.0.0.1", 0), proxy.Handler)
        auth = {"x-api-key": SECRET}
        return srv, SECRET, [("POST", "/v1/messages", {**auth, "Content-Length": "abc"}, 400),
                             ("POST", "/v1/messages", {**auth, "Content-Length": BIG}, 413),
                             ("POST", "/v1/messages", {**auth, "Transfer-Encoding": "chunked", "Content-Length": "2"}, 400)]

    def slack(self):
        bridge = slack_approvals.Bridge({"signing_secret": b"slack-signing"}, None)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), slack_approvals.make_handler(bridge))
        signed = {"X-Slack-Signature": f"v0={SECRET}", "X-Slack-Request-Timestamp": str(int(time.time()))}
        return srv, SECRET, [("POST", f"/nope?token={SECRET}", signed, 404), ("POST", slack_approvals.PATH, signed, 401),
                             ("POST", slack_approvals.PATH, {**signed, "Content-Length": BIG}, 413),
                             ("GET", slack_approvals.PATH, {}, 501)]

    PROBES = {"tracekit/observe.py:Handler": viewer, "tracekit/transport/http.py:_Handler": signer_http,
              "tracekit/gateway.py:_Handler": gateway, "tracekit/executor.py:_Executor": executor,
              "tracekit/mcp_gateway.py:_McpGateway": mcp_gateway, "tracekit/signer/metrics.py:Handler": metrics,
              "tracekit/a2a_gateway.py:_A2aGateway": a2a_gateway,
              "tracekit/egress.py:_Handler": egress,
              "tracekit/otlp.py:H": otlp, "tracekit/ingest.py:H": ingest, "tracekit/witness_server.py:H": witness,
              "tracekit/proxy.py:Handler": proxy, "tracekit/slack_approvals.py:Handler": slack,
              "tracekit/public_witness_server.py:H": public_witness}

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

    def kept_alive(self):
        """Each server that keeps a connection open for another request (the issuer serves the signer's handler),
        started: [(name, port, requests it reads a body for, requests it answers without needing one)]."""
        signer = self.signer_http()[0]
        signer.otlp = lambda identity, body, content_type, encoding: (200, {}, b"{}")
        return [(name, self.start(srv), reads, answers) for name, srv, reads, answers in (
            ("gateway", self.gateway()[0], ["POST /v1/chat/completions"], ["GET /v1/chat/completions"]),
            ("executor", self.executor()[0], ["POST /v1/actions/pay"], ["GET /v1/actions"]),
            ("mcp gateway", self.mcp_gateway()[0], ["POST /mcp"], ["GET /mcp", "DELETE /mcp"]),
            ("a2a gateway", self.a2a_gateway()[0], ["POST /a2a/up"], ["GET /a2a/up"]),
            ("signer", signer, ["POST /v2/rpc", "POST /v1/traces"], ["GET /v2/rpc"]),
            ("otlp", self.otlp()[0], ["POST /v1/traces"], ["GET /v1/traces"]),
            ("proxy", self.proxy()[0], ["GET /__tracekit_health"], ["GET /__tracekit_health"]))]

    def test_a_body_no_route_reads_is_never_the_next_request(self):
        """A route that answers without reading the body a request declares closes the connection after it: the body,
        a whole request here, is never answered as the next one (a proxy in front would be one answer behind)."""
        for name, port, _, answers in self.kept_alive():
            for request in answers:
                with self.subTest(server=name, request=request):
                    statuses, _ = exchange(port, wire(request, AUTH + [f"Content-Length: {len(NEXT)}"], NEXT))
                    self.assertEqual(len(statuses), 1, statuses)

    def test_transfer_encoding_is_refused_on_every_method(self):
        chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(NEXT), NEXT)
        for name, port, reads, answers in self.kept_alive():
            for request in reads + answers:
                with self.subTest(server=name, request=request):
                    statuses, closed = exchange(port, wire(request, AUTH + ["Transfer-Encoding: chunked"], chunked))
                    self.assertIn(statuses, ([400], [501]))   # 501: a method the server serves no route for
                    self.assertTrue(closed)

    def test_more_than_one_content_length_is_refused(self):
        """A proxy in front that frames the body by the other value would send the rest as another request."""
        lengths = ["Content-Length: 2", f"Content-Length: {2 + len(NEXT)}"]
        for name, port, reads, _ in self.kept_alive():
            for request in reads:
                with self.subTest(server=name, request=request):
                    self.assertEqual(exchange(port, wire(request, AUTH + lengths, b"{}" + NEXT)), ([400], True))

    def test_a_malformed_header_line_is_refused(self):
        """Python's parser drops a line like `Transfer-Encoding : chunked` and every header after it, so the body would
        be framed by the Content-Length a proxy in front may have read past."""
        lines = AUTH + ["Content-Length: 2", "Transfer-Encoding : chunked"]
        for name, port, reads, _ in self.kept_alive():
            for request in reads:
                with self.subTest(server=name, request=request):
                    self.assertEqual(exchange(port, wire(request, lines, b"{}")), ([400], True))

    def test_a_header_hidden_in_a_folded_line_or_after_a_bare_cr_is_refused(self):
        """Python's parser reads an obs-fold line as part of the header before it, and takes a bare CR as a line end
        (ending the headers, or starting a header mid-line), with no defect: a proxy in front that reads the line
        otherwise frames the body otherwise."""
        for shape in (["X-A: b", " Content-Length: 2"], ["X-A: b\r", "Content-Length: 2"],
                      ["X-A: b\rContent-Length: 2"]):
            for name, port, reads, _ in self.kept_alive():
                for request in reads:
                    with self.subTest(shape=shape, server=name, request=request):
                        self.assertEqual(exchange(port, wire(request, AUTH + shape, b"{}")), ([400], True))

    def test_content_length_is_ascii_digits_only(self):
        """int() takes `+2` and `1_0`; an empty value is no length, not 0."""
        for request, srv in (("POST /v1/traces", self.otlp()[0]), ("GET /__tracekit_health", self.proxy()[0])):
            port = self.start(srv)
            for value in ("+2", "1_0", ""):
                with self.subTest(request=request, value=value):
                    self.assertEqual(exchange(port, wire(request, [f"Content-Length: {value}"], b"{}")), ([400], True))

    def test_digits_int_cannot_read_are_refused_not_a_crash(self):
        """`²` passes str.isdigit(), and int() reads at most 4,300 digits: each is answered, never left unanswered."""
        run = "Proxy-Authorization: Basic " + base64.b64encode(f"run-1:{SECRET}".encode()).decode()
        slack, egress_port = self.start(self.slack()[0]), self.start(self.egress()[0])
        for port, request, lines, status in ((slack, f"POST {slack_approvals.PATH}", [], 400),
                                             (egress_port, "POST http://x.example/", [run], 411)):
            for value in ("²", "9" * 5000):
                with self.subTest(request=request, value=value[:9]):
                    self.assertEqual(exchange(port, wire(request, lines + [f"Content-Length: {value}"]))[0], [status])

    def test_a_body_cut_short_is_never_acted_on(self):
        """Fewer bytes than the Content-Length, then nothing more (the client stopped, or the deadline cut it): the part
        that came is never acted on, and nothing is answered."""
        forwarded, registered = [], []
        token = ingest.add_token(self.d, "box")
        intake = ingest.serve(self.d, "127.0.0.1", 0, forward=lambda req: forwarded.append(req) or {"ok": True})
        witness, witness_token, _ = self.witness()
        public = self.public_witness()[0]
        public.witness.register = lambda ip, req: registered.append(req) or (200, "registered\n")
        short = "Content-Length: 1000"
        for name, srv, request in (
                ("ingest", intake, wire("POST /v1/rpc", [f"Authorization: Bearer {token}", short], b'{"op": "status"}')),
                ("witness", witness,
                 wire("POST /v1/checkpoints", [f"Authorization: Bearer {witness_token}", short], b"{}")),
                ("public witness", public, wire("POST /register", [short], b"{}")),
                ("slack", self.slack()[0], wire(f"POST {slack_approvals.PATH}", [short], b"payload=%7B%7D")),
                ("otlp", self.otlp()[0], wire("POST /v1/traces", [short], b"{}"))):
            with self.subTest(server=name):
                self.assertEqual(exchange(self.start(srv), request, half_close=True), ([], True))
        self.assertEqual((forwarded, registered), ([], []))

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
                    if key == "tracekit/observe.py:Handler":   # the browser surface
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
                self.assertEqual(re.findall(r"<script[^>]*>", page.decode(), re.I), [f'<script nonce="{nonce}">'])
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
        self.port, self.key = srv.server_address[1], srv.RequestHandlerClass.session_key
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
        self.assertEqual(re.findall(r"<script[^>]*>", page.decode(), re.I), [f'<script nonce="{nonce}">'])
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
                (dict(self.good, Cookie=f"{observe.COOKIE}={_session(self.key, int(time.time()) + 60)}"), body,
                 403),   # the operator token's session
                (dict(self.good, Host="evil.example"), body, 403),
                (dict(self.good, **{"Content-Length": BIG}), b"", 413),
                (self.good, b"[1]", 400)):
            with self.subTest(headers=headers, body=data):
                self.assertEqual(self.request("POST", "/api/approvals/apr-1", headers, data)[0].status, status)
        for _ in range(10):   # refused before its body is read: the answer still arrives (no reset on close)
            self.assertEqual(self.request("POST", "/api/approvals/apr-1", {"Content-Type": "application/json"},
                                          b"x" * (512 * 1024))[0].status, 403)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.request("POST", "/api/approvals/apr-1", self.good, body)[0].status, 200)
        self.assertEqual(self.calls, ["approval_decide"])

    def test_a_body_cut_short_decides_nothing(self):
        lines = [f"{k}: {v}" for k, v in self.good.items()] + ["Content-Length: 1000"]
        self.assertEqual(exchange(self.port, wire("POST /api/approvals/apr-1", lines, b'{"decision": "approve"}'),
                                  half_close=True), ([], True))
        self.assertEqual(self.calls, [])


class PlainHttp(unittest.TestCase):
    """The CLIs that serve HTTP refuse plain HTTP beyond loopback (view, the signer's http section and the issuer have
    their own tests); ingest and the witnesses take --insecure-http for TLS terminated in front."""

    def test_plain_http_beyond_loopback_is_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for main, argv, code in ((observe.main, ["--host", "0.0.0.0", "--home", d], 1),
                                 (ingest.main, ["serve", "--experimental", "--home", d, "--host", "0.0.0.0"], 2),
                                 (witness_server.main, ["serve", "--home", d, "--host", "0.0.0.0"], 2),
                                 (public_witness_server.main, ["serve", "--home", d, "--host", "0.0.0.0"], 2),
                                 (otlp.main, ["serve", "--experimental", "--host", "0.0.0.0"], 2),
                                 (why_cli.main, ["serve", d, "--host", "0.0.0.0"], 2)):
            with self.subTest(main.__module__), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(argv), code)
                self.assertRegex(err.getvalue(), "loopback")

    def test_loopback_receivers_answer_only_a_loopback_host(self):
        """A web page can point a name it controls at 127.0.0.1; the OTLP receiver and the proxy answer only
        requests addressed to a loopback name."""
        for srv, method, path in ((otlp.serve("127.0.0.1", 0, otlp.Receiver(lambda event, attach: {})), "POST", "/nope"),
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
            # the hrefs set: the downloaded bundle's object URL, and a run link that is a fixed page plus an encoded run
            # id in the fragment, never data as a URL; location.hash is read (a run id to select), never navigated to
            self.assertNotRegex(page, r"\beval\(|new Function|\.href\s*=(?! URL\.createObjectURL\(await r\.blob\(\)\);"
                                      r"| page \+ \"#run=\" \+ encodeURIComponent\(id\);)"
                                      r"|window\.open|document\.write|\blocation\s*=|location\.(?:assign|replace)\(")
        # the run link's page is one of the viewer's own paths, never data
        self.assertIn('const page = document.querySelector(\'.nav a[href="/"]\') ? "/" : document.querySelector('
                      '\'.nav a[href="/runs"]\') ? "/runs" : null;', self.approvals)


if __name__ == "__main__":
    unittest.main()
