"""Network services (tracekit/netserver.py: the ingest gateway, the signer's HTTPS transport, the viewer, metrics, the
Slack bridge): a client that connects and says nothing, or sends a byte at a time, must not stall anyone else, over TLS
or not.  python3 -m pytest tests/test_netserver.py -q"""
import datetime
import http.client
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from tracekit import ingest, netserver, slack_approvals, view  # noqa: E402
from tracekit.identity.token import BearerToken  # noqa: E402
from tracekit.signer import metrics  # noqa: E402
from tracekit.transport import http as tk_http  # noqa: E402


def self_signed(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    return ctx


class RefusedBody(unittest.TestCase):
    def test_a_refused_post_with_an_unread_body_still_gets_its_answer(self):
        """A handler that answers without reading the body (an auth failure) must not reset the connection under the
        client before it reads the answer (Windows resets it always; others when the body is still arriving)."""
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(403)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"no")

            def log_message(self, *a):
                pass
        srv = netserver.Server(("127.0.0.1", 0), Handler)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        for _ in range(20):
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            try:
                c.request("POST", "/", body=b"x" * (512 * 1024))
                r = c.getresponse()
                self.assertEqual((r.status, r.read()), (403, b"no"))
            finally:
                c.close()


class SilentClient(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ctx = self_signed(self.d)
        self.servers, self.socks = [], []

    def tearDown(self):
        for s in self.socks:
            s.close()
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()
        shutil.rmtree(self.d, ignore_errors=True)

    def start(self, srv):
        self.servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv.server_address[1]

    def silent(self, port):
        s = socket.create_connection(("127.0.0.1", port))
        self.socks.append(s)
        time.sleep(0.2)  # the server has accepted it and is waiting for a handshake that never comes

    def request(self, port, method="POST", path="/v1/rpc", tls=True):   # unauthenticated: 401
        c = (http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=ssl._create_unverified_context()) if tls
             else http.client.HTTPConnection("127.0.0.1", port, timeout=3))
        try:
            c.request(method, path)
            return c.getresponse().status
        finally:
            c.close()

    def test_ingest_gateway_serves_a_second_client_while_one_is_silent(self):
        port = self.start(ingest.serve(self.d, "127.0.0.1", 0, self.ctx, forward=lambda req: {"ok": True}))
        self.silent(port)
        self.assertEqual(self.request(port), 401)

    def test_silent_plain_http_client_times_out_and_threads_are_bounded(self):
        srv = netserver.Server(("127.0.0.1", 0), self.handler(), timeout=1.5, max_threads=1)
        port = self.start(srv)
        self.silent(port)  # holds the only handler slot
        over = socket.create_connection(("127.0.0.1", port))
        self.socks.append(over)
        over.settimeout(3)
        t0 = time.monotonic()
        self.assertEqual(over.recv(1), b"", "a connection over the thread limit is closed after a short wait")
        self.assertLess(time.monotonic() - t0, 1.4)
        self.socks[0].settimeout(3)
        self.assertEqual(self.socks[0].recv(1), b"", "the silent connection is closed when its read times out")
        self.assertEqual(self.request(port, tls=False), 401)

    def handler(self):
        return ingest.make_handler(self.d, forward=lambda req: {"ok": True})

    def test_dripping_clients_do_not_block_a_request(self):
        self.drip_then_request(tls=False)

    def test_dripping_tls_clients_do_not_block_a_request(self):
        self.drip_then_request(tls=True)

    def drip_then_request(self, tls):
        srv = netserver.Server(("127.0.0.1", 0), self.handler(), self.ctx if tls else None, timeout=0.3, max_threads=3,
                               deadline=1.0)
        port = self.start(srv)
        stop = threading.Event()
        self.addCleanup(stop.set)

        def drip():  # one byte just inside every read timeout, a request line that never ends
            s = socket.create_connection(("127.0.0.1", port))
            if tls:  # the deadline must hold after the handshake too
                s = ssl._create_unverified_context().wrap_socket(s)
            self.socks.append(s)
            try:
                while not stop.wait(0.15):
                    s.sendall(b"G")
            except OSError:
                pass
        for _ in range(3):
            threading.Thread(target=drip, daemon=True).start()
        time.sleep(0.4)  # every handler slot is held by a dripping client
        self.assertEqual(self.request(port, tls=tls), 401)

    def test_connections_per_ip_are_capped(self):
        port = self.start(netserver.Server(("127.0.0.1", 0), self.handler(), timeout=3, max_per_ip=1))
        self.silent(port)
        over = socket.create_connection(("127.0.0.1", port))
        self.socks.append(over)
        over.settimeout(0.5)
        self.assertEqual(over.recv(1), b"", "a second connection from the same IP is closed at once")

    def drip(self, port, data=b"G"):
        """A client sending one byte every 0.1 s, a request that never ends: closed by the server's deadline."""
        s = socket.create_connection(("127.0.0.1", port))
        self.socks.append(s)
        s.settimeout(0.1)
        t0 = time.monotonic()
        while time.monotonic() - t0 < 3:
            try:
                s.sendall(data)
                if s.recv(1) == b"":
                    return
            except socket.timeout:
                continue
            except OSError:
                return
        self.fail("a dripping client was not cut off")

    def test_signer_https_cuts_a_dripping_client_and_an_idle_connection(self):
        srv = tk_http.HttpServer(("127.0.0.1", 0), [BearerToken(self.bearer())], None,
                                 lambda identity, frame: time.sleep(0.4) or {"ok": True}, read_timeout=3)
        srv.deadline = 0.2
        port = self.start(srv)
        self.drip(port)
        s = socket.create_connection(("127.0.0.1", port))
        self.socks.append(s)
        for _ in range(2):   # answering (an approval_wait) is not under the deadline; keep-alive still works
            s.sendall(b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + b"t" * 40 +
                      b"\r\nContent-Length: 17\r\n\r\n{\"method\":\"ping\"}")
            r = http.client.HTTPResponse(s)
            r.begin()
            self.assertEqual(r.read(), b'{"ok":true}')
        s.settimeout(2)
        t0 = time.monotonic()
        self.assertEqual(s.recv(1), b"", "an idle kept-alive connection is closed at the deadline")
        self.assertLess(time.monotonic() - t0, 1.5)

    def bearer(self):
        path = os.path.join(self.d, "bearer")
        with open(path, "w") as f:
            f.write("t" * 40)
        return path

    def test_viewer_cuts_a_dripping_client_but_not_its_event_stream(self):
        feed = types.SimpleNamespace(records=[], base=0, lock=threading.Condition(), verify=lambda: (0, [], None))
        srv = view.server(feed, "127.0.0.1", 0, "tok")
        srv.deadline = 0.3
        port = self.start(srv)
        self.drip(port)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/api/stream?from=0", headers={"Authorization": "Bearer tok"})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        time.sleep(0.5)   # past the deadline
        with feed.lock:
            feed.records.append({"tool_name": "late"})
            feed.lock.notify_all()
        self.assertIn(b"late", r.fp.readline())
        c.close()

    def test_metrics_closes_a_silent_client(self):
        srv = metrics.server({"listen": "127.0.0.1:0"}, metrics.SignerMetrics())
        srv.conn_timeout = 0.3
        port = self.start(srv)
        self.silent(port)
        self.socks[0].settimeout(2)
        self.assertEqual(self.socks[0].recv(1), b"")

    def test_slack_bridge_serves_a_second_client_while_one_is_silent(self):
        signer = types.SimpleNamespace(approval_list=lambda q: {"approvals": [], "next_cursor": None})
        srv, _ = slack_approvals.serve({"channel": "C1", "signing_secret": b"s" * 32, "bot_token": "x",
                                        "listen": "127.0.0.1:0", "poll_s": 3600, "api_url": "https://127.0.0.1:1",
                                        "tls": {"cert": os.path.join(self.d, "c.pem"),
                                                "key": os.path.join(self.d, "k.pem")}}, signer)
        self.servers.append(srv)
        port = srv.server_address[1]
        self.silent(port)
        self.assertEqual(self.request(port, path=slack_approvals.PATH), 401)


if __name__ == "__main__":
    unittest.main()
