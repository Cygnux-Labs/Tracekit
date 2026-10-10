"""Network services that face other machines (the ingest gateway): a client that connects and says nothing
must not stall anyone else, over TLS or not.  python3 -m pytest tests/test_netserver.py -q"""
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
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from tracekit import ingest, netserver  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
