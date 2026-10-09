"""Frame transports: newline-delimited JSON with a line limit, per-frame identity and read timeouts
(tracekit/transport/), over a Unix socket and over loopback TCP with mutual HMAC (tcp_dev.py)."""
import io
import json
import os
import shutil
import socket
import stat
import tempfile
import threading
import unittest
from unittest import mock

from tracekit.identity import uid as uid_auth
from tracekit.identity.token import DevToken
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import read_frame, tcp_dev


def echo(identity, frame):
    if frame.get("method") == "fail":
        raise RPCError("unknown_run", "no such run")
    return {"subject": identity.subject, "method": frame.get("method")}


def start(server):
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    return server


class Client:
    def __init__(self, sock, rfile=None):
        self.sock, self.rfile = sock, rfile or sock.makefile("rb")

    def send(self, raw):
        self.sock.sendall(raw)

    def call(self, frame):
        self.send(json.dumps(frame).encode() + b"\n")
        return self.recv()

    def recv(self):
        line = self.rfile.readline()
        return json.loads(line) if line else None


class Frames(unittest.TestCase):
    def test_limit_is_one_mib(self):
        exact = b'{"a":"' + b"x" * (MAX_LINE - 8) + b'"}'
        self.assertEqual(len(exact), MAX_LINE)
        self.assertEqual(len(read_frame(io.BytesIO(exact + b"\n"))["a"]), MAX_LINE - 8)
        with self.assertRaises(RPCError) as cm:
            read_frame(io.BytesIO(b'{"a":"' + b"x" * MAX_LINE + b'"}\n'))
        self.assertEqual(cm.exception.code, "quota_exceeded")

    def test_bad_frames(self):
        for raw in (b"[1]\n", b'{"a":1,"a":2}\n', b"{nope\n", b"\xff\n"):
            with self.assertRaises(RPCError) as cm:
                read_frame(io.BytesIO(raw))
            self.assertEqual(cm.exception.code, "invalid_request", raw)

    def test_end_of_stream(self):
        self.assertIsNone(read_frame(io.BytesIO(b"")))
        self.assertIsNone(read_frame(io.BytesIO(b'{"a":1}')))   # cut mid-line


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class UnixTransport(unittest.TestCase):
    def setUp(self):
        from tracekit.transport.unix import UnixServer
        self.dir = tempfile.mkdtemp(dir="/tmp")   # short path: macOS caps socket paths at 104 bytes
        self.path = os.path.join(self.dir, "s.sock")
        self.server = start(UnixServer(self.path, echo, read_timeout=0.3))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir)

    def connect(self):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(5)
        s.connect(self.path)
        self.addCleanup(s.close)
        return Client(s)

    def test_identity_is_peer_uid_and_socket_is_private(self):
        self.assertEqual(self.connect().call({"method": "status"}), {"subject": str(os.getuid()), "method": "status"})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_identity_is_read_for_every_frame(self):
        c = self.connect()
        with mock.patch.object(uid_auth.peercred, "peer", side_effect=[(1, 1000), (1, 1001), (None, None)]):
            self.assertEqual(c.call({"method": "status"})["subject"], "1000")
            self.assertEqual(c.call({"method": "status"})["subject"], "1001")
            self.assertEqual(c.call({"method": "status"})["error"]["code"], "unauthenticated")
        self.assertIsNone(c.recv())   # closed after the failed frame

    def test_refusals_keep_the_connection(self):
        c = self.connect()
        self.assertEqual(c.call({"method": "fail"})["error"]["code"], "unknown_run")
        c.send(b"not json\n")
        self.assertEqual(c.recv()["error"]["code"], "invalid_request")
        self.assertEqual(c.call({"method": "status"})["method"], "status")

    def test_oversized_line_closes(self):
        c = self.connect()
        c.send(b"x" * (MAX_LINE + 1))
        self.assertEqual(c.recv()["error"]["code"], "quota_exceeded")
        self.assertIsNone(c.recv())

    def test_idle_connection_times_out(self):
        self.assertIsNone(self.connect().recv())


class TcpDevTransport(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.endpoint = os.path.join(self.dir, "endpoint.json")
        self.now = 1000.0
        self.token = DevToken("dev", {"status"}, ttl_s=60, clock=lambda: self.now)
        self.server = start(tcp_dev.TcpDevServer(self.endpoint, self.token, echo, read_timeout=2))
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def connect(self):
        sock, rfile = tcp_dev.connect(self.endpoint, timeout=5)
        self.addCleanup(sock.close)
        return Client(sock, rfile)

    def test_endpoint_written_after_bind(self):
        with open(self.endpoint) as f:
            ep = json.load(f)
        self.assertEqual(self.server.server_address, ("127.0.0.1", ep["port"]))
        self.assertEqual(ep["token"], self.token.secret)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.endpoint).st_mode), 0o600)

    def test_mutual_proof_then_scoped_frames(self):
        c = self.connect()
        self.assertEqual(c.call({"method": "status"}), {"subject": "dev", "method": "status"})
        self.assertEqual(c.call({"method": "decide"})["error"]["code"], "forbidden")
        self.now += 60
        self.assertEqual(c.call({"method": "status"})["error"]["code"], "unauthenticated")
        self.assertIsNone(c.recv())

    def test_client_with_wrong_proof_is_refused(self):
        s = socket.create_connection(self.server.server_address, 5)
        self.addCleanup(s.close)
        c = Client(s)
        reply = c.call({"method": "hello", "nonce": "c" * 32})
        self.assertIn("proof", reply)
        self.assertNotIn(self.token.secret, json.dumps(reply))
        self.assertEqual(c.call({"proof": "0" * 64})["error"]["code"], "unauthenticated")
        self.assertIsNone(c.recv())

    def test_frames_before_the_handshake_are_refused(self):
        s = socket.create_connection(self.server.server_address, 5)
        self.addCleanup(s.close)
        self.assertEqual(Client(s).call({"method": "status"})["error"]["code"], "unauthenticated")

    def test_port_squatter_never_sees_the_token(self):
        squatter = socket.socket()
        squatter.bind(("127.0.0.1", 0))
        squatter.listen(1)
        self.addCleanup(squatter.close)
        with open(self.endpoint) as f:
            ep = json.load(f)
        ep["port"] = squatter.getsockname()[1]
        fake = os.path.join(self.dir, "squatted.json")
        with open(fake, "w") as f:
            json.dump(ep, f)
        received = []

        def squat():
            conn, _ = squatter.accept()
            with conn:
                rfile = conn.makefile("rb")
                received.append(rfile.readline())
                conn.sendall(b'{"proof":"' + b"0" * 64 + b'","nonce":"' + b"s" * 32 + b'"}\n')
                received.append(rfile.readline())   # b"" once the client hangs up

        t = threading.Thread(target=squat)
        t.start()
        with self.assertRaises(RPCError) as cm:
            tcp_dev.connect(fake, timeout=5)
        t.join(5)
        self.assertEqual(cm.exception.code, "unauthenticated")
        self.assertEqual(received[1], b"")
        self.assertNotIn(self.token.secret.encode(), b"".join(received))
