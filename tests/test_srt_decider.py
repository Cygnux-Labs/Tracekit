"""srt-proxy's request decider (tracekit/srt_decider.py): a stand-in for srt-proxy speaks the decider protocol as
sandbox-runtime's src/sandbox/decider-client.ts does (626a596, protocol version 1) and checks every frame the decider
sends against that file's schemas; the decider decides through a real signer, in this process for the policy cases and
the same-user dev signer for the command."""
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

from adapter_contract import _serve, tmpdir
from tracekit import srt_decider
from tracekit.bundle_v2 import export
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer.service import SignerService
from tracekit.verify import v2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = {"tools": {"srt:request": "http"},
          "deny": [{"id": "NO-PASTE", "class": "http", "field": "host", "pattern": "^paste\\.example$"}],
          "ask": [{"id": "ASK-WRITE", "class": "http", "field": "method", "pattern": "^(POST|PUT)$"}]}
MAX_BODY = 32 << 20


def frame(msg):
    """encodeFrame (decider-client.ts:570): a 4-byte big-endian length, then JSON.stringify's bytes."""
    body = json.dumps(msg, separators=(",", ":")).encode()
    return struct.pack(">I", len(body)) + body


def unique_keys(pairs):
    keys = [k for k, _ in pairs]
    assert len(keys) == len(set(keys)), f"duplicate key in {keys}"   # parseStrictJson (decider-client.ts:770)
    return dict(pairs)


def checked(v):
    """A verdict as decider-client.ts's allowSchema, denySchema and needBodySchema (:164-221) take it, else raises."""
    assert v["t"] == "verdict" and isinstance(v["id"], int) and v["id"] >= 1, v
    if v["action"] == "allow":
        assert set(v) <= {"t", "id", "action", "setHeaders", "removeHeaders", "cred", "credential"}, v
    elif v["action"] == "deny":
        assert set(v) <= {"t", "id", "action", "status", "reason"} and 400 <= v["status"] <= 599, v
        r = v.get("reason")
        assert r is None or 1 <= len(r.encode()) <= 1024 and not any(
            (ord(c) < 0x20 and c != "\t") or 0x7f <= ord(c) <= 0x9f for c in r), v
    else:
        assert v["action"] == "need_body" and set(v) == {"t", "id", "action", "max"} and 1 <= v["max"] <= MAX_BODY, v
    return v


class Proxy:
    """srt-proxy's end of the decider stream: it speaks first, numbers requests from 1 (strictly increasing), sends
    each request's fields as reqFrameFields does (decider-client.ts:632: optional fields left out, never empty) and a
    body frame (encodeBodyFrame, :582) only after need_body."""

    def __init__(self, sock):
        self.sock, self.rfile, self.last = sock, sock.makefile("rb"), 0

    def recv(self):
        n = struct.unpack(">I", self.rfile.read(4))[0]
        assert n <= 1 << 20, n   # MAX_READ_FRAME
        return json.loads(self.rfile.read(n), object_pairs_hook=unique_keys)

    def hello(self):
        self.sock.sendall(frame({"t": "hello", "proto": 1}))
        h = self.recv()
        assert set(h) == {"t", "proto", "allowedDomains", "deniedDomains"}, h   # helloSchema (:155), strict
        assert all(len(set(x)) == len(x) for x in (h["allowedDomains"], h["deniedDomains"])), h
        return h

    def request(self, method, host, port=443, path="/", query=None, headers=None, body=b"", tls=True):
        self.last += 1
        rid = self.last
        req = {"t": "req", "id": rid, "method": method, "host": host, "port": port, "hostHeader": host,
               **({"sni": host} if tls else {}), "path": path, **({"query": query} if query else {}),
               **({"headers": headers} if headers else {})}
        self.sock.sendall(frame(req))
        v = checked(self.recv())
        assert v["id"] == rid, v
        if v["action"] == "need_body":
            assert method not in ("GET", "HEAD", "OPTIONS"), v   # the proxy would refuse it: bodyless_method_body
            data = base64.b64encode(body[:v["max"]]).decode()
            self.sock.sendall(frame({"t": "body", "id": rid, "data": data, **({"cut": True} if len(body) > v["max"]
                                                                                else {})}))
            v = checked(self.recv())
            assert v["id"] == rid and v["action"] != "need_body", v
        return v


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "srt-proxy takes the decider as an inherited socket (Linux, macOS)")
class Deciding(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.s = SignerService(self.dir, policy=Engine(POLICY), grace_s=0)
        self.addCleanup(self.s.close)
        self.path = _serve(self, self.s.handle_frame)
        self.run = Client(self.path).run("srt-proxy")
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        theirs.settimeout(30)
        self.decider = srt_decider.Decider(ours, self.run, ["api.example.com", "paste.example", "api.example.com"])
        threading.Thread(target=self.decider.serve, daemon=True).start()
        self.proxy = Proxy(theirs)
        self.assertEqual(self.proxy.hello(), {"t": "hello", "proto": 1, "deniedDomains": [],
                                              "allowedDomains": ["api.example.com", "paste.example"]})

    def events(self):
        return [r["event"] for r in self.s.log.storage.iter_run("default", self.run.run_id)]

    def approval(self, verdict):
        self.assertEqual(verdict["status"], 403, verdict)
        self.assertIn("held for a person's approval", verdict["reason"])
        return verdict["reason"].split("(", 1)[1].split(")", 1)[0]

    def test_allowed_request_is_forwarded_recorded_and_verifies(self):
        # a GET announcing a body is decided without it: the proxy refuses need_body for one
        v = self.proxy.request("GET", "api.example.com", path="/v1/things", query="limit=10",
                               headers={"accept": ["*/*"], "content-length": ["5"]})
        self.assertEqual(v, {"t": "verdict", "id": 1, "action": "allow"})
        types = [(e["type"], e["data"].get("tool"), e["data"].get("decision")) for e in self.events()]
        self.assertIn(("policy.decision", "srt:request", "allow"), types)
        self.assertIn("tool.result", [t for t, *_ in types])
        self.run.close()
        self.s.sweep(time.monotonic() + 1)
        self.s.checkpoint()
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", self.run.run_id, self.s.log.storage.checkpoint_latest()[1], bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual(code, 0, [c for c in rep.checks if c["status"] != "ok"])
        self.assertNotIn("decided_not_completed", json.dumps(rep.checks))

    def test_denied_host_is_refused_naming_the_rule(self):
        v = self.proxy.request("GET", "paste.example", path="/x")
        self.assertEqual((v["action"], v["status"]), ("deny", 403))
        self.assertIn("NO-PASTE", v["reason"])
        self.assertIn(("policy.decision", "deny"), [(e["type"], e["data"].get("decision")) for e in self.events()])

    def test_ask_holds_the_exact_request_and_its_approval_allows_it_once(self):
        body, headers = b'{"title": "hi"}', {"content-type": ["application/json"], "content-length": ["15"]}

        def post(data=body):
            return self.proxy.request("POST", "api.example.com", port=8443, path="/v1/issues", query="x=1",
                                      headers=headers, body=data)
        aid = self.approval(post())
        got = Client(self.path).call("approval_get", {"approval_id": aid})
        self.assertEqual(json.loads(got["args"]) if isinstance(got["args"], str) else got["args"],
                         {"method": "POST", "url": "https://api.example.com:8443/v1/issues?x=1",
                          "body": "sha256:" + hashlib.sha256(body).hexdigest()})
        self.assertEqual(self.approval(post()), aid)   # waiting: the same approval, not a new one
        Client(self.path).call("approval_decide", {"approval_id": aid, "decision": "approve"})
        self.assertNotEqual(self.approval(post(b'{"title": "other"}')), aid)   # another body: asked on its own
        self.assertEqual(post()["action"], "allow")
        self.assertNotEqual(self.approval(post()), aid)   # used once: the next one asks again

    def test_plain_http_url_and_rejected_approval(self):
        v = self.proxy.request("PUT", "api.example.com", port=80, path="/a", headers={"transfer-encoding": ["chunked"]},
                               body=b"x", tls=False)
        aid = self.approval(v)
        self.assertEqual(Client(self.path).call("approval_get", {"approval_id": aid})["tool"], "srt:request")
        Client(self.path).call("approval_decide", {"approval_id": aid, "decision": "reject"})
        v = self.proxy.request("PUT", "api.example.com", port=80, path="/a", headers={"transfer-encoding": ["chunked"]},
                               body=b"x", tls=False)
        self.assertEqual(v["reason"], f"Tracekit: approval {aid} was rejected")

    def test_body_over_the_limit_is_refused(self):
        with mock.patch.object(srt_decider, "MAX_BODY", 4):
            v = self.proxy.request("POST", "api.example.com", headers={"content-length": ["10"]}, body=b"0123456789")
        self.assertEqual((v["action"], v["status"]), ("deny", 413))

    def test_unreachable_signer_denies_whatever_the_fail_mode(self):
        self.run.registered["fail_modes"] = {"default": "open"}
        self.run.client = Client(os.path.join(self.dir, "gone.sock"))
        with self.assertWarns(UserWarning):
            v = self.proxy.request("GET", "api.example.com")
        self.assertEqual((v["action"], v["status"]), ("deny", 503))
        self.assertIn("signer unavailable", v["reason"])

    def test_a_run_the_signer_closed_stops_the_proxy(self):
        self.run.close()   # as the signer does after idle_s without a call
        v = self.proxy.request("GET", "api.example.com")
        self.assertEqual((v["action"], v["status"]), ("deny", 403))
        self.assertIn("run_closed", v["reason"])
        self.assertEqual(self.proxy.rfile.read(1), b"")   # the decider's stream ended: srt-proxy exits

    def upload(self, path="/upload"):
        """Send a PUT with a body, as srt-proxy does before it reads the body: its id."""
        p = self.proxy
        p.last += 1
        p.sock.sendall(frame({"t": "req", "id": p.last, "method": "PUT", "host": "api.example.com", "port": 443,
                              "sni": "api.example.com", "path": path, "headers": {"content-length": ["1"]}}))
        return p.last

    def test_bodies_still_coming_hold_no_worker(self):
        uploads = [self.upload() for _ in range(srt_decider.WORKERS + 1)]   # bodies srt-proxy reads from slow clients
        self.assertEqual(sorted(checked(self.proxy.recv())["id"] for _ in uploads), uploads)   # need_body, each
        t = time.monotonic()
        self.assertEqual(self.proxy.request("GET", "api.example.com")["action"], "allow")
        self.assertLess(time.monotonic() - t, 2)   # within srt-proxy's 5 s wait for a verdict
        self.proxy.sock.sendall(frame({"t": "body", "id": uploads[0], "data": base64.b64encode(b"x").decode()}))
        v = checked(self.proxy.recv())
        self.assertEqual(v["id"], uploads[0])
        self.assertIn("held for a person's approval", v["reason"])   # decided once its body came

    def test_a_body_that_never_comes_is_refused_at_the_next_frame(self):
        with mock.patch.object(srt_decider, "BODY_WAIT_S", 0):
            rid = self.upload()
            self.assertEqual(checked(self.proxy.recv())["action"], "need_body")
            self.proxy.sock.sendall(frame({"t": "req", "id": rid + 1, "method": "GET", "host": "api.example.com",
                                           "port": 443, "sni": "api.example.com", "path": "/"}))
            self.proxy.last += 1
            late, get = checked(self.proxy.recv()), checked(self.proxy.recv())
        self.assertEqual((late["id"], late["status"], late["reason"]),
                         (rid, 408, "Tracekit: the request's body did not arrive"))
        self.assertEqual((get["id"], get["action"]), (rid + 1, "allow"))

    def test_reason_fits_what_the_proxy_takes(self):
        self.assertEqual(srt_decider.deny(403, "a\nb\x85c" + "é" * 600)["reason"], "a b c" + "é" * 509)


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "srt-proxy takes the decider as an inherited socket (Linux, macOS)")
class ProtocolVersion(unittest.TestCase):
    def test_another_version_is_not_answered(self):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        theirs.sendall(frame({"t": "hello", "proto": 2}))
        with self.assertRaisesRegex(ValueError, "not decider protocol version 1"):
            srt_decider.Decider(ours, None, ["api.example.com"]).serve()
        theirs.setblocking(False)
        with self.assertRaises(BlockingIOError):
            theirs.recv(1)


FAKE_PROXY = textwrap.dedent("""
    import json, os, socket, struct, sys
    sys.path.insert(0, {tests!r})
    from test_srt_decider import Proxy
    argv = sys.argv[1:]
    sock = socket.socket(fileno=int(argv[argv.index("--decider-fd") + 1]))
    with os.fdopen(int(argv[argv.index("--ca-fd") + 1])) as ca:
        print(ca.read(), flush=True)
    p = Proxy(sock)
    p.hello()
    print(json.dumps(p.request("GET", "api.example.com", path="/v1")), flush=True)
    sys.exit(7)
""")


@unittest.skipUnless(os.name == "posix", "inherited descriptors and the same-user dev signer's Unix socket")
class Command(unittest.TestCase):
    """`tracekit srt-decider -- <srt-proxy>` against the same-user dev signer (its default policy)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir="/tmp")   # macOS caps socket paths
        self.addCleanup(shutil.rmtree, self.dir, True)
        home = os.path.join(self.dir, "home")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("TRACEKIT_")}
        self.env.update(HOME=home, XDG_DATA_HOME=os.path.join(home, "data"), PYTHONPATH=ROOT,
                        TRACEKIT_RUNTIME_DIR=os.path.join(self.dir, "run"), TRACEKIT_DEV_IDLE="60",
                        TRACEKIT_DEV_GRACE="0.2")
        self.addCleanup(self.tracekit, "down")
        self.proxy = os.path.join(self.dir, "srt-proxy.py")
        with open(self.proxy, "w") as f:
            f.write(FAKE_PROXY.format(tests=os.path.dirname(os.path.abspath(__file__))))

    def tracekit(self, *argv, pass_fds=()):
        return subprocess.run([sys.executable, "-m", "tracekit", *argv], env=self.env, cwd=self.dir, text=True,
                              capture_output=True, timeout=120, pass_fds=pass_fds)

    def test_runs_srt_proxy_with_its_descriptors_and_records_the_run(self):
        r, w = os.pipe()
        os.write(w, b"-----BEGIN CERTIFICATE-----")
        os.close(w)
        self.addCleanup(os.close, r)
        p = self.tracekit("srt-decider", "--allow-domain", "api.example.com", "--", sys.executable, self.proxy,
                          "--listen", "127.0.0.1:0", "--ca-fd", str(r), pass_fds=(r,))
        self.assertEqual(p.returncode, 7, p.stderr)   # srt-proxy's exit code
        ca, verdict = p.stdout.splitlines()
        self.assertEqual((ca, json.loads(verdict)), ("-----BEGIN CERTIFICATE-----",
                                                     {"t": "verdict", "id": 1, "action": "allow"}))
        self.assertIn("the srt-proxy decider is experimental", p.stderr)
        last = self.tracekit("last")
        self.assertEqual(last.returncode, 0, last.stderr)
        self.assertIn("(srt-proxy)", last.stdout)
        self.assertIn("Integrity: VERIFIED.", last.stdout)

    def test_no_signer_no_srt_proxy(self):
        marker = os.path.join(self.dir, "started")
        self.env["TRACEKIT_SIGNER"] = os.path.join(self.dir, "gone.sock")
        p = self.tracekit("srt-decider", "--allow-domain", "api.example.com", "--", sys.executable, "-c",
                          f"open({marker!r}, 'w')")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("srt-proxy is not started", p.stderr)
        self.assertFalse(os.path.exists(marker))


if __name__ == "__main__":
    unittest.main()
