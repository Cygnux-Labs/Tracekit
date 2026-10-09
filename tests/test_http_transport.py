"""The signer over HTTPS (tracekit/transport/http.py, sdk/client.py https://): config checks, body size and read
timeouts, per-op authorization, and the cross-tenant matrix (E12 core) for k8s_sa and mtls identities."""
import http.client
import os
import socket
import ssl
import time
import unittest
from unittest import mock

import test_signer_service as ts
from cryptography import x509
from test_identity_k8s import AUD, Jwks, claims, jwt
from test_identity_mtls import Pki, echo, post, serve, tmpdir
from tracekit.identity.base import CallerIdentity
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.transport import answering_hello, hello
from tracekit.transport import http as tk_http


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.pki = Pki(self.d)
        self.cert, self.key = self.pki.issue("server")

    def test_tls_required_except_explicit_insecure_loopback(self):
        tk_http.configure({"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                           "token_file": self.secret()})
        for cfg in ({"listen": "0.0.0.0:8443", "insecure_loopback": True},
                    {"listen": "127.0.0.1:8443"},
                    {"listen": "127.0.0.1:8443", "insecure_loopback": True, "cert": self.cert},
                    {"listen": "127.0.0.1:8443", "insecure_loopback": True, "authenticators": ["mtls"]},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["mtls"]},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["oidc"]},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["k8s_sa"],
                     "k8s_sa": {"audience": AUD, "jwks_uri": "https://x", "issuer": "i", "extra": 1}},
                    {"listen": "127.0.0.1:8443", "cert": self.cert, "key": self.key, "authenticators": ["token"],
                     "colour": "blue"}):
            with self.subTest(cfg), self.assertRaises(ValueError):
                tk_http.configure({"authenticators": ["token"], "token_file": self.secret(), **cfg})

    def secret(self):
        path = os.path.join(self.d, "bearer")
        with open(path, "w") as f:
            f.write("s" * 40)
        return path

    def test_load_config_resolves_paths_and_refuses_unknown_keys(self):
        path = os.path.join(self.d, "signer.yaml")
        with open(path, "w") as f:
            f.write(f"data_dir: data\nhttp:\n  listen: 127.0.0.1:8443\n  cert: {os.path.basename(self.cert)}\n"
                    f"  key: {os.path.basename(self.key)}\n  authenticators: [token]\n  token_file: bearer\n")
        self.secret()
        self.assertEqual(svc.load_config(path)["http"]["cert"], self.cert)
        with open(path, "a") as f:
            f.write("  port: 1\n")
        with self.assertRaises(ValueError):
            svc.load_config(path)


class TestLimits(unittest.TestCase):
    def setUp(self):
        d = tmpdir(self)
        self.pki = Pki(d)
        cert, key = self.pki.issue("server")
        token = os.path.join(d, "bearer")
        with open(token, "w") as f:
            f.write("t" * 40)
        self.port = serve(self, {"cert": cert, "key": key, "authenticators": ["token"], "token_file": token}, echo,
                          read_timeout=0.3)
        self.ctx = ssl.create_default_context(cafile=self.pki.path)

    def tls(self):
        s = self.ctx.wrap_socket(socket.create_connection(("127.0.0.1", self.port), 5), server_hostname="127.0.0.1")
        self.addCleanup(s.close)
        return s

    @staticmethod
    def response(sock):
        r = http.client.HTTPResponse(sock)
        r.begin()
        return r

    def test_bearer_token_and_keep_alive(self):
        s = self.tls()
        for _ in range(2):   # two requests on one connection
            s.sendall(b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + b"t" * 40 +
                      b"\r\nContent-Length: 17\r\n\r\n{\"method\":\"ping\"}")
            self.assertEqual(self.response(s).read(), b'{"scheme":"token","subject":"http"}')
        self.assertEqual(post(self.port, {"method": "x"}, self.ctx, {"Authorization": "Bearer wrong"})[1]["error"]["code"],
                         "unauthenticated")

    def test_oversize_body_is_refused(self):
        s = self.tls()
        s.sendall(b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % (MAX_LINE + 1))
        r = self.response(s)
        self.assertEqual(r.status, 413)
        self.assertIn(b"quota_exceeded", r.read())

    def test_slow_client_is_cut_off(self):
        for partial in (b"POST /v2/rpc HTTP/1.1\r\nHost: x\r\n", b"POST /v2/rpc HTTP/1.1\r\nContent-Length: 50\r\n\r\n{"):
            s = self.tls()
            s.sendall(partial)
            t = time.monotonic()
            self.assertEqual(s.recv(65536), b"")   # closed by the server after its read timeout
            self.assertLess(time.monotonic() - t, 3)


class TestAuthorization(unittest.TestCase):
    def setUp(self):
        self.s = svc.SignerService(ts.tmpdir(self), policy=ts.PAY_ASKS, authorize={
            "mtls:spiffe://example.org/a": ["status"], "k8s_sa:system:serviceaccount:acme:*": ["status", "register_run"]})
        self.addCleanup(self.s.close)

    def forbidden(self, identity, method, req):
        with self.assertRaises(RPCError) as cm:
            self.s.call(identity, method, req)
        self.assertEqual(cm.exception.code, "forbidden")

    def test_unconfigured_methods_and_identities_are_denied(self):
        a = CallerIdentity("mtls", "spiffe://example.org/a", True)
        self.s.call(a, "status", {})
        self.forbidden(a, "register_run", {"request_id": "r", "agent": {"name": "x"}})
        self.forbidden(CallerIdentity("mtls", "spiffe://example.org/b", True), "status", {})
        sa = CallerIdentity("k8s_sa", "system:serviceaccount:acme:agent", True)
        self.s.call(sa, "register_run", {"request_id": "r", "agent": {"name": "x"}})
        self.forbidden(sa, "close_run", {"request_id": "r2", "run_id": "x", "run_token": "x.y"})
        self.forbidden(CallerIdentity("token", "http", True), "status", {})
        self.s.call(ts.OTHER, "status", {})   # a uid keeps every method

    def test_tenant_map_takes_prefixes(self):
        self.s.tenants.update({"k8s_sa:system:serviceaccount:acme:*": "acme", "k8s_sa:system:serviceaccount:acme:x*": "x"})
        reg = self.s.call(CallerIdentity("k8s_sa", "system:serviceaccount:acme:agent", True), "register_run",
                          {"request_id": "r", "agent": {"name": "x"}})
        self.assertEqual((reg["tenant"], reg["tenant_attested"]), ("acme", True))
        self.assertEqual(svc.lookup(self.s.tenants, "k8s_sa:system:serviceaccount:acme:xy"), "x")   # longest prefix
        self.assertIsNone(svc.lookup(self.s.tenants, "k8s_sa:system:serviceaccount:acmex:a"))


class TestCrossTenant(unittest.TestCase):
    """E12 core: an identity of tenant b cannot read, approve, list, complete or close tenant a's runs or approvals."""

    def setUp(self):
        d = tmpdir(self)
        self.pki = Pki(d)
        self.jwks = Jwks(self, self.pki)
        all_methods = sorted(REQUESTS)
        self.s = svc.SignerService(ts.tmpdir(self), policy=ts.PAY_ASKS, tenants={
            "k8s_sa:system:serviceaccount:a:*": "a", "k8s_sa:system:serviceaccount:b:*": "b",
            "mtls:spiffe://example.org/a/*": "a", "mtls:spiffe://example.org/b/*": "b"},
            authorize={"k8s_sa:system:serviceaccount:*": all_methods, "mtls:spiffe://example.org/*": all_methods})
        self.addCleanup(self.s.close)
        cert, key = self.pki.issue("server")
        port = serve(self, {"cert": cert, "key": key, "client_ca": self.pki.path, "authenticators": ["k8s_sa", "mtls"],
                            "k8s_sa": self.jwks.config(self.pki)}, answering_hello(self.s.handle_frame, hello()))
        self.url, self.d = f"https://127.0.0.1:{port}", d

    def client(self, scheme, tenant):
        env = {"TRACEKIT_SIGNER_CA": self.pki.path}
        if scheme == "k8s_sa":
            env["TRACEKIT_SIGNER_TOKEN_FILE"] = path = os.path.join(self.d, f"token-{tenant}")
            with open(path, "w") as f:
                f.write(jwt(self.jwks.ec, claims(sub=f"system:serviceaccount:{tenant}:agent")))
        else:
            env["TRACEKIT_SIGNER_CERT"], env["TRACEKIT_SIGNER_KEY"] = self.pki.issue(
                f"client-{tenant}", [x509.UniformResourceIdentifier(f"spiffe://example.org/{tenant}/agent")])
        with mock.patch.dict(os.environ, env):
            c = Client(self.url, timeout=5)
        self.addCleanup(c.close)
        return c

    def test_matrix(self):
        for scheme in ("k8s_sa", "mtls"):
            with self.subTest(scheme):
                a, b = self.client(scheme, "a"), self.client(scheme, "b")
                run = a.run("agent")
                self.assertEqual((run.registered["tenant"], run.registered["tenant_attested"]), ("a", True))
                self.assertEqual(b.status()["identity"]["scheme"], scheme)
                d = run.decide("tc-1", "pay", {"amount": 5})
                self.assertEqual(d["decision"], "ask")
                aid = run.call("approval_request", tool_call_id="tc-1")["approval_id"]
                self.assertIn(aid, [x["approval_id"] for x in a.approval_list()["approvals"]])
                theirs = {"run_id": run.run_id, "run_token": run.run_token}
                for code, method, req in [
                        ("run_token_invalid", "read", theirs),
                        ("run_token_invalid", "complete", {**theirs, "tool_call_id": "tc-1", "status": "ok",
                                                           "decision_id": d["decision_id"],
                                                           "args_digest": "sha256:" + "0" * 64}),
                        ("run_token_invalid", "close_run", theirs),
                        ("run_token_invalid", "approval_wait", {**theirs, "approval_id": aid}),
                        ("unknown_approval", "approval_get", {"approval_id": aid}),
                        ("unknown_approval", "approval_decide", {"approval_id": aid, "decision": "approve"})]:
                    with self.assertRaises(RPCError, msg=method) as cm:
                        b.call(method, req)
                    self.assertEqual(cm.exception.code, code, method)
                self.assertEqual(b.approval_list()["approvals"], [])
                self.assertEqual(a.approval_get({"approval_id": aid})["state"], "requested")
                run.close()


if __name__ == "__main__":
    unittest.main()
