"""Remote clients over the HTTPS transport (tracekit/identity/token.TokenStore, tracekit/transport/http.py): named
tokens that expire and can be revoked or rotated without a restart, failed-authentication limits with bounded memory,
refusals without log state, run tokens bound to the token identity, and `tracekit init --remote --v2`."""
import contextlib
import io
import json
import os
import ssl
import threading
import types
import unittest
from unittest import mock

import test_signer_service as ts
from test_identity_mtls import Pki, post, tmpdir
from tracekit import cli
from tracekit.identity.k8s_sa import K8sSaAuthenticator
from tracekit.identity.token import TokenStore, parse_ttl
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.transport import answering_hello, hello
from tracekit.transport import http as tk_http


def conn(token, addr="10.0.0.1"):
    return types.SimpleNamespace(headers={"Authorization": f"Bearer {token}"}, client_address=(addr, 1))


class TestTokenStore(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.store = TokenStore(os.path.join(tmpdir(self), "tokens.json"), clock=lambda: self.now)

    def test_expired_and_revoked_tokens_are_refused(self):
        a, b = self.store.add("a", 60, tenant="acme"), self.store.add("b", 3600)
        identity = self.store.authenticate(conn(a), {})
        self.assertEqual((identity.scheme, identity.subject, identity.claims["tenant"]), ("token", "a", "acme"))
        self.assertNotIn(a.split(".")[1], open(self.store.path).read())   # only a salted hash is stored
        self.now += 60
        self.store.revoke("b")
        for token in (a, b, a[:-1] + "x", "tk2_nobody.x"):
            with self.subTest(token), self.assertRaises(RPCError) as cm:
                self.store.authenticate(conn(token), {})
            self.assertEqual(cm.exception.code, "unauthenticated")
        self.assertIsNone(self.store.authenticate(conn("not-ours"), {}))   # left to the next authenticator

    def test_k8s_sa_first_leaves_a_token_to_the_store(self):
        k8s = K8sSaAuthenticator(audience="a", tokenreview="https://127.0.0.1:1", token_file="unused")
        srv = tk_http.HttpServer(("127.0.0.1", 0), [k8s, self.store], None, None)
        self.addCleanup(srv.server_close)
        with mock.patch.object(k8s, "_review", side_effect=AssertionError("sent to TokenReview")):
            self.assertEqual(srv.authenticate(conn(self.store.add("a", 60)), {}).subject, "a")

    def test_an_unreadable_store_is_an_error_not_a_crash(self):
        token = self.store.add("a", 60)
        for content in ('{"a": [1]}', '{"a": {"salt": "zz"}}', "[]", '{"a'):
            with open(self.store.path, "w") as f:
                f.write(content)
            with self.subTest(content), self.assertRaises(RPCError) as cm:
                self.store.authenticate(conn(token), {})
            self.assertEqual(cm.exception.code, "unavailable")

    def test_names_cannot_collide(self):
        for name in ("a:b", "token:x", "A", "", "x" * 65, "dev", "http", "a.b"):
            with self.subTest(name), self.assertRaises(ValueError):
                self.store.add(name, 60)
        self.store.add("a", 60)
        self.store.revoke("a")
        with self.assertRaises(ValueError):   # a revoked name is not reissued
            self.store.add("a", 60)

    def test_ttl(self):
        self.assertEqual([parse_ttl(t) for t in ("30d", "12h", "90m", "5s")], [2592000, 43200, 5400, 5])
        for t in ("0d", "30", "1w", "-1d", None):
            with self.subTest(t), self.assertRaises(ValueError):
                parse_ttl(t)


class TestFailedAuth(unittest.TestCase):
    def test_limited_per_address_and_bounded(self):
        failures = []
        srv = tk_http.HttpServer(("127.0.0.1", 0), [TokenStore(os.path.join(tmpdir(self), "t.json"))], None, None,
                                 on_auth_failure=lambda: failures.append(1),
                                 failed=(Limits(events_per_s=0.001, burst=3, buckets=4),
                                         Limits(events_per_s=0.001, burst=100, buckets=1)))
        self.addCleanup(srv.server_close)
        token = srv.authenticators[0].add("a", 60)
        for _ in range(3):
            with self.assertRaises(RPCError) as cm:
                srv.authenticate(conn("tk2_a.wrong"), {})
            self.assertEqual(cm.exception.code, "unauthenticated")
        with self.assertRaises(RPCError) as cm:   # past the limit even a valid token is not looked at
            srv.authenticate(conn(token), {})
        self.assertEqual(cm.exception.code, "quota_exceeded")
        self.assertEqual(srv.authenticate(conn(token, "10.0.0.2"), {}).subject, "a")
        self.assertEqual(len(failures), 3)
        for i in range(50):
            with contextlib.suppress(RPCError):
                srv.authenticate(conn("nope", f"10.1.0.{i}"), {})
        self.assertLessEqual(len(srv.failed[0]._buckets), 4)
        codes = []
        for i in range(60):   # the total limit: 53 failures so far of 100, then every failure is refused as over it
            try:
                srv.authenticate(conn("nope", f"10.2.0.{i}"), {})
            except RPCError as e:
                codes.append(e.code)
        self.assertEqual(codes, ["unauthenticated"] * 47 + ["quota_exceeded"] * 13)
        self.assertEqual(srv.authenticate(conn(token, "10.3.0.1"), {}).subject, "a")   # yet a valid token gets in


class TestRemoteSigner(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.pki = Pki(self.d)
        self.tokens = TokenStore(os.path.join(self.d, "tokens.json"))
        self.s = svc.SignerService(ts.tmpdir(self), policy=ts.PAY_ASKS, authorize={"token:*": sorted(REQUESTS)})
        self.addCleanup(self.s.close)
        cert, key = self.pki.issue("server")
        addr, auths, tls = tk_http.configure({"listen": "127.0.0.1:0", "cert": cert, "key": key,
                                              "authenticators": ["token"], "tokens": self.tokens.path})
        srv = tk_http.HttpServer(addr, auths, tls, answering_hello(self.s.handle_frame, hello()),
                                 on_auth_failure=self.s.metrics.auth_failures.inc,
                                 failed=(Limits(events_per_s=0.001, burst=2), tk_http.FAILED_TOTAL))
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.port, self.ctx = srv.server_address[1], ssl.create_default_context(cafile=self.pki.path)

    def client(self, token):
        path = os.path.join(self.d, f"token-{token[4:9]}")
        with open(path, "w") as f:
            f.write(token)
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_CA": self.pki.path, "TRACEKIT_SIGNER_TOKEN_FILE": path}):
            c = Client(f"https://127.0.0.1:{self.port}", timeout=5)
        self.addCleanup(c.close)
        return c, path

    def test_identities_cannot_write_each_others_runs(self):
        a, _ = self.client(self.tokens.add("a", 3600, tenant="acme"))
        b, _ = self.client(self.tokens.add("b", 3600, tenant="acme"))
        run = a.run("agent")
        self.assertEqual(run.registered["tenant"], "acme")
        reg = next(r["event"] for r in ts.records(self.s.data_dir) if r["event"]["type"] == "run.registered")["data"]
        self.assertEqual((reg["signer_isolation"], reg["identity"]["subject"]), ("remote", "a"))
        theirs = {"run_id": run.run_id, "run_token": run.run_token}
        for method, req in (("state_write", {**theirs, "key": "k", "value_digest": "sha256:" + "0" * 64}), ("close_run", theirs), ("read", theirs)):
            with self.subTest(method), self.assertRaises(RPCError) as cm:
                b.call(method, req)
            self.assertEqual(cm.exception.code, "run_token_invalid")
        run.close()

    def test_rotation_without_restart(self):
        c, path = self.client(self.tokens.add("v1", 3600))
        self.assertEqual(c.status()["identity"]["subject"], "v1")
        with open(path, "w") as f:   # the signer gets a new token, the client a rewritten file; neither restarts
            f.write(self.tokens.add("v2", 3600))
        self.tokens.revoke("v1")
        self.assertEqual(c.status()["identity"]["subject"], "v2")
        with open(path, "w") as f:
            f.write(f"tk2_v1.{'x' * 43}")
        with self.assertRaises(RPCError) as cm:
            c.status()
        self.assertEqual(cm.exception.code, "unauthenticated")

    def test_refusals_carry_no_log_state(self):
        a, _ = self.client(self.tokens.add("a", 3600))
        run = a.run("agent")
        frame = {"method": "read", "run_id": run.run_id, "run_token": run.run_token}
        bodies = [post(self.port, frame, self.ctx, {"Authorization": "Bearer tk2_a.wrong"}) for _ in range(3)]
        self.assertEqual([b[1]["error"]["code"] for b in bodies], ["unauthenticated", "unauthenticated", "quota_exceeded"])
        self.assertEqual(next(self.s.metrics.auth_failures.samples())[-1], 2)
        for status, body in bodies:
            self.assertEqual((status, set(body), set(body["error"]) - {"retry_after_ms"}), (200, {"error"},
                                                                                        {"code", "message"}))
            for leak in (run.run_id, '"seq"', "sha256:", "hash"):
                self.assertNotIn(leak, json.dumps(body))


class TestCli(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        pki = Pki(self.d)
        cert, key = pki.issue("server")
        self.cfg = os.path.join(self.d, "signer.yaml")
        with open(self.cfg, "w") as f:
            f.write(f"data_dir: data\nhttp:\n  listen: 0.0.0.0:8443\n  cert: {os.path.basename(cert)}\n"
                    f"  key: {os.path.basename(key)}\n  authenticators: [token]\n  tokens: tokens.json\n")

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = svc.main(["token", *argv, "--config", self.cfg])
        return code, out.getvalue(), err.getvalue()

    def test_token_add_list_revoke(self):
        code, token, _ = self.run_cli("add", "ci-1", "--ttl", "1d", "--tenant", "acme")
        self.assertEqual(code, 0)
        self.assertTrue(token.startswith("tk2_ci-1."))
        self.assertEqual(self.run_cli("add", "ci:1")[0], 2)
        self.assertEqual(self.run_cli("revoke", "ci-1")[0], 0)
        code, listed, _ = self.run_cli("list")
        [entry] = json.loads(listed)
        self.assertEqual((entry["name"], entry["tenant"], entry["expires"] - entry["created"]), ("ci-1", "acme", 86400))
        self.assertIsNotNone(entry["revoked"])
        self.assertNotIn(token.split(".")[1].strip(), listed)

    def test_init_remote_v2_wires_the_hooks(self):
        token = os.path.join(self.d, "token")
        with open(token, "w") as f:
            f.write("tk2_a.secret")
        cwd = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, cwd)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["init", "--remote", "https://signer.example:8443", "--v2", "--token-file", token,
                                       "--ca", token, "--project"]), 0)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["init", "--remote", "http://127.0.0.1:8443", "--v2", "--token-file", token,
                                           "--project"]), 2)
        with open(os.path.join(self.d, ".claude", "settings.json")) as f:
            env = json.load(f)["env"]
        self.assertEqual(env, {"TRACEKIT_SIGNER": "https://signer.example:8443", "TRACEKIT_SIGNER_TOKEN_FILE": token,
                               "TRACEKIT_SIGNER_CA": token})


if __name__ == "__main__":
    unittest.main()
