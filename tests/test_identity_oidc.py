"""OIDC identities (tracekit/identity/oidc.py): an in-test provider (discovery, JWKS, token endpoint over HTTPS on
loopback, keys made here) for token validation and key rotation, approvals and attested principals over the signer's
HTTPS transport, and the viewer's login (tracekit/view.py:OidcLogin) with tenant scoping."""
import base64
import hashlib
import http.client
import json
import os
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import test_signer_service as ts
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from test_identity_k8s import b64, b64int, https_server, jwt
from test_identity_mtls import Pki, serve, tmpdir
from tracekit import observe
from tracekit.identity import k8s_sa, oidc
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.transport import answering_hello, hello
from tracekit.view import OidcLogin

AUD = "tracekit-signer"


def token(key, kid, **claims):
    """A JWT of `key` (RSA, EC, Ed25519, HMAC bytes or None) under `kid`."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        msg = f"{b64(json.dumps({'alg': 'EdDSA', 'kid': kid}).encode())}.{b64(json.dumps(claims).encode())}"
        return f"{msg}.{b64(key.sign(msg.encode()))}"
    return jwt(key, claims, "HS256" if isinstance(key, bytes) else None, kid)


class Provider:
    """An OIDC provider: its discovery document, JWKS (`keys`: kid -> private key; 500 while `fail`) and token
    endpoint, which answers a code of `codes` (code -> (PKCE challenge, ID token claims)) once."""

    def __init__(self, case, pki):
        self.keys = {"rs": rsa.generate_private_key(65537, 2048), "es": ec.generate_private_key(ec.SECP256R1()),
                     "ed": ed25519.Ed25519PrivateKey.generate()}
        self.fail, self.codes, self.fetches = False, {}, 0
        p = self

        class H(BaseHTTPRequestHandler):
            def answer(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    return self.answer(200, {"issuer": p.iss, "jwks_uri": p.iss + "/jwks",
                                             "authorization_endpoint": p.iss + "/authorize",
                                             "token_endpoint": p.iss + "/token"})
                p.fetches += 1
                self.answer(500 if p.fail else 200, {"keys": [p.jwk(k, v) for k, v in p.keys.items()]})

            def do_POST(self):
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
                challenge, claims = p.codes.pop(form.get("code"), (None, None))
                verifier = base64.urlsafe_b64encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
                if challenge is None or verifier.rstrip(b"=").decode() != challenge:
                    return self.answer(400, {"error": "invalid_grant"})
                self.answer(200, {"id_token": p.token(**claims)})

            def log_message(self, *a):
                pass
        self.iss = https_server(case, pki, H)

    @staticmethod
    def jwk(kid, key):
        pub = key.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            n = pub.public_numbers()
            return {"kty": "RSA", "kid": kid, "n": b64int(n.n), "e": b64int(n.e)}
        if isinstance(pub, ec.EllipticCurvePublicKey):
            n = pub.public_numbers()
            return {"kty": "EC", "kid": kid, "crv": "P-256", "x": b64int(n.x), "y": b64int(n.y)}
        return {"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": b64(pub.public_bytes_raw())}

    def claims(self, sub="u-bob", **kw):
        now = int(time.time())
        return {"iss": self.iss, "aud": AUD, "sub": sub, "email": sub.split("-", 1)[1] + "@corp.example", "email_verified": True,
                "tenant": "acme",
                "groups": [], "iat": now, "exp": now + 600, **kw}

    def token(self, kid="es", **kw):
        return token(self.keys[kid], kid, **self.claims(**kw))

    def config(self, pki, **kw):
        return {"corp": {"issuer": self.iss, "audience": AUD, "ca": pki.path, "person_claim": "email",
                         "tenant_claim": "tenant", **kw}}


class TestValidate(unittest.TestCase):
    def setUp(self):
        self.pki = Pki(tmpdir(self))
        self.idp = Provider(self, self.pki)
        self.now = time.time()
        self.auth = oidc.OidcAuthenticator(self.idp.config(self.pki), clock=lambda: self.now)

    def refused(self, tok, why):
        with self.assertRaises(RPCError) as cm:
            self.auth.validate(tok)
        self.assertEqual(cm.exception.code, "unauthenticated")
        self.assertIn(why, str(cm.exception))

    def test_each_alg_maps_to_identity_person_groups_and_tenant(self):
        for kid in ("rs", "es", "ed"):
            ident = self.auth.validate(self.idp.token(kid, groups=["ops", 7, ""]))
            self.assertEqual((ident.scheme, ident.subject, ident.attested), ("oidc", "corp/u-bob", True))
            self.assertEqual(ident.claims, {"person": "corp/bob@corp.example", "groups": ["corp/ops"], "tenant": "acme"})
            self.assertEqual(oidc.keys(ident), ["oidc:corp/u-bob", "person:corp/bob@corp.example", "group:corp/ops"])
        self.assertEqual(self.idp.fetches, 1)   # cached

    def test_refusals(self):
        now = int(time.time())
        es = self.idp.keys["es"]
        for why, tok in [("issuer", self.idp.token(iss="https://evil.example")),
                         ("email not verified", self.idp.token(email_verified=False)),
                         ("email not verified", token(es, "es", **{k: v for k, v in self.idp.claims().items()
                                                                   if k != "email_verified"})),
                         ("audience", self.idp.token(aud="other")),
                         ("expired", self.idp.token(exp=now - 120)),
                         ("unknown kid", token(es, "nope", **self.idp.claims())),
                         ("alg 'none'", jwt(None, self.idp.claims(), kid="es")),
                         ("alg 'HS256'", jwt(b"k" * 32, self.idp.claims(), "HS256", kid="es")),
                         ("unknown kid", jwt(es, self.idp.claims(), kid="rs")),   # an ES256 token under the RSA kid
                         ("bad signature", self.idp.token()[:-8] + "AAAAAAAA"),
                         ("no sub or email", self.idp.token(email=None))]:
            with self.subTest(why):
                self.refused(tok, why if why != "issuer" else "configured issuer")
        header = b64(json.dumps({"alg": "ES256"}).encode())   # no kid
        self.refused(header + self.idp.token()[self.idp.token().index("."):], "unknown kid")
        # another issuer's JWT is another authenticator's credential, unless it is a principal_token
        req = types.SimpleNamespace(headers={"Authorization": f"Bearer {self.idp.token(iss='https://other.example')}"},
                                    client_address=("127.0.0.1", 1))
        self.assertIsNone(self.auth.authenticate(req, {}))

    def test_key_rotation_and_expiry_of_cached_keys(self):
        self.auth.validate(self.idp.token())
        self.idp.keys = {"es2": ec.generate_private_key(ec.SECP256R1())}   # rotated: es is gone
        self.refused(self.idp.token("es2"), "unknown kid")   # refetched at most every REFETCH_S
        self.now += k8s_sa.REFETCH_S
        self.auth.validate(self.idp.token("es2"))
        self.now += k8s_sa.REFETCH_S
        self.refused(token(ec.generate_private_key(ec.SECP256R1()), "es", **self.idp.claims()), "unknown kid")
        self.idp.fail = True
        self.now += k8s_sa.JWKS_MAX_AGE_S
        with self.assertRaises(RPCError) as cm:
            self.auth.validate(self.idp.token("es2"))
        self.assertEqual(cm.exception.code, "unavailable")

    def test_config_refusals(self):
        for cfg in ({}, {"corp": {"issuer": "http://idp.example", "audience": AUD}},
                    {"corp": {"issuer": "https://idp.example"}}, {"a/b": {"issuer": "https://idp.example", "audience": AUD}},
                    {"corp": {"issuer": "https://idp.example", "audience": AUD, "extra": 1}},
                    {"a": {"issuer": "https://idp.example", "audience": AUD},
                     "b": {"issuer": "https://idp.example", "audience": AUD}}):
            with self.subTest(cfg), self.assertRaises(ValueError):
                oidc.OidcAuthenticator(cfg)


class TestSigner(unittest.TestCase):
    """approval_decide and principal_token over HTTPS with OIDC identities."""

    def setUp(self):
        d = tmpdir(self)
        self.pki, self.d = Pki(d), d
        self.idp = Provider(self, self.pki)
        cfg = self.idp.config(self.pki)
        self.data = ts.tmpdir(self)
        self.s = svc.SignerService(self.data, policy=ts.PAY_ASKS, authorize={"oidc:corp/*": sorted(REQUESTS.keys() - {svc.ON_BEHALF})},
                                   approvals={"self_approval": "deny", "approvers": ["group:corp/approvers"],
                                              "break_glass": ["group:corp/oncall"]},
                                   oidc=oidc.OidcAuthenticator(cfg))
        self.addCleanup(self.s.close)
        cert, key = self.pki.issue("server")
        port = serve(self, {"cert": cert, "key": key, "authenticators": ["oidc"], "oidc": cfg},
                     answering_hello(self.s.handle_frame, hello()))
        self.url = f"https://127.0.0.1:{port}"

    def client(self, sub, groups=()):
        path = os.path.join(self.d, f"token-{sub}")
        with open(path, "w") as f:
            f.write(self.idp.token(sub=sub, groups=list(groups)))
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_CA": self.pki.path, "TRACEKIT_SIGNER_TOKEN_FILE": path}):
            c = Client(self.url, timeout=5)
        self.addCleanup(c.close)
        return c

    def ask(self, run, tcid):
        run.decide(tcid, "pay", {"amount": 5})
        return run.call("approval_request", tool_call_id=tcid)["approval_id"]

    def decide(self, c, aid, **kw):
        return c.call("approval_decide", {"approval_id": aid, "decision": "approve", **kw})

    def forbidden(self, c, aid, why, **kw):
        with self.assertRaises(RPCError) as cm:
            self.decide(c, aid, **kw)
        self.assertEqual(cm.exception.code, "forbidden")
        self.assertIn(why, str(cm.exception))

    def test_attested_principal_approvers_aliases_and_break_glass(self):
        app, end_user = self.client("u-app"), self.idp.token(sub="u-bob")
        run = app.run("agent", principal_token=end_user)
        self.assertEqual((run.registered["principal"], run.registered["principal_attested"]),
                         ("corp/bob@corp.example", True))
        aids = [self.ask(run, f"tc-{i}") for i in range(4)]
        # the run's principal, as an approver or under break glass, never answers its run's calls
        bob = self.client("u-bob", ["approvers", "oncall"])
        self.forbidden(bob, aids[0], "run's principal", reason="urgent")
        # an alias of the run's owner (another subject, the same person) is the owner
        self.forbidden(self.client("u2-app", ["approvers"]), aids[0], "its own run's approval")
        with self.assertRaises(RPCError) as cm:   # not an approver: not even shown
            self.decide(self.client("u-eve"), aids[0])
        self.assertEqual(cm.exception.code, "unknown_approval")
        self.assertEqual(self.decide(self.client("u-dan", ["approvers"]), aids[0])["state"], "approved")
        erin = self.client("u-erin", ["oncall"])
        self.forbidden(erin, aids[1], "needs a reason")
        self.decide(erin, aids[1], reason="incident 7")
        run.close()
        recs = [r["event"] for r in ts.records(self.data)]
        reg = next(e for e in recs if e["type"] == "run.registered")
        self.assertEqual((reg["principal"], reg["principal_attested"], reg["data"]["identity"]["person"]),
                         ("corp/bob@corp.example", True, "corp/app@corp.example"))
        self.assertNotIn(end_user.split(".")[2], json.dumps(recs))
        approvals = [e["data"] for e in recs if e["type"] == "approval"]
        self.assertEqual([(a["approver_identity"]["person"], a.get("break_glass", False)) for a in approvals],
                         [("corp/dan@corp.example", False), ("corp/erin@corp.example", True)])

    def test_principal_survives_a_restart(self):
        run = self.client("u-app").run("agent", principal_token=self.idp.token(sub="u-bob"))
        aid = self.ask(run, "tc-1")
        self.s.close()
        s = svc.SignerService(self.data, policy=ts.PAY_ASKS, authorize={"oidc:corp/*": sorted(REQUESTS.keys() - {svc.ON_BEHALF})},
                              approvals={"approvers": ["group:corp/approvers"]})
        self.addCleanup(s.close)
        bob = oidc.OidcAuthenticator(self.idp.config(self.pki)).validate(
            self.idp.token(sub="u-bob2", email="bob@corp.example", groups=["approvers"]))   # an alias of the principal
        with self.assertRaises(RPCError) as cm:
            s.call(bob, "approval_decide", {"approval_id": aid, "decision": "approve", "request_id": "r1"})
        self.assertIn("run's principal", str(cm.exception))

    def test_asserted_principal_and_refusals(self):
        app = self.client("u-app")
        run = app.run("agent", principal="bob")
        self.assertEqual((run.registered["principal"], run.registered["principal_attested"]), ("bob", False))
        run.close()
        for code, fields in (("invalid_request", {"principal": "bob", "principal_token": self.idp.token()}),
                             ("unauthenticated", {"principal_token": self.idp.token(aud="other")}),
                             ("unauthenticated", {"principal_token": "not-a-jwt"})):
            with self.subTest(fields), self.assertRaises(RPCError) as cm:
                app.run("agent", **fields)
            self.assertEqual(cm.exception.code, code)


class TestViewerLogin(unittest.TestCase):
    """Authorization code + PKCE login; a session sees its tenant's records only; the token login stays."""

    def setUp(self):
        self.pki = Pki(tmpdir(self))
        self.idp = Provider(self, self.pki)
        feed = types.SimpleNamespace(
            records=[{"tool_name": "a1", "tenant": "acme"}, {"tool_name": "b1", "tenant": "beta"}], base=0,
            lock=threading.Condition(), verify=lambda tenant=None: (0, [f"tenant {tenant}"], None))
        login = OidcLogin({"issuer": "corp", "client_id": AUD, "redirect_uri": "http://127.0.0.1/callback",
                           "roles": {"auditor": ["group:corp/auditors"], "approver": ["person:corp/ann@corp.example"]}},
                          self.idp.config(self.pki))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), observe.make_handler(feed, "tok", ["127.0.0.1"], login=login))
        self.port, srv.daemon_threads = srv.server_address[1], True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)

    def get(self, path, cookie=""):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
            r = c.getresponse()
            return r, r.read()
        finally:
            c.close()

    def sign_in(self, **claims):
        """(callback answer, its body, its session cookie or None) of a login of a person with `claims`."""
        r, _ = self.get("/login")
        self.assertEqual(r.status, 303)
        loc = urlsplit(r.getheader("Location"))
        self.assertEqual(f"{loc.scheme}://{loc.netloc}{loc.path}", self.idp.iss + "/authorize")
        q = {k: v[0] for k, v in parse_qs(loc.query).items()}
        self.assertEqual((q["code_challenge_method"], q["response_type"]), ("S256", "code"))
        login_cookie = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", login_cookie)
        self.idp.codes["c-" + q["state"]] = (q["code_challenge"], dict(claims, nonce=q["nonce"]))
        r, body = self.get(f"/callback?code=c-{q['state']}&state={q['state']}", login_cookie.split(";")[0])
        cookies = [v for k, v in r.getheaders() if k == "Set-Cookie" and v.startswith(observe.COOKIE + "=")]
        return r, body, cookies[0] if cookies else None

    def test_auditor_session_sees_its_tenant_only(self):
        r, body, cookie = self.sign_in(sub="u-aud", groups=["auditors"])
        self.assertEqual(r.status, 200)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn(b'http-equiv="refresh"', body)
        session = cookie.split(";")[0]
        r, body = self.get("/api/snapshot", session)
        self.assertEqual([x["tool_name"] for x in json.loads(body)["records"]], ["a1"])
        _, body = self.get("/api/verify", session)
        self.assertEqual(json.loads(body)["problems"], ["tenant acme"])
        r, body = self.get("/api/snapshot", "tracekit_observe=forged")
        self.assertEqual(r.status, 401)
        # the laptop's token login still sees everything
        r, _ = self.get("/?token=tok")
        _, body = self.get("/api/snapshot", r.getheader("Set-Cookie").split(";")[0])
        self.assertEqual(len(json.loads(body)["records"]), 2)

    def test_approver_role_by_person(self):
        r, _, cookie = self.sign_in(sub="u-ann", tenant="beta")
        self.assertEqual(r.status, 200)
        _, body = self.get("/api/snapshot", cookie.split(";")[0])
        self.assertEqual([x["tool_name"] for x in json.loads(body)["records"]], ["b1"])

    def test_refusals(self):
        for claims in ({"sub": "u-nobody"}, {"sub": "u-aud", "groups": ["auditors"], "tenant": None},
                       {"sub": "u-aud", "groups": ["auditors"], "aud": "other"}):
            with self.subTest(claims):
                r, _, cookie = self.sign_in(**claims)
                self.assertEqual((r.status, cookie), (403, None))
        r, _ = self.get("/login")
        state = parse_qs(urlsplit(r.getheader("Location")).query)["state"][0]
        for path, cookie in ((f"/callback?code=x&state={state}", ""),   # no login cookie: another browser's state
                             (f"/callback?code=x&state={state}", f"tracekit_login={state}"),   # the IdP refuses x
                             (f"/callback?code=x&state={state}", f"tracekit_login={state}")):   # state used up
            self.assertEqual(self.get(path, cookie)[0].status, 403)


if __name__ == "__main__":
    unittest.main()
