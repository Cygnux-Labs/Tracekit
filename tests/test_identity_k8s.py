"""Kubernetes service-account identity (tracekit/identity/k8s_sa.py): JWKS mode against a fake issuer and TokenReview
mode against a fake API server, both HTTPS on loopback with certificates made here. `Jwks` and `jwt` are shared with
tests/test_http_transport.py."""
import base64
import json
import ssl
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from test_identity_mtls import Pki, tmpdir
from tracekit.identity import k8s_sa
from tracekit.signer.rpc_schema import RPCError

ISS, AUD = "https://issuer.example", "tracekit-signer"
SA = "system:serviceaccount:acme:agent"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64int(n):
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def jwt(key, claims, alg=None, kid=None):
    """A JWT over `claims`: RS256 for an RSA key, ES256 for an EC key, HS256 for bytes, `none` for None."""
    alg = alg or ("RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256" if key else "none")
    header = {"alg": alg, "kid": kid or alg}
    msg = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}".encode()
    if isinstance(key, rsa.RSAPrivateKey):
        sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif key:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(msg)
        sig = h.finalize()
    else:
        sig = b""
    return f"{msg.decode()}.{b64(sig)}"


def claims(sub=SA, **kw):
    now = int(time.time())
    return {"iss": ISS, "aud": [AUD], "sub": sub, "iat": now, "nbf": now, "exp": now + 600,
            "kubernetes.io": {"namespace": "acme", "serviceaccount": {"name": "agent", "uid": "u-1"},
                              "pod": {"name": "agent-7d9", "uid": "p-1"}}, **kw}


def https_server(case, pki, handler):
    """A ThreadingHTTPServer over TLS on loopback with a certificate of `pki`; its base URL."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*pki.issue("fake-server"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return f"https://127.0.0.1:{srv.server_address[1]}"


class Jwks:
    """An issuer with an RSA and an EC key whose JWKS is served at `self.uri`; counts the fetches."""

    def __init__(self, case, pki):
        self.rsa, self.ec, self.fetches = rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP256R1()), 0
        rn, en = self.rsa.public_key().public_numbers(), self.ec.public_key().public_numbers()
        body = json.dumps({"keys": [{"kty": "RSA", "kid": "RS256", "n": b64int(rn.n), "e": b64int(rn.e)},
                                    {"kty": "EC", "kid": "ES256", "crv": "P-256", "x": b64int(en.x),
                                     "y": b64int(en.y)}]}).encode()
        issuer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                issuer.fetches += 1
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.uri = https_server(case, pki, H) + "/openid/v1/jwks"

    def config(self, pki):
        return {"audience": AUD, "issuer": ISS, "jwks_uri": self.uri, "ca": pki.path}


def request(token):
    return types.SimpleNamespace(headers={"Authorization": f"Bearer {token}"})


class TestJwks(unittest.TestCase):
    def setUp(self):
        self.pki = Pki(tmpdir(self))
        self.jwks = Jwks(self, self.pki)
        self.auth = k8s_sa.K8sSaAuthenticator(**self.jwks.config(self.pki))

    def refused(self, token):
        with self.assertRaises(RPCError) as cm:
            self.auth.authenticate(request(token), {})
        self.assertEqual(cm.exception.code, "unauthenticated")

    def test_valid_token_gives_identity_and_claims(self):
        for key in (self.jwks.rsa, self.jwks.ec):
            ident = self.auth.authenticate(request(jwt(key, claims())), {})
            self.assertEqual((ident.scheme, ident.subject, ident.attested), ("k8s_sa", SA, True))
            self.assertEqual(ident.claims, {"namespace": "acme", "service_account": "agent", "pod_name": "agent-7d9",
                                            "pod_uid": "p-1"})
        self.assertEqual(self.jwks.fetches, 1)   # cached

    def test_refusals(self):
        now = int(time.time())
        for name, token in [
                ("wrong aud", jwt(self.jwks.rsa, claims(aud=["other"]))),
                ("wrong iss", jwt(self.jwks.rsa, claims(iss="https://evil.example"))),
                ("expired", jwt(self.jwks.rsa, claims(exp=now - 120))),
                ("nbf in the future", jwt(self.jwks.rsa, claims(nbf=now + 120))),
                ("no exp", jwt(self.jwks.rsa, {k: v for k, v in claims().items() if k != "exp"})),
                ("alg none", jwt(None, claims(), kid="RS256")),
                ("HS256", jwt(b"k" * 32, claims(), "HS256", kid="RS256")),
                ("alg swapped for the kid", jwt(self.jwks.ec, claims(), kid="RS256")),
                ("unknown kid", jwt(self.jwks.rsa, claims(), kid="other")),
                ("bad signature", jwt(self.jwks.rsa, claims())[:-8] + "AAAAAAAA"),
                ("not a service account", jwt(self.jwks.rsa, claims(sub="alice")))]:
            with self.subTest(name):
                self.refused(token)

    def test_unknown_kid_refetches_at_most_every_refetch_s(self):
        for _ in range(3):
            self.refused(jwt(self.jwks.rsa, claims(), kid="other"))
        self.assertEqual(self.jwks.fetches, 1)

    def test_other_bearer_tokens_are_left_to_other_authenticators(self):
        self.assertIsNone(self.auth.authenticate(request("x" * 40), {}))
        self.assertIsNone(self.auth.authenticate(types.SimpleNamespace(headers={}), {}))

    def test_config_is_checked(self):
        for cfg in ({"issuer": ISS, "jwks_uri": self.jwks.uri},
                    {"audience": AUD, "jwks_uri": self.jwks.uri},
                    {"audience": AUD, "issuer": ISS, "jwks_uri": "http://127.0.0.1/jwks"},
                    {"audience": AUD, "issuer": ISS, "jwks_uri": self.jwks.uri, "tokenreview": "https://k"}):
            with self.subTest(cfg), self.assertRaises(ValueError):
                k8s_sa.K8sSaAuthenticator(**cfg)


class TestTokenReview(unittest.TestCase):
    def setUp(self):
        d = tmpdir(self)
        self.pki, self.reviews, self.now = Pki(d), [], time.time()
        own = f"{d}/own-token"
        with open(own, "w") as f:
            f.write("signer-own-token\n")
        test = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                review = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                test.reviews.append((self.path, self.headers["Authorization"], review))
                token = review["spec"]["token"]
                status = {"authenticated": False}
                if token.startswith("good"):
                    status = {"authenticated": True, "audiences": review["spec"]["audiences"],
                              "user": {"username": SA, "extra": {"authentication.kubernetes.io/pod-name": ["agent-7d9"],
                                                                 "authentication.kubernetes.io/pod-uid": ["p-1"]}}}
                body = json.dumps({"status": status}).encode()
                self.send_response(201)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.auth = k8s_sa.K8sSaAuthenticator(audience=AUD, tokenreview=https_server(self, self.pki, H), token_file=own,
                                              ca=self.pki.path, clock=lambda: self.now)

    def token(self, name, ttl=600):
        """A JWT-shaped token the fake API server judges by its prefix; only its exp is read by the signer."""
        return f"{name}.{b64(json.dumps({'exp': int(self.now) + ttl}).encode())}.sig"

    def test_valid_token_is_reviewed_once_then_cached(self):
        good = self.token("good")
        for _ in range(2):
            ident = self.auth.authenticate(request(good), {})
            self.assertEqual((ident.subject, ident.claims["pod_name"], ident.claims["pod_uid"]), (SA, "agent-7d9", "p-1"))
        self.assertEqual(len(self.reviews), 1)
        path, authz, review = self.reviews[0]
        self.assertEqual((path, authz), ("/apis/authentication.k8s.io/v1/tokenreviews", "Bearer signer-own-token"))
        self.assertEqual((review["spec"]["token"], review["spec"]["audiences"]), (good, [AUD]))

    def test_negative_answers_are_not_cached(self):
        for _ in range(2):
            with self.assertRaises(RPCError) as cm:
                self.auth.authenticate(request(self.token("bad")), {})
            self.assertEqual(cm.exception.code, "unauthenticated")
        self.assertEqual(len(self.reviews), 2)

    def test_cache_lifetime_is_bounded_by_review_ttl_and_token_exp(self):
        long, short = self.token("good-long"), self.token("good-short", ttl=10)
        for t in (long, short):
            self.auth.authenticate(request(t), {})
        self.now += 11   # short has expired: reviewed again
        for t in (long, short):
            self.auth.authenticate(request(t), {})
        self.assertEqual(len(self.reviews), 3)
        self.now += k8s_sa.REVIEW_TTL_S   # past REVIEW_TTL_S: long is reviewed again
        self.auth.authenticate(request(long), {})
        self.assertEqual(len(self.reviews), 4)

    def test_cache_is_bounded_lru(self):
        with mock.patch.object(k8s_sa, "CACHE_MAX", 2):
            a, b, c = (self.token(f"good-{n}") for n in "abc")
            for t in (a, b, a, c):   # c evicts b, the least recently used
                self.auth.authenticate(request(t), {})
            self.assertEqual(len(self.auth._cache), 2)
            self.auth.authenticate(request(a), {})
            self.assertEqual(len(self.reviews), 3)
            self.auth.authenticate(request(b), {})
            self.assertEqual(len(self.reviews), 4)


if __name__ == "__main__":
    unittest.main()
