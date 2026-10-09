"""mTLS identity (tracekit/identity/mtls.py) over the HTTPS transport: the SPIFFE ID of a client certificate the
configured CA vouches for; no certificate, a certificate from another CA, or not exactly one spiffe:// URI is refused.
`Pki` and `serve` are shared with tests/test_identity_k8s.py and tests/test_http_transport.py."""
import datetime
import http.client
import ipaddress
import json
import os
import shutil
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tracekit.transport import http as tk_http

LOCAL = x509.IPAddress(ipaddress.ip_address("127.0.0.1"))


def tmpdir(case):
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, True)
    return d


class Pki:
    """A CA whose certificate is written to `self.path`; issue() writes a leaf certificate and key signed by it."""

    def __init__(self, d, name="ca"):
        self.d, self.key = d, ec.generate_private_key(ec.SECP256R1())
        self.cert = self._cert(name, self.key.public_key(), x509.Name([]), [], ca=True)
        self.path = self._write(f"{name}.pem", self.cert.public_bytes(serialization.Encoding.PEM))

    def _cert(self, name, public_key, issuer, sans, ca=False):
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject if ca else issuer)
             .public_key(public_key).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(hours=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             # what Python 3.13's strict X.509 verification (ssl.create_default_context) requires of a chain
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
             .add_extension(x509.KeyUsage(digital_signature=not ca, key_cert_sign=ca, crl_sign=ca, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True))
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return b.sign(self.key, hashes.SHA256())

    def _write(self, name, data):
        path = os.path.join(self.d, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def issue(self, name, sans=(LOCAL,)):
        """(cert path, key path) of a leaf named `name` with `sans`."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._cert(name, key.public_key(), self.cert.subject, list(sans))
        return (self._write(f"{name}.pem", cert.public_bytes(serialization.Encoding.PEM)),
                self._write(f"{name}.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                             serialization.NoEncryption())))


def serve(case, cfg, handle, read_timeout=5):
    """An HttpServer on a free loopback port for the `http` config `cfg`; its port."""
    _, auths, tls = tk_http.configure({"listen": "127.0.0.1:0", **cfg})
    srv = tk_http.HttpServer(("127.0.0.1", 0), auths, tls, handle, read_timeout)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return srv.server_address[1]


def echo(identity, frame):
    return {"scheme": identity.scheme, "subject": identity.subject}


def post(port, frame, ctx, headers=None):
    """(status, answer) of one POST /v2/rpc."""
    c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    try:
        c.request("POST", "/v2/rpc", json.dumps(frame), headers or {})
        r = c.getresponse()
        return r.status, json.loads(r.read())
    finally:
        c.close()


class TestMtls(unittest.TestCase):
    def setUp(self):
        d = tmpdir(self)
        self.pki, self.other = Pki(d), Pki(d, "other-ca")
        cert, key = self.pki.issue("server")
        self.port = serve(self, {"cert": cert, "key": key, "client_ca": {"example.org": self.pki.path},
                                 "authenticators": ["mtls"]}, echo)

    def ctx(self, pki=None, sans=()):
        ctx = ssl.create_default_context(cafile=self.pki.path)
        if pki:
            ctx.load_cert_chain(*pki.issue(f"client{len(sans)}", sans))
        return ctx

    def test_spiffe_id_is_the_subject(self):
        status, out = post(self.port, {"method": "status"}, self.ctx(self.pki, [x509.UniformResourceIdentifier(
            "spiffe://example.org/ns/a/sa/agent")]))
        self.assertEqual((status, out), (200, {"scheme": "mtls", "subject": "spiffe://example.org/ns/a/sa/agent"}))

    def test_no_certificate_is_refused(self):
        self.assertEqual(post(self.port, {"method": "status"}, self.ctx())[1]["error"]["code"], "unauthenticated")

    def test_certificate_of_another_ca_is_refused(self):
        with self.assertRaises(OSError):
            post(self.port, {"method": "status"}, self.ctx(self.other, [x509.UniformResourceIdentifier("spiffe://x/a")]))

    def test_not_exactly_one_spiffe_uri_is_refused(self):
        for sans in ([], [x509.UniformResourceIdentifier("https://example.org/a")],
                     [x509.UniformResourceIdentifier("spiffe://x/a"), x509.UniformResourceIdentifier("spiffe://x/b")]):
            out = post(self.port, {"method": "status"}, self.ctx(self.pki, sans))[1]
            self.assertEqual(out["error"]["code"], "unauthenticated", sans)


    def test_each_trust_domain_only_from_its_own_ca(self):
        cert, key = self.pki.issue("server2")
        self.port = serve(self, {"cert": cert, "key": key, "authenticators": ["mtls"],
                                 "client_ca": {"example.org": self.pki.path, "other.org": self.other.path}}, echo)
        ok = post(self.port, {"method": "status"}, self.ctx(self.other, [x509.UniformResourceIdentifier("spiffe://other.org/a")]))
        self.assertEqual(ok[1], {"scheme": "mtls", "subject": "spiffe://other.org/a"})
        for pki, sid in ((self.other, "spiffe://example.org/a"), (self.pki, "spiffe://other.org/a"),
                         (self.pki, "spiffe://unknown.org/a")):
            out = post(self.port, {"method": "status"}, self.ctx(pki, [x509.UniformResourceIdentifier(sid)]))[1]
            self.assertEqual(out["error"]["code"], "unauthenticated", sid)

    def test_client_ca_is_a_trust_domain_map(self):
        cert, key = self.pki.issue("server3")
        for cas in (self.pki.path, {}, {"example.org": 1}):
            with self.subTest(cas), self.assertRaises(ValueError):
                tk_http.configure({"listen": "127.0.0.1:0", "cert": cert, "key": key, "client_ca": cas,
                                   "authenticators": ["mtls"]})


if __name__ == "__main__":
    unittest.main()
