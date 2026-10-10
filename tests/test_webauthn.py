"""tracekit.identity.webauthn against a software authenticator: it builds clientDataJSON and authenticatorData and signs
them as a browser and a platform authenticator do (WebAuthn Level 2 §6.1, §7.2), ES256 and EdDSA."""
import hashlib
import json
import os
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tracekit.identity import webauthn
from tracekit.identity.webauthn import UP, UV, b64url

RP_ID, ORIGIN = "view.example", "https://view.example"
CHALLENGE = webauthn.challenge("apr-1", "sha256:" + "ab" * 32, "approve")


class Authenticator:
    """A software passkey for RP_ID."""

    def __init__(self, alg="ES256"):
        self.key = ec.generate_private_key(ec.SECP256R1()) if alg == "ES256" else ed25519.Ed25519PrivateKey.generate()
        self.id, self.count = os.urandom(16), 0
        self.spki = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, challenge, typ="webauthn.get", origin=ORIGIN, rp_id=RP_ID, flags=UP | UV, count=None):
        """An assertion over `challenge`, as the approval API takes it (base64url fields)."""
        self.count += 1
        client = json.dumps({"type": typ, "challenge": b64url(challenge), "origin": origin}).encode()
        auth = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags])
                + (self.count if count is None else count).to_bytes(4, "big"))
        signed = auth + hashlib.sha256(client).digest()
        sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256())) if isinstance(self.key, ec.EllipticCurvePrivateKey) \
            else self.key.sign(signed)
        return {"credential_id": b64url(self.id), "client_data_json": b64url(client),
                "authenticator_data": b64url(auth), "signature": b64url(sig)}


def check(auth, assertion, count=0, challenge=CHALLENGE):
    return webauthn.verify(auth.spki, count, RP_ID, ORIGIN, challenge,
                           *(webauthn.unb64url(assertion[k]) for k in ("client_data_json", "authenticator_data",
                                                                       "signature")))


class TestVerify(unittest.TestCase):
    def test_es256_and_eddsa_assertions_verify_and_return_the_sign_count(self):
        for alg in ("ES256", "EdDSA"):
            a = Authenticator(alg)
            self.assertEqual(check(a, a.sign(CHALLENGE)), 1, alg)
            self.assertEqual(check(a, a.sign(CHALLENGE), count=1), 2, alg)

    def test_an_authenticator_without_a_counter_passes_with_zero(self):
        a = Authenticator()
        self.assertEqual(check(a, a.sign(CHALLENGE, count=0)), 0)

    def test_refusals(self):
        a, other = Authenticator(), Authenticator()
        good = a.sign(CHALLENGE)
        cases = {   # what the refusal names -> an assertion that fails that check only
            "type": a.sign(CHALLENGE, typ="webauthn.create"),
            "challenge": a.sign(webauthn.challenge("apr-1", "sha256:" + "ab" * 32, "reject")),
            "origin": a.sign(CHALLENGE, origin="https://evil.example"),
            "rpIdHash": a.sign(CHALLENGE, rp_id="evil.example"),
            "UP and UV": a.sign(CHALLENGE, flags=UP),
            "signCount": a.sign(CHALLENGE, count=2),
            "signature": dict(good, signature=other.sign(CHALLENGE)["signature"]),
        }
        cases["signature "] = dict(good, client_data_json=b64url(json.dumps(
            {"type": "webauthn.get", "challenge": b64url(CHALLENGE), "origin": ORIGIN, "x": 1}).encode()))
        for why, assertion in cases.items():
            with self.subTest(why), self.assertRaisesRegex(ValueError, why.strip()):
                check(a, assertion, count=2 if why == "signCount" else 0)
        with self.assertRaisesRegex(ValueError, "UP and UV"):
            check(a, a.sign(CHALLENGE, flags=UV))

    def test_only_p256_and_ed25519_keys(self):
        p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        for spki in (p384, b"not a key"):
            with self.assertRaises(ValueError):
                webauthn.public_key(spki)


if __name__ == "__main__":
    unittest.main()
