"""Passkey (WebAuthn) assertions over approvals, verified by the signer (04-design §5; W3C WebAuthn Level 2 §7.2).

An ask rule with `approval: {passkey: required}` is approved only with an assertion whose challenge is
`challenge(approval_id, binding_digest, decision)`: the binding digest covers the call's args commitment, so the
assertion answers that one approval, those arguments and that decision only. The minimal checks: clientDataJSON's type,
challenge and origin; authenticatorData's rpIdHash, the UP and UV flags and a growing signCount; the signature over
authenticatorData || SHA-256(clientDataJSON) under the registered key, ES256 (P-256) or EdDSA (Ed25519). Attestation is
not checked: the key is whatever the person registered (`passkey_register`).
"""
import base64
import hashlib
import hmac
import json

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tracekit.format.canon import canonical

UP, UV = 0x01, 0x04


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def challenge(approval_id, binding_digest, decision):
    """The bytes a passkey signs to give `decision` on approval `approval_id`, bound by `binding_digest`."""
    return hashlib.sha256(canonical({"v": 1, "approval_id": approval_id, "binding_digest": binding_digest,
                                     "decision": decision})).digest()


def public_key(spki_der):
    """The P-256 or Ed25519 key of a DER SubjectPublicKeyInfo; ValueError for any other."""
    try:
        key = serialization.load_der_public_key(spki_der)
    except UnsupportedAlgorithm:
        key = None
    if isinstance(key, ed25519.Ed25519PublicKey) or (
            isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)):
        return key
    raise ValueError("a passkey must be ES256 (P-256) or EdDSA (Ed25519)")


def verify(spki_der, count, rp_id, origin, expected, client_data_json, authenticator_data, signature):
    """The authenticator's new signCount for a valid assertion over challenge `expected`; ValueError otherwise.
    `count` is the last signCount seen for this credential."""
    try:
        client = json.loads(client_data_json)
    except (UnicodeDecodeError, ValueError):
        raise ValueError("clientDataJSON is not JSON") from None
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        raise ValueError("clientDataJSON type is not webauthn.get")
    if not hmac.compare_digest(str(client.get("challenge", "")).encode(), b64url(expected).encode()):
        raise ValueError("the challenge is not this approval's")
    if client.get("origin") != origin or client.get("crossOrigin") is True:
        raise ValueError("the origin is not the viewer's")
    if len(authenticator_data) < 37 or not hmac.compare_digest(authenticator_data[:32],
                                                               hashlib.sha256(rp_id.encode()).digest()):
        raise ValueError("rpIdHash is not the relying party's")
    if authenticator_data[32] & (UP | UV) != UP | UV:
        raise ValueError("the authenticator did not verify the user (UP and UV)")
    n = int.from_bytes(authenticator_data[33:37], "big")
    if (n or count) and n <= count:
        raise ValueError("signCount did not grow: a cloned authenticator or a replay")
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    key = public_key(spki_der)
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed)
        else:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("the passkey signature does not verify") from None
    return n
