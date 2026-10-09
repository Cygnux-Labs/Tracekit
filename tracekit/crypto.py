"""Ed25519.

Signing and key generation (the signer's private-key operations) always use the `cryptography`
package, a reviewed, constant-time implementation. It is a required dependency.

Verification uses `cryptography` when installed and otherwise falls back to a small pure-Python
RFC 8032 implementation, so `tracekit verify` runs on any machine with only the standard
library. Verification handles only public data, so the fallback's lack of timing hardening does
not matter there. The pure-Python signing routine exists only to check the RFC test vectors."""
import hashlib
import os

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    BACKEND = "cryptography"
except Exception:  # pragma: no cover - exercised via force_pure in tests
    BACKEND = "pure-python"

FORCE_PURE = os.environ.get("TRACEKIT_PURE_ED25519") == "1"


# ---------------- pure-python RFC 8032 ----------------
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_SQRT_M1 = pow(2, (_p - 1) // 4, _p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _SQRT_M1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % _p, P[1] * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _expand(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _hq(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little") % _L


def _pure_public(secret):
    return _compress(_mul(_expand(secret)[0], _G))


def _pure_sign(secret, msg):
    a, prefix = _expand(secret)
    A = _compress(_mul(a, _G))
    r = _hq(prefix + msg)
    Rs = _compress(_mul(r, _G))
    s = (r + _hq(Rs + A + msg) * a) % _L
    return Rs + int.to_bytes(s, 32, "little")


def _pure_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = _hq(sig[:32] + public + msg)
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


# ---------------- public API ----------------
def _use_pure():
    """Verification only: TRACEKIT_PURE_ED25519=1 forces the fallback (used by tests)."""
    return FORCE_PURE or BACKEND != "cryptography"


class SigningUnavailable(RuntimeError):
    pass


def _require_backend():
    if BACKEND != "cryptography":
        raise SigningUnavailable("signing needs the `cryptography` package (pip install cryptography); "
                                 "the pure-Python fallback is for verification only")


def generate():
    """Return (secret32, public32)."""
    _require_backend()
    k = Ed25519PrivateKey.generate()
    secret = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return secret, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_from_secret(secret):
    _require_backend()
    k = Ed25519PrivateKey.from_private_bytes(secret)
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign_fn(secret):
    """sign(msg) bound to one key, for signing many messages without reloading it."""
    _require_backend()
    return Ed25519PrivateKey.from_private_bytes(secret).sign


def sign(secret, msg):
    return sign_fn(secret)(msg)


def verify(public, msg, sig):
    if _use_pure():
        return _pure_verify(public, msg, sig)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def kid(public):
    return "ed25519:" + hashlib.sha256(public).hexdigest()[:16]


# ---------------- format v2 ----------------
# DER SubjectPublicKeyInfo header of an Ed25519 key (RFC 8410)
_ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
_IDENTITY = (0, 1, 1, 0)


def spki(public):
    """DER SubjectPublicKeyInfo of a raw Ed25519 public key."""
    return _ED25519_SPKI + public


def key_alg(spki_der):
    """The algorithm a SubjectPublicKeyInfo is for, or None if it is not one we support."""
    if len(spki_der) == 44 and spki_der.startswith(_ED25519_SPKI):
        return "ed25519"
    return None


def spki_kid(spki_der):
    """v2 key id. It hashes the whole SubjectPublicKeyInfo, so it binds the key's algorithm too."""
    return "sha256:" + hashlib.sha256(spki_der).hexdigest()


def _verify_ed25519_strict(public, msg, sig):
    """The v2 Ed25519 rules, identical on both backends: S < L, a canonically encoded public key that is not of small
    order, and the cofactorless equation [S]B = R + [k]A (both backends check it that way)."""
    if len(public) != 32 or len(sig) != 64 or int.from_bytes(sig[32:], "little") >= _L:
        return False
    A = _decompress(public)
    if A is None or _equal(_mul(8, A), _IDENTITY):
        return False
    return verify(public, msg, sig)


def verify_v2(alg, spki_der, msg, sig):
    """False unless `alg` is the key's own algorithm and the signature holds under that algorithm's v2 rules."""
    if key_alg(spki_der) != alg:
        return False
    return _verify_ed25519_strict(spki_der[len(_ED25519_SPKI):], msg, sig)
