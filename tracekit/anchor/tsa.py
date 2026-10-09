"""RFC 3161 timestamps of checkpoint notes, from a TSA listed in a Sigstore signing config, checked offline against
the TSA certificates of a Sigstore trusted_root.

A token is trusted only when its signature verifies under the leaf certificate of a pinned TSA chain whose `validFor`
and certificate validity cover the token's time; certificates carried in the token are never used. Parsing is a
minimal DER reader (stdlib), so no new dependency; signatures use `cryptography`."""
import base64
import datetime
import hashlib
import secrets
import urllib.error
import urllib.request

from tracekit.tlog_witness import WitnessError

TIMEOUT_S = 30.0
MAX_RESPONSE = 64 * 1024
SHA256 = bytes.fromhex("608648016503040201")
ID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
ID_TST_INFO = bytes.fromhex("2a864886f70d0109100104")
ID_CONTENT_TYPE = bytes.fromhex("2a864886f70d010903")
ID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")
DIGESTS = {SHA256: hashlib.sha256, bytes.fromhex("608648016503040202"): hashlib.sha384,
           bytes.fromhex("608648016503040203"): hashlib.sha512}
SIGNATURES = {bytes.fromhex("2a8648ce3d040302"): ("ecdsa", "SHA256"), bytes.fromhex("2a8648ce3d040303"): ("ecdsa", "SHA384"),
              bytes.fromhex("2a8648ce3d040304"): ("ecdsa", "SHA512"),
              bytes.fromhex("2a864886f70d01010b"): ("rsa", "SHA256"), bytes.fromhex("2a864886f70d01010c"): ("rsa", "SHA384"),
              bytes.fromhex("2a864886f70d01010d"): ("rsa", "SHA512")}


class AnchorError(WitnessError, ValueError):
    """`written`: Rekor may have logged the entry, so a retry before the next cadence slot could log another."""

    def __init__(self, msg, retryable=False, written=False):
        super().__init__(msg, retryable)
        self.written = written


def der(tag, *parts):
    body = b"".join(parts)
    n = len(body)
    size = bytes([n]) if n < 0x80 else bytes([0x80 | (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + size + body


def der_int(v):
    return der(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))


def items(data):
    """[(tag, content, whole element)] of the DER elements in `data`, single-byte tags only."""
    out, i = [], 0
    try:
        while i < len(data):
            start, tag, n = i, data[i], data[i + 1]
            i += 2
            if n & 0x80:
                k = n & 0x7F
                if not 0 < k <= 4:
                    raise AnchorError("bad DER length")
                n, i = int.from_bytes(data[i:i + k], "big"), i + k
            if i + n > len(data):
                raise AnchorError("truncated DER")
            out.append((tag, data[i:i + n], data[start:i + n]))
            i += n
    except IndexError:
        raise AnchorError("truncated DER") from None
    return out


def _one(data, tag):
    got = items(data)
    if len(got) != 1 or got[0][0] != tag:
        raise AnchorError(f"expected one DER element of tag {tag:#x}")
    return got[0][1]


def _time(text):
    """A Sigstore validFor time (RFC 3339)."""
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def valid_at(entry, at):
    span = entry.get("validFor") or {}
    return "start" in span and _time(span["start"]) <= at and ("end" not in span or at <= _time(span["end"]))


def request(data):
    """(DER TimeStampReq over SHA-256(data), with a nonce and the signing certificate asked for, nonce)."""
    nonce = secrets.randbits(63)
    imprint = der(0x30, der(0x30, der(0x06, SHA256), der(0x05)), der(0x04, hashlib.sha256(data).digest()))
    return der(0x30, der_int(1), imprint, der_int(nonce), der(0x01, b"\xff")), nonce


def timestamp(url, data, trusted_root, timeout=TIMEOUT_S):
    """A verified RFC 3161 response (DER) from the TSA at `url` over `data`, and its time."""
    body, nonce = request(data)
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/timestamp-query"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            tsr = r.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as e:
        raise AnchorError(f"TSA {url}: HTTP {e.code}", e.code == 429 or e.code >= 500) from None
    except (OSError, ValueError) as e:   # refused, reset, timeout
        raise AnchorError(f"TSA {url}: {e}", True) from None
    if len(tsr) > MAX_RESPONSE:
        raise AnchorError(f"TSA {url}: response too large")
    return tsr, verify(tsr, data, trusted_root, nonce)


def verify(tsr, data, trusted_root, nonce=None):
    """The time (UTC datetime) of an RFC 3161 response over `data`, verified offline against the TSAs of
    `trusted_root`; AnchorError otherwise."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    resp = items(_one(tsr, 0x30))
    if not resp or resp[0][0] != 0x30 or _one(items(resp[0][1])[0][2], 0x02) not in (b"\x00", b"\x01"):
        raise AnchorError("the TSA did not grant the timestamp")
    if len(resp) != 2:
        raise AnchorError("no timestamp token")
    ci = items(resp[1][1])
    if len(ci) != 2 or ci[0][:2] != (0x06, ID_SIGNED_DATA) or ci[1][0] != 0xA0:
        raise AnchorError("the token is not CMS signed data")
    sd = items(_one(ci[1][1], 0x30))
    encap = items(sd[2][1])
    if encap[0][:2] != (0x06, ID_TST_INFO) or encap[1][0] != 0xA0:
        raise AnchorError("the token does not hold a TSTInfo")
    tst = _one(encap[1][1], 0x04)
    infos = items(sd[-1][1]) if sd[-1][0] == 0x31 else []
    if len(infos) != 1:
        raise AnchorError("the token needs exactly one signer")
    si = items(infos[0][1])
    digest = DIGESTS.get(_one(items(si[2][1])[0][2], 0x06))
    if digest is None or si[3][0] != 0xA0:
        raise AnchorError("unsupported digest or no signed attributes")
    attrs = {}
    for _, attr, _ in items(si[3][1]):
        oid, values = items(attr)
        attrs[oid[1]] = items(values[1])
    if (attrs.get(ID_CONTENT_TYPE, [(None, None)])[0][1] != ID_TST_INFO
            or attrs.get(ID_MESSAGE_DIGEST, [(None, None)])[0][1] != digest(tst).digest()):
        raise AnchorError("the signed attributes do not bind the TSTInfo")
    alg = SIGNATURES.get(_one(items(si[4][1])[0][2], 0x06))
    if alg is None or si[5][0] != 0x04:
        raise AnchorError("unsupported signature algorithm")
    signed, sig = b"\x31" + si[3][2][1:], si[5][1]   # the signature covers the attributes as a SET
    info = items(_one(tst, 0x30))
    imprint = items(info[2][1])
    if _one(items(imprint[0][1])[0][2], 0x06) != SHA256 or imprint[1][1] != hashlib.sha256(data).digest():
        raise AnchorError("the timestamp is not over these note bytes")
    if nonce is not None and not any(t == 0x02 and int.from_bytes(v, "big") == nonce for t, v, _ in info[5:]):
        raise AnchorError("the TSA answered without our nonce")
    text = info[4][1].decode("ascii") if info[4][0] == 0x18 else ""
    try:
        at = datetime.datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        raise AnchorError("bad genTime") from None
    for ta in trusted_root.get("timestampAuthorities") or ():
        try:
            leaf = x509.load_der_x509_certificate(base64.b64decode(ta["certChain"]["certificates"][0]["rawBytes"]))
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        utc = datetime.timezone.utc   # cryptography < 42 has only the naive UTC properties
        lo, hi = (getattr(leaf, f"not_valid_{s}_utc", None) or getattr(leaf, f"not_valid_{s}").replace(tzinfo=utc)
                  for s in ("before", "after"))
        if not (valid_at(ta, at) and lo <= at <= hi):
            continue
        key, h = leaf.public_key(), getattr(hashes, alg[1])()
        try:
            if alg[0] == "ecdsa" and isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(sig, signed, ec.ECDSA(h))
            elif alg[0] == "rsa" and not isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(sig, signed, padding.PKCS1v15(), h)
            else:
                continue
        except (InvalidSignature, TypeError, ValueError):
            continue
        return at
    raise AnchorError("the timestamp is not signed by a pinned TSA valid at its time")
