"""C2SP checkpoint notes (signed-note, tlog-checkpoint and tlog-cosignature, all v1.1.0).

    <origin>\\n<tree size>\\n<base64 root>\\n\\n— <key name> <base64(key id ‖ signature)>\\n ...

The log signs with type 0x01 (Ed25519 over the note text) under a key named after the origin; witnesses cosign with
type 0x04 (8-byte timestamp ‖ Ed25519 over "cosignature/v1\\ntime <t>\\n" + text). Key id = SHA-256(name ‖ 0x0A ‖ type ‖
public key)[:4]. Keys are pinned as vkeys, `name+hex8+base64(type ‖ public key)`. A verifier ignores signature lines of
keys it doesn't pin (unknown types too), and rejects the note when a pinned key's signature fails.

Hybrid line (04-design §3.1): the log may also sign with SLH-DSA-SHA2-128s (FIPS 205) under a second key of the same
name, type 0xff, whose "public key" is SLH_DSA ‖ the 32-byte SLH-DSA public key. When a verifier pins it, a note of its
origin needs both the Ed25519 line and a valid hybrid line. Witnesses never get it (tlog_witness.log_signed)."""
import base64
import binascii
import hashlib
import struct

from tracekit import crypto
from tracekit.format import slh_dsa

ED25519, COSIGNATURE, HYBRID = 0x01, 0x04, 0xff
SLH_DSA = b"tracekit/slh-dsa-sha2-128s"
MAX_NOTE = 1 << 20
MAX_SIGNATURES = 64
DASH = "— "


class NoteError(ValueError):
    pass


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _unb64(s):
    """Canonical base64 only."""
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise NoteError("bad base64") from None
    if _b64(raw) != s:
        raise NoteError("non-canonical base64")
    return raw


def _check_name(name):
    if (not name or "+" in name or len(name.encode("utf-8")) > 255
            or any(c.isspace() or ord(c) < 0x20 for c in name)):
        raise NoteError(f"bad key name {name[:64]!r}")


def key_id(name, type_, public):
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([type_]) + public).digest()[:4]


def vkey(name, type_, public):
    _check_name(name)
    return f"{name}+{key_id(name, type_, public).hex()}+{_b64(bytes([type_]) + public)}"


def parse_vkey(text):
    """(name, key id, type, public key) of a vkey."""
    parts = text.split("+", 2)  # the base64 key may itself contain '+'
    if len(parts) != 3:
        raise NoteError("a vkey is name+id+key")
    name, hid, key = parts
    _check_name(name)
    raw = _unb64(key)
    if not (len(raw) == 33 and raw[0] in (ED25519, COSIGNATURE)
            or len(raw) == 1 + len(SLH_DSA) + slh_dsa.PK_SIZE and raw[0] == HYBRID and raw[1:].startswith(SLH_DSA)):
        raise NoteError("not an Ed25519 log, cosignature or SLH-DSA log vkey")
    kid = key_id(name, raw[0], raw[1:])
    if hid != kid.hex():
        raise NoteError("vkey id does not match the key")
    return name, kid, raw[0], raw[1:]


def body(origin, size, root):
    _check_name(origin)
    return f"{origin}\n{size}\n{_b64(root)}\n"


def sign(text, name, secret):
    """A type 0x01 signature line over the note text."""
    return log_line(name, crypto.public_from_secret(secret), crypto.sign(secret, text.encode("utf-8")))


def log_line(name, public, sig, type_=ED25519):
    """The signature line of `sig`, the signature of the note text by the key `public` of type `type_`."""
    return f"{DASH}{name} {_b64(key_id(name, type_, public) + sig)}\n"


def signers(note):
    """(name, key id) of each readable signature line of a note, without verifying any signature."""
    out = set()
    for line in note.partition("\n\n")[2].splitlines():
        name, _, blob = line[len(DASH):].partition(" ")
        try:
            out.add((name, _unb64(blob)[:4]))
        except NoteError:
            pass
    return out


def _cosigned(text, ts):
    return f"cosignature/v1\ntime {ts}\n{text}".encode("utf-8")


def cosign(text, name, secret, ts):
    """A type 0x04 cosignature line over the note text, made at unix time `ts`."""
    sig = struct.pack(">Q", ts) + crypto.sign(secret, _cosigned(text, ts))
    return f"{DASH}{name} {_b64(key_id(name, COSIGNATURE, crypto.public_from_secret(secret)) + sig)}\n"


def open_note(note, log_keys, witness_keys=()):
    """Verify a checkpoint note against pinned vkeys. Returns (origin, size, root bytes, [(witness vkey, timestamp)]).
    A pinned Ed25519 log key named after the origin must sign it, and so must each pinned hybrid key of the origin."""
    if isinstance(note, (bytes, bytearray)):
        if len(note) > MAX_NOTE:
            raise NoteError("note too large")
        try:
            note = bytes(note).decode("utf-8")
        except UnicodeDecodeError:
            raise NoteError("note is not UTF-8") from None
    if len(note) > MAX_NOTE or not note.endswith("\n") or any(ord(c) < 0x20 and c != "\n" for c in note):
        raise NoteError("malformed note")
    i = note.find("\n\n")
    if i < 0:
        raise NoteError("no signature block")
    text, lines = note[:i + 1], note[i + 2:-1].split("\n")
    if len(lines) > MAX_SIGNATURES:
        raise NoteError("too many signatures")
    head = text[:-1].split("\n")
    if len(head) != 3:
        raise NoteError("a checkpoint is origin, size and root")
    origin, size, root = head
    _check_name(origin)
    if not size.isdigit() or not size.isascii() or (size != "0" and size[0] == "0") or len(size) > 20:
        raise NoteError("bad tree size")
    root = _unb64(root)
    if len(root) != 32:
        raise NoteError("bad root hash")
    pinned = {}
    for keys, want in ((log_keys, (ED25519, HYBRID)), (witness_keys, (COSIGNATURE,))):
        for k in keys:
            name, kid, type_, public = parse_vkey(k)
            if type_ not in want:
                raise NoteError(f"pinned key {name} has the wrong signature type")
            pinned[(name, kid)] = (k, type_, public)
    hybrids = {k for k, v in pinned.items() if v[1] == HYBRID and k[0] == origin}
    seen, logged, cosigs = set(), False, []
    for line in lines:
        if not line.startswith(DASH):
            raise NoteError("malformed signature line")
        parts = line[len(DASH):].split(" ")
        if len(parts) != 2:
            raise NoteError("malformed signature line")
        name, blob = parts
        _check_name(name)
        raw = _unb64(blob)
        if len(raw) < 5:
            raise NoteError("short signature")
        if (name, raw[:4]) in seen:
            raise NoteError("two signatures from one key")
        seen.add((name, raw[:4]))
        key = pinned.get((name, raw[:4]))
        if key is None:
            continue
        k, type_, public = key
        sig = raw[4:]
        if type_ == ED25519:
            if not crypto.verify_v2("ed25519", crypto.spki(public), text.encode("utf-8"), sig):
                raise NoteError(f"bad signature from pinned key {name}")
            logged = logged or name == origin
        elif type_ == HYBRID:
            if not slh_dsa.verify(public[len(SLH_DSA):], text.encode("utf-8"), sig):
                raise NoteError(f"bad SLH-DSA signature from pinned key {name}")
            hybrids.discard((name, raw[:4]))
        else:
            ts = struct.unpack(">Q", sig[:8])[0] if len(sig) == 72 else None
            if ts is None or not crypto.verify_v2("ed25519", crypto.spki(public), _cosigned(text, ts), sig[8:]):
                raise NoteError(f"bad cosignature from pinned witness {name}")
            cosigs.append((k, ts))
    if not logged:
        raise NoteError(f"no signature from a pinned log key for origin {origin}")
    if hybrids:
        raise NoteError(f"no SLH-DSA signature from the pinned hybrid key for origin {origin}")
    return origin, int(size), root, cosigs
