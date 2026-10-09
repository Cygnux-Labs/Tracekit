"""C2SP checkpoint notes (signed-note, tlog-checkpoint and tlog-cosignature, all v1.1.0).

    <origin>\\n<tree size>\\n<base64 root>\\n\\n— <key name> <base64(key id ‖ signature)>\\n ...

The log signs with type 0x01 (Ed25519 over the note text) under a key named after the origin; witnesses cosign with
type 0x04 (8-byte timestamp ‖ Ed25519 over "cosignature/v1\\ntime <t>\\n" + text). Key id = SHA-256(name ‖ 0x0A ‖ type ‖
public key)[:4]. Keys are pinned as vkeys, `name+hex8+base64(type ‖ public key)`. A verifier ignores signature lines of
keys it doesn't pin (unknown types too), and rejects the note when a pinned key's signature fails."""
import base64
import binascii
import hashlib
import struct

from tracekit import crypto

ED25519, COSIGNATURE = 0x01, 0x04
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
    if len(raw) != 33 or raw[0] not in (ED25519, COSIGNATURE):
        raise NoteError("not an Ed25519 log or cosignature vkey")
    kid = key_id(name, raw[0], raw[1:])
    if hid != kid.hex():
        raise NoteError("vkey id does not match the key")
    return name, kid, raw[0], raw[1:]


def body(origin, size, root):
    _check_name(origin)
    return f"{origin}\n{size}\n{_b64(root)}\n"


def sign(text, name, secret):
    """A type 0x01 signature line over the note text."""
    sig = crypto.sign(secret, text.encode("utf-8"))
    return f"{DASH}{name} {_b64(key_id(name, ED25519, crypto.public_from_secret(secret)) + sig)}\n"


def _cosigned(text, ts):
    return f"cosignature/v1\ntime {ts}\n{text}".encode("utf-8")


def open_note(note, log_keys, witness_keys=()):
    """Verify a checkpoint note against pinned vkeys. Returns (origin, size, root bytes, [(witness vkey, timestamp)]).
    A pinned log key named after the origin must sign it."""
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
    for keys, want in ((log_keys, ED25519), (witness_keys, COSIGNATURE)):
        for k in keys:
            name, kid, type_, public = parse_vkey(k)
            if type_ != want:
                raise NoteError(f"pinned key {name} has the wrong signature type")
            pinned[(name, kid)] = (k, type_, public)
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
        else:
            ts = struct.unpack(">Q", sig[:8])[0] if len(sig) == 72 else None
            if ts is None or not crypto.verify_v2("ed25519", crypto.spki(public), _cosigned(text, ts), sig[8:]):
                raise NoteError(f"bad cosignature from pinned witness {name}")
            cosigs.append((k, ts))
    if not logged:
        raise NoteError(f"no signature from a pinned log key for origin {origin}")
    return origin, int(size), root, cosigs
