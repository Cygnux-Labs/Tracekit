"""Canonical JSON, hashing, time, ids, and the v1 record envelope.

A ledger line is one *record*:
    {"v": 1, "event": {...v1 event...}, "hash": H, "sig": S, "kid": K}
    H = sha256(canon(event))                      (hex)
    S = Ed25519(canon({"hash": H, "prev_hash": event.prev_hash, "seq": event.seq}))   (base64)
Signing (hash, prev_hash, seq) rather than the hash alone lets a bundle *elide* a record
(keep only hash/prev_hash/seq/sig) and still prove the chain and the counter have no gaps.
"""
import base64
import datetime as _dt
import hashlib
import json
import os

GENESIS = "0" * 64
SCHEMA_VERSION = "tracekit.event.v1"


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def event_hash(event):
    return sha256_hex(canon(event))


def sig_message(h, prev_hash, seq):
    return canon({"hash": h, "prev_hash": prev_hash, "seq": seq}).encode("utf-8")


def now_ts():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_id():
    return os.urandom(16).hex()


def b64e(b):
    return base64.b64encode(b).decode("ascii")


def b64d(s):
    return base64.b64decode(s.encode("ascii"))


def content_ref(value, redacted=False):
    """Hash reference for content that is not recorded in clear."""
    raw = value if isinstance(value, str) else canon(value)
    data = raw.encode("utf-8")
    return {"hash": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data), "redacted": redacted}


def content_value(value, redacted=False):
    return {"value": value, "redacted": redacted}


# small file helpers that always close what they open
def read_text(path, encoding="utf-8"):
    with open(path, encoding=encoding) as f:
        return f.read()


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_text(path, text, encoding="utf-8"):
    with open(path, "w", encoding=encoding) as f:
        f.write(text)


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


def write_json(path, obj, **kw):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, **kw)
