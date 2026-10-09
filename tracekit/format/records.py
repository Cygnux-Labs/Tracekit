"""Format v2 records: {"v": 2, "event", "hash": sha256(JCS(event)), "alg", "kid", "sig"}."""
import base64

from tracekit import crypto
from tracekit.format.canon import event_hash
from tracekit.format.sigmsg import sig_message_v2

KEYS = {"v", "event", "hash", "alg", "kid", "sig"}
_EVENT_FIELDS = ("log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash")


class RecordError(ValueError):
    pass


def _message(event, alg, kid, h):
    return sig_message_v2({**{k: event.get(k) for k in _EVENT_FIELDS}, "alg": alg, "kid": kid, "hash": h})


class RecordSigner:
    """Signs records with one Ed25519 secret key, derived into a signing key, SPKI and kid once."""
    alg = "ed25519"

    def __init__(self, secret):
        self.spki = crypto.spki(crypto.public_from_secret(secret))
        self.kid = crypto.spki_kid(self.spki)
        self._sign = crypto.sign_fn(secret)

    def __call__(self, event):
        h = event_hash(event)
        sig = self._sign(_message(event, self.alg, self.kid, h))
        return {"v": 2, "event": event, "hash": h, "alg": self.alg, "kid": self.kid,
                "sig": base64.b64encode(sig).decode("ascii")}


def make_record(event, secret):
    """Sign `event` with an Ed25519 secret key."""
    return RecordSigner(secret)(event)


def verify_record(record, keys, algs):
    """Raise RecordError unless `record` is a v2 record signed by one of `keys` (SPKI DER) with an algorithm from
    `algs`, the verifier's pinned allow-list, that is also the key's own algorithm."""
    if (not isinstance(record, dict) or set(record) != KEYS or record["v"] != 2 or not isinstance(record["event"], dict)
            or not all(isinstance(record[k], str) for k in ("hash", "alg", "kid", "sig"))):
        raise RecordError("not a v2 record")
    try:
        h = event_hash(record["event"])
    except ValueError as e:
        raise RecordError(f"event is not canonical JSON: {e}") from None
    if record["hash"] != h:
        raise RecordError("hash does not match the event")
    alg = record["alg"]
    if alg not in algs:
        raise RecordError(f"algorithm {alg!r} is not allowed")
    key = {crypto.spki_kid(k): k for k in keys}.get(record["kid"])
    if key is None:
        raise RecordError("unknown kid")
    if crypto.key_alg(key) != alg:
        raise RecordError(f"algorithm {alg!r} is not the key's algorithm")
    try:
        sig = base64.b64decode(record["sig"], validate=True)
    except ValueError:  # binascii.Error, non-ASCII text
        raise RecordError("sig is not base64") from None
    if not crypto.verify_v2(alg, key, _message(record["event"], alg, record["kid"], h), sig):
        raise RecordError("bad signature")
