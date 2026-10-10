"""Record-key certificates (04-design §3): small signed JSON documents, not X.509.

    {"cert": {"kid", "spki", "log_id", "tenants", "not_before", "not_after", "serial"}, "sig"}
    {"revocation": {"serial", "last_seq"?}, "sig"}

`sig` is the issuer's CA key (Ed25519) over sigmsg.message("cert", cert) or ("retire", revocation). `spki` is base64
DER, `kid` its sha256 kid, times are unix seconds, `serial` hex. A revocation without `last_seq` covers every record of
the key; with it, the records after that seq. Each document is a leaf of the issuer's issuance log: leaf data is
SHA-256(JCS(document)). An issuance entry, as the issuer answers and signer.epoch carries it:

    {"certificate": <cert document>, "index", "inclusion": [base64 hash, ...], "checkpoint": <cosigned C2SP note>}

An issuer is pinned as {"vkey": <CA vkey, type 0x01, named after the issuer>, "issuance_log_vkey": <log key vkey>}."""
import base64
import hashlib

from tracekit import crypto, merkle
from tracekit.format import checkpoint
from tracekit.format.canon import canonical
from tracekit.format.sigmsg import message

CERT_KEYS = {"kid", "spki", "log_id", "tenants", "not_before", "not_after", "serial"}
ENTRY_KEYS = {"certificate", "index", "inclusion", "checkpoint"}
PURPOSE = {"cert": "cert", "revocation": "retire"}


def pop_message(spki, log_id, tenants, ttl_s):
    """What a certificate request's proof of possession signs, with the requested key."""
    return message("cert", {"pop": {"spki": spki, "log_id": log_id, "tenants": tenants, "ttl_s": ttl_s}})


def sign(kind, body, ca_sign):
    """The document {kind: body, sig} ("cert" or "revocation") signed by `ca_sign` (a key's sign(msg))."""
    return {kind: body, "sig": base64.b64encode(ca_sign(message(PURPOSE[kind], body))).decode("ascii")}


def leaf(doc):
    """The issuance log leaf data of a signed document."""
    return hashlib.sha256(canonical(doc)).digest()


def signed_by(doc, vkey):
    """True when `doc` (a cert or revocation document) is signed by the CA key of `vkey`."""
    kind = "cert" if "cert" in doc else "revocation"
    try:
        sig = base64.b64decode(doc["sig"], validate=True)
        public = checkpoint.parse_vkey(vkey)[3]
        return crypto.verify_v2("ed25519", crypto.spki(public), message(PURPOSE[kind], doc[kind]), sig)
    except (ValueError, KeyError, TypeError):
        return False


def _is_cert(c):
    return (isinstance(c, dict) and set(c) == CERT_KEYS
            and all(isinstance(c[k], str) for k in ("kid", "spki", "log_id", "serial"))
            and isinstance(c["tenants"], list) and c["tenants"] and all(isinstance(t, str) for t in c["tenants"])
            and all(type(c[k]) is int for k in ("not_before", "not_after")))


def check(entry, issuers, witnesses=(), required=0):
    """(certificate, pinned issuer) of an issuance entry: signed by the CA key of one of `issuers`, and included in that
    issuer's issuance log at a checkpoint its log key signed and at least `required` of the pinned `witnesses`
    (cosignature vkeys) cosigned. ValueError otherwise."""
    if not (isinstance(entry, dict) and set(entry) == ENTRY_KEYS and isinstance(entry["certificate"], dict)
            and set(entry["certificate"]) == {"cert", "sig"} and _is_cert(entry["certificate"]["cert"])
            and type(entry["index"]) is int and isinstance(entry["inclusion"], list)
            and isinstance(entry["checkpoint"], str)):
        raise ValueError("not a certificate issuance entry")
    doc = entry["certificate"]
    pin = next((p for p in issuers if signed_by(doc, p["vkey"])), None)
    if pin is None:
        raise ValueError("certificate not signed by a pinned issuer")
    try:
        _, size, root, cosigs = checkpoint.open_note(entry["checkpoint"], [pin["issuance_log_vkey"]], list(witnesses))
        proof = [base64.b64decode(p, validate=True) for p in entry["inclusion"]]
    except (checkpoint.NoteError, ValueError, TypeError) as e:
        raise ValueError(f"issuance checkpoint: {e}") from None
    if len(cosigs) < required:
        raise ValueError(f"issuance checkpoint has {len(cosigs)} pinned cosignature(s), {required} required")
    if not merkle.verify_inclusion(entry["index"], size, merkle.leaf_hash(leaf(doc)), proof, root):
        raise ValueError("certificate not in the issuer's issuance log")
    return doc["cert"], pin


def revocation(doc, issuers):
    """(pinned issuer vkey, serial, last_seq or -1) of a revocation document signed by one of `issuers`; None when it
    is not a revocation document; ValueError when no pinned issuer signed it."""
    r = doc.get("revocation") if isinstance(doc, dict) and set(doc) == {"revocation", "sig"} else None
    if r is None:
        return None
    if not (isinstance(r, dict) and isinstance(r.get("serial"), str) and set(r) <= {"serial", "last_seq"}
            and type(r.get("last_seq", -1)) is int):
        raise ValueError("malformed revocation")
    pin = next((p for p in issuers if signed_by(doc, p["vkey"])), None)
    if pin is None:
        raise ValueError(f"revocation of serial {r['serial'][:64]} not signed by a pinned issuer")
    return pin["vkey"], r["serial"], r.get("last_seq", -1)
