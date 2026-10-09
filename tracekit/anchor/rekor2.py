"""Anchor checkpoint notes in a Rekor v2 log (decision S2): a `hashedrekord` v0.0.2 entry over the note bytes, signed
with the signer's P-256 publishing key (Rekor v2 refuses plain Ed25519), plus an RFC 3161 timestamp of the same bytes
(Rekor v2 entries carry no time). The note bytes are the note text and the log's signature line alone
(`tlog_witness.log_signed`): Ed25519 is deterministic, so they are the same for every later copy of the note, whatever
cosignatures it gathers.

The write URLs come from a Sigstore TUF `signing_config` (Rekor `majorApiVersion` 2, TSA 1, valid now), the keys
from its `trusted_root`, whose `tlogs` keep every shard (selected by log id, valid at the timestamp's time).

    POST <rekor>/api/v2/log/entries  {"hashedRekordRequestV002": {...}}  -> TransparencyLogEntry (JSON)

An anchor is {"rekor": TransparencyLogEntry, "tsa": base64 RFC 3161 response}; `verify` checks one offline."""
import base64
import datetime
import hashlib
import json
import urllib.error
import urllib.request

from tracekit.anchor import tsa
from tracekit.anchor.tsa import AnchorError
from tracekit.merkle import leaf_hash, verify_inclusion
from tracekit.tlog_witness import log_signed

TIMEOUT_S = 30.0   # a write returns once Rekor publishes a checkpoint, about 5 s
MAX_RESPONSE = 1 << 20
MIN_EVERY_S = 3600.0   # at most 24 entries a day (Sigstore usage policy)
KEY_DETAILS = "PKIX_ECDSA_P256_SHA_256"


def new_key():
    """A P-256 publishing key's 32-byte private scalar."""
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value.to_bytes(32, "big")


def _private(secret):
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP256R1())


def publishing_key(secret):
    """The base64 DER SubjectPublicKeyInfo of a publishing key, as trust configs pin it."""
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(_private(secret).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")


def _verify_sig(spki, sig, data):
    """Whether `sig` over `data` verifies under a DER SPKI (Ed25519, or ECDSA with SHA-256)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    try:
        key = load_der_public_key(spki)
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(sig, data)
        return True
    except (InvalidSignature, TypeError, ValueError, AttributeError):
        return False


def _b64(s):
    return base64.b64decode(s, validate=True)


def _rekor_checkpoint(envelope, tlog):
    """(size, root) of a Rekor checkpoint note signed by `tlog`'s key. Rekor's key id is the first 4 bytes of its log
    id, not the C2SP key hash."""
    i = envelope.find("\n\n")
    if i < 0:
        raise AnchorError("the Rekor checkpoint has no signatures")
    text, head = envelope[:i + 1], envelope[:i].split("\n")
    spki, kid = _b64(tlog["publicKey"]["rawBytes"]), _b64(tlog["logId"]["keyId"])[:4]
    for line in envelope[i + 2:].splitlines():
        parts = line.split(" ")
        if len(parts) == 3 and parts[:2] == ["—", head[0]]:
            raw = _b64(parts[2])
            if raw[:4] == kid and _verify_sig(spki, raw[4:], text.encode("utf-8")):
                return int(head[1]), _b64(head[2])
    raise AnchorError(f"the Rekor checkpoint is not signed by the pinned key of {head[0][:100]}")


def verify(anchor, data, publishing_spki, trusted_root):
    """(time, Rekor log origin) of an anchor of the note bytes `data`, checked offline: the TSA token over `data`,
    the hashedrekord body binding `data` and the pinned publishing key (DER SPKI), the inclusion proof, and the cosigned
    Rekor checkpoint under the key of the shard (by log id) valid at that time. AnchorError otherwise."""
    if not isinstance(anchor, dict) or not isinstance(anchor.get("rekor"), dict):
        raise AnchorError("not an anchor")
    try:
        at = tsa.verify(_b64(anchor.get("tsa", "")), data, trusted_root)
        tle = anchor["rekor"]
        body = _b64(tle["canonicalizedBody"])
        entry = json.loads(body)
        spec = entry["spec"]["hashedRekordV002"]
        if ((entry["apiVersion"], entry["kind"]) != ("0.0.2", "hashedrekord")
                or spec["data"] != {"algorithm": "SHA2_256",
                                    "digest": base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")}):
            raise AnchorError("the Rekor entry is not a hashedrekord v0.0.2 of these note bytes")
        verifier = spec["signature"]["verifier"]
        if (verifier.get("keyDetails") != KEY_DETAILS or _b64(verifier["publicKey"]["rawBytes"]) != publishing_spki
                or not _verify_sig(publishing_spki, _b64(spec["signature"]["content"]), data)):
            raise AnchorError("the Rekor entry is not signed by the pinned publishing key")
        tlog = next((t for t in trusted_root.get("tlogs") or () if t["logId"]["keyId"] == tle["logId"]["keyId"]), None)
        if tlog is None or not tsa.valid_at(tlog["publicKey"], at):
            raise AnchorError("the Rekor entry is from no shard of the trusted root valid at its time")
        ip = tle["inclusionProof"]
        size, root = int(ip["treeSize"]), _b64(ip["rootHash"])
        if not verify_inclusion(int(ip["logIndex"]), size, leaf_hash(body), [_b64(h) for h in ip["hashes"]], root):
            raise AnchorError("the Rekor inclusion proof does not verify")
        if _rekor_checkpoint(ip["checkpoint"]["envelope"], tlog) != (size, root):
            raise AnchorError("the Rekor checkpoint is not of the proof's tree")
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
        if isinstance(e, AnchorError):
            raise
        raise AnchorError(f"malformed anchor: {type(e).__name__}: {e}") from None
    return at, ip["checkpoint"]["envelope"].split("\n", 1)[0]


def _url(entries, major, now):
    for e in entries or ():
        if isinstance(e, dict) and e.get("majorApiVersion") == major and tsa.valid_at(e, now):
            return e["url"].rstrip("/")
    return None


class RekorAnchor:
    """A publisher for the signer's anchor loop: `add_checkpoint` anchors a note and returns the anchor."""
    name = "rekor"

    def __init__(self, signing_config, trusted_root, secret, every_s=MIN_EVERY_S, timeout=TIMEOUT_S):
        """`signing_config` and `trusted_root`: paths of Sigstore TUF files, pinned local copies.
        lean: pinned TUF files, not fetched and verified from the TUF repository; full TUF client in M3."""
        if not every_s >= MIN_EVERY_S:
            raise ValueError(f"anchors every_s must be at least {MIN_EVERY_S:g} (at most 24 a day)")
        with open(signing_config, "rb") as f:
            self.signing_config = json.loads(f.read())
        with open(trusted_root, "rb") as f:
            self.trusted_root = json.loads(f.read())
        self.every_s, self.timeout, self.key = every_s, timeout, _private(secret)
        self.spki = _b64(publishing_key(secret))
        self._urls()

    def _urls(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        rekor = _url(self.signing_config.get("rekorTlogUrls"), 2, now)
        ts = _url(self.signing_config.get("tsaUrls"), 1, now)
        if not (rekor and ts):
            raise AnchorError("the signing config lists no Rekor v2 log or no TSA valid now")
        return rekor, ts

    def add_checkpoint(self, note, log_vkey, old, proof):
        """Timestamp and anchor the log-signed `note`; the anchor, verified. `old` and `proof` are unused (a witness's
        arguments)."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        rekor, ts = self._urls()
        data = log_signed(note, log_vkey).encode("utf-8")
        tsr, _ = tsa.timestamp(ts, data, self.trusted_root, self.timeout)
        b64 = lambda b: base64.b64encode(b).decode("ascii")   # noqa: E731
        body = json.dumps({"hashedRekordRequestV002": {"digest": b64(hashlib.sha256(data).digest()), "signature": {
            "content": b64(self.key.sign(data, ec.ECDSA(hashes.SHA256()))),
            "verifier": {"publicKey": {"rawBytes": b64(self.spki)}, "keyDetails": KEY_DETAILS}}}}).encode("utf-8")
        req = urllib.request.Request(rekor + "/api/v2/log/entries", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                tle = json.loads(r.read(MAX_RESPONSE))
        except urllib.error.HTTPError as e:
            raise AnchorError(f"Rekor {rekor}: HTTP {e.code}", e.code == 429 or e.code >= 500) from None
        except urllib.error.URLError as e:   # refused, DNS, TLS: not sent; a timeout may be after the write
            raise AnchorError(f"Rekor {rekor}: {e}", True, isinstance(e.reason, TimeoutError)) from None
        except (OSError, ValueError) as e:   # reset, timeout or not JSON after the answer began
            raise AnchorError(f"Rekor {rekor}: {e}", True, True) from None
        anchor = {"rekor": tle, "tsa": b64(tsr)}
        try:
            verify(anchor, data, self.spki, self.trusted_root)
        except AnchorError as e:
            raise AnchorError(str(e), False, True) from None
        return anchor
