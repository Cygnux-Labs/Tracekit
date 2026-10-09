"""Rekor transparency-log witness (experimental, off unless TRACEKIT_ENABLE_REKOR=1).

Publishing puts the signed checkpoint in a public, append-only Sigstore log. Reading is strict:
every entry must carry a signed entry timestamp from a Rekor key you pinned (TRACEKIT_REKOR_PUBKEY, the
PEM from <server>/api/v1/log/publicKey) AND a valid RFC 6962 inclusion proof. Without a pinned key
`read()` refuses rather than trust whatever a server says.

The cryptography here (Merkle inclusion proofs, ECDSA signed entry timestamps, Ed25519 SPKI encoding) is
tested offline against self-generated logs. It has not been exercised against the live Sigstore service
from this build environment (network allowlist); treat the first real run as a validation step."""
import base64
import hashlib
import json
import os
import urllib.error
import urllib.request

from .core import b64d, b64e, canon

MAX_ENTRIES = 5000
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


# ---------- RFC 6962 / RFC 9162 Merkle tree ----------
def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(leaf_index, tree_size, leaf, proof, root):
    """RFC 9162 section 2.1.3.2. All hashes are raw bytes."""
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        return False
    fn, sn, r = leaf_index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root


# ---------- keys and signed entry timestamps ----------
def ed25519_spki_pem(public):
    der = _ED25519_SPKI_PREFIX + bytes(public)
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n").encode()


def verify_set(entry, rekor_pubkey_pem):
    """Check Rekor's signed entry timestamp over {body, integratedTime, logID, logIndex}."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = serialization.load_pem_public_key(rekor_pubkey_pem)
        payload = {"body": entry["body"], "integratedTime": entry["integratedTime"],
                   "logID": entry["logID"], "logIndex": entry["logIndex"]}
        key.verify(base64.b64decode(entry["verification"]["signedEntryTimestamp"]),
                   canon(payload).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def entry_checkpoint(entry):
    """The signed checkpoint a rekord entry commits to (its content plus the entry's signature), or None."""
    try:
        body = json.loads(base64.b64decode(entry["body"]))
        cp = json.loads(base64.b64decode(body["spec"]["data"]["content"]))
        if not isinstance(cp, dict):
            return None
        return dict(cp, sig=b64e(base64.b64decode(body["spec"]["signature"]["content"])))
    except (KeyError, TypeError, ValueError):
        return None


def check_entry(entry, rekor_pubkey_pem):
    """-> None if the entry is authentic, else the reason it is not."""
    proof = (entry.get("verification") or {}).get("inclusionProof")
    if not proof:
        return "no inclusion proof"
    try:
        ok = verify_inclusion(int(proof["logIndex"]), int(proof["treeSize"]), leaf_hash(base64.b64decode(entry["body"])),
                              [bytes.fromhex(h) for h in proof["hashes"]], bytes.fromhex(proof["rootHash"]))
    except (KeyError, TypeError, ValueError):
        return "malformed inclusion proof"
    if not ok:
        return "inclusion proof does not verify"
    if not verify_set(entry, rekor_pubkey_pem):
        return "signed entry timestamp does not verify against the pinned Rekor key"
    return None


class RekorWitness:
    needs_public = True

    def __init__(self, url, pubkey_path=None):
        self.url = url.rstrip("/")
        if not self.url.startswith("https://") and not self.url.startswith("http://127.0.0.1"):
            raise ValueError("rekor URL must be https://")
        self.name = f"rekor:{self.url}"
        self.pubkey_path = pubkey_path or os.environ.get("TRACEKIT_REKOR_PUBKEY")
        self.public = None

    def bind_key(self, public):
        self.public = public

    # transport, replaceable in tests
    def _http(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, None

    def _key_b64(self, public):
        return base64.b64encode(ed25519_spki_pem(public)).decode()

    def publish(self, cp):
        if not self.public:
            raise RuntimeError("rekor witness has no signer key bound")
        content = canon({k: v for k, v in cp.items() if k != "sig"}).encode("utf-8")
        entry = {"apiVersion": "0.0.1", "kind": "rekord", "spec": {
            "data": {"content": base64.b64encode(content).decode()},
            "signature": {"format": "x509", "content": base64.b64encode(b64d(cp["sig"])).decode(),
                          "publicKey": {"content": self._key_b64(self.public)}}}}
        status, _ = self._http("POST", "/api/v1/log/entries", entry)
        if status not in (200, 201, 409):  # 409: already in the log
            raise RuntimeError(f"rekor answered HTTP {status}")
        return self.name

    def read(self, public=None):
        public = public or self.public
        if not public:
            raise RuntimeError("rekor witness needs the signer's public key to find its checkpoints")
        if not self.pubkey_path:
            raise RuntimeError("set TRACEKIT_REKOR_PUBKEY to the pinned Rekor public key (PEM): unauthenticated log "
                               "responses are not trusted")
        with open(self.pubkey_path, "rb") as f:
            rekor_pem = f.read()
        status, uuids = self._http("POST", "/api/v1/index/retrieve", {"publicKey": {"format": "x509", "content": self._key_b64(public)}})
        if status != 200 or not isinstance(uuids, list):
            raise RuntimeError(f"rekor index lookup failed (HTTP {status})")
        out = []
        for uuid in uuids[:MAX_ENTRIES]:
            status, got = self._http("GET", "/api/v1/log/entries/" + str(uuid))
            if status != 200 or not isinstance(got, dict):
                continue
            for entry in got.values():
                if isinstance(entry, dict) and check_entry(entry, rekor_pem) is None:
                    cp = entry_checkpoint(entry)
                    if cp:
                        out.append(cp)
        return out
