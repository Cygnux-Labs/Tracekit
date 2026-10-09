"""Rekor witness: Merkle proofs, signed entry timestamps and the client flow against a local fake log."""
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from tracekit import crypto, rekor, witness  # noqa: E402
from tracekit.core import canon  # noqa: E402
from tracekit.ledger import Keys  # noqa: E402


def mth(leaves):
    """RFC 6962 Merkle tree hash of raw leaf hashes."""
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return rekor.node_hash(mth(leaves[:k]), mth(leaves[k:]))


def path(m, leaves):
    """RFC 6962 audit path for leaf m."""
    n = len(leaves)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]


class Merkle(unittest.TestCase):
    def test_inclusion_proofs_for_every_leaf_of_every_small_tree(self):
        for n in range(1, 34):
            leaves = [rekor.leaf_hash(f"entry{i}".encode()) for i in range(n)]
            root = mth(leaves)
            for m in range(n):
                self.assertTrue(rekor.verify_inclusion(m, n, leaves[m], path(m, leaves), root), (n, m))

    def test_wrong_leaf_index_size_or_proof_fails(self):
        n = 13
        leaves = [rekor.leaf_hash(bytes([i])) for i in range(n)]
        root, proof = mth(leaves), path(5, leaves)
        self.assertFalse(rekor.verify_inclusion(6, n, leaves[5], proof, root))
        self.assertFalse(rekor.verify_inclusion(5, 40, leaves[5], proof, root))
        self.assertFalse(rekor.verify_inclusion(5, n, leaves[4], proof, root))
        self.assertFalse(rekor.verify_inclusion(5, n, leaves[5], proof[:-1], root))
        self.assertFalse(rekor.verify_inclusion(5, n, leaves[5], proof + [b"x" * 32], root))
        self.assertFalse(rekor.verify_inclusion(-1, n, leaves[5], proof, root))
        self.assertFalse(rekor.verify_inclusion(0, 0, leaves[0], [], root))

    def test_known_single_leaf_vector(self):
        # RFC 6962: the hash of the empty-string leaf is SHA-256(0x00)
        self.assertEqual(rekor.leaf_hash(b"").hex(), hashlib.sha256(b"\x00").hexdigest())


class FakeLog(rekor.RekorWitness):
    """An in-memory Rekor: stores rekord entries, signs timestamps with its own ECDSA key."""

    def __init__(self, tmp):
        super().__init__("https://rekor.test", pubkey_path=os.path.join(tmp, "rekor.pem"))
        self.key = ec.generate_private_key(ec.SECP256R1())
        with open(self.pubkey_path, "wb") as f:
            f.write(self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.bodies, self.by_key, self.tamper = [], {}, None

    def _entry(self, i):
        leaves = [rekor.leaf_hash(b) for b in self.bodies]
        body = base64.b64encode(self.bodies[i]).decode()
        e = {"body": body, "integratedTime": 1700000000 + i, "logID": "abc", "logIndex": i}
        sig = self.key.sign(canon({k: e[k] for k in ("body", "integratedTime", "logID", "logIndex")}).encode(), ec.ECDSA(hashes.SHA256()))
        e["verification"] = {"signedEntryTimestamp": base64.b64encode(sig).decode(),
                             "inclusionProof": {"logIndex": i, "treeSize": len(leaves), "rootHash": mth(leaves).hex(),
                                                "hashes": [h.hex() for h in path(i, leaves)]}}
        return e

    def _http(self, method, p, payload=None):
        if method == "POST" and p == "/api/v1/log/entries":
            body = json.dumps(payload, sort_keys=True).encode()
            self.bodies.append(body)
            self.by_key.setdefault(payload["spec"]["signature"]["publicKey"]["content"], []).append(len(self.bodies) - 1)
            return 201, {}
        if method == "POST" and p == "/api/v1/index/retrieve":
            return 200, [f"u{i}" for i in self.by_key.get(payload["publicKey"]["content"], [])]
        if method == "GET" and p.startswith("/api/v1/log/entries/u"):
            e = self._entry(int(p.rsplit("u", 1)[1]))
            if self.tamper:
                self.tamper(e)
            return 200, {p.rsplit("/", 1)[1]: e}
        return 404, None


class RekorFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.keys = Keys(*crypto.generate())
        self.log = FakeLog(self.tmp)
        self.log.bind_key(self.keys.public)

    def cp(self, seq):
        return witness.make_checkpoint(seq, hashlib.sha256(str(seq).encode()).hexdigest(), self.keys)

    def test_publish_then_read_returns_the_checkpoints(self):
        cps = [self.cp(s) for s in (10, 20, 30)]
        for c in cps:
            self.log.publish(c)
        got = self.log.read()
        self.assertEqual(sorted(g["head_seq"] for g in got), [10, 20, 30])
        for g in got:
            self.assertTrue(g["head_hash"])
            self.assertTrue(witness.verify_checkpoint(g, self.keys.public), "read() returns the signed checkpoint")
        self.assertEqual(sorted(got, key=lambda g: g["head_seq"]), cps)

    def test_published_entry_binds_the_checkpoint_signature_and_key(self):
        c = self.cp(7)
        self.log.publish(c)
        body = json.loads(self.log.bodies[0])
        self.assertEqual(body["kind"], "rekord")
        self.assertEqual(len(base64.b64decode(body["spec"]["signature"]["content"])), 64)  # an Ed25519 signature
        data = json.loads(base64.b64decode(body["spec"]["data"]["content"]))
        self.assertEqual(data["head_seq"], 7)
        pem = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
        self.assertTrue(pem.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_forged_or_unproven_entries_are_dropped(self):
        self.log.publish(self.cp(1))
        for name, mutate in {
            "bad inclusion": lambda e: e["verification"]["inclusionProof"].update(rootHash="00" * 32),
            "bad SET": lambda e: e["verification"].update(signedEntryTimestamp=base64.b64encode(b"x" * 70).decode()),
            "no proof": lambda e: e["verification"].pop("inclusionProof"),
            "edited body": lambda e: e.update(body=base64.b64encode(b"{}").decode()),
        }.items():
            self.log.tamper = mutate
            self.assertEqual(self.log.read(), [], name)

    def test_entry_signed_by_a_different_rekor_key_is_rejected(self):
        self.log.publish(self.cp(1))
        other = ec.generate_private_key(ec.SECP256R1())
        with open(self.log.pubkey_path, "wb") as f:
            f.write(other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.assertEqual(self.log.read(), [])

    def test_read_refuses_without_a_pinned_key(self):
        self.log.pubkey_path = None
        with self.assertRaises(RuntimeError):
            self.log.read()

    def test_spec_requires_opt_in_and_https(self):
        os.environ.pop("TRACEKIT_ENABLE_REKOR", None)
        with self.assertRaises(ValueError):
            witness.from_spec("rekor:https://rekor.sigstore.dev")
        os.environ["TRACEKIT_ENABLE_REKOR"] = "1"
        try:
            self.assertIsInstance(witness.from_spec("rekor:https://rekor.sigstore.dev"), rekor.RekorWitness)
            with self.assertRaises(ValueError):
                witness.from_spec("rekor:http://example.com")
        finally:
            os.environ.pop("TRACEKIT_ENABLE_REKOR", None)

    def test_spki_encoding_of_ed25519_key(self):
        pem = rekor.ed25519_spki_pem(self.keys.public)
        key = serialization.load_pem_public_key(pem)
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertEqual(raw, bytes(self.keys.public))


class VerifyAgainstRekor(unittest.TestCase):
    def test_verify_with_a_rekor_witness_passes(self):
        import shutil
        from unittest import mock
        from tracekit import bundle, install
        from tracekit.agent_sdk import Tracer
        d = tempfile.mkdtemp()
        old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(d, "client")
        home = os.path.join(d, "signer")
        try:
            install.init_dev(home, [], start=True)
            with Tracer(agent="bot", session_id="rk-1", cwd=d) as t:
                with t.tool("Bash", {"command": "ls"}) as c:
                    c.result("x")
            tkb = os.path.join(d, "run.tkb")
            bundle.export(home, tkb, run="rk-1")
            manifest, blobs = bundle.load_bundle(tkb)
            log = FakeLog(d)
            log.bind_key(blobs["signer.pub"])
            for line in blobs["checkpoints.jsonl"].decode().splitlines():
                log.publish(json.loads(line))
            with mock.patch.object(bundle, "from_spec", return_value=log):
                rep, code = bundle.verify(tkb, ["rekor:https://rekor.test"])
            self.assertEqual(code, 0, rep.checks)
            trust = next(c for c in rep.checks if c["check"] == "trust root")
            self.assertEqual(trust["status"], "pass", trust)
            self.assertIn("rekor:https://rekor.test", trust["detail"])
        finally:
            install.stop_dev_daemon(home)
            if old is None:
                os.environ.pop("TRACEKIT_CLIENT_HOME", None)
            else:
                os.environ["TRACEKIT_CLIENT_HOME"] = old
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
