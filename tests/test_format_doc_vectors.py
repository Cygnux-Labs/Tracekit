"""The worked examples in docs/format-v2.md, recomputed from the code, so the spec can't drift from it."""
import hmac
import json
import os
import types
import unittest

from tracekit import merkle
from tracekit.format import canon, checkpoint, registry, sigmsg
from tracekit.signer import service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*path):
    with open(os.path.join(ROOT, *path), encoding="utf-8") as f:
        return f.read()


DOC = _read("docs", "format-v2.md")


class FormatDocVectors(unittest.TestCase):
    def test_canonical_json_example(self):
        self.assertEqual(canon.canonical(json.loads('{"b":1,"a":[1.0,"é",1e21]}')).decode(), '{"a":[1,"é",1e+21],"b":1}')
        self.assertIn('{"b":1,"a":[1.0,"é",1e21]}  →  {"a":[1,"é",1e+21],"b":1}', DOC)

    def test_domain_tags(self):
        for purpose in sigmsg.PURPOSES:
            self.assertIn(sigmsg.message(purpose, {}).decode(), DOC)

    def test_signature_message_and_leaf_hash(self):
        v = json.loads(_read("tests", "vectors", "sig_v2.jsonl").splitlines()[0])
        r = v["record"]
        msg = sigmsg.sig_message_v2({**r["event"], "alg": r["alg"], "kid": r["kid"], "hash": r["hash"]}).decode()
        self.assertEqual(msg, v["message"])
        self.assertIn(msg, DOC)
        self.assertIn(merkle.leaf_hash(bytes.fromhex(r["hash"][7:])).hex(), DOC)
        self.assertIn(merkle.root([]).hex(), DOC)

    def test_checkpoint_note(self):
        v = json.loads(_read("tests", "vectors", "c2sp_checkpoint.json"))
        origin, size, root, cosigs = checkpoint.open_note(v["note"], [v["log_vkey"]], [v["wit_vkey"]])
        self.assertEqual(checkpoint.body(origin, size, root), v["text"])
        self.assertEqual(len(cosigs), 1)
        self.assertIn(v["text"], DOC)
        for k in (v["log_vkey"], v["wit_vkey"]):
            self.assertIn(k, DOC)
        self.assertIn(f"key id\n`{checkpoint.parse_vkey(v['log_vkey'])[1].hex()}`", DOC)

    def test_args_commitment(self):
        _, digest = service.SignerService._args({"tool": "Bash", "args_source": "parsed", "args": {"command": "ls -la"}})
        self.assertIn(f"digest      {digest}", DOC)
        salt = bytes(range(32))
        self.assertIn(f"commitment  hmac-sha256:{hmac.new(salt, digest.encode(), 'sha256').hexdigest()}", DOC)
        # what the signer publishes is that formula under the salt `reveal` prints for the record's label
        key, label = b"k" * 32, "tool.call:" + "0" * 32
        signer = types.SimpleNamespace(_salt_key=key)
        self.assertEqual(service.SignerService._commit(signer, label, digest),
                         "hmac-sha256:" + hmac.new(service._salt(key, label), digest.encode(), "sha256").hexdigest())

    def test_registry_example(self):
        tsalt = registry.tenant_salt(bytes(32), "acme")
        self.assertIn(f"tenant_salt        {tsalt.hex()}", DOC)
        self.assertIn(f'H(salt ‖ "run-1")  {registry.run_hash(tsalt, "run-1").hex()}', DOC)
        self.assertIn(f"registry origin    {registry.origin('tracekit.example.org/log/1', tsalt)}", DOC)
        self.assertEqual(registry.LEAF_SIZE, 1 + 32 + 16 + 8 + 32)
        for name, n in registry.LEAF_TYPES.items():
            self.assertIn(f"| {n} | `{name}`", DOC)


if __name__ == "__main__":
    unittest.main()
