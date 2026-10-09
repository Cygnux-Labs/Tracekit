"""The v1 → v2 format bridge (tracekit/signer/format_bridge.py) and its continuity check in the v2 verifier."""
import hashlib
import json
import os
import time
import unittest
import zipfile
from unittest import mock

from factories import ev, make_signer
from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from test_signer_service import ME, records, tmpdir
from tracekit import crypto
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.checkpoint import ED25519
from tracekit.ledger import Keys, Ledger
from tracekit.signer import format_bridge
from tracekit.signer import service as svc
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "v1")
GOLDEN_PUB = os.path.join(GOLDEN, "golden.pub")
GOLDEN_SECRET = hashlib.sha256(b"tracekit golden corpus: file key").digest()   # tests/golden/make_golden.py


class Bridge(unittest.TestCase):
    def setUp(self):
        d = tmpdir(self)
        self.home, self.data = os.path.join(d, "v1"), os.path.join(d, "v2")
        self.ledger, self.key = os.path.join(self.home, "ledger", "ledger.jsonl"), os.path.join(self.home, "keys", "signer.key")
        os.makedirs(os.path.dirname(self.ledger))
        os.makedirs(os.path.dirname(self.key), mode=0o700)
        with zipfile.ZipFile(os.path.join(GOLDEN, "torn-ledger.tkb")) as z, open(self.ledger, "wb") as f:
            f.write(z.read("records.jsonl"))
        with open(self.key, "wb") as f:
            f.write(GOLDEN_SECRET)
        with open(GOLDEN_PUB, "rb") as f:
            self.assertEqual(crypto.public_from_secret(GOLDEN_SECRET), f.read())

    def ledger_bytes(self):
        with open(self.ledger, "rb") as f:
            return f.read()

    def bundle(self):
        """A v2 signer run on the bridged store, closed to run.final, exported with a checkpoint of the whole log."""
        s = svc.SignerService(self.data, grace_s=60)
        run = s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        run = {"run_id": run["run_id"], "run_token": run["run_token"]}
        s.call(ME, "close_run", {"request_id": "r2", **run})
        s.sweep(time.monotonic() + 61)
        s.close()
        store = FileStorage(os.path.join(self.data, "store"))
        self.addCleanup(store.close)
        size = store.tree.size
        text = checkpoint.body(ORIGIN, size, store.tree.root_at(size))
        out, self.trust = os.path.join(self.data, "run.tkb"), os.path.join(self.data, "trust.json")
        export(store, "default", run["run_id"], text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET), out)
        with open(self.trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))], "algs": ["ed25519"]}, f)
        return out

    def verify(self, out):
        rep, code = v2.verify(out, self.trust, self.ledger, GOLDEN_PUB)
        return rep, code, {c["check"]: c for c in rep.checks}

    def test_bridged_ledger_continues_into_a_verified_v2_bundle(self):
        b = format_bridge.bridge(self.home, self.data)
        first = records(self.data)[0]["event"]
        self.assertEqual((first["seq"], first["type"], first["data"]["bridge"]), (0, "signer.epoch", b))
        self.assertEqual(b["v1_last_seq"], 4)   # golden seq 0..2, then format_upgrade and the key retirement
        self.assertFalse(os.path.exists(self.key))
        self.assertTrue(os.path.exists(os.path.join(self.home, "keys", "signer.pub")))
        rep, code, checks = self.verify(self.bundle())
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
        self.assertEqual(checks["format bridge"]["status"], "pass")

    def test_v1_record_after_the_bridge_fails(self):
        copy = Keys(GOLDEN_SECRET, crypto.public_from_secret(GOLDEN_SECRET))   # taken before the bridge destroys it
        format_bridge.bridge(self.home, self.data)
        led = Ledger(self.ledger, copy)
        led.append({**ev("tool.call", {"tool_use_id": "t9", "name": "Bash", "input": {}}, "golden-torn"),
                    "schema_version": "tracekit.event.v1", "id": "0" * 32})
        led.close()
        rep, code, checks = self.verify(self.bundle())
        self.assertEqual((code, rep.integrity), (1, "FAILED"))
        self.assertIn("v1 record after format bridge", checks["format bridge"]["problems"][0])

    def test_second_run_is_a_no_op(self):
        b = format_bridge.bridge(self.home, self.data)
        before = (self.ledger_bytes(), records(self.data))
        self.assertEqual(format_bridge.bridge(self.home, self.data), b)
        self.assertEqual((self.ledger_bytes(), records(self.data)), before)

    def test_interrupted_after_the_v1_records_resumes(self):
        with mock.patch.object(svc, "SignerService", side_effect=OSError("killed")):
            with self.assertRaises(OSError):
                format_bridge.bridge(self.home, self.data)
        self.assertTrue(os.path.exists(self.key))
        v1 = self.ledger_bytes()
        b = format_bridge.bridge(self.home, self.data)
        self.assertEqual(self.ledger_bytes(), v1)   # no second bridge
        self.assertEqual(records(self.data)[0]["event"]["data"]["bridge"], b)
        self.assertFalse(os.path.exists(self.key))

    def test_store_with_records_is_refused(self):
        svc.SignerService(self.data).close()
        v1 = self.ledger_bytes()
        with self.assertRaisesRegex(format_bridge.BridgeError, "already has records"):
            format_bridge.bridge(self.home, self.data)
        self.assertEqual(self.ledger_bytes(), v1)
        self.assertTrue(os.path.exists(self.key))

    def test_running_v1_daemon_is_refused(self):
        s = make_signer(self.home, mode="dev", witnesses=[])
        try:
            with self.assertRaisesRegex(format_bridge.BridgeError, "tracekitd is running"):
                format_bridge.bridge(self.home, self.data)
        finally:
            s.ledger.close()
        self.assertTrue(os.path.exists(self.key))


if __name__ == "__main__":
    unittest.main()
