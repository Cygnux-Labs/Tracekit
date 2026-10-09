"""The v1 → v2 format bridge (tracekit/signer/format_bridge.py) and its continuity check in the v2 verifier."""
import base64
import hashlib
import json
import os
import time
import unittest
import zipfile
from unittest import mock

from factories import ev, make_signer
from test_bundle_v2 import KEY1, LOG_SECRET, ORIGIN, Log, pub, spki
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
        self.trust = os.path.join(d, "trust.json")
        with open(self.trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, ED25519, pub(LOG_SECRET))], "algs": ["ed25519"]}, f)

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
        out = os.path.join(self.data, "run.tkb")
        export(store, "default", run["run_id"], text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET), out)
        return out

    def epochs(self, *bridged):
        """A bundle of a log that starts with one signer.epoch per entry of `bridged`, carrying the bridge if true."""
        b = format_bridge.bridge(self.home, self.data)
        name = "-".join(map(str, bridged))
        log = Log(os.path.join(self.data, name))
        self.addCleanup(log.store.close)
        der = spki(KEY1)
        keys = [{"kid": crypto.spki_kid(der), "alg": "ed25519", "spki": base64.b64encode(der).decode()}]
        for bridge in bridged:
            log.add("signer.epoch", {"keys": keys, **({"bridge": b} if bridge else {})}, run="signer", key=KEY1)
        log.register()
        log.final()
        out = os.path.join(self.data, f"{name}.tkb")
        export(log.store, "acme", "run-a", log.note(), out)
        return out

    def verify(self, out, v1_key=GOLDEN_PUB):
        rep, code = v2.verify(out, self.trust, self.ledger, v1_key)
        return rep, code, {c["check"]: c for c in rep.checks}

    def assert_bridge_fails(self, out, why, v1_key=GOLDEN_PUB):
        rep, code, checks = self.verify(out, v1_key)
        self.assertEqual((code, checks["format bridge"]["status"]), (1, "fail"), rep.checks)
        self.assertIn(why, str(checks["format bridge"]["problems"]))

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

    def test_bridge_epoch_must_be_the_only_one_and_first(self):
        self.assertEqual(self.verify(self.epochs(True))[2]["format bridge"]["status"], "pass")
        for bridged in ((False, True), (True, True)):
            with self.subTest(bridged):
                self.assert_bridge_fails(self.epochs(*bridged), "does not start with one signer.epoch that bridges")

    def test_wrong_v1_key_fails(self):
        format_bridge.bridge(self.home, self.data)
        out = self.bundle()
        other = os.path.join(self.data, "other.pub")
        with open(other, "wb") as f:
            f.write(pub(LOG_SECRET))
        self.assert_bridge_fails(out, "the v1 key is", other)

    def test_v1_chain_break_before_the_bridge_fails(self):
        format_bridge.bridge(self.home, self.data)
        lines = self.ledger_bytes().splitlines(keepends=True)
        seq1 = next(i for i, x in enumerate(lines) if x.startswith(b"{") and json.loads(x).get("event", {}).get("seq") == 1)
        with open(self.ledger, "wb") as f:
            f.write(b"".join(lines[:seq1] + lines[seq1 + 1:]))
        self.assert_bridge_fails(self.bundle(), "does not continue the chain")

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
