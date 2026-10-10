"""Hybrid checkpoint signatures (04-design §3.1): an SLH-DSA-SHA2-128s line (tracekit/format/slh_dsa.py) under a type
0xff key next to the log's Ed25519 line, on every stored note; never sent to witnesses; required by a verifier that
pins it."""
import base64
import contextlib
import io
import json
import os
import unittest
from unittest import mock

from factories import wait_for
from test_signer_service import ME, tmpdir
from test_witness_publish import NAME, ORIGIN, VKEY, FakeWitness
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint, registry, slh_dsa
from tracekit.signer import service as svc
from tracekit.storage.base import RECORDS, registry_tree
from tracekit.tlog_witness import TlogWitness
from tracekit.verify import v2

TESTS = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(TESTS, "vectors", "slh_dsa_note.json"), encoding="utf-8") as _f:
    VEC = json.load(_f)


def lines(note):
    return note.split("\n\n", 1)[1].splitlines(keepends=True)


class Vector(unittest.TestCase):
    def test_vector_keys_ids_and_signature(self):
        pk = bytes.fromhex(VEC["slh_public"])
        self.assertEqual(slh_dsa.keygen(bytes.fromhex(VEC["slh_seed"]))[1], pk)
        origin = VEC["text"].split("\n")[0]
        self.assertEqual(checkpoint.vkey(origin, checkpoint.HYBRID, checkpoint.SLH_DSA + pk), VEC["slh_vkey"])
        self.assertEqual(checkpoint.parse_vkey(VEC["slh_vkey"]),
                         (origin, bytes.fromhex(VEC["slh_key_id"]), checkpoint.HYBRID, checkpoint.SLH_DSA + pk))
        self.assertEqual(checkpoint.parse_vkey(VEC["log_vkey"])[1].hex(), VEC["log_key_id"])
        sig = base64.b64decode(lines(VEC["note"])[1].split(" ")[-1])[4:]   # made by another implementation
        self.assertTrue(slh_dsa.verify(pk, VEC["text"].encode(), sig))
        self.assertEqual(checkpoint.open_note(VEC["note"], [VEC["log_vkey"], VEC["slh_vkey"]])[1], 13)
        self.assertEqual(checkpoint.open_note(VEC["note"], [VEC["log_vkey"]])[1], 13)   # unpinned: ignored

    def test_both_pinned_lines_must_hold(self):
        ed, hybrid = lines(VEC["note"])
        text, pinned = VEC["text"], [VEC["log_vkey"], VEC["slh_vkey"]]
        blob = bytearray(base64.b64decode(hybrid.split(" ")[-1]))
        blob[100] ^= 1
        bad_hybrid = hybrid.rsplit(" ", 1)[0] + " " + base64.b64encode(blob).decode() + "\n"
        blob = bytearray(base64.b64decode(ed.split(" ")[-1]))
        blob[10] ^= 1
        forged_ed = ed.rsplit(" ", 1)[0] + " " + base64.b64encode(blob).decode() + "\n"
        for note, error in ((text + "\n" + ed, "no SLH-DSA signature"),
                            (text + "\n" + ed + bad_hybrid, "bad SLH-DSA signature"),
                            (text + "\n" + forged_ed + hybrid, "bad signature from pinned key"),
                            (text + "\n" + hybrid, "no signature from a pinned log key")):
            with self.subTest(error), self.assertRaisesRegex(checkpoint.NoteError, error):
                checkpoint.open_note(note, pinned)

    def test_sign_and_verify(self):
        sk, pk = slh_dsa.keygen()
        sig = slh_dsa.sign(sk, b"note\n")
        self.assertEqual((len(sig), slh_dsa.public(sk)), (slh_dsa.SIG_SIZE, pk))
        self.assertTrue(slh_dsa.verify(pk, b"note\n", sig))
        self.assertFalse(slh_dsa.verify(pk, b"note!", sig))
        self.assertFalse(slh_dsa.verify(pk, b"note\n", sig[:-1]))
        self.assertFalse(slh_dsa.verify(slh_dsa.keygen()[1], b"note\n", sig))

    def test_a_pinned_hybrid_key_fails_a_bundle_without_its_line(self):
        golden = os.path.join(TESTS, "golden", "v2")
        with open(os.path.join(golden, "trust.json")) as f:
            trust = json.load(f)
        origin = checkpoint.parse_vkey(trust["logs"][0])[0]
        trust["logs"].append(checkpoint.vkey(origin, checkpoint.HYBRID, checkpoint.SLH_DSA + slh_dsa.keygen()[1]))
        path = os.path.join(tmpdir(self), "trust.json")
        with open(path, "w") as f:
            json.dump(trust, f)
        rep, code = v2.verify(os.path.join(golden, "closed.tkb"), path)
        self.assertEqual((rep.integrity, code), ("FAILED", 1), rep.checks)
        self.assertIn("no SLH-DSA signature", next(c["detail"] for c in rep.checks if c["check"] == "checkpoint"))


class Signer(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir(self)
        self.key = os.path.join(self.dir, "keys", "log-slh.key")
        self.w = FakeWitness()
        self.addCleanup(self.w.stop)
        p = mock.patch.object(svc, "TICK_S", 0.05)
        p.start()
        self.addCleanup(p.stop)
        s = svc.SignerService(self.dir, origin=ORIGIN)   # the witness knows the logs before the startup check
        s.close()
        public = checkpoint.parse_vkey(s.vkey)[3]
        for origin in (ORIGIN, registry.origin(ORIGIN, s.log.tenant_salt("default"))):
            self.w.logs[origin] = checkpoint.vkey(origin, checkpoint.ED25519, public)
        self.s = svc.SignerService(self.dir, grace_s=0, origin=ORIGIN, slh_dsa_file=self.key,
                                   witnesses=[TlogWitness(self.w.url, VKEY, timeout=2)])
        self.addCleanup(self.s.close)

    def cosigned(self, tree=RECORDS):
        latest = self.s.log.storage.checkpoint_latest(tree)
        return latest and f"— {NAME} " in latest[1] and latest

    def test_hybrid_notes_witnessed_without_the_line_and_verified(self):
        out = self.s.call(ME, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        self.s.call(ME, "close_run", {"request_id": "r2", "run_id": out["run_id"], "run_token": out["run_token"]})
        self.s.sweep()
        self.s.checkpoint()
        size, note = wait_for(self.cosigned, 15)
        reg = wait_for(lambda: self.cosigned(registry_tree("default")), 15)[1]
        vkeys = svc.read_vkeys(self.dir)
        self.assertEqual([checkpoint.parse_vkey(k)[2] for k in vkeys], [checkpoint.ED25519, checkpoint.HYBRID])
        self.assertEqual(checkpoint.open_note(note, vkeys, [VKEY])[1], size)
        reg_origin = reg.split("\n", 1)[0]
        checkpoint.open_note(reg, [checkpoint.vkey(reg_origin, *checkpoint.parse_vkey(k)[2:]) for k in vkeys])
        sent = [b.decode().split("\n\n", 1)[1] for b in self.w.bodies]
        self.assertTrue(sent)
        for body in sent:   # the note text and the Ed25519 line only
            self.assertEqual(len(lines(body)), 1, body)
        self.assertEqual(len(lines(note)), 3)   # Ed25519, SLH-DSA, the witness's cosignature

        trust = os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": vkeys, "witnesses": [{"vkey": VKEY, "class": "customer"}], "algs": ["ed25519"],
                       "witnesses_required": 1}, f)
        bundle = os.path.join(self.dir, "run.tkb")
        export(self.s.log.storage, "default", out["run_id"], note, bundle)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual((rep.integrity, code), ("VERIFIED", 0), rep.checks)
        self.assertIn(f"checkpoint Ed25519 + SLH-DSA-SHA2-128s ({ORIGIN})", rep.assurance)
        self.assertIn("; earliest independent anchor ", rep.assurance)

        ed = lines(note)[0]   # a forged Ed25519 signature next to a valid SLH-DSA line still fails
        text = note[:note.index("\n\n") + 1]
        bad = bytearray(base64.b64decode(ed.split(" ")[2]))
        bad[10] ^= 1
        forged = text + "\n" + ed.rsplit(" ", 1)[0] + " " + base64.b64encode(bad).decode() + "\n" + "".join(
            lines(note)[1:])
        export(self.s.log.storage, "default", out["run_id"], forged, bundle + "2")
        rep, code = v2.verify(bundle + "2", trust)
        self.assertEqual((rep.integrity, code), ("FAILED", 1), rep.checks)
        self.assertIn("checkpoint", rep.failures)

    def test_config_vkey_and_trust(self):
        cfg = os.path.join(self.dir, "signer.yaml")
        for log_key, ok in (({"slh_dsa": {"file": "keys/log-slh.key"}}, True),
                            ({"aws_kms": {"key_id": "k", "region": "r"}, "slh_dsa": {"file": "x"}}, True),
                            ({"slh_dsa": {}}, False), ({"slh_dsa": {"file": ""}}, False), ({}, False),
                            ({"slh_dsa": {"file": "x"}, "other": 1}, False)):
            with open(cfg, "w") as f:
                json.dump({"data_dir": ".", "log_key": log_key}, f)
            if ok:
                self.assertTrue(os.path.isabs(svc.load_config(cfg)["log_key"]["slh_dsa"]["file"]))
            else:
                with self.assertRaises(ValueError):
                    svc.load_config(cfg)
        with open(cfg, "w") as f:
            json.dump({"data_dir": ".", "log_key": {"slh_dsa": {"file": "keys/log-slh.key"}}}, f)
        self.assertEqual(svc.load_config(cfg)["log_key"]["slh_dsa"]["file"], self.key)
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(svc.main(["vkey", "--config", cfg]), 0)
        self.assertEqual(printed.getvalue().split(), svc.read_vkeys(self.dir))
        out = os.path.join(self.dir, "trust.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(svc.main(["trust", "--config", cfg, "-o", out]), 0)
        with open(out) as f:
            self.assertEqual(json.load(f)["logs"], svc.read_vkeys(self.dir))

    def test_off_unless_configured(self):
        d = tmpdir(self)
        s = svc.SignerService(d)
        self.addCleanup(s.close)
        s.checkpoint()
        self.assertEqual(len(lines(s.log.storage.checkpoint_latest()[1])), 1)
        self.assertEqual(svc.read_vkeys(d), [s.vkey])


if __name__ == "__main__":
    unittest.main()
