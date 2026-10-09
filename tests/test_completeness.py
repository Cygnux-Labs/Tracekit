"""v1 run completeness: elided stubs, missing run boundaries, bundles cut at a checkpoint, integrity/assurance lines.

    python3 -m unittest tests.test_completeness -v
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, cli, policy  # noqa: E402
from tracekit.core import sha256_hex  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402
from factories import ev, make_signer, rewrite_bundle, run_start, tool_call  # noqa: E402


def rewrite(src, dst, recs_fn, cps_fn=None):
    """Re-pack a bundle with edited records (signatures untouched) and a manifest that matches the new files."""
    with zipfile.ZipFile(src) as z:
        manifest = json.loads(z.read("manifest.json"))
        blobs = {n: z.read(n) for n in z.namelist() if n != "manifest.json"}
    recs = recs_fn([json.loads(l) for l in blobs["records.jsonl"].decode().splitlines()])
    blobs["records.jsonl"] = "".join(json.dumps(r) + "\n" for r in recs).encode()
    if cps_fn:
        cps = cps_fn([json.loads(l) for l in blobs["checkpoints.jsonl"].decode().splitlines() if l.strip()])
        blobs["checkpoints.jsonl"] = "".join(json.dumps(c, sort_keys=True) + "\n" for c in cps).encode()
    last = recs[-1]["seq"] if recs[-1].get("elided") else recs[-1]["event"]["seq"]
    manifest["seq_range"] = [0, last]
    manifest["files"] = {k: sha256_hex(v) for k, v in blobs.items()}
    with zipfile.ZipFile(dst, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        for k, v in blobs.items():
            z.writestr(k, v)
    return dst


def seq_of(r):
    return r["seq"] if r.get("elided") else r["event"]["seq"]


class Completeness(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.s = make_signer(self.home, checkpoint_every=1000)
        self.pol, self.pol_raw = policy.load()
        self.cseq = {}
        self.key = os.path.join(self.home, "ledger", "signer.pub")
        self.witness = f"file:{self.home}/witness.jsonl"

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def send(self, e, peer_uid=None):
        n = self.cseq.get(e["run_id"], 0)
        self.cseq[e["run_id"]] = n + 1
        req = {"op": "append", "cseq": n, "event": e}
        if e["type"] == "run.start":
            req["attach"] = {"policy": self.pol_raw}
        r = self.s.handle(req, peer_uid)
        self.assertTrue(r["ok"], r)
        return r["seq"]

    def two_runs(self, mid_checkpoint=False):
        self.send(run_start("r1", self.pol))
        self.send(run_start("r2", self.pol))
        for i in range(3):
            self.send(tool_call(f"a{i}", run="r1"))
            self.send(tool_call(f"b{i}", run="r2"))
        if mid_checkpoint:
            self.s.handle({"op": "checkpoint"})
        self.send(tool_call("a9", run="r1"))
        self.send(ev("run.end", {"reason": "done"}, "r1"))
        self.send(ev("run.end", {"reason": "done"}, "r2"))

    def export(self, **kw):
        out = os.path.join(self.d, f"b{len(os.listdir(self.d))}.tkb")
        bundle.export(self.home, out, **kw)
        return out

    def verdict(self, path, witness=()):
        rep, code = bundle.verify(path, witness, trusted_key=self.key)
        buf = io.StringIO()
        bundle.print_report(rep, code, buf)
        lines = buf.getvalue().splitlines()
        integ = next(l for l in lines if l.startswith("Integrity: "))
        return integ, code, {c["check"]: c for c in rep.checks}, lines

    def path(self, name):
        return os.path.join(self.d, name)

    def test_honest_exports_verify(self):
        self.two_runs()
        integ, code, chk, _ = self.verdict(self.export(since="0"), [self.witness])
        self.assertEqual(code, 0)
        self.assertEqual(integ, "Integrity: VERIFIED.")
        self.assertEqual(chk["run boundaries"]["status"], "pass")
        self.assertEqual(chk["run tail witnessed"]["status"], "pass")
        self.assertEqual(chk["run completeness"]["problems"], [])  # a whole bundle lists no elision problems
        integ, code, chk, _ = self.verdict(self.export(run="r2"), [self.witness])
        self.assertEqual(code, 0)  # r1 is elided: a warning, never a failure
        self.assertIn("WITH GAPS (run completeness)", integ)

    def test_export_keeps_whole_selected_run(self):
        self.two_runs()
        out = self.export(run="r1")
        with zipfile.ZipFile(out) as z:
            recs = [json.loads(l) for l in z.read("records.jsonl").decode().splitlines()]
        ledger = [r["event"]["seq"] for _, r, _ in read_records(self.s.ledger.path) if r and r["event"]["run_id"] == "r1"]
        self.assertEqual(sorted(r["event"]["seq"] for r in recs if not r.get("elided") and r["event"]["run_id"] == "r1"),
                         ledger)

    def test_stubbing_selected_records_is_not_verified(self):
        self.two_runs()
        src = self.export(since="0")
        r1 = lambda r: not r.get("elided") and r["event"]["run_id"] == "r1"  # noqa: E731
        middle = rewrite(src, self.path("mid.tkb"), lambda rs: [bundle._elide(r) if r1(r) and r["event"]["type"] == "tool.call"
                                                                  else r for r in rs])
        integ, code, chk, lines = self.verdict(middle)
        self.assertEqual(code, 0)
        self.assertNotEqual(integ, "Integrity: VERIFIED.")
        self.assertIn("run completeness", integ)
        self.assertIn("run r1: run completeness unproven (v1 bundle with elided records)", chk["run completeness"]["problems"])
        self.assertIn("run r2: run completeness unproven (v1 bundle with elided records)", chk["run completeness"]["problems"])
        lead = rewrite(src, self.path("lead.tkb"), lambda rs: [bundle._elide(r) if r1(r) and r["event"]["type"] == "run.start"
                                                                else r for r in rs])
        integ, code, chk, _ = self.verdict(lead)
        self.assertNotEqual(integ, "Integrity: VERIFIED.")
        self.assertTrue(any("run r1: run boundaries unproven" in p for p in chk["run boundaries"]["problems"]))

    def test_dropping_trailing_records_is_not_verified(self):
        self.two_runs()
        src = self.export(since="0")
        end = next(r["event"]["seq"] for _, r, _ in read_records(self.s.ledger.path)
                   if r and r["event"]["run_id"] == "r1" and r["event"]["type"] == "run.end")
        cut = rewrite(src, self.path("tail.tkb"), lambda rs: [r for r in rs if seq_of(r) < end],
                      lambda cs: [c for c in cs if c["head_seq"] < end])
        integ, code, chk, _ = self.verdict(cut)
        self.assertNotEqual(integ, "Integrity: VERIFIED.")
        self.assertTrue(any("run r1: tail unproven" in p for p in chk["run boundaries"]["problems"]))

    def test_cut_inside_a_run_at_a_checkpoint_is_tail_unproven(self):
        self.two_runs(mid_checkpoint=True)
        src = self.export(since="0")
        with zipfile.ZipFile(src) as z:
            cps = [json.loads(l) for l in z.read("checkpoints.jsonl").decode().splitlines() if l.strip()]
        mid = min(c["head_seq"] for c in cps)
        cut = rewrite(src, self.path("cp.tkb"), lambda rs: [r for r in rs if seq_of(r) <= mid],
                      lambda cs: [c for c in cs if c["head_seq"] <= mid])
        for witness in ((), [self.witness]):  # an open run is never plain VERIFIED, and never a FAIL on its own
            integ, code, chk, _ = self.verdict(cut, witness)
            self.assertEqual(code, 0, integ)
            self.assertNotEqual(integ, "Integrity: VERIFIED.")
            self.assertTrue(any("run r1: tail unproven" in p for p in chk["run boundaries"]["problems"]))

    def test_bundle_stopping_before_a_witnessed_checkpoint_after_run_end_fails(self):
        self.two_runs()
        recs = [r for _, r, _ in read_records(self.s.ledger.path) if r]
        end1 = next(r["event"]["seq"] for r in recs if r["event"]["run_id"] == "r1" and r["event"]["type"] == "run.end")
        wpath = self.witness[len("file:"):]
        with open(wpath) as f:  # the checkpoint at r1's run.end never reached the witness; a later one did
            kept = [l for l in f if json.loads(l)["head_seq"] != end1]
        with open(wpath, "w") as f:
            f.writelines(kept)
        later = min(json.loads(l)["head_seq"] for l in kept if json.loads(l)["head_seq"] > end1)
        cut = rewrite(self.export(since="0"), self.path("late.tkb"), lambda rs: [r for r in rs if seq_of(r) < later],
                      lambda cs: [c for c in cs if c["head_seq"] < later])
        integ, code, chk, _ = self.verdict(cut, [self.witness])
        self.assertEqual(code, 1, integ)
        self.assertEqual(chk["run tail witnessed"]["status"], "fail")
        self.assertTrue(any("run r1: tail not covered by a witnessed checkpoint" in p
                            for p in chk["run tail witnessed"]["problems"]))

    def test_bundle_ending_at_its_own_checkpoint_missing_from_the_witness_warns(self):
        self.two_runs()
        recs = [r for _, r, _ in read_records(self.s.ledger.path) if r]
        end1 = next(r["event"]["seq"] for r in recs if r["event"]["run_id"] == "r1" and r["event"]["type"] == "run.end")
        wpath = self.witness[len("file:"):]
        with open(wpath) as f:  # the checkpoint at r1's run.end missed its publish; a later one reached the witness
            kept = [l for l in f if json.loads(l)["head_seq"] != end1]
        with open(wpath, "w") as f:
            f.writelines(kept)
        cut = rewrite(self.export(run="r1"), self.path("cp.tkb"), lambda rs: [r for r in rs if seq_of(r) <= end1],
                      lambda cs: [c for c in cs if c["head_seq"] <= end1])
        integ, code, chk, _ = self.verdict(cut, [self.witness])
        self.assertEqual(code, 0, integ)
        self.assertEqual(chk["run tail witnessed"]["status"], "warn")
        self.assertTrue(any("run r1: checkpoint not on the witness" in p for p in chk["run tail witnessed"]["problems"]))
        self.assertNotIn(f"covered by checkpoint(s) [{end1}]", chk["head matches a witness checkpoint"]["detail"])

    def test_witness_without_a_checkpoint_after_run_end_is_not_a_failure(self):
        self.two_runs()
        wpath = self.witness[len("file:"):]
        open(wpath, "w").close()  # witness has seen nothing yet (late publish)
        integ, code, chk, _ = self.verdict(self.export(since="0"), [self.witness])
        self.assertNotEqual(code, 1, integ)
        self.assertEqual(chk["run tail witnessed"]["status"], "pass")

    def assurance(self, isolation, peer_uid):
        self.send(run_start("r1", self.pol, isolation=isolation), peer_uid)
        self.send(ev("run.end", {"reason": "done"}, "r1"))
        out = self.export(run="r1")
        start = next(r["event"] for _, r, _ in read_records(self.s.ledger.path) if r and r["event"]["type"] == "run.start")
        return start["data"]["signer_isolation"], self.verdict(out)[3]

    @unittest.skipUnless(hasattr(os, "getuid"), "the v1 signer stamps isolation from the peer's uid; Windows has none")
    def test_signer_stamps_isolation_over_the_client_claim(self):
        recorded, lines = self.assurance("separate-user", os.getuid())  # a dev signer: the client runs as its user
        self.assertEqual(recorded, "same-user")
        self.assertIn("Assurance: dev (signer ran as the agent's own user: the agent could have rewritten the ledger).",
                      lines)

    def test_unattested_isolation_is_client_reported(self):
        recorded, lines = self.assurance("separate-user", None)
        self.assertEqual(recorded, "separate-user")
        self.assertIn("Assurance: unknown (client-reported signer_isolation=separate-user).", lines)

    @unittest.skipUnless(hasattr(os, "getuid"), "the v1 signer stamps isolation from the peer's uid; Windows has none")
    def test_attested_separate_user(self):
        recorded, lines = self.assurance("same-user", os.getuid() + 1)
        self.assertEqual(recorded, "separate-user")
        self.assertIn("Assurance: signer_isolation=separate-user (stamped by the signer since 0.3.0; earlier bundles: "
                      "client-reported).", lines)

    def test_deep_json_is_a_structure_failure(self):
        self.two_runs()
        src = self.export(since="0")
        deep = b"[" * 200000
        for name in ("records.jsonl", "checkpoints.jsonl", "coverage.json", "manifest.json"):
            with self.subTest(name):
                out = self.path(name + ".tkb")
                if name == "manifest.json":
                    with zipfile.ZipFile(src) as z, zipfile.ZipFile(out, "w") as o:
                        for n in z.namelist():
                            o.writestr(n, deep if n == name else z.read(n))
                else:
                    rewrite_bundle(src, out, lambda files, _m: files.update({name: files[name] + b"\n" + deep + b"\n"}))
                rep, code = bundle.verify(out, trusted_key=self.key)
                if name != "coverage.json":  # coverage.json only feeds the replay.html comparison
                    self.assertEqual(code, 1)
                    self.assertIn("bundle structure", rep.failures)

    def test_verify_json_has_integrity_assurance_and_notes(self):
        self.two_runs()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["verify", self.export(run="r1"), "--json", "--key", self.key])
        js = json.loads(out.getvalue())
        self.assertEqual(js["integrity"], "VERIFIED WITH GAPS (run completeness)")
        self.assertTrue(js["assurance"].startswith("dev"))
        self.assertEqual(js["notes"], [])

    def test_replay_from_another_version_is_not_compared(self):
        for name in ("demo-run.tkb", "demo-run-tampered.tkb"):
            with mock.patch.object(bundle, "__version__", "0.3.0"):
                rep, _ = bundle.verify(os.path.join(ROOT, "docs", "sample", name))
            self.assertFalse(any("differs" in n for n in rep.notes), rep.notes)
            self.assertTrue(any("generated by tracekit '0.2.0rc1' and is not compared" in n for n in rep.notes), rep.notes)
        self.two_runs()
        swapped = self.path("swapped.tkb")
        rewrite_bundle(self.export(run="r1"), swapped, lambda files, _m: files.update({"replay.html": b"<p>other</p>"}))
        rep, _ = bundle.verify(swapped)
        self.assertTrue(any("replay.html differs" in n for n in rep.notes), rep.notes)

    def test_dev_signer_never_prints_bare_verified(self):
        start = run_start("r1", self.pol)
        start["data"]["signer_isolation"] = "same-user"
        self.send(start)
        self.send(ev("run.end", {"reason": "done"}, "r1"))
        integ, code, _, lines = self.verdict(self.export(run="r1"))
        self.assertEqual(code, 0)
        self.assertEqual(integ, "Integrity: VERIFIED.")
        self.assertTrue(any(l.startswith("Assurance: dev") for l in lines))
        self.assertNotIn("VERIFIED.", [l.strip() for l in lines])


if __name__ == "__main__":
    unittest.main()
