"""The v2 conformance kit (tests/kit): every case cites the section of docs/format-v2.md that decides it, covers every
golden v2 bundle, and the reference verifier passes every case but the proposed rules'. test_ts_verifier.py and
test_go_verifier.py hold the other two verifiers to it."""
import hashlib
import json
import os
import sys
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS, "kit"))
import run_kit as kit  # noqa: E402

from tracekit.verify import v2  # noqa: E402


def reference(case):
    """What the reference verifier says of `case`, as run_kit.run reads a verifier's report."""
    rep, code = v2.verify(os.path.join(TESTS, case["input"]), os.path.join(TESTS, case["trust"]))
    return {"exit": code, "verdict": kit.verdict(rep.integrity),
            "level": rep.assurance.split(";")[0].strip() if code == 0 else None,
            "failed": [c["check"] for c in rep.checks if c["status"] == "fail"]}


class Kit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(TESTS, "kit", "cases.json"), encoding="utf-8") as f:
            cls.kit = json.load(f)
        cls.cases = cls.kit["cases"]

    def test_each_case_is_decided_by_the_format(self):
        for c in self.cases:
            with self.subTest(c["name"]):
                self.assertTrue(c["decided_by"].startswith("proposed: " if c.get("proposed") else "§"), c)
                self.assertEqual(set(c) - {"addon", "needs", "proposed"},
                                 {"name", "input", "trust", "exit", "verdict", "level", "failed_check", "decided_by"})
        self.assertEqual(len({c["name"] for c in self.cases}), len(self.cases))
        for p in self.kit["primitives"]:
            self.assertTrue(os.path.isfile(os.path.join(TESTS, p["input"])), p)

    def test_its_files_are_the_ones_it_was_made_from(self):
        for name, digest in self.kit["files"].items():
            with open(os.path.join(TESTS, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, name)

    def test_every_golden_v2_bundle_is_a_case(self):
        golden = os.path.join(TESTS, "golden")
        bundles = {f"golden/{d}/{n}" for d in ("v2", "negative", "parts")
                   for n in os.listdir(os.path.join(golden, d)) if n.endswith(".tkb")}
        self.assertEqual(bundles - {c["input"] for c in self.cases}, set())

    def test_the_reference_passes_every_case_but_the_proposed_rules(self):
        for c in self.cases:
            with self.subTest(c["name"]):
                ok, how = kit.score(c, reference(c))
                self.assertTrue(ok or c.get("proposed"), how)

    def test_the_runner_scores_add_ons_versions_and_failed_checks(self):
        case = {"exit": 1, "verdict": "FAILED", "level": None, "failed_check": ["keys"]}
        failed = {"exit": 1, "verdict": "FAILED", "level": None, "failed": ["keys", "signatures"]}
        unverifiable = {"exit": 2, "verdict": "UNVERIFIABLE", "level": None, "failed": []}
        self.assertEqual(kit.score(case, failed)[0], True)
        self.assertEqual(kit.score(case, {**failed, "failed": ["signatures"]})[0], False)
        self.assertEqual(kit.score(case, unverifiable)[0], False)
        self.assertEqual(kit.score({**case, "addon": "x"}, unverifiable)[0], True)
        verified = {"exit": 0, "verdict": "VERIFIED", "level": "witnessed", "failed_check": None, "needs": "1.4.1"}
        self.assertEqual(kit.score(verified, unverifiable, "1.4.0")[0], True)
        self.assertEqual(kit.score(verified, {"exit": 0, "verdict": "VERIFIED", "level": "witnessed", "failed": []},
                                   "1.4.0")[0], False)
        self.assertEqual(kit.score(verified, {"exit": 0, "verdict": "VERIFIED", "level": "dev", "failed": []})[0],
                         False)
        self.assertEqual(kit.score(case, {"error": "no JSON"})[0], False)


if __name__ == "__main__":
    unittest.main()
