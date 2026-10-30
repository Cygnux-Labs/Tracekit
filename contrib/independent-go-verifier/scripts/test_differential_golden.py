"""Offline tests for the differential runner (not a substitute for corpus parity)."""
import json
from pathlib import Path
import tempfile
import unittest

from differential_golden import cases, go_args, python_command, invoke, compare


class Discovery(unittest.TestCase):
    def make_corpus(self, root):
        fixture = root / "tests" / "golden"
        for section in ("v1", "v2", "negative", "parts"):
            (fixture / section).mkdir(parents=True)
        manifest = {"cases": [{"name": "v1 signed", "command": "verify", "dir": "v1",
                                "args": ["signed.tkb", "--key", "signer.pub"]},
                               {"name": "v0.1 migration", "command": "migrate", "dir": "v01",
                                "args": ["old.jsonl"]}]}
        (fixture / "expected.json").write_text(json.dumps(manifest))
        manifest = {"cases": [{"name": "v2 pinned", "command": "verify", "dir": "v2",
                                "args": ["closed.tkb", "--trust", "trust.json"]}]}
        (fixture / "v2" / "expected.json").write_text(json.dumps(manifest))
        for section in ("negative", "parts"):
            (fixture / section / "expected.json").write_text(json.dumps(
                {"cases": [{"name": section, "bundle": "broken.tkb"}]}))
        for section, name in (("v1", "signed.tkb"), ("v2", "closed.tkb"),
                              ("negative", "broken.tkb"), ("parts", "broken.tkb")):
            (fixture / section / name).write_bytes(b"fixture")
        return fixture

    def test_covers_all_bundles_and_resolves_trust(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.make_corpus(Path(tmp))
            rows = list(cases(fixture))
            self.assertEqual(4, len(rows))
            self.assertEqual((fixture / "v2" / "trust.json").resolve(), Path(rows[1][2][-1]).resolve())
            self.assertEqual(["-bundle", rows[1][2][0], "-trust", rows[1][2][-1], "-json"],
                             go_args(rows[1][2]))
            self.assertEqual(["-bundle", rows[0][2][0], "-key", rows[0][2][2], "-json"],
                             go_args(rows[0][2]))

    def test_maps_verification_flags_and_preserves_values(self):
        python_args = [
            "bundle.tkb",
            "--key", "signer.pub",
            "--witness", "file:C:/golden/witness log.jsonl",
            "--trust", "trust.json",
            "--v1-key", "legacy.pub",
            "--v1-ledger", "legacy-ledger.jsonl",
        ]
        self.assertEqual(
            ["-bundle", "bundle.tkb",
             "-key", "signer.pub",
             "-witness", "file:C:/golden/witness log.jsonl",
             "-trust", "trust.json",
             "-v1-key", "legacy.pub",
             "-v1-ledger", "legacy-ledger.jsonl",
             "-json"],
            go_args(python_args),
        )

    def test_rejects_incomplete_or_unknown_verification_flags(self):
        with self.assertRaisesRegex(ValueError, "missing value"):
            go_args(["bundle.tkb", "--key"])
        with self.assertRaisesRegex(ValueError, "unsupported verification flag"):
            go_args(["bundle.tkb", "--unknown", "value"])

    def test_reference_routing_for_corrupt_v2_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.make_corpus(Path(tmp))
            rows = list(cases(fixture))
            for _, _, args, section in rows:
                cmd = python_command(section, args)
                if section == "v1":
                    self.assertEqual(cmd[1:4], ["-m", "tracekit", "verify"])
                else:
                    self.assertEqual(cmd[1], "-c")
                    self.assertIn("v2.verify", cmd[2])
                    self.assertEqual([args[0], args[-1]], cmd[-2:])

    def test_v2_reference_subprocess_reports_malformed_bundle(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "tracekit" / "verify"
            pkg.mkdir(parents=True)
            (root / "tracekit" / "__init__.py").write_text("")
            (pkg / "__init__.py").write_text("")
            (pkg / "v2.py").write_text(
                "class Report:\n"
                "    integrity = 'UNUSABLE BUNDLE'\n"
                "    assurance = 'not evaluated'\n"
                "def verify(bundle, trust):\n"
                "    assert bundle.endswith('broken.tkb')\n"
                "    assert trust.endswith('trust.json')\n"
                "    return Report(), 2\n"
            )
            bundle, trust = root / "broken.tkb", root / "trust.json"
            bundle.write_bytes(b"bad v2 manifest")
            trust.write_text("{}")
            env = {**os.environ, "PYTHONPATH": str(root)}
            command = python_command("negative", [str(bundle), "--trust", str(trust)])
            got = invoke(command, root, env)
            self.assertEqual(got, {"exit_code": 2,
                                   "integrity": "UNUSABLE BUNDLE",
                                   "assurance": "not evaluated",
                                   "warning_checks": [], "failed_checks": []})

    def test_invoke_compares_warning_and_failure_check_names(self):
        import os
        import sys
        command = [sys.executable, "-c",
                   "import json; print(json.dumps({'exit_code': 0, 'integrity': 'VERIFIED', 'assurance': 'ok', 'checks': [{'check': 'coverage', 'status': 'warn'}, {'check': 'chain', 'status': 'fail'}, {'check': 'other', 'status': 'pass'}]}))"]
        self.assertEqual(invoke(command, Path.cwd(), os.environ.copy()),
                         {"exit_code": 0, "integrity": "VERIFIED", "assurance": "ok",
                          "warning_checks": ["coverage"], "failed_checks": ["chain"]})

    def test_known_and_unknown_check_differences_and_verdicts(self):
        base = {"exit_code": 0, "integrity": "VERIFIED", "assurance": "ok",
                "warning_checks": [], "failed_checks": []}
        other = {**base, "warning_checks": ["keys", "reviews"]}
        match, known, unexpected = compare(base, other, "v2")
        self.assertTrue(match)
        self.assertEqual(known["warning_checks"], ["keys", "reviews"])
        self.assertFalse(any(unexpected.values()))
        self.assertFalse(compare(base, other, "v1")[0])
        self.assertFalse(compare(base, {**other, "failed_checks": ["chain"]}, "v2")[0])
        self.assertFalse(compare({**base, "warning_checks": ["chain"]},
                                 {**base, "failed_checks": ["chain"]}, "v2")[0])
        self.assertFalse(compare(base, {**other, "exit_code": 1}, "v2")[0])

    def test_non_json_invocation_is_reported_as_error(self):
        import os
        import sys
        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            invoke([sys.executable, "-c", "import sys; print('not json'); sys.exit(2)"],
                   Path.cwd(), os.environ.copy())

    def test_unlisted_bundles_cannot_be_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.make_corpus(Path(tmp))
            (fixture / "v2" / "extra.tkb").write_bytes(b"not listed")
            with self.assertRaisesRegex(ValueError, "missing from test cases"):
                list(cases(fixture))


if __name__ == "__main__":
    unittest.main()
