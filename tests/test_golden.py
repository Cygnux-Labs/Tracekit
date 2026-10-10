"""Golden verifier corpus: frozen v0.1, v1 and v2 evidence, a v2 negative corpus (one defect per bundle), and what the
verifier says about each case. Regenerate only by hand (tests/golden/make_golden.py) when a task says the corpus may
change.

    python3 -m pytest tests/test_golden.py -q
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tracekit.verify import v2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "tests", "golden")


def load(*path):
    with open(os.path.join(GOLDEN, *path), encoding="utf-8") as f:
        return json.load(f)


EXPECTED, V2, NEGATIVE = load("expected.json"), load("v2", "expected.json"), load("negative", "expected.json")


def corpus_problems(golden, dirs=("v1", "v01"), want=None):
    """Files under `dirs` that are missing, changed, or not listed in `want` (default: expected.json's v1 and v0.1
    files); a directory's own expected.json is not part of it."""
    found = {}
    for d in dirs:
        for dirpath, _, names in os.walk(os.path.join(golden, d)):
            for n in names:
                p = os.path.join(dirpath, n)
                if n == "expected.json" and dirpath == os.path.join(golden, d):
                    continue
                with open(p, "rb") as f:
                    found[os.path.relpath(p, golden).replace(os.sep, "/")] = hashlib.sha256(f.read()).hexdigest()
    want = EXPECTED["files"] if want is None else want
    return sorted([f"{n}: changed" for n in want if n in found and found[n] != want[n]] +
                  [f"{n}: missing" for n in want if n not in found] +
                  [f"{n}: not listed in expected.json" for n in found if n not in want])


def run(case):
    cwd = os.path.join(GOLDEN, case["dir"])
    env = {**os.environ, "PYTHONPATH": ROOT}
    cli = [sys.executable, "-m", "tracekit", case["command"], *case["args"]]
    text = subprocess.run(cli, cwd=cwd, env=env, capture_output=True, text=True)
    got = {"exit_code": text.returncode}
    if case["command"] == "migrate":
        got["output"] = text.stdout.splitlines()
        return got
    js = json.loads(subprocess.run(cli + ["--json"], cwd=cwd, env=env, capture_output=True, text=True).stdout)
    lines = text.stdout.splitlines()
    got["integrity"] = next((l for l in lines if l.startswith("Integrity: ")), None)
    got["assurance"] = next((l for l in lines if l.startswith("Assurance: ")), None)
    got["checks"] = [[c["check"], c["status"]] for c in js["checks"]]
    return got


class Corpus(unittest.TestCase):
    def test_files_match_recorded_hashes(self):
        self.assertEqual(corpus_problems(GOLDEN), [])
        self.assertEqual(corpus_problems(GOLDEN, ("v2",), V2["files"]), [])
        self.assertEqual(corpus_problems(GOLDEN, ("negative",), NEGATIVE["files"]), [])
        for expected in (EXPECTED, V2):
            for c in expected["cases"]:
                for n, h in c["files"].items():
                    self.assertEqual(expected["files"][f"{c['dir']}/{n}"], h, (c["name"], n))

    def test_one_changed_byte_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            for sub in ("v1", "v01"):
                shutil.copytree(os.path.join(GOLDEN, sub), os.path.join(d, sub))
            for name in EXPECTED["files"]:
                p = os.path.join(d, name)
                with open(p, "r+b") as f:
                    b = f.read(1)
                    f.seek(0)
                    f.write(bytes([b[0] ^ 1]))
                self.assertEqual(corpus_problems(d), [f"{name}: changed"])
                with open(p, "r+b") as f:
                    f.write(b)
            open(os.path.join(d, "v1", "extra.tkb"), "wb").close()
            self.assertEqual(corpus_problems(d), ["v1/extra.tkb: not listed in expected.json"])


class Verdicts(unittest.TestCase):
    def test_verifier_reproduces_expected_results(self):
        for case in EXPECTED["cases"] + V2["cases"]:
            with self.subTest(case["name"]):
                self.assertEqual(run(case), case["expected"])

    def test_negative_corpus(self):
        self.assertGreaterEqual(len(NEGATIVE["cases"]), 25)
        trust = os.path.join(GOLDEN, "negative", "trust.json")
        for case in NEGATIVE["cases"]:
            with self.subTest(case["name"]):
                rep, code = v2.verify(os.path.join(GOLDEN, "negative", case["bundle"]), trust)
                self.assertEqual({"exit_code": code, "integrity": rep.integrity, "first_failure": next(
                    (c["check"] for c in rep.checks if c["status"] == "fail"), None)}, case["expected"])
                self.assertFalse(code == 0 and rep.integrity == "VERIFIED", rep.checks)


if __name__ == "__main__":
    unittest.main()
