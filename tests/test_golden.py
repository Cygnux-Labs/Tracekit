"""Golden verifier corpus: frozen v0.1 and v1 evidence and what the verifier says about each case.
Regenerate only by hand (tests/golden/make_golden.py) when a task says the corpus may change.

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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "tests", "golden")
with open(os.path.join(GOLDEN, "expected.json"), encoding="utf-8") as f:
    EXPECTED = json.load(f)


def corpus_problems(golden):
    """Files under v1/ and v01/ that are missing, changed, or not listed in expected.json."""
    found = {}
    for d in ("v1", "v01"):
        for dirpath, _, names in os.walk(os.path.join(golden, d)):
            for n in names:
                p = os.path.join(dirpath, n)
                with open(p, "rb") as f:
                    found[os.path.relpath(p, golden).replace(os.sep, "/")] = hashlib.sha256(f.read()).hexdigest()
    want = EXPECTED["files"]
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
        for c in EXPECTED["cases"]:
            for n, h in c["files"].items():
                self.assertEqual(EXPECTED["files"][f"{c['dir']}/{n}"], h, (c["name"], n))

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
        for case in EXPECTED["cases"]:
            with self.subTest(case["name"]):
                self.assertEqual(run(case), case["expected"])


if __name__ == "__main__":
    unittest.main()
