"""The recorded demos (docs/demos/): every saved bundle still verifies as its verify.txt says, and every demo still
runs end to end against a fresh signer to the verdicts it recorded (`scripts/record_demos.py --check`; of a demo whose
optional dependency is missing, only the saved bundle is checked). A demo with no bundle (why) has only its transcript,
and its check is what its output says."""
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "record_demos.py")
if os.path.exists(SCRIPT):
    sys.path.insert(0, os.path.dirname(SCRIPT))
    from record_demos import DEMOS, OUTPUT, SCENARIOS


@unittest.skipUnless(os.path.exists(SCRIPT), "a checkout's: an sdist ships neither scripts/ nor the transcripts")
class Demos(unittest.TestCase):
    def test_every_folder_is_a_demo_the_script_records(self):
        self.assertEqual(sorted(d for d in os.listdir(DEMOS) if os.path.isdir(os.path.join(DEMOS, d))),
                         sorted(SCENARIOS))
        for name in SCENARIOS:
            files = ["README.md", "transcript.txt"] if name in OUTPUT else \
                ["README.md", "run.tkb", "transcript.txt", "trust.json", "verify.txt"]
            self.assertEqual(sorted(os.listdir(os.path.join(DEMOS, name))), files, name)

    def test_each_demo_verifies_and_runs_as_recorded(self):
        p = subprocess.run([sys.executable, SCRIPT, "--check"], capture_output=True, text=True, timeout=600)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(len(p.stdout.splitlines()), len(SCENARIOS), p.stdout)


if __name__ == "__main__":
    unittest.main()
