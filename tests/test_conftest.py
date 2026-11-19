"""tests/conftest.py's end-of-session checks under pytest-xdist, as CI runs the suite (`-n auto`): a dev signer a
worker's session left running fails the run, as it does in one process. xdist's controller takes no exit status from
its workers, so the conftest passes each worker's findings to it."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)

# a dev signer still running in the session's runtime dir at its end: autospawn.down fails as on one that won't stop
LEFT_RUNNING = """
from tracekit.sdk import autospawn


def _down(**kw):
    raise OSError("it would not stop")


autospawn.down = _down


def test_anything():
    pass
"""


@unittest.skipUnless(importlib.util.find_spec("xdist"), "pytest-xdist is not installed (the dev extra has it)")
class SessionEnd(unittest.TestCase):
    def run_session(self, *args):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        shutil.copy(os.path.join(TESTS, "conftest.py"), d)
        with open(os.path.join(d, "test_left_running.py"), "w", encoding="utf-8") as f:
            f.write(LEFT_RUNNING)
        env = dict(os.environ, HOME=d, PYTHONPATH=os.pathsep.join(filter(None, [ROOT, os.environ.get("PYTHONPATH")])))
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args, d], cwd=d,
                              env=env, capture_output=True, text=True, timeout=120)

    def test_a_dev_signer_left_running_fails_the_run_in_parallel_too(self):
        for args in ((), ("-n", "2")):
            with self.subTest(args=args):
                p = self.run_session(*args)
                self.assertIn("1 passed", p.stdout)
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                self.assertIn("a dev signer a test left running in the session's runtime dir didn't stop", p.stderr)
                self.assertIn("it would not stop", p.stderr)


if __name__ == "__main__":
    unittest.main()
