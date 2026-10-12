"""The recorded demos (docs/demos/): every saved bundle still verifies as its verify.txt says, and every demo still
runs end to end against a fresh signer to the verdicts it recorded (`scripts/record_demos.py --check`; of a demo whose
optional dependency is missing, only the saved bundle is checked). A demo with no bundle (why) has only its transcript,
and its check is what its output says."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "record_demos.py")
if os.path.exists(SCRIPT):
    sys.path.insert(0, os.path.dirname(SCRIPT))
    import record_demos
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

    def test_a_demo_that_hangs_is_a_failure_not_a_traceback(self):
        """A demo past its timeout raised TimeoutExpired out of --check, so no other demo's result was printed."""
        hang, tmp = subprocess.TimeoutExpired(["demo"], 300), tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(record_demos.subprocess, "run", side_effect=[hang, mock.Mock()]), \
                mock.patch.object(record_demos.tempfile, "mkdtemp", return_value=tmp):
            ok, said = record_demos.check("why")
        self.assertFalse(ok)
        self.assertIn("ran past 300 s", said)


FAIL_AFTER_THE_PROXY = """
import json, runpy, subprocess, sys
pids, real = [], subprocess.Popen.__init__
def init(self, *a, **k):
    real(self, *a, **k)
    pids.append(self.pid)
subprocess.Popen.__init__ = init
from tracekit.sdk import client
def boom(*a, **k):
    raise RuntimeError("boom")
client.Client.run = boom   # the run starts after the signer and the egress observer
sys.argv = [sys.argv[1]]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
finally:
    print("PIDS", json.dumps(pids), flush=True)
"""


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@unittest.skipUnless(os.name == "posix", "the demos' signer approves on a Unix socket")
class Cleanup(unittest.TestCase):
    """A demo that fails, or is interrupted, leaves no signer, egress observer or temp dir behind."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_a_signer_that_does_not_start_is_stopped_and_its_dir_removed(self):
        sys.path.insert(0, os.path.join(ROOT, "examples", "v2"))
        self.addCleanup(sys.path.remove, os.path.join(ROOT, "examples", "v2"))
        import story
        proc = mock.Mock()
        proc.stdout.readline.return_value = ""   # it exited before saying it serves
        with mock.patch.object(story.subprocess, "Popen", return_value=proc), \
                mock.patch.object(story.tempfile, "mkdtemp", return_value=os.path.join(self.tmp, "tk-x")), \
                mock.patch.object(story.os, "environ", dict(os.environ)), \
                self.assertRaises(SystemExit):
            os.makedirs(os.path.join(self.tmp, "tk-x"))
            story.Signer("version: x\n", {})
        proc.terminate.assert_called_once_with()
        self.assertEqual(os.listdir(self.tmp), [])

    def test_the_egress_demo_stops_its_observer_and_signer_when_it_fails(self):
        """The egress observer outlived a demo that failed between starting it and its run's end."""
        env = dict(os.environ, TMPDIR=self.tmp, HOME=self.tmp,
                   PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        for k in ("TRACEKIT_SIGNER", "TRACEKIT_SIGNER_TOKEN", "TRACEKIT_SIGNER_TOKEN_FILE", "TRACEKIT_EGRESS_PROXY"):
            env.pop(k, None)
        out, err = (tempfile.TemporaryFile("w+") for _ in range(2))   # not pipes: a child left running holds them
        with out, err:
            code = subprocess.run([sys.executable, "-c", FAIL_AFTER_THE_PROXY,
                                   os.path.join(ROOT, "examples", "v2", "demos", "egress.py")],
                                  cwd=self.tmp, env=env, stdout=out, stderr=err, timeout=120).returncode
            out.seek(0), err.seek(0)
            stdout, stderr = out.read(), err.read()
        self.assertNotEqual(code, 0)
        self.assertIn("RuntimeError: boom", stderr)
        pids = json.loads(stdout.rsplit("PIDS ", 1)[1])
        left = [pid for pid in pids if alive(pid)]
        for pid in left:
            os.kill(pid, 9)
        self.assertEqual(left, [], "processes the demo started are still running")
        self.assertEqual([d for d in os.listdir(self.tmp) if d.startswith("tk-")], [])


if __name__ == "__main__":
    unittest.main()
