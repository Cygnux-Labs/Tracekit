"""Compliance proof packs (#12): report and control map; the pack carries no verifier.
python3 -m pytest contrib/proofpack/tests -q"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

import tracekit_proofpack as proofpack
from tracekit import bundle, install
from tracekit.agent_sdk import Tracer
from factories import patch_env


class Pack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.home = os.path.join(cls.d, "signer")
        patch_env(cls)
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(cls.d, "client")
        install.init_dev(cls.home, [], start=True)
        with Tracer(agent="audit-bot", session_id="pp-1", cwd=cls.d) as t:
            with t.tool("Bash", {"command": "ls"}) as c:
                c.result("x")
            try:
                with t.tool("Bash", {"command": "sudo rm -rf /"}):
                    pass
            except PermissionError:
                pass
        subprocess.run([sys.executable, "-m", "tracekit", "analyze", "--home", cls.home, "--run", "pp-1"], capture_output=True)
        cls.tkb = os.path.join(cls.d, "run.tkb")
        bundle.export(cls.home, cls.tkb, run="pp-1")
        cls.pub = os.path.join(cls.home, "ledger", "signer.pub")

    @classmethod
    def tearDownClass(cls):
        install.stop_dev_daemon(cls.home)
        shutil.rmtree(cls.d, ignore_errors=True)

    def unpack(self, key=None):
        out = os.path.join(self.d, "pack.zip")
        code = proofpack.build(out, self.tkb, key=key)
        x = tempfile.mkdtemp(dir=self.d)
        self.addCleanup(shutil.rmtree, x, True)
        with zipfile.ZipFile(out) as z:
            z.extractall(x)
        return code, x

    def test_pack_carries_no_verifier(self):
        code, x = self.unpack()
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(x)), ["REPORT.md", "controls.json", "run.tkb"])
        with open(os.path.join(x, "run.tkb"), "rb") as a, open(self.tkb, "rb") as b:
            self.assertEqual(a.read(), b.read(), "the bundle goes in unchanged")
        self.assertNotIn("verify.pyz", open(os.path.join(x, "REPORT.md")).read())

    def test_swapped_replay_does_not_change_the_verdict(self):
        rep0, code0 = bundle.verify(self.tkb, (), False, self.pub)
        self.assertEqual(rep0.notes, [], "a freshly exported replay.html matches what the verifier generates")
        fake = os.path.join(self.d, "swapped.tkb")
        with zipfile.ZipFile(self.tkb) as z, zipfile.ZipFile(fake, "w") as o:
            for n in z.namelist():
                o.writestr(n, b"<html>all good</html>" if n == "replay.html" else z.read(n))
        rep1, code1 = bundle.verify(fake, (), False, self.pub)
        self.assertEqual((code1, rep1.checks), (code0, rep0.checks))
        self.assertTrue(any("replay.html" in n for n in rep1.notes))
        out = io.StringIO()
        bundle.print_report(rep1, code1, out)
        self.assertIn("warning: replay.html differs", out.getvalue())

    def test_report_says_what_it_proves_and_what_it_does_not(self):
        md, code = proofpack.report(self.tkb, key=self.pub)
        self.assertEqual(code, 0)
        self.assertIn("**Verification: VERIFIED.**", md)
        self.assertIn("| Tool calls | 2 (1 denied, 0 flagged) |", md)
        self.assertIn("Art. 12 Record-keeping", md)
        self.assertIn("Not covered:", md)
        self.assertIn("not a compliance determination", md)
        unanchored, _ = proofpack.report(self.tkb)
        self.assertIn("unanchored", unanchored)

    def test_cli(self):
        out = os.path.join(self.d, "cli.zip")
        p = subprocess.run([sys.executable, "-m", "tracekit_proofpack", "--home", self.home, "--run", "pp-1", "-o", out],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run([sys.executable, "-m", "tracekit_proofpack", "--report-only", self.tkb], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.startswith("# Evidence report: pp-1"))


if __name__ == "__main__":
    unittest.main()
