"""Compliance proof packs (#12): report, control map, and a verifier that runs with nothing but Python.
python3 -m pytest tests/test_proofpack.py -q"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, install, proofpack  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402


class Pack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.home = os.path.join(cls.d, "signer")
        cls.old = os.environ.get("TRACEKIT_CLIENT_HOME")
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
        subprocess.run([sys.executable, "-m", "tracekit", "analyze", "--home", cls.home, "--run", "pp-1"], capture_output=True, cwd=ROOT)
        cls.tkb = os.path.join(cls.d, "run.tkb")
        bundle.export(cls.home, cls.tkb, run="pp-1")
        cls.pub = os.path.join(cls.home, "ledger", "signer.pub")

    @classmethod
    def tearDownClass(cls):
        install.stop_dev_daemon(cls.home)
        if cls.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = cls.old
        shutil.rmtree(cls.d, ignore_errors=True)

    def unpack(self, key=None):
        out = os.path.join(self.d, "pack.zip")
        code = proofpack.build(out, self.tkb, key=key)
        x = tempfile.mkdtemp(dir=self.d)
        with zipfile.ZipFile(out) as z:
            z.extractall(x)
        return code, x

    def test_pack_contents_and_sums(self):
        code, x = self.unpack()
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(x)), ["REPORT.md", "SHA256SUMS", "controls.json", "run.tkb", "verify.pyz"])
        for line in open(os.path.join(x, "SHA256SUMS")):
            h, name = line.split()
            self.assertEqual(hashlib.sha256(open(os.path.join(x, name), "rb").read()).hexdigest(), h)
        with open(os.path.join(x, "run.tkb"), "rb") as a, open(self.tkb, "rb") as b:
            self.assertEqual(a.read(), b.read(), "the bundle goes in unchanged")

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

    def test_verifier_runs_with_only_the_standard_library(self):
        _, x = self.unpack()
        env = {"PATH": os.environ.get("PATH", ""), "HOME": x}
        # -I: isolated, -S: no site-packages, so no `cryptography`: pure-Python Ed25519 does the signature checks
        p = subprocess.run([sys.executable, "-I", "-S", os.path.join(x, "verify.pyz"), os.path.join(x, "run.tkb"), "--key", self.pub],
                           capture_output=True, text=True, cwd=x, env=env, timeout=300)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("signatures valid", p.stdout)
        self.assertIn("VERIFIED", p.stdout)
        bad = os.path.join(x, "bad.tkb")
        with zipfile.ZipFile(os.path.join(x, "run.tkb")) as z, zipfile.ZipFile(bad, "w") as o:
            for n in z.namelist():
                b = z.read(n)
                o.writestr(n, b.replace(b'"ls"', b'"id"') if n == "records.jsonl" else b)
        p = subprocess.run([sys.executable, "-I", "-S", os.path.join(x, "verify.pyz"), bad], capture_output=True, text=True, cwd=x, env=env, timeout=300)
        self.assertEqual(p.returncode, 1)

    def test_cli(self):
        out = os.path.join(self.d, "cli.zip")
        p = subprocess.run([sys.executable, "-m", "tracekit", "proofpack", "--home", self.home, "--run", "pp-1", "-o", out],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run([sys.executable, "-m", "tracekit", "report", self.tkb], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.startswith("# Evidence report: pp-1"))


if __name__ == "__main__":
    unittest.main()
