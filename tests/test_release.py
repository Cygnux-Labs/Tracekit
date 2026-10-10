"""Release scripts (scripts/release/, docs/RELEASING.md): verify-release.sh --dry-run checks sums and the SBOM offline;
with TRACEKIT_RELEASE=1 (`make release-dry-run`; needs the package index and npm) the build is byte-identical across two
runs and a full dry run verifies."""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "scripts", "release", "build.py")
VERIFY = os.path.join(ROOT, "scripts", "release", "verify-release.sh")
spec = importlib.util.spec_from_file_location("release_build", BUILD)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def verify(*args):
    return subprocess.run(["sh", VERIFY, "--dry-run", *args], capture_output=True, text=True)


@unittest.skipIf(os.name == "nt", "verify-release.sh is a POSIX shell script")
class VerifyDryRun(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for name, data in (("tracekit_ai-1.0-py3-none-any.whl", b"w"), ("tracekit_ai-1.0.tar.gz", b"s"),
                           ("cygnux-tracekit-1.0.tgz", b"n"), (release.PY_SBOM, b'{"bomFormat": "CycloneDX"}')):
            with open(os.path.join(self.dir, name), "wb") as f:
                f.write(data)
        release.write_sums(self.dir)

    def test_ok(self):
        r = verify(self.dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_changed_file_fails(self):
        with open(os.path.join(self.dir, "tracekit_ai-1.0.tar.gz"), "wb") as f:
            f.write(b"x")
        self.assertNotEqual(verify(self.dir).returncode, 0)

    def test_missing_sbom_fails(self):
        os.remove(os.path.join(self.dir, release.PY_SBOM))
        release.write_sums(self.dir)
        self.assertNotEqual(verify(self.dir).returncode, 0)

    def test_unlisted_artifact_fails(self):
        with open(os.path.join(self.dir, "other-1.0.tgz"), "wb") as f:
            f.write(b"o")
        self.assertNotEqual(verify(self.dir).returncode, 0)


@unittest.skipUnless(os.environ.get("TRACEKIT_RELEASE") == "1", "builds from the package index: TRACEKIT_RELEASE=1")
class ReleaseBuild(unittest.TestCase):
    def test_python_dists_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            outs = []
            for i in (1, 2):
                src, out = os.path.join(tmp, f"src{i}"), os.path.join(tmp, f"out{i}")
                release.export_head(src)
                release.python_dists(src, out, 1700000000)
                outs.append({n: open(os.path.join(out, n), "rb").read() for n in os.listdir(out)})
            self.assertEqual(sorted(outs[0]), sorted(outs[1]))
            self.assertEqual(len(outs[0]), 2)
            for name in outs[0]:
                self.assertEqual(outs[0][name], outs[1][name], name)

    def test_dry_run(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, BUILD, out], check=True)
            names = os.listdir(out)
            for suffix in (".whl", ".tar.gz", ".tgz", release.PY_SBOM, "SHA256SUMS"):
                self.assertTrue(any(n.endswith(suffix) for n in names), (suffix, names))
            r = verify(out)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
