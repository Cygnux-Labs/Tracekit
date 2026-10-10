"""scripts/build-signer-bundles.py offline: the target table against the npm optionalDependencies, the generated
package.json, a build with the PBS download and pip mocked, and the pinned-hash check."""
import importlib.util
import io
import json
import os
import re
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
spec = importlib.util.spec_from_file_location("build_signer_bundles", os.path.join(ROOT, "scripts", "build-signer-bundles.py"))
bsb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bsb)


def fake_pbs(url, digest, dest):
    with tarfile.open(dest, "w:gz") as tar:
        for name in ["python/bin/python3", "python/include/python3.12/Python.h",
                     "python/lib/python3.12/test/test_x.py", "python/lib/python3.12/os.py",
                     "python/Lib/os.py", "python/python.exe"]:
            info = tarfile.TarInfo(name)
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
    return dest


def fake_pip(platforms, version, dest):
    os.makedirs(dest)
    with zipfile.ZipFile(os.path.join(dest, f"tracekit_ai-{version}-py3-none-any.whl"), "w") as z:
        z.writestr("tracekit/__init__.py", f'__version__ = "{version}"\n')
        z.writestr("tracekit/tests/test_x.py", "")


class TestSignerBundles(unittest.TestCase):
    def test_targets_are_the_optional_dependencies(self):
        with open(os.path.join(ROOT, "sdk", "typescript", "package.json")) as f:
            pkg = json.load(f)
        self.assertEqual(pkg["optionalDependencies"],
                         {f"@cygnux/tracekit-signer-{k}": pkg["version"] for k in bsb.TARGETS})
        for key, (triple, digest, npm_os, cpu, platforms) in bsb.TARGETS.items():
            self.assertTrue(key.startswith(f"{npm_os}-{cpu}"), key)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertTrue(platforms)

    def test_package_json(self):
        linux = bsb.package_json("linux-arm64-gnu", "1.2.3")
        self.assertEqual((linux["name"], linux["version"], linux["os"], linux["cpu"], linux["libc"]),
                         ("@cygnux/tracekit-signer-linux-arm64-gnu", "1.2.3", ["linux"], ["arm64"], ["glibc"]))
        mac = bsb.package_json("darwin-x64", "1.2.3")
        self.assertEqual((mac["os"], mac["cpu"]), (["darwin"], ["x64"]))
        self.assertNotIn("libc", mac)
        self.assertNotIn("scripts", mac)   # no postinstall

    def test_build_offline(self):
        with tempfile.TemporaryDirectory() as out, mock.patch.object(bsb, "download", fake_pbs), \
                mock.patch.object(bsb, "pip_download", fake_pip):
            for key, site in [("linux-x64-gnu", "python/lib/python3.12/site-packages"),
                              ("win32-x64", "python/Lib/site-packages")]:
                self.assertGreater(bsb.build(key, "9.9.9", out), 0)
                pkg = os.path.join(out, f"tracekit-signer-{key}")
                with open(os.path.join(pkg, "package.json")) as f:
                    self.assertEqual(json.load(f), bsb.package_json(key, "9.9.9"))
                self.assertTrue(os.path.exists(os.path.join(pkg, site, "tracekit", "__init__.py")))
                for gone in [site + "/tracekit/tests", "python/include", "python/lib/python3.12/test"]:
                    self.assertFalse(os.path.exists(os.path.join(pkg, gone)), gone)
                self.assertTrue(os.path.exists(os.path.join(pkg, "python/lib/python3.12/os.py")))
                with open(os.path.join(pkg, "wheels.sha256")) as f:
                    self.assertRegex(f.read(), re.compile(r"^[0-9a-f]{64}  tracekit_ai-9\.9\.9-py3-none-any\.whl\n$"))

    def test_download_refuses_a_wrong_hash(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "x")
            fetch = lambda url, path: open(path, "wb").write(b"evil")   # noqa: E731
            with mock.patch.object(bsb.urllib.request, "urlretrieve", fetch), self.assertRaises(SystemExit):
                bsb.download("https://example.invalid/x", "0" * 64, dest)
            self.assertFalse(os.path.exists(dest))


if __name__ == "__main__":
    unittest.main()
