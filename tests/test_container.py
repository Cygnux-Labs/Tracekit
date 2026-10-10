"""The signer image (deploy/docker/Dockerfile): deploy/docker/smoke.sh builds it and checks it end to end."""
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _docker():
    if not shutil.which("docker"):
        return "docker is not installed"
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "docker info timed out"
    return None if p.returncode == 0 else "the docker daemon is not reachable"


NO_DOCKER = _docker()


@unittest.skipIf(os.name == "nt", "smoke.sh is POSIX shell and builds a Linux image")
@unittest.skipIf(NO_DOCKER, NO_DOCKER)
class SignerImage(unittest.TestCase):
    def test_smoke(self):
        p = subprocess.run(["sh", os.path.join(ROOT, "deploy", "docker", "smoke.sh")], capture_output=True, text=True,
                           timeout=900)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("smoke: ok", p.stdout)
