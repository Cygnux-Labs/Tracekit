"""The signer image (deploy/docker/Dockerfile): its config runs the server policy pack, its dependencies are pinned, and
deploy/docker/smoke.sh builds it and checks it end to end."""
import os
import shutil
import subprocess
import tempfile
import unittest

from tracekit.policy2 import compile as policy_compile
from tracekit.signer import service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKS = os.path.join(ROOT, "tracekit", "policy2", "packs")


def _docker():
    if not shutil.which("docker"):
        return "docker is not installed"
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "docker info timed out"
    return None if p.returncode == 0 else "the docker daemon is not reachable"


NO_DOCKER = _docker()


def parent_is_server_pack(policy_text):
    """Whether `policy_text`, as /etc/tracekit/policy.yaml next to the image's /etc/tracekit/packs, compiles cleanly
    with the server pack as its only parent."""
    with tempfile.TemporaryDirectory() as d:
        shutil.copytree(PACKS, os.path.join(d, "packs"))
        with open(os.path.join(d, "policy.yaml"), "w", encoding="utf-8") as f:
            f.write(policy_text)
        pol, errors = policy_compile.build(os.path.join(d, "policy.yaml"))
    server, _ = policy_compile.build(os.path.join(PACKS, "server.yaml"))
    return not errors and pol.get("extends") == policy_compile.policy_hash(server)


class ImageConfig(unittest.TestCase):
    def read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            return f.read()

    @unittest.skipIf(os.name == "nt", "the example names Linux container paths")
    def test_example_runs_the_server_pack(self):
        cfg = service.load_config(os.path.join(ROOT, "deploy", "docker", "signer.yaml.example"))
        self.assertEqual(cfg["policy"], "/etc/tracekit/packs/server.yaml")
        df = self.read("deploy/docker/Dockerfile")
        self.assertIn("os.symlink(os.path.join(os.path.dirname(p.__file__), 'packs'), '/etc/tracekit/packs')", df)
        self.assertTrue(os.path.isfile(os.path.join(PACKS, "server.yaml")))

    def test_dependencies_are_pinned(self):
        pins = [line for line in self.read("scripts/release/runtime-constraints.txt").splitlines()
                if line and not line.startswith("#")]
        self.assertTrue(pins)
        for line in pins:
            self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.]*$")
        names = {p.split("==")[0].lower().replace("_", "-") for p in pins}
        self.assertLessEqual({"cryptography", "rfc8785", "regex", "google-re2", "psycopg", "boto3"}, names)
        self.assertIn('PIP_CONSTRAINT="scripts/release/constraints.txt scripts/release/runtime-constraints.txt"',
                      self.read("deploy/docker/Dockerfile"))
        ignore = self.read(".dockerignore").splitlines()
        self.assertLessEqual({"!scripts/release/constraints.txt", "!scripts/release/runtime-constraints.txt"},
                             set(ignore))


@unittest.skipIf(os.name == "nt", "smoke.sh is POSIX shell and builds a Linux image")
@unittest.skipIf(NO_DOCKER, NO_DOCKER)
class SignerImage(unittest.TestCase):
    def test_smoke(self):
        p = subprocess.run(["sh", os.path.join(ROOT, "deploy", "docker", "smoke.sh")], capture_output=True, text=True,
                           timeout=900)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("smoke: ok", p.stdout)
