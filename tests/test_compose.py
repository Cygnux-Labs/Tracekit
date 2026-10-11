"""The compose stack (deploy/compose/): `tracekit deploy compose` output, the compose file's shape, no reference left
to the removed v1 witness server, and deploy/compose/e2e.sh when docker (and root or sudo) is there.
python3 -m pytest tests/test_compose.py -q"""
import base64
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from test_container import NO_DOCKER, parent_is_server_pack  # noqa: E402

from tracekit import crypto  # noqa: E402
from tracekit.core import b64e, canon  # noqa: E402
from tracekit.deploy import compose  # noqa: E402
from tracekit.format import checkpoint  # noqa: E402
from tracekit.signer.service import load_config  # noqa: E402
from tracekit.witness import STH_TYPE, verify_sth  # noqa: E402


def deploy(out, *args):
    return compose.main(["compose", "--dir", out, *args])


class DeployCompose(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.out = os.path.join(self.d, "stack")
        self.assertEqual(deploy(self.out, "--witness-class", "customer"), 0)

    def read(self, rel):
        with open(os.path.join(self.out, rel), encoding="utf-8") as f:
            return f.read()

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_files_and_modes(self):
        for rel in compose.COPIED[1:]:   # the compose file only gets the source checkout as its build context
            with open(os.path.join(compose.TEMPLATES, rel), encoding="utf-8") as f:
                self.assertEqual(self.read(rel), f.read())
        self.assertIn(f"context: {compose.SRC}", self.read("docker-compose.yaml"))
        self.assertNotIn("context: ../..", self.read("docker-compose.yaml"))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.out, "secrets")).st_mode), 0o700)
        for name in compose.OWNERS:
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.out, "secrets", name)).st_mode), 0o600, name)
        self.assertTrue(os.access(os.path.join(self.out, "postgres", "10-roles.sh"), os.X_OK))
        sql = self.read("postgres/20-schema.sql")
        self.assertIn("GRANT SELECT, INSERT ON tracekit_records", sql)
        self.assertIn("TO tracekit_signer", sql)
        self.assertNotIn("INSERT", sql.split("TO tracekit_signer")[-1].replace("INSERT INTO", ""))   # viewer: SELECT
        pw = self.read("secrets/pg-signer.password").strip()
        self.assertIn(f"user=tracekit_signer password='{pw}'", self.read("secrets/signer.dsn"))
        self.assertNotEqual(pw, self.read("secrets/pg-viewer.password").strip())

    @unittest.skipIf(os.name == "nt", "the stack's config names Linux container paths (/run/secrets)")
    def test_signer_yaml_pins_the_stack_witness(self):
        cfg = load_config(os.path.join(self.out, "signer.yaml"))
        _, _, name, _, raw = self.read("secrets/witness.key").strip().split("+", 4)
        seed = base64.b64decode(raw)[1:]
        vkey = checkpoint.vkey(name, checkpoint.COSIGNATURE, crypto.public_from_secret(seed))
        self.assertEqual(cfg["witnesses"], [{"url": "http://witness:8080", "vkey": vkey, "class": "customer"}])
        self.assertEqual(self.read("witness.vkey").strip(), vkey)
        self.assertEqual(cfg["storage"], {"postgres": {"dsn_file": "/run/secrets/signer.dsn"}})
        self.assertEqual(cfg["policy"], "/etc/tracekit/policy.yaml")
        self.assertTrue(parent_is_server_pack(self.read("policy.yaml")))
        from cryptography.hazmat.primitives import serialization
        ssh = serialization.load_ssh_private_key(self.read("secrets/witness.ssh").encode(), None)
        self.assertEqual(ssh.private_bytes_raw(), seed)   # litewitness gets the same key
        self.assertEqual(load_config(os.path.join(self.out, "viewer.yaml"))["storage"],
                         {"postgres": {"dsn_file": "/run/secrets/viewer.dsn"}})

    def test_idempotent_and_refuses_changed_files(self):
        before = {rel: self.read(rel) for rel in compose.plan(self.out, "x", "customer")}
        self.assertEqual(deploy(self.out, "--witness-class", "customer"), 0)
        self.assertEqual({rel: self.read(rel) for rel in before}, before)   # keys and passwords kept
        own = "extends: packs/server.yaml\ntools: {my_search: web}\n"
        with open(os.path.join(self.out, "policy.yaml"), "w", encoding="utf-8") as f:
            f.write(own)
        self.assertEqual(deploy(self.out, "--witness-class", "customer"), 0)
        self.assertEqual(self.read("policy.yaml"), own)   # the operator's policy is kept
        os.unlink(os.path.join(self.out, "viewer.yaml"))
        with open(os.path.join(self.out, "signer.yaml"), "a", encoding="utf-8") as f:
            f.write("# edited\n")
        self.assertEqual(deploy(self.out, "--witness-class", "customer"), 1)
        self.assertFalse(os.path.exists(os.path.join(self.out, "viewer.yaml")), "nothing written on a refusal")
        self.assertEqual(deploy(self.out), 1)   # another class: signer.yaml would change


class ComposeFile(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.out = os.path.join(self.d, "stack")
        self.assertEqual(deploy(self.out), 0)

    @unittest.skipIf(NO_DOCKER, NO_DOCKER)
    def test_docker_compose_config(self):
        p = subprocess.run(["docker", "compose", "-f", os.path.join(self.out, "docker-compose.yaml"), "--profile",
                            "agent", "config", "-q"], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_shape(self):
        import yaml
        with open(os.path.join(self.out, "docker-compose.yaml"), encoding="utf-8") as f:
            c = yaml.safe_load(f)
        s = c["services"]
        self.assertEqual(set(s), {"postgres", "signer", "witness", "viewer", "agent"})
        for name, svc in s.items():
            for sec in svc.get("secrets", ()):
                self.assertTrue(os.path.isfile(os.path.join(self.out, c["secrets"][sec]["file"])), sec)
            self.assertLessEqual(set(svc["networks"]), set(c["networks"]), name)
            for k, v in (svc.get("environment") or {}).items():   # keys and DSNs are files, never environment
                self.assertTrue(k.endswith("_FILE") or k == "POSTGRES_DB", (name, k))
            if name != "postgres":
                self.assertTrue(svc["read_only"] and svc["cap_drop"] == ["ALL"], name)
        self.assertTrue(s["postgres"]["image"].split("@")[1].startswith("sha256:"))
        self.assertEqual(s["postgres"]["networks"], ["db"])
        self.assertEqual(s["agent"]["volumes"], ["signer-run:/run/tracekit-signer:ro"])
        self.assertIn("./policy.yaml:/etc/tracekit/policy.yaml:ro", s["signer"]["volumes"])
        self.assertEqual(s["agent"]["networks"], ["agent"])
        self.assertNotIn("secrets", s["agent"])
        self.assertEqual(s["agent"]["user"], "1000:1000")
        others = [v for n, svc in s.items() if n != "agent" for v in svc.get("volumes", ())]
        self.assertEqual([v for v in others if v.startswith("signer-run:")], ["signer-run:/run/tracekit-signer"])
        self.assertTrue(all(v.get("internal") for n, v in c["networks"].items() if n != "front"))
        self.assertEqual([n for n, svc in s.items() if "front" in svc["networks"]], ["viewer"])
        self.assertTrue(all(p.startswith("127.0.0.1:") for p in s["viewer"]["ports"]))
        with open(os.path.join(self.out, ".env.example"), encoding="utf-8") as f:
            env = [line for line in f.read().splitlines() if line and not line.startswith("#")]
        self.assertEqual([line.split("=")[0] for line in env], ["VIEWER_PORT"])
        with open(os.path.join(self.out, "witness", "Dockerfile"), encoding="utf-8") as f:
            df = f.read()
        self.assertRegex(df, r"ARG GO=golang:[^@\s]+@sha256:[0-9a-f]{64}")
        self.assertRegex(df, r"ARG OMNIWITNESS=[0-9a-f]{40}\n")


class ShippedWitnessOnly(unittest.TestCase):
    def test_no_stack_or_doc_uses_the_v1_witness_server(self):
        """The stacks and docs use the shipped C2SP witness; tracekit/witness_server.py stays only until its removal from
        the context files is approved (M3-08)."""
        files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        # context files, release notes and the frozen paper record history
        skip = ("CHANGELOG.md", "AGENTS.md", "CONTEXT_MANIFEST.json", "paper/", "tests/test_compose.py",
                "tracekit/witness_server.py", "tests/test_witness_server.py", "tracekit/cli.py",
                "docs/security-checklist.md", "tests/test_security_checklist.py")   # it is an HTTP surface until deleted
        hits = []
        for rel in files:
            if rel.startswith(skip) or not os.path.isfile(os.path.join(ROOT, rel)):
                continue
            with open(os.path.join(ROOT, rel), "rb") as f:
                data = f.read()
            if re.search(rb"(?<!public_)witness_server|tracekit witness ", data):   # not the public witness
                hits.append(rel)
        self.assertEqual(hits, [])

    def test_v1_tree_heads_still_verify(self):
        secret = os.urandom(32)
        sth = {"type": STH_TYPE, "tree_size": 2, "root_hash": "00" * 32, "ts": "2026-10-10T00:00:00Z"}
        sth["sig"] = b64e(crypto.sign(secret, canon(sth).encode("utf-8")))
        self.assertTrue(verify_sth(sth, crypto.public_from_secret(secret)))
        self.assertFalse(verify_sth(dict(sth, tree_size=3), crypto.public_from_secret(secret)))


def _e2e_blocked():
    if NO_DOCKER:
        return NO_DOCKER
    if not hasattr(os, "geteuid"):
        return "POSIX only"
    if os.geteuid() != 0 and not (shutil.which("sudo") and subprocess.run(["sudo", "-n", "true"],
                                                                         capture_output=True).returncode == 0):
        return "needs root or passwordless sudo"
    return None


@unittest.skipIf(_e2e_blocked(), _e2e_blocked())
class EndToEnd(unittest.TestCase):
    def test_e2e(self):
        p = subprocess.run(["sh", os.path.join(ROOT, "deploy", "compose", "e2e.sh")], capture_output=True, text=True,
                           timeout=1800, env=dict(os.environ, PYTHON=sys.executable))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("e2e: ok", p.stdout)


if __name__ == "__main__":
    unittest.main()
