"""The v2 examples (examples/v2/<framework>/agent.py) run to completion in scripted mode on a dev signer they start on
demand, each with its deny, its approval and a verified bundle; and `tracekit demo --server` verifies its bundle and
fails the tampered copy. A temp HOME and runtime dir keep them off the user's own dev signer."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEEDS = {"custom": (), "langchain": ("langchain", "langgraph"), "openai_agents": ("agents",),
         "claude_agent_sdk": ("claude_agent_sdk",), "mcp": ("mcp",)}


def python(*argv, env, cwd):
    return subprocess.run([sys.executable, *argv], capture_output=True, text=True, env=env, cwd=cwd, timeout=180)


class Examples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
        cls.addClassCleanup(shutil.rmtree, cls.dir, True)
        home = os.path.join(cls.dir, "home")
        cls.env = dict(os.environ, HOME=home, USERPROFILE=home, LOCALAPPDATA=os.path.join(home, "local"),
                       XDG_DATA_HOME=os.path.join(home, "data"), TRACEKIT_RUNTIME_DIR=os.path.join(cls.dir, "run"),
                       PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        for k in ("TRACEKIT_SIGNER", "TRACEKIT_SIGNER_TOKEN"):
            cls.env.pop(k, None)
        cls.addClassCleanup(python, "-m", "tracekit", "down", env=cls.env, cwd=cls.dir)

    def run_example(self, name):
        missing = [m for m in NEEDS[name] if importlib.util.find_spec(m) is None]
        if missing:
            self.skipTest(f"{', '.join(missing)} not installed")
        p = python(os.path.join(ROOT, "examples", "v2", name, "agent.py"), "--scripted", env=self.env, cwd=self.dir)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("Integrity: VERIFIED.\nAssurance: dev", p.stdout)
        self.assertIn("approved: apr-", p.stdout)
        self.assertIn("blocked by policy: TK-DEMO-DENY" if name == "mcp" else "TK-D001", p.stdout)
        return p.stdout

    def test_custom(self):
        self.run_example("custom")

    def test_langchain(self):
        self.run_example("langchain")

    def test_openai_agents(self):
        self.run_example("openai_agents")

    def test_claude_agent_sdk(self):
        self.run_example("claude_agent_sdk")

    def test_mcp(self):
        self.run_example("mcp")


class DemoServer(unittest.TestCase):
    def test_bundle_verifies_and_the_tampered_copy_fails(self):
        p = subprocess.run([sys.executable, "-m", "tracekit", "demo", "--server"], capture_output=True, text=True,
                           timeout=120, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        verified, tampered = p.stdout.split("tamper test")
        self.assertIn("Integrity: VERIFIED.", verified)
        self.assertIn("cosigned ed25519 by witness.demo.tracekit.local", verified)
        self.assertIn("Integrity: FAILED.", tampered)


if __name__ == "__main__":
    unittest.main()
