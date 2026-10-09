"""Every example in examples/ runs end to end against a fresh dev signer and leaves a ledger that verifies.
Examples whose framework isn't installed are skipped, not failed."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import bundle, install  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402

EXAMPLES = {  # file -> (modules it needs, tool names the ledger must show)
    "custom_agent.py": ((), ["http_get", "parse_table", "Bash"]),
    "langgraph_agent.py": (("langgraph",), ["node:plan", "node:tools", "Read", "node:report"]),
    "mcp_client.py": ((), ["mcp__github__create_issue", "mcp__github__delete_repo"]),
    "model_calls.py": (("httpx",), []),
}


class Examples(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.env = dict(os.environ, TRACEKIT_CLIENT_HOME=os.path.join(self.d, "client"), PYTHONPATH=ROOT)
        self.env.pop("TRACEKIT_POLICY", None)
        self.old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = self.env["TRACEKIT_CLIENT_HOME"]
        install.init_dev(self.home, [], start=True)

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        if self.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = self.old
        shutil.rmtree(self.d, ignore_errors=True)

    def run_example(self, name):
        needs, expected = EXAMPLES[name]
        missing = [m for m in needs if importlib.util.find_spec(m) is None]
        if missing:
            self.skipTest(f"{name} needs {missing}")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "examples", name)], env=self.env, cwd=self.d,
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("finished", p.stdout)
        events = [r["event"] for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r]
        names = [e["data"]["name"] for e in events if e["type"] == "tool.call"]
        for n in expected:
            self.assertIn(n, names)
        out = os.path.join(self.d, "x.tkb")
        bundle.export(self.home, out)
        self.assertEqual(bundle.verify(out)[1], 0)
        return p.stdout, events

    def test_custom_agent(self):
        self.run_example("custom_agent.py")

    def test_langgraph(self):
        _, events = self.run_example("langgraph_agent.py")
        names = [e["data"]["name"] for e in events if e["type"] == "tool.call"]
        self.assertEqual(names, ["node:plan", "node:tools", "Read", "node:report"])

    def test_mcp(self):
        out, events = self.run_example("mcp_client.py")
        self.assertIn("denied:", out)
        self.assertIn("deny", [e["data"]["decision"] for e in events if e["type"] == "policy.decision"])

    def test_model_calls(self):
        out, events = self.run_example("model_calls.py")
        providers = out.rsplit("finished:", 1)[1].strip().split(", ")
        responses = [e["data"] for e in events if e["type"] == "model.exchange" and e["data"].get("phase") == "response"]
        self.assertEqual(len(responses), sum(
            {"openai": 2, "anthropic": 1, "gemini": 1}.get(p, 0) for p in providers))
        self.assertTrue(all(r.get("usage") for r in responses))
        if "openai" in providers:
            self.assertEqual([r.get("streamed") for r in responses[:2]], [False, True])


if __name__ == "__main__":
    unittest.main()
