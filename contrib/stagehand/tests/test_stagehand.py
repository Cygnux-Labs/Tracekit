"""Stagehand page hooks against a duck-typed stand-in (stagehand is not a test dependency), and the browser example.
python3 -m pytest contrib/stagehand/tests -q"""
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from tracekit_stagehand import instrument_stagehand
from tracekit import bundle, install
from tracekit.agent_sdk import Tracer
from tracekit.ledger import read_records


class Page:
    def __init__(self):
        self.ran = []

    async def act(self, instruction):
        self.ran.append(instruction)
        return {"success": True}

    def goto(self, url):
        self.ran.append(url)
        return "loaded"


class Stagehand(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = {k: os.environ.get(k) for k in ("TRACEKIT_CLIENT_HOME", "TRACEKIT_POLICY")}
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        os.environ.pop("TRACEKIT_POLICY", None)
        install.init_dev(self.home, [], start=True)

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.d, ignore_errors=True)

    def events(self):
        return [r["event"] for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r]

    def test_page_methods(self):
        pol = os.path.join(self.d, "p.yaml")
        with open(pol, "w") as f:
            f.write("extends: default\nversion: browser-test\ndeny:\n  - id: X-BANK\n    tool: 'browser:goto'\n"
                    "    pattern: 'bank\\.example'\n    reason: agents stay off the bank\n")
        os.environ["TRACEKIT_POLICY"] = pol
        page = Page()
        with Tracer(agent="sh", cwd=self.d) as t:
            instrument_stagehand(page, t)
            instrument_stagehand(page, t)  # idempotent
            self.assertEqual(asyncio.run(page.act("click the login button")), {"success": True})
            self.assertEqual(page.goto("https://docs.example"), "loaded")
            with self.assertRaises(PermissionError):
                page.goto("https://bank.example")
        self.assertEqual(page.ran, ["click the login button", "https://docs.example"])
        names = [e["data"]["name"] for e in self.events() if e["type"] == "tool.call"]
        self.assertEqual(names, ["browser:act", "browser:goto", "browser:goto"])

    def test_example(self):
        p = subprocess.run([sys.executable, os.path.join(HERE, "browser_agent.py")], cwd=self.d, env=dict(os.environ, TMPDIR=self.d), capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("denied:", p.stdout)
        names = [e["data"]["name"] for e in self.events() if e["type"] == "tool.call"]
        for n in ["browser:goto", "browser:act", "browser:extract"]:
            self.assertIn(n, names)
        out = os.path.join(self.d, "x.tkb")
        bundle.export(self.home, out)
        self.assertEqual(bundle.verify(out)[1], 0)


if __name__ == "__main__":
    unittest.main()
