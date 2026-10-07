"""Browser Use and Stagehand action hooks, against duck-typed stand-ins (neither library is a test dependency)."""
import asyncio
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import install  # noqa: E402
from tracekit.adapters.browser import instrument_browser_use, instrument_stagehand  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402


class Result:
    def __init__(self, extracted_content=None, error=None):
        self.extracted_content, self.error = extracted_content, error

    def model_dump(self, exclude_none=False):
        d = {"extracted_content": self.extracted_content, "error": self.error, "images": ["big"]}
        return {k: v for k, v in d.items() if v is not None} if exclude_none else d


class Registry:
    def __init__(self):
        self.ran = []

    async def execute_action(self, action_name, params, browser_session=None, **kwargs):
        self.ran.append(action_name)
        if action_name == "click":
            return Result(error="element not found")
        return Result(extracted_content="ok:" + action_name)


class Tools:
    def __init__(self):
        self.registry = Registry()


class Page:
    def __init__(self):
        self.ran = []

    async def act(self, instruction):
        self.ran.append(instruction)
        return {"success": True}

    def goto(self, url):
        self.ran.append(url)
        return "loaded"


class Browser(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = {k: os.environ.get(k) for k in ("TRACEKIT_CLIENT_HOME", "TRACEKIT_POLICY")}
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        pol = os.path.join(self.d, "p.yaml")
        with open(pol, "w") as f:
            f.write("extends: default\nversion: browser-test\ndeny:\n  - id: X-BANK\n    tool: 'browser:(navigate|goto)'\n"
                    "    pattern: 'bank\\.example'\n    reason: agents stay off the bank\n")
        os.environ["TRACEKIT_POLICY"] = pol
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

    def test_browser_use_actions_are_gated_and_recorded(self):
        tools = Tools()
        with Tracer(agent="bu", cwd=self.d) as t:
            instrument_browser_use(tools, t)
            instrument_browser_use(tools, t)  # idempotent

            async def go():
                ok = await tools.registry.execute_action("navigate", {"url": "https://docs.example/a"})
                try:  # an error result with browser_use installed, PermissionError without it
                    bad = await tools.registry.execute_action("navigate", {"url": "https://bank.example/login"})
                except PermissionError as e:
                    bad = e
                err = await tools.registry.execute_action("click", {"index": 3})
                return ok, bad, err
            ok, bad, err = asyncio.run(go())
        self.assertEqual(ok.extracted_content, "ok:navigate")
        self.assertEqual(tools.registry.ran, ["navigate", "click"])  # the denied action never ran
        self.assertTrue(isinstance(bad, PermissionError) or "Blocked by Tracekit policy" in str(getattr(bad, "error", "")))
        evs = self.events()
        self.assertEqual([e["data"]["name"] for e in evs if e["type"] == "tool.call"],
                         ["browser:navigate", "browser:navigate", "browser:click"])
        self.assertEqual([e["data"]["decision"] for e in evs if e["type"] == "policy.decision"], ["allow", "deny", "allow"])
        self.assertEqual([e["data"]["ok"] for e in evs if e["type"] == "tool.result"], [True, False])
        self.assertEqual(err.error, "element not found")

    def test_stagehand_page_methods(self):
        page = Page()
        with Tracer(agent="sh", cwd=self.d) as t:
            instrument_stagehand(page, t)
            self.assertEqual(asyncio.run(page.act("click the login button")), {"success": True})
            self.assertEqual(page.goto("https://docs.example"), "loaded")
            with self.assertRaises(PermissionError):
                page.goto("https://bank.example")
        self.assertEqual(page.ran, ["click the login button", "https://docs.example"])
        names = [e["data"]["name"] for e in self.events() if e["type"] == "tool.call"]
        self.assertEqual(names, ["browser:act", "browser:goto", "browser:goto"])


if __name__ == "__main__":
    unittest.main()
