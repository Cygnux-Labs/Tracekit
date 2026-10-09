"""Browser Use action hooks, against duck-typed stand-ins (browser-use is not a test dependency)."""
import asyncio
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit.adapters.browser import instrument_browser_use  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402
from factories import DaemonCase  # noqa: E402


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


class Browser(DaemonCase):
    policy_yaml = ("extends: default\nversion: browser-test\ndeny:\n  - id: X-BANK\n    tool: 'browser:(navigate|goto)'\n"
                   "    pattern: 'bank\\.example'\n    reason: agents stay off the bank\n")

    def events(self):
        return [r["event"] for r in self.records()]

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


if __name__ == "__main__":
    unittest.main()
