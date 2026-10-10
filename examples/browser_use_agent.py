#!/usr/bin/env python3
"""Browser Use actions gated by the signer with the browser policy pack, offline: a stand-in for browser_use's Tools
(anything with `.registry.execute_action`) and FakeSigner deciding with tracekit/policy2/packs/browser.yaml. With
browser-use installed, wrap the real `Tools()` the same way and run a signer whose policy is the browser pack."""
import asyncio
import os
import sys
import types

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from tracekit.integrations.browser_use import trace_tools  # noqa: E402
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.testing import FakeSigner  # noqa: E402

try:
    from browser_use.agent.views import ActionResult
except ImportError:   # the stand-in's result type, where the adapter looks for browser_use's
    class ActionResult(types.SimpleNamespace):
        def __init__(self, extracted_content=None, error=None):
            super().__init__(extracted_content=extracted_content, error=error)

        def model_dump(self, mode=None, exclude_none=False):
            return {k: v for k, v in vars(self).items() if v is not None}
    for name in ("browser_use", "browser_use.agent", "browser_use.agent.views"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["browser_use.agent.views"].ActionResult = ActionResult


class Registry:   # stand-in for browser_use's action registry
    async def execute_action(self, action_name, params, browser_session=None, sensitive_data=None, **kw):
        return ActionResult(extracted_content=f"{action_name} ok")


class Page:
    async def get_current_page_url(self):
        return "https://docs.python.org/3/"


engine = Engine(pc.build(os.path.join(ROOT, "tracekit", "policy2", "packs", "browser.yaml"))[0])


def rule(tool, args):
    d = engine.decide(tool, args)
    return ("allow" if d["verdict"] == "flag" else d["verdict"]), d["rule_ids"]


async def main():
    signer = FakeSigner(rule)
    run = signer.register_run({"request_id": "r1", "agent": {"name": "browser-example"}})
    tools = trace_tools(types.SimpleNamespace(registry=Registry()), signer, run, approval_wait_s=0)
    for action, params in [("navigate", {"url": "https://docs.python.org/3/"}),
                           ("navigate", {"url": "file:///etc/passwd"}),
                           ("input", {"index": 3, "text": "<secret>pw</secret>"})]:
        out = await tools.registry.execute_action(action, params, browser_session=Page(),
                                                  sensitive_data={"pw": "not-sent-to-the-signer"})
        print(action, params, "->", out.error or out.extracted_content)
    events = signer.read({**{k: run[k] for k in ("run_id", "run_token")}, "limit": 100})["events"]
    print([(e["type"], e["data"].get("decision")) for e in events])


asyncio.run(main())
print("browser example finished")
