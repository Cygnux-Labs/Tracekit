#!/usr/bin/env python3
"""Browser-agent actions as policy-checked, signed steps. Runs offline: a Stagehand-shaped page stand-in, plus
Browser Use's real Tools registry when `browser-use` is installed (a custom action, no browser launched).
A policy rule keeps the agent off one domain; the denied action never runs."""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tracekit.adapters.browser import instrument_browser_use, instrument_stagehand  # noqa: E402
from tracekit_sdk import Tracer  # noqa: E402

if "TRACEKIT_POLICY" not in os.environ:
    pol = os.path.join(tempfile.mkdtemp(), "policy.yaml")
    with open(pol, "w") as f:
        f.write("extends: default\nversion: browser-example\ndeny:\n  - id: EX-NO-BANK\n    tool: 'browser:.*'\n"
                "    pattern: 'bank\\.example'\n    reason: agents stay off the bank\n")
    os.environ["TRACEKIT_POLICY"] = pol


class Page:  # stand-in with Stagehand's page API
    async def goto(self, url):
        return f"loaded {url}"

    async def act(self, instruction):
        return {"success": True, "action": instruction}

    async def extract(self, instruction):
        return {"title": "Pricing"}


async def stagehand(t):
    page = instrument_stagehand(Page(), t)
    print(await page.goto("https://shop.example/pricing"))
    print(await page.act("click the monthly toggle"))
    print(await page.extract("get the page title"))
    try:
        await page.goto("https://bank.example/login")
    except PermissionError as e:
        print("denied:", e)


async def browser_use(t):
    try:
        from browser_use import Tools
        from browser_use.agent.views import ActionResult
    except ImportError:
        print("browser-use not installed: skipping that half")
        return
    tools = Tools()

    @tools.action("Record a note (example action)")
    async def note(text: str) -> ActionResult:
        return ActionResult(extracted_content="noted: " + text)

    instrument_browser_use(tools, t)
    print((await tools.registry.execute_action("note", {"text": "monthly plan is $20"})).extracted_content)
    print("denied:", (await tools.registry.execute_action("note", {"text": "visit bank.example"})).error)


with Tracer(agent="browser-example") as t:
    asyncio.run(stagehand(t))
    asyncio.run(browser_use(t))
print("browser example finished; session", t.session_id)
