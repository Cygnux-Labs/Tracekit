"""A Claude Agent SDK agent on the v2 signer, offline: a mock CLI (it plays the `claude` process and its model) asks
for three shell commands, each through the SDK's PreToolUse and PostToolUse hooks. The dev signer allows `ls`, denies
`sudo rm -rf /` (the model gets the reason as the tool's error and goes on) and holds an unparsable command in the hook
until a person approves. Then the run is exported and verified.

    python examples/v2/claude_agent_sdk/agent.py [--scripted]
"""
import asyncio
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

from claude_agent_sdk import ClaudeAgentOptions, query   # noqa: E402
from claude_agent_sdk._internal.transport import Transport   # noqa: E402

from tracekit.integrations.claude_agent_sdk import tracekit_hooks   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402

MODEL = [("toolu_1", SAFE), ("toolu_2", RISKY), ("toolu_3", HELD)]   # the mock model's tool calls, in order


class MockCLI(Transport):
    """The SDK's control protocol, as the CLI speaks it: it calls the registered hooks around each tool call."""

    def __init__(self):
        self.out, self.hooks, self.waiting, self.n = asyncio.Queue(), {}, {}, 0

    async def connect(self):
        pass

    def is_ready(self):
        return True

    async def end_input(self):
        pass

    async def close(self):
        pass

    async def read_messages(self):
        while (m := await self.out.get()) is not None:
            yield m

    async def write(self, data):
        m = json.loads(data)
        if m["type"] == "control_request" and m["request"]["subtype"] == "initialize":
            self.hooks = m["request"]["hooks"] or {}
            await self.out.put({"type": "control_response",
                                "response": {"subtype": "success", "request_id": m["request_id"], "response": {}}})
        elif m["type"] == "control_response":
            self.waiting.pop(m["response"]["request_id"]).set_result(m["response"].get("response") or {})
        elif m["type"] == "user":
            self.task = asyncio.ensure_future(self.turn())

    async def hook(self, event, **fields):
        out = {}
        for matcher in self.hooks.get(event, []):
            for cid in matcher["hookCallbackIds"]:
                self.n += 1
                rid = f"cli-{self.n}"
                self.waiting[rid] = asyncio.get_running_loop().create_future()
                await self.out.put({"type": "control_request", "request_id": rid, "request": {
                    "subtype": "hook_callback", "callback_id": cid, "tool_use_id": fields["tool_use_id"],
                    "input": {"hook_event_name": event, "session_id": "s1", "transcript_path": "", "cwd": "/", **fields}}})
                out.update(await self.waiting[rid])
        return out

    async def turn(self):
        for tid, command in MODEL:
            call = {"tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": tid}
            pre = (await self.hook("PreToolUse", **call)).get("hookSpecificOutput", {})
            if pre.get("permissionDecision") == "deny":
                print(f"Bash {command!r}: {pre['permissionDecisionReason']}; the agent goes on")
                continue
            print(f"Bash {command!r}: (pretend) ran {command}")
            await self.hook("PostToolUse", **call, tool_response={"stdout": f"(pretend) ran {command}"})
        await self.out.put({"type": "result", "subtype": "success", "duration_ms": 0, "duration_api_ms": 0,
                            "is_error": False, "num_turns": 1, "session_id": "s1"})
        await self.out.put(None)


async def prompt():
    yield {"type": "user", "message": {"role": "user", "content": "tidy up"}, "parent_tool_use_id": None,
           "session_id": ""}


async def main(run):
    options = ClaudeAgentOptions(hooks=tracekit_hooks(run.client, run.registered))
    async for _ in query(prompt=prompt(), options=options, transport=MockCLI()):   # drop transport= for the real CLI
        pass


with Client().run(agent="claude-agent-sdk-example") as run, approver(run.client, run.run_id):
    asyncio.run(main(run))
sys.exit(export_and_verify(run.run_id))
