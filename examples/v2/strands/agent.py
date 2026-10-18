"""A Strands agent gated by Tracekit, offline: a scripted model (no API key) asks for three shell commands. The dev
signer allows `ls`, denies `sudo rm -rf /` (the model reads why and the run goes on) and holds an unparsable command
for a person. Then the run is exported and verified.

    python examples/v2/strands/agent.py [--scripted]
"""
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

from strands import Agent, tool   # noqa: E402
from strands.models import Model   # noqa: E402

from tracekit.integrations.strands import Tracekit   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


class MockModel(Model):
    """The mock model: the three commands in one response, then what each tool returned."""

    def update_config(self, **config):
        pass

    def get_config(self):
        return {}

    async def structured_output(self, *args, **kwargs):
        raise NotImplementedError
        yield

    async def stream(self, messages, *args, **kwargs):
        results = [c["toolResult"] for c in messages[-1]["content"] if "toolResult" in c]
        yield {"messageStart": {"role": "assistant"}}
        if results:
            text = "\n".join(f"{r['toolUseId']}: {r['content'][0]['text']}" for r in results)
            yield {"contentBlockDelta": {"delta": {"text": text}}}
            yield {"contentBlockStop": {}}
        for i, command in enumerate(() if results else (SAFE, RISKY, HELD), 1):
            yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": f"call-{i}", "name": "Bash"}}}}
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps({"command": command})}}}}
            yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": "end_turn" if results else "tool_use"}}


@tool
def Bash(command: str) -> str:   # noqa: N802 - the coding pack maps the tool name Bash to the shell class
    """Run a shell command."""
    return f"(pretend) ran {command}"


with Client().run(agent="strands-example") as run, approver(run.client, run.run_id):
    agent = Agent(model=MockModel(), tools=[Bash], hooks=[Tracekit(run)], callback_handler=None)
    print(agent("tidy up the build directory"))
sys.exit(export_and_verify(run.run_id))
