"""An OpenAI Agents SDK agent on the v2 signer, offline: a mock model asks for three shell commands. The dev signer
allows `ls`, denies `sudo rm -rf /` (the model gets the refusal as the tool output and goes on) and holds an unparsable
command: the run is interrupted until a person approves, then resumed. Then the run is exported and verified.

    python examples/v2/openai_agents/agent.py [--scripted]
"""
import asyncio
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify, wait   # noqa: E402

from agents import Agent, Model, ModelResponse, Runner, function_tool, set_tracing_disabled   # noqa: E402
from agents.usage import Usage   # noqa: E402
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText   # noqa: E402

from tracekit.integrations.openai_agents import TracekitAgents   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


def call(n, command):
    return ResponseFunctionToolCall(id=f"fc_{n}", call_id=f"call-{n}", type="function_call", name="Bash",
                                    arguments=json.dumps({"command": command}), status="completed")


REPLIES = [   # the mock model's replies, in order
    [call(1, SAFE), call(2, RISKY)],
    [call(3, HELD)],
    [ResponseOutputMessage(id="msg_1", type="message", role="assistant", status="completed", content=[
        ResponseOutputText(type="output_text", annotations=[],
                           text="Listed the files; the delete was refused; the echo ran once approved.")])],
]


class MockModel(Model):
    async def get_response(self, *args, **kw):
        return ModelResponse(output=REPLIES.pop(0), usage=Usage(), response_id=None)

    async def stream_response(self, *args, **kw):
        raise NotImplementedError


@function_tool(name_override="Bash")
def bash(command: str) -> str:
    """Run a shell command."""
    return f"(pretend) ran {command}"


async def main(run):
    tk = TracekitAgents(run.client, run.registered)
    agent = Agent(name="shell", model=MockModel(), tools=[tk.tool(bash)])
    result = await Runner.run(agent, "tidy up", context={}, hooks=tk)   # the run context must be a dict
    while result.interruptions:   # an ask: the run is paused until a person decides in the signer
        approvals = result.context_wrapper.context["tracekit"]["approvals"]   # call id -> approval id
        for item in result.interruptions:
            print(f"{item.raw_item.name} paused for approval")
            await asyncio.to_thread(wait, run, approvals[item.raw_item.call_id])
        state = result.to_state()
        await tk.apply_decisions(state)
        result = await Runner.run(agent, state, hooks=tk)
    for item in result.new_items:
        if item.type == "tool_call_output_item":
            print(f"{item.raw_item['call_id']}: {item.output}")
    print(result.final_output)


set_tracing_disabled(True)   # offline: no traces sent to OpenAI
with Client().run(agent="openai-agents-example") as run, approver(run.client, run.run_id):
    asyncio.run(main(run))
sys.exit(export_and_verify(run.run_id))
