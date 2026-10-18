"""A Microsoft Agent Framework agent gated by Tracekit, offline: a scripted chat client (no API key) asks for three
shell commands. The dev signer allows `ls`, denies `sudo rm -rf /` (the model reads why and the run goes on) and holds
an unparsable command for a person. Then the run is exported and verified.

    python examples/v2/agent_framework/agent.py [--scripted]
"""
import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

from agent_framework import (Agent, BaseChatClient, ChatResponse, Content, FunctionInvocationLayer,   # noqa: E402
                             Message)

from tracekit.integrations.agent_framework import Tracekit   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


class ScriptedModel(FunctionInvocationLayer, BaseChatClient):
    """The mock model: the three commands in one response, then what each call returned."""

    def _inner_get_response(self, *, messages, stream, options, **kwargs):
        results = [c for m in messages for c in m.contents if c.type == "function_result"]
        contents = ([Content.from_text("\n".join(f"{r.call_id}: {r.result}" for r in results))] if results else
                    [Content.from_function_call(f"call-{i}", "Bash", arguments={"command": c})
                     for i, c in enumerate((SAFE, RISKY, HELD), 1)])

        async def response():
            return ChatResponse(messages=[Message(role="assistant", contents=contents)])
        return response()


def Bash(command: str) -> str:   # noqa: N802 - the coding pack maps the tool name Bash to the shell class
    """Run a shell command."""
    return f"(pretend) ran {command}"


with Client().run(agent="agent-framework-example") as run, approver(run.client, run.run_id):
    agent = Agent(client=ScriptedModel(), tools=[Bash], middleware=[Tracekit(run)])
    print(asyncio.run(agent.run("tidy up the build directory")).text)
sys.exit(export_and_verify(run.run_id))
