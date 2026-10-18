"""A Pydantic AI agent gated by Tracekit, offline: a FunctionModel (no API key) asks for three shell commands. The dev
signer allows `ls`, denies `sudo rm -rf /` (the model reads why and the run goes on) and holds an unparsable command
for a person. Then the run is exported and verified.

    python examples/v2/pydantic_ai/agent.py [--scripted]
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

from pydantic_ai import Agent   # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart   # noqa: E402
from pydantic_ai.models.function import FunctionModel   # noqa: E402

from tracekit.integrations.pydantic_ai import Tracekit   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


def model(messages, info):
    """The mock model: the three commands in one response, then what each tool returned."""
    returns = [p for m in messages for p in m.parts if isinstance(p, ToolReturnPart)]
    if not returns:
        return ModelResponse(parts=[ToolCallPart("Bash", {"command": c}, f"call-{i}")
                                    for i, c in enumerate((SAFE, RISKY, HELD), 1)])
    return ModelResponse(parts=[TextPart("\n".join(f"{r.tool_call_id}: {r.content}" for r in returns))])


def Bash(command: str) -> str:   # noqa: N802 - the coding pack maps the tool name Bash to the shell class
    """Run a shell command."""
    return f"(pretend) ran {command}"


with Client().run(agent="pydantic-ai-example") as run, approver(run.client, run.run_id):
    agent = Agent(FunctionModel(model), tools=[Bash], capabilities=[Tracekit(run)])
    print(agent.run_sync("tidy up the build directory").output)
sys.exit(export_and_verify(run.run_id))
