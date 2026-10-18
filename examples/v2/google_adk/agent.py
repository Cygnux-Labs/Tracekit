"""A Google ADK agent gated by Tracekit, offline: a scripted model (no API key) asks for three shell commands. The dev
signer allows `ls`, denies `sudo rm -rf /` (the model reads why and the run goes on) and holds an unparsable command
for a person. Then the run is exported and verified.

    python examples/v2/google_adk/agent.py [--scripted]
"""
import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

from google.adk.agents import LlmAgent   # noqa: E402
from google.adk.apps import App   # noqa: E402
from google.adk.models.base_llm import BaseLlm   # noqa: E402
from google.adk.models.llm_response import LlmResponse   # noqa: E402
from google.adk.runners import InMemoryRunner   # noqa: E402
from google.genai import types   # noqa: E402

from tracekit.integrations.google_adk import Tracekit   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


class ScriptedModel(BaseLlm):
    """The mock model: the three commands in one response, then what each tool returned."""
    model: str = "scripted"

    async def generate_content_async(self, llm_request, stream=False):
        returns = [p.function_response for c in llm_request.contents for p in c.parts or () if p.function_response]
        if not returns:
            parts = [types.Part(function_call=types.FunctionCall(name="Bash", args={"command": c}, id=f"call-{i}"))
                     for i, c in enumerate((SAFE, RISKY, HELD), 1)]
        else:
            parts = [types.Part(text="\n".join(f"{r.id}: {r.response}" for r in returns))]
        yield LlmResponse(content=types.Content(role="model", parts=parts))


def Bash(command: str) -> str:   # noqa: N802 - the coding pack maps the tool name Bash to the shell class
    """Run a shell command."""
    return f"(pretend) ran {command}"


async def main(run):
    agent = LlmAgent(name="tidy", model=ScriptedModel(), tools=[Bash])
    runner = InMemoryRunner(app=App(name="google_adk_example", root_agent=agent, plugins=[Tracekit(run)]))
    for event in await runner.run_debug("tidy up the build directory", quiet=True):
        if event.is_final_response():
            print(event.content.parts[0].text)


with Client().run(agent="google-adk-example") as run, approver(run.client, run.run_id):
    asyncio.run(main(run))
sys.exit(export_and_verify(run.run_id))
