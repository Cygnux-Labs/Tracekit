"""A CrewAI agent gated by Tracekit, offline: a scripted model (no API key) asks for three shell commands. The dev
signer allows `ls`, denies `sudo rm -rf /` (the model reads why and the run goes on) and holds an unparsable command
for a person. Then the run is exported and verified.

    python examples/v2/crewai/agent.py [--scripted]
"""
import json
import os
import sys
from typing import Any, Dict, List, Optional, Union

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from crewai import Agent, BaseLLM, Crew, Task   # noqa: E402
from crewai.hooks import register_after_tool_call_hook, register_before_tool_call_hook   # noqa: E402
from crewai.tools import BaseTool   # noqa: E402

from tracekit.integrations.crewai import hooks   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


def observations(messages) -> List[str]:
    """What each tool returned, read back from the conversation CrewAI sends the model."""
    found = []
    for m in messages if isinstance(messages, list) else []:
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        content = m.get("content")
        if isinstance(content, str) and "\nObservation:" in content:
            # CrewAI appends its tool instructions after the observation, so cut at the blank lines
            found.append(content.split("\nObservation:", 1)[1].split("\n\n\n")[0].strip())
    return found


class ScriptedLLM(BaseLLM):
    """The scripted model: one ReAct step per call; the last step repeats what the tools returned."""

    def __init__(self, responses: List[str]):
        super().__init__(model="scripted", temperature=0)
        self.responses = responses
        self.i = 0

    def call(
        self,
        messages: Union[str, List[Dict[str, str]]],
        tools: Optional[List[dict]] = None,
        callbacks: Optional[List[Any]] = None,
        available_functions: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Union[str, Any]:
        step = self.i
        self.i += 1
        if step < len(self.responses):
            return self.responses[step]
        return "Thought: Done.\nFinal Answer: " + "\n".join(observations(messages))

    def supports_function_calling(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return 8192


class BashTool(BaseTool):
    """Run a shell command."""

    name: str = "Bash"
    description: str = "Run a shell command."

    def _run(self, command: str) -> str:
        return f"(pretend) ran {command}"


def react(thought: str, command: str) -> str:
    return f"Thought: {thought}\nAction: Bash\nAction Input: {json.dumps({'command': command})}"


mock_responses = [
    react("Run the first command.", SAFE),
    react("Run the second command.", RISKY),
    react("Run the third command.", HELD),
]


with Client().run(agent="crewai-example") as run, approver(run.client, run.run_id):
    before, after = hooks(run)
    register_before_tool_call_hook(before)
    register_after_tool_call_hook(after)

    agent = Agent(
        role="System Administrator",
        goal="Tidy up the build directory using shell commands",
        backstory="An expert executing maintenance scripts.",
        tools=[BashTool()],
        llm=ScriptedLLM(mock_responses),
        allow_delegation=False,
    )
    task = Task(
        description="Run the commands.",
        expected_output="Commands executed.",
        agent=agent,
    )
    crew = Crew(agents=[agent], tasks=[task], verbose=False)
    print(crew.kickoff())
sys.exit(export_and_verify(run.run_id))