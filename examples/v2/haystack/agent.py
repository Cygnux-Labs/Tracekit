"""A Haystack agent gated by Tracekit, offline: a MockChatGenerator (no API key) asks for three shell commands. The dev
signer allows `ls`, denies `sudo rm -rf /` (the model reads why and the run goes on) and holds an unparsable command
for a person. Then the run is exported and verified.

    python examples/v2/haystack/agent.py [--scripted]
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

os.environ.setdefault("HAYSTACK_TELEMETRY_ENABLED", "False")   # Haystack's usage telemetry: off, offline
from haystack.components.agents import Agent   # noqa: E402
from haystack.components.generators.chat import MockChatGenerator   # noqa: E402
from haystack.dataclasses import ChatMessage, ToolCall   # noqa: E402
from haystack.tools import tool   # noqa: E402

from tracekit.integrations.haystack import Tracekit   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


def model(messages):
    """The mock model: the three commands in one response, then what each tool returned."""
    results = [m.tool_call_result for m in messages if m.tool_call_result]
    if not results:
        return ChatMessage.from_assistant(tool_calls=[ToolCall("Bash", {"command": c}, f"call-{i}")
                                                      for i, c in enumerate((SAFE, RISKY, HELD), 1)])
    return "\n".join(f"{r.origin.id}: {r.result}" for r in sorted(results, key=lambda r: r.origin.id))


@tool
def Bash(command: str) -> str:   # noqa: N802 - the coding pack maps the tool name Bash to the shell class
    """Run a shell command."""
    return f"(pretend) ran {command}"


with Client().run(agent="haystack-example") as run, approver(run.client, run.run_id):
    tk = Tracekit(run)
    agent = Agent(chat_generator=MockChatGenerator(response_fn=model), tools=[Bash],
                  hooks={"before_tool": [tk], "after_tool": [tk]})
    print(agent.run([ChatMessage.from_user("tidy up the build directory")])["last_message"].text)
sys.exit(export_and_verify(run.run_id))
