"""A LlamaIndex AgentWorkflow gated by Tracekit, offline: scripted MockFunctionCallingLLMs (no API key) have the triage
agent hand off to the ops agent, which asks for three shell commands. The dev signer allows `ls`, denies
`sudo rm -rf /` (the model reads why and the run goes on) and holds an unparsable command for a person. Then the run is
exported and verified.

    python examples/v2/llama_index/agent.py [--scripted]
"""
import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify   # noqa: E402

from llama_index.core.agent.workflow import AgentWorkflow, FunctionAgent   # noqa: E402
from llama_index.core.base.llms.types import ToolCallBlock   # noqa: E402
from llama_index.core.llms import ChatMessage   # noqa: E402
from llama_index.core.llms.mock import MockFunctionCallingLLM   # noqa: E402

from tracekit.integrations.llama_index import Tracekit   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


def triage(messages, **kw):
    """The triage agent's mock model: hands the request to ops."""
    return ChatMessage(role="assistant", blocks=[ToolCallBlock(tool_call_id="handoff-1", tool_name="handoff",
                                                               tool_kwargs={"to_agent": "ops",
                                                                            "reason": "it runs shell commands"})])


def ops(messages, **kw):
    """The ops agent's mock model: the three commands in one response, then what each tool returned."""
    returns = [m for m in messages if m.role == "tool" and m.additional_kwargs["tool_call_id"].startswith("call-")]
    if not returns:
        return ChatMessage(role="assistant", blocks=[ToolCallBlock(tool_call_id=f"call-{i}", tool_name="Bash",
                                                                   tool_kwargs={"command": c})
                                                     for i, c in enumerate((SAFE, RISKY, HELD), 1)])
    return ChatMessage(role="assistant", content="\n".join(f"{m.additional_kwargs['tool_call_id']}: {m.content}"
                                                           for m in returns))


def Bash(command: str) -> str:   # noqa: N802 - the coding pack maps the tool name Bash to the shell class
    """Run a shell command."""
    return f"(pretend) ran {command}"


async def main(run):
    agents = [FunctionAgent(name="triage", description="Routes requests.",
                            llm=MockFunctionCallingLLM(response_generator=triage)),
              FunctionAgent(name="ops", description="Runs shell commands.", tools=[Bash],
                            llm=MockFunctionCallingLLM(response_generator=ops))]
    workflow = Tracekit(run).gate(AgentWorkflow(agents=agents, root_agent="triage"))
    print(await workflow.run(user_msg="tidy up the build directory"))


with Client().run(agent="llama-index-example") as run, approver(run.client, run.run_id):
    asyncio.run(main(run))
sys.exit(export_and_verify(run.run_id))
