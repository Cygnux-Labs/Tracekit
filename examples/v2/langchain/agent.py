"""A LangGraph agent (ToolNode + checkpointer) on the v2 signer, offline: a mock model asks for three shell commands.
The dev signer allows `ls`, denies `sudo rm -rf /` (the model gets the refusal and goes on) and holds an unparsable
command: the graph pauses with interrupt() until a person approves, then resumes. Then the run is exported and verified.

    python examples/v2/langchain/agent.py [--scripted]
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify, wait   # noqa: E402

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel   # noqa: E402
from langchain_core.messages import AIMessage   # noqa: E402
from langchain_core.tools import tool   # noqa: E402
from langgraph.checkpoint.memory import InMemorySaver   # noqa: E402
from langgraph.graph import START, MessagesState, StateGraph   # noqa: E402
from langgraph.prebuilt import tools_condition   # noqa: E402
from langgraph.types import Command   # noqa: E402

from tracekit.integrations.langchain import TracekitCheckpointer, tracekit_tool_node   # noqa: E402
from tracekit.sdk.client import Client   # noqa: E402


def call(n, command):
    return {"name": "Bash", "args": {"command": command}, "id": f"call-{n}"}


MODEL = GenericFakeChatModel(messages=iter([   # the mock model's replies, in order
    AIMessage("", tool_calls=[call(1, SAFE), call(2, RISKY)]),
    AIMessage("", tool_calls=[call(3, HELD)]),
    AIMessage("Listed the files; the delete was refused; the echo ran once approved."),
]))


@tool("Bash")
def bash(command: str) -> str:
    """Run a shell command."""
    return f"(pretend) ran {command}"


with Client().run(agent="langgraph-example") as run, approver(run.client, run.run_id):
    g = StateGraph(MessagesState)
    g.add_node("model", lambda state: {"messages": [MODEL.invoke(state["messages"])]})
    g.add_node("tools", tracekit_tool_node([bash], run.client, run.registered))   # every call through the signer
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    agent = g.compile(checkpointer=TracekitCheckpointer(InMemorySaver(), run.client, run.registered))
    thread = {"configurable": {"thread_id": "example"}}
    out = agent.invoke({"messages": [("user", "tidy up")]}, thread)
    while "__interrupt__" in out:   # an ask: the graph is paused and saved until a person decides
        ask = out["__interrupt__"][0].value["tracekit"]
        print(f"{ask['tool']} paused for approval ({', '.join(ask['rule_ids'])})")
        wait(run, ask["approval_id"])
        out = agent.invoke(Command(resume={"approval_id": ask["approval_id"]}), thread)
    for m in out["messages"][1:]:
        print(f"{m.type}: {m.content or [c['args']['command'] for c in m.tool_calls]}")
sys.exit(export_and_verify(run.run_id))
