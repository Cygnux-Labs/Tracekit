"""One message: an allowed echo and N asking pays in one tracekit_tool_node. Approve every pay as each pause shows it,
resuming after each; print how often each tool ran and what the model read."""
import asyncio
import json
import sys
import warnings

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition
from langgraph.types import Command

from tracekit.integrations.langchain import tracekit_tool_node
from tracekit.testing import FakeSigner

warnings.simplefilter("ignore")
RAN = []
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1


@tool
def pay(to: str) -> str:
    """Pay someone."""
    RAN.append(to)
    return f"paid {to}"


@tool
def echo(text: str) -> str:
    """Echo."""
    RAN.append("echo")
    return text


class Model(BaseChatModel):
    def _generate(self, messages, stop=None, run_manager=None, **kw):
        if isinstance(messages[-1], HumanMessage):
            calls = [{"name": "echo", "args": {"text": "hi"}, "id": "e"}]
            calls += [{"name": "pay", "args": {"to": f"p{i}"}, "id": f"c{i}"} for i in range(N)]
            msg = AIMessage("", tool_calls=calls)
        else:
            msg = AIMessage("done")
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kw):
        return self

    @property
    def _llm_type(self):
        return "stub"


signer = FakeSigner(lambda tool, args: ("ask", ["R-PAY"]) if tool == "pay" else ("allow", []))
run = signer.register_run({"request_id": "reg", "agent": {"name": "t"}})
g = StateGraph(MessagesState)
g.add_node("model", lambda s: {"messages": [Model().invoke(s["messages"])]})
g.add_node("tools", tracekit_tool_node([pay, echo], signer, run))
g.add_edge(START, "model")
g.add_conditional_edges("model", tools_condition)
g.add_edge("tools", "model")
a = g.compile(checkpointer=InMemorySaver())
cfg = {"configurable": {"thread_id": "t"}}
out = a.invoke({"messages": [HumanMessage("go")]}, cfg)
step = 0
while "__interrupt__" in out and step < 10:
    shown = out["__interrupt__"][0].value["tracekit"]
    for x in shown.get("approvals", [shown]):
        signer.approval_decide({"request_id": f"d{step}{x['approval_id']}", "approval_id": x["approval_id"],
                                "decision": "approve"})
    out = a.invoke(Command(resume={"approval_id": shown["approval_id"]}), cfg)
    step += 1
print("resumes:", step, "| ran:", sorted(RAN), "|",
      {m.tool_call_id: m.content[:60] for m in out["messages"] if isinstance(m, ToolMessage)})
