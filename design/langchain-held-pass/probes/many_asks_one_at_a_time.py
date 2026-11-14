"""Three `ask` calls in one ToolNode message: approve the shown one, resume, and see what runs; then approve the next
shown one and resume again. Prints what ran and the ToolMessages after each resume."""
import asyncio
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
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3


@tool
def pay(to: str) -> str:
    """Pay someone."""
    RAN.append(to)
    return f"paid {to}"


class Model(BaseChatModel):
    def _generate(self, messages, stop=None, run_manager=None, **kw):
        if isinstance(messages[-1], HumanMessage):
            msg = AIMessage("", tool_calls=[{"name": "pay", "args": {"to": f"p{i}"}, "id": f"c{i}"} for i in range(N)])
        else:
            msg = AIMessage("done")
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kw):
        return self

    @property
    def _llm_type(self):
        return "stub"


signer = FakeSigner(lambda tool, args: ("ask", ["R-PAY"]))
run = signer.register_run({"request_id": "reg", "agent": {"name": "t"}})
g = StateGraph(MessagesState)
g.add_node("model", lambda s: {"messages": [Model().invoke(s["messages"])]})
g.add_node("tools", tracekit_tool_node([pay], signer, run))
g.add_edge(START, "model")
g.add_conditional_edges("model", tools_condition)
g.add_edge("tools", "model")
a = g.compile(checkpointer=InMemorySaver())
cfg = {"configurable": {"thread_id": "t"}}
mode = sys.argv[2] if len(sys.argv) > 2 else "sync"
inv = a.invoke if mode == "sync" else (lambda v, c: asyncio.run(a.ainvoke(v, c)))
out = inv({"messages": [HumanMessage("go")]}, cfg)
for step in range(N + 1):
    if "__interrupt__" not in out:
        break
    shown = out["__interrupt__"][0].value["tracekit"]
    signer.approval_decide({"request_id": f"d{step}", "approval_id": shown["approval_id"], "decision": "approve"})
    out = inv(Command(resume={"approval_id": shown["approval_id"]}), cfg)
    msgs = {m.tool_call_id: m.content[:90] for m in out.get("messages", []) if isinstance(m, ToolMessage)}
    print(f"resume {step}: approved {shown['tool_call_id']}; ran so far {RAN}; paused again {'__interrupt__' in out}")
    for k, v in msgs.items():
        print("   ", k, v)
