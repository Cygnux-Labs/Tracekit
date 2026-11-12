"""Probe #687: tracekit_tool_node (one ToolNode task runs every call of a message) with two calls that both ask, under
ainvoke. LangGraph numbers interrupts in the order the gates reach interrupt(); the gate now runs in worker threads.
Resume with the approval id the first pause showed, after a person approves it, and see which call gets it."""
import asyncio
import json
import random
import sys
import time
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


@tool
def pay(to: str) -> str:
    """Pay someone."""
    RAN.append(to)
    return f"paid {to}"


class Model(BaseChatModel):
    def _generate(self, messages, stop=None, run_manager=None, **kw):
        if isinstance(messages[-1], HumanMessage):
            msg = AIMessage("", tool_calls=[{"name": "pay", "args": {"to": "alice"}, "id": "c1"},
                                            {"name": "pay", "args": {"to": "bob"}, "id": "c2"}])
        else:
            msg = AIMessage("done")
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kw):
        return self

    @property
    def _llm_type(self):
        return "stub"


def trial(jitter):
    RAN.clear()
    signer = FakeSigner(lambda tool, args: ("ask", ["R-PAY"]))
    run = signer.register_run({"request_id": "reg", "agent": {"name": "t"}})
    decide = signer.approval_request
    signer.approval_request = lambda req: (time.sleep(random.random() * jitter), decide(req))[1]
    g = StateGraph(MessagesState)
    g.add_node("model", lambda s: {"messages": [Model().invoke(s["messages"])]})
    g.add_node("tools", tracekit_tool_node([pay], signer, run))
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    a = g.compile(checkpointer=InMemorySaver())
    cfg = {"configurable": {"thread_id": "t"}}
    out = asyncio.run(a.ainvoke({"messages": [HumanMessage("go")]}, cfg))
    shown = out["__interrupt__"][0].value["tracekit"]
    signer.approval_decide({"request_id": "d1",
                            "approval_id": shown["approval_id"], "decision": "approve"})
    out = asyncio.run(a.ainvoke(Command(resume={"approval_id": shown["approval_id"]}), cfg))
    msgs = {m.tool_call_id: m.content[:60] for m in out.get("messages", []) if isinstance(m, ToolMessage)}
    return shown["tool_call_id"], list(RAN), msgs, "__interrupt__" in out


jitter = float(sys.argv[1]) if len(sys.argv) > 1 else 0.05
results = {}
for i in range(int(sys.argv[2]) if len(sys.argv) > 2 else 12):
    try:
        shown, ran, msgs, paused = trial(jitter)
        key = f"pause showed {shown}; ran {ran}; paused again {paused}; refused: " + \
              ", ".join(f"{k}" for k, v in msgs.items() if "blocked" in v)
    except Exception as e:
        key = f"raised {type(e).__name__}: {str(e)[:120]}"
    results[key] = results.get(key, 0) + 1
for k, v in results.items():
    print(v, "x", k)
