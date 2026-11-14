"""A tool that asks the person itself (interrupt("confirm?")) under a Tracekit ask, plus siblings. For each builder
(create_agent, tracekit_tool_node), shape (one call, several) and mode (invoke, ainvoke): approve what Tracekit shows,
answer the tool's own question with "yes-<n>", and print what the tool got, what ran, what the model read, and the
signer's records."""
import asyncio
import json
import sys
import warnings

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition
from langgraph.types import Command, interrupt

from tracekit.integrations.langchain import TracekitMiddleware, tracekit_tool_node
from tracekit.testing import FakeSigner

warnings.simplefilter("ignore")
RAN, GOT = [], []


@tool
def pay(to: str) -> str:
    """Pay, after the person confirms."""
    answer = interrupt(f"confirm paying {to}?")
    GOT.append((to, answer))
    RAN.append(to)
    return f"paid {to} ({answer})"


@tool
def echo(text: str) -> str:
    """Echo."""
    RAN.append("echo")
    return text


class Model(BaseChatModel):
    def _generate(self, messages, stop=None, run_manager=None, **kw):
        if isinstance(messages[-1], HumanMessage):
            msg = AIMessage("", tool_calls=json.loads(messages[-1].content))
        else:
            msg = AIMessage("done")
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kw):
        return self

    @property
    def _llm_type(self):
        return "stub"


def trial(builder, shape, mode):
    RAN.clear(), GOT.clear()
    signer = FakeSigner(lambda t, a: ("ask", ["R-PAY"]) if t == "pay" else ("allow", []))
    run = signer.register_run({"request_id": "reg", "agent": {"name": "t"}})
    if builder == "create_agent":
        a = create_agent(Model(), [pay, echo], checkpointer=InMemorySaver(),
                         middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"])])
    else:
        g = StateGraph(MessagesState)
        g.add_node("model", lambda s: {"messages": [Model().invoke(s["messages"])]})
        g.add_node("tools", tracekit_tool_node([pay, echo], signer, run))
        g.add_edge(START, "model")
        g.add_conditional_edges("model", tools_condition)
        g.add_edge("tools", "model")
        a = g.compile(checkpointer=InMemorySaver())
    cfg = {"configurable": {"thread_id": "t"}}
    go = a.invoke if mode == "sync" else (lambda v, c: asyncio.run(a.ainvoke(v, c)))
    calls = [{"name": "pay", "args": {"to": "p0"}, "id": "c0"}]
    if shape == "several":
        calls += [{"name": "pay", "args": {"to": "p1"}, "id": "c1"}, {"name": "echo", "args": {"text": "hi"}, "id": "e"}]
    out = go({"messages": [HumanMessage(json.dumps(calls))]}, cfg)
    steps, n = [], 0
    while "__interrupt__" in out and n < 8:
        n += 1
        answers = {}
        for i in out["__interrupt__"]:   # parallel tasks (create_agent's Send) pause together: one answer each
            v = i.value
            if isinstance(v, dict) and "tracekit" in v:
                first = v["tracekit"]
                signer.approval_decide({"request_id": f"d{n}{first['approval_id']}", "approval_id": first["approval_id"],
                                        "decision": "approve"})
                steps.append(f"approved {first['tool_call_id']}")
                answers[i.id] = {"approval_id": first["approval_id"]}
            else:
                steps.append(f"tool asked {v!r}")
                answers[i.id] = f"yes-{n}"
        out = go(Command(resume=answers), cfg)
    ev = signer.read({"run_id": run["run_id"], "run_token": run["run_token"], "limit": 1000})["events"]
    count = lambda t: sorted(e["data"].get("tool_call_id") or e["data"].get("approval_id") for e in ev if e["type"] == t)
    msgs = {m.tool_call_id: m.content[:48] for m in out.get("messages", []) if isinstance(m, ToolMessage)}
    print(f"{builder:13} {shape:7} {mode:5} | {' -> '.join(steps)} | got {GOT} | ran {RAN} | {msgs} | "
          f"approval.request {len(count('approval.request'))} results {count('tool.result')}")


for builder in ("create_agent", "tool_node"):
    for shape in ("one", "several"):
        for mode in ("sync", "async"):
            try:
                trial(builder, shape, mode)
            except Exception as e:
                print(builder, shape, mode, "raised", type(e).__name__, str(e)[:150])
