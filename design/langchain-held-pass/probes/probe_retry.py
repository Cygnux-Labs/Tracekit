"""A held ToolNode under a LangGraph RetryPolicy: a flaky tool fails once beside echo. Does the retry run the flaky tool
again?"""
import json, sys, asyncio
sys.path.insert(0, sys.argv[1] + "/tests")
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition
from langgraph.types import RetryPolicy
from test_contract_langchain import StubModel
from tracekit.testing import FakeSigner
from tracekit.integrations.langchain import tracekit_tool_node
import adapter_contract as ac

RAN, FAILS = [], []
@tool
def flaky(x: int) -> str:
    """Fails the first time."""
    RAN.append("flaky")
    if not FAILS:
        FAILS.append(1)
        raise ConnectionError("transient")
    return "ok"

@tool
def echo(text: str) -> str:
    """Echo."""
    RAN.append("echo")
    return text

for mode in ("sync", "async"):
    RAN.clear(); FAILS.clear()
    s = FakeSigner(ac._rule)
    r = s.register_run({"request_id": "reg", "agent": {"name": "p"}})
    g = StateGraph(MessagesState)
    g.add_node("model", lambda st: {"messages": [StubModel().invoke(st["messages"])]})
    g.add_node("tools", tracekit_tool_node([flaky, echo], s, r), retry_policy=RetryPolicy(max_attempts=3, initial_interval=0.01,
                                                                                           retry_on=ConnectionError))
    g.add_edge(START, "model"); g.add_conditional_edges("model", tools_condition); g.add_edge("tools", "model")
    g = g.compile(checkpointer=InMemorySaver())
    msg = {"messages": [HumanMessage(json.dumps([{"name": "flaky", "args": {"x": 1}, "id": "f"},
                                                 {"name": "echo", "args": {"text": "hi"}, "id": "e"}]))]}
    T = {"configurable": {"thread_id": "t"}}
    try:
        out = g.invoke(msg, T) if mode == "sync" else asyncio.run(g.ainvoke(msg, T))
        res = {m.tool_call_id: m.content for m in out["messages"] if isinstance(m, ToolMessage)}
    except Exception as e:
        res = f"raised {type(e).__name__}: {e}"
    ev = s.read({"run_id": r["run_id"], "run_token": r["run_token"], "limit": 100})["events"]
    print(f"{mode:5} ran={RAN} outcome={res} results={[(e['data']['tool_call_id'], e['data']['status']) for e in ev if e['type'] == 'tool.result']}")
