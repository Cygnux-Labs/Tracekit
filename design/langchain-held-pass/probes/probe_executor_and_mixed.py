"""Probe 1: an executor tool beside another call in one ToolNode message: does the middleware decide it (it must not;
the executor decides it)?  Probe 2: [pay0 ask, pay1 ask, confirm (its own interrupt)]: approve pay0, leave pay1, resume
twice; how often does pay0 run, and what does the model read?"""
import json, sys, asyncio
sys.path.insert(0, sys.argv[1] + "/tests")
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.types import Command, interrupt
from test_contract_langchain import TOOLS
from test_integration_langchain import tool_graph
from tracekit.testing import FakeSigner
from tracekit.integrations.langchain import tracekit_tool_node
from tracekit.integrations.executor_tools import EXECUTOR, CALL_ID
import adapter_contract as ac

T = {"configurable": {"thread_id": "t"}}
def recorded(s, run, typ):
    return [e["data"] for e in s.read({**run, "limit": 1000})["events"] if e["type"] == typ]

EX = []
@tool
def refund(cents: int) -> str:
    """An executor action (the executor decides it)."""
    EX.append(CALL_ID.get())
    return "refunded"
refund.metadata = {EXECUTOR: True}

for mode in ("sync", "async"):
    s = FakeSigner(ac._rule)
    r = s.register_run({"request_id": "reg", "agent": {"name": "p"}})
    run = {"run_id": r["run_id"], "run_token": r["run_token"]}
    g = tool_graph(tracekit_tool_node([*TOOLS, refund], s, r))
    inv = g.invoke if mode == "sync" else (lambda v, c: asyncio.run(g.ainvoke(v, c)))
    out = inv({"messages": [HumanMessage(json.dumps([{"name": "refund", "args": {"cents": 1}, "id": "x1"},
                                                     {"name": "echo", "args": {"text": "hi"}, "id": "e1"}]))]}, T)
    print(f"executor {mode}: middleware decisions for={[d['tool_call_id'] for d in recorded(s, run, 'policy.decision')]}"
          f" results for={[d['tool_call_id'] for d in recorded(s, run, 'tool.result')]} executor ran={EX}")
    EX.clear()

PAID = []
@tool
def pay(to: str, cents: int) -> str:
    """Send money."""
    PAID.append(cents)
    return f"paid {cents}"

@tool
def confirm(question: str) -> str:
    """Ask the user."""
    return interrupt(question)

for mode in ("sync", "async"):
    PAID.clear()
    s = FakeSigner(ac._rule)
    r = s.register_run({"request_id": "reg", "agent": {"name": "p"}})
    run = {"run_id": r["run_id"], "run_token": r["run_token"]}
    g = tool_graph(tracekit_tool_node([*TOOLS, pay, confirm], s, r))
    inv = g.invoke if mode == "sync" else (lambda v, c: asyncio.run(g.ainvoke(v, c)))
    calls = [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"},
             {"name": "pay", "args": {"to": "a", "cents": 1}, "id": "p1"},
             {"name": "confirm", "args": {"question": "sure?"}, "id": "q"}]
    out = inv({"messages": [HumanMessage(json.dumps(calls))]}, T)
    aprs = {a["tool_call_id"]: a["approval_id"] for a in recorded(s, run, "approval.request")}
    s.approval_decide({"request_id": "d", "decision": "approve", "approval_id": aprs["p0"]})
    out = inv(Command(resume={"approval_id": aprs["p0"]}), T)
    steps = [("resume1", out.get("__interrupt__"), list(PAID))]
    if out.get("__interrupt__"):
        out = inv(Command(resume="yes"), T)
        steps.append(("resume2", out.get("__interrupt__"), list(PAID)))
    print(f"mixed {mode}: " + "; ".join(f"{n}: paused={bool(i)} paid={p}" for n, i, p in steps))
    print(f"   model read={ {m.tool_call_id: m.content[:60] for m in out['messages'] if isinstance(m, ToolMessage)} }")
    print(f"   recorded results={[(d['tool_call_id'], d['status']) for d in recorded(s, run, 'tool.result')]} "
          f"refused={[d['tool_call_id'] for d in recorded(s, run, 'approval.refused')]} "
          f"approval requests={[(a['tool_call_id'], a.get('attempt')) for a in recorded(s, run, 'approval.request')]}")
