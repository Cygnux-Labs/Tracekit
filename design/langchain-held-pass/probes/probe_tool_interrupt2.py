"""Six variants, driven to the end: approve, resume, answer the tool's own question; what did the tool get, how many
times did its body pass the interrupt, what was recorded?"""
import json, sys, asyncio
sys.path.insert(0, sys.argv[1] + "/tests")
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command, interrupt
from test_contract_langchain import StubModel, TOOLS
from test_integration_langchain import tool_graph
from tracekit.testing import FakeSigner
from tracekit.integrations.langchain import TracekitMiddleware, tracekit_tool_node

ANSWERS = []
@tool
def transfer(cents: int) -> str:
    """Move money after the user confirms."""
    answer = interrupt(f"confirm transfer of {cents}?")
    ANSWERS.append(answer)
    return f"moved after {answer}"

T = {"configurable": {"thread_id": "t"}}
def rec(s, run, typ):
    return [e["data"] for e in s.read({**run, "limit": 1000})["events"] if e["type"] == typ]

def go(kind, calls, mode):
    ANSWERS.clear()
    s = FakeSigner(lambda tool, args: ("ask", ["R-T"]) if tool == "transfer" else ("allow", []))
    r = s.register_run({"request_id": "reg", "agent": {"name": "p"}})
    run = {"run_id": r["run_id"], "run_token": r["run_token"]}
    g = (create_agent(StubModel(), [*TOOLS, transfer], checkpointer=InMemorySaver(),
                      middleware=[TracekitMiddleware(s, run["run_id"], run["run_token"])])
         if kind == "create_agent" else tool_graph(tracekit_tool_node([*TOOLS, transfer], s, r)))
    inv = g.invoke if mode == "sync" else (lambda v, c: asyncio.run(g.ainvoke(v, c)))
    out = inv({"messages": [HumanMessage(json.dumps(calls))]}, T)
    pauses = []
    while "__interrupt__" in out and len(pauses) < 6:
        v = out["__interrupt__"][0].value
        if isinstance(v, dict) and "tracekit" in v:
            pauses.append("tracekit")
            aid = v["tracekit"]["approval_id"]
            s.approval_decide({"request_id": aid, "decision": "approve", "approval_id": aid})
            out = inv(Command(resume={"approval_id": aid}), T)
        else:
            pauses.append(v)
            out = inv(Command(resume="PERSON-SAID-YES"), T)
    print(f"{kind:12} {mode:5} {[c['name'] for c in calls]}: pauses={pauses} tool got={ANSWERS} "
          f"read={[m.content for m in out['messages'] if isinstance(m, ToolMessage)]} "
          f"results={[(d['tool_call_id'], d['status']) for d in rec(s, run, 'tool.result')]} "
          f"refused={[d['tool_call_id'] for d in rec(s, run, 'approval.refused')]} "
          f"approvals={len(rec(s, run, 'approval.request'))} decisions={len(rec(s, run, 'policy.decision'))}")

for kind in ("create_agent", "tool_node"):
    for mode in ("sync", "async"):
        go(kind, [{"name": "transfer", "args": {"cents": 5}, "id": "c1"}], mode)
for mode in ("sync", "async"):
    go("tool_node", [{"name": "transfer", "args": {"cents": 5}, "id": "c1"},
                     {"name": "echo", "args": {"text": "hi"}, "id": "e1"}], mode)
