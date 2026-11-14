"""Probe: a tool that calls interrupt() itself (a HITL confirm) under a Tracekit `ask`. Does the tool's own question
reach the person, or does it get the approval's resume value?"""
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
    return "moved" if answer else "cancelled"

T = {"configurable": {"thread_id": "t"}}

def recorded(s, run, typ):
    return [e["data"] for e in s.read({**run, "limit": 1000})["events"] if e["type"] == typ]

def go(kind, calls, mode):
    ANSWERS.clear()
    s = FakeSigner(lambda tool, args: ("ask", ["R-T"]) if tool == "transfer" else ("allow", []))
    r = s.register_run({"request_id": "reg", "agent": {"name": "p"}})
    run = {"run_id": r["run_id"], "run_token": r["run_token"]}
    if kind == "create_agent":
        g = create_agent(StubModel(), [*TOOLS, transfer], checkpointer=InMemorySaver(),
                         middleware=[TracekitMiddleware(s, run["run_id"], run["run_token"])])
    else:
        g = tool_graph(tracekit_tool_node([*TOOLS, transfer], s, r))
    inv = g.invoke if mode == "sync" else (lambda v, c: asyncio.run(g.ainvoke(v, c)))
    out = inv({"messages": [HumanMessage(json.dumps(calls))]}, T)
    first = out["__interrupt__"][0].value
    [apr] = [a for a in recorded(s, run, "approval.request")]
    s.approval_decide({"request_id": "d", "decision": "approve", "approval_id": apr["approval_id"]})
    out = inv(Command(resume={"approval_id": apr["approval_id"]}), T)
    second = out.get("__interrupt__")
    print(f"{kind:13} {mode:5} calls={[c['name'] for c in calls]}: first pause={first}")
    print(f"   after approve+resume: paused again={bool(second)} {second[0].value if second else ''}; "
          f"tool got answers={ANSWERS}; tool msgs={[m.content for m in out['messages'] if isinstance(m, ToolMessage)]}")

for kind in ("create_agent", "tool_node"):
    for mode in ("sync", "async"):
        go(kind, [{"name": "transfer", "args": {"cents": 5}, "id": "c1"}], mode)
for mode in ("sync", "async"):
    go("tool_node", [{"name": "transfer", "args": {"cents": 5}, "id": "c1"},
                     {"name": "echo", "args": {"text": "hi"}, "id": "e1"}], mode)
