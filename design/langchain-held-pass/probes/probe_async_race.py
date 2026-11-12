"""Async held pass where a tool's own interrupt() comes back before a sibling call finishes: is the sibling run once,
recorded once, and not asked twice? (sync for comparison)"""
import json, sys, time, asyncio
sys.path.insert(0, sys.argv[1] + "/tests")
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.types import Command, interrupt
from test_integration_langchain import tool_graph
from tracekit.testing import FakeSigner
from tracekit.integrations.langchain import tracekit_tool_node
import adapter_contract as ac

RAN = []
@tool
def slow_echo(text: str) -> str:
    """Echo, slowly (a sync tool)."""
    time.sleep(0.3)
    RAN.append("slow_echo")
    return text

@tool("pay")
def slow_pay(to: str, cents: int) -> str:
    """Send money, slowly."""
    time.sleep(0.3)
    RAN.append(f"pay{cents}")
    return f"paid {cents}"

@tool
def confirm(question: str) -> str:
    """Ask the person."""
    a = interrupt(question)
    RAN.append(f"confirm:{a}")
    return a

T = {"configurable": {"thread_id": "t"}}
for label, tools, calls, approve in [
        ("allowed slow sibling", [slow_echo, confirm],
         [{"name": "slow_echo", "args": {"text": "hi"}, "id": "e"}, {"name": "confirm", "args": {"question": "sure?"}, "id": "q"}], set()),
        ("approved slow sibling", [slow_pay, confirm],
         [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"}, {"name": "confirm", "args": {"question": "sure?"}, "id": "q"}], {"p0"})]:
    for mode in ("sync", "async"):
        RAN.clear()
        s = FakeSigner(ac._rule)
        r = s.register_run({"request_id": "reg", "agent": {"name": "p"}})
        run = {"run_id": r["run_id"], "run_token": r["run_token"]}
        g = tool_graph(tracekit_tool_node(tools, s, r))
        inv = g.invoke if mode == "sync" else (lambda v, c: asyncio.run(g.ainvoke(v, c)))
        out, pauses = inv({"messages": [HumanMessage(json.dumps(calls))]}, T), []
        while "__interrupt__" in out and len(pauses) < 6:
            v = out["__interrupt__"][0].value
            if isinstance(v, dict) and "tracekit" in v:
                pauses.append("tk")
                for a in v["tracekit"]["approvals"]:
                    if a["tool_call_id"] in approve and s._approvals[a["approval_id"]]["state"] == "requested":
                        s.approval_decide({"request_id": a["approval_id"], "decision": "approve", "approval_id": a["approval_id"]})
                out = inv(Command(resume={"approval_id": v["tracekit"]["approval_id"]}), T)
            else:
                pauses.append(v)
                out = inv(Command(resume="yes"), T)
        ev = s.read({**run, "limit": 1000})["events"]
        print(f"{label:22} {mode:5} pauses={pauses} ran={RAN} "
              f"read={ {m.tool_call_id: m.content[:40] for m in out['messages'] if isinstance(m, ToolMessage)} } "
              f"results={[e['data']['tool_call_id'] for e in ev if e['type'] == 'tool.result']} "
              f"approval requests={[e['data']['tool_call_id'] for e in ev if e['type'] == 'approval.request']}")
