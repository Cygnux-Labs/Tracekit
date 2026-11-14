"""Resume in "another process" (a new gate and graph on the same checkpointer and the real signer) after a tool's own
pause. Does every call that runs have a decision, does none run twice under one approval, and what is recorded?"""
import json, os, sys, tempfile, time, asyncio
sys.path.insert(0, sys.argv[1] + "/tests")
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition
from langgraph.types import Command, interrupt
from test_contract_langchain import StubModel
from test_signer_service import ME, OTHER, PAY_ASKS
from tracekit.signer import service as svc
from tracekit.integrations.langchain import tracekit_tool_node

RAN = []
@tool("pay")
def pay(to: str, cents: int) -> str:
    """Send money."""
    RAN.append(f"pay{cents}")
    return f"paid {cents}"

@tool("pay")
def confirmed_pay(to: str, cents: int) -> str:
    """Send money after the person confirms (its own pause)."""
    a = interrupt(f"pay {cents}?")
    RAN.append(f"pay{cents}:{a}")
    return f"paid {cents} after {a}"

@tool
def echo(text: str) -> str:
    """Echo."""
    RAN.append("echo")
    return text

@tool
def confirm(question: str) -> str:
    """Ask the person."""
    a = interrupt(question)
    RAN.append(f"confirm:{a}")
    return a

class Agent:
    def __init__(self, s, who):
        self.s, self.who = s, who
    def __getattr__(self, m):
        return lambda req: self.s.call(self.who, m, req)

def graph(tools, signer, run, saver):
    g = StateGraph(MessagesState)
    g.add_node("model", lambda st: {"messages": [StubModel().invoke(st["messages"])]})
    g.add_node("tools", tracekit_tool_node(tools, signer, run))
    g.add_edge(START, "model"); g.add_conditional_edges("model", tools_condition); g.add_edge("tools", "model")
    return g.compile(checkpointer=saver)

def scenario(name, tools, calls, mode, approve, switch_after):
    """switch_after: the number of resumes made in process 1 before process 2 takes over"""
    RAN.clear()
    d = tempfile.mkdtemp(dir="/tmp")
    s = svc.SignerService(os.path.join(d, "data"), policy=PAY_ASKS, grace_s=0, fsck_every_s=0)
    try:
        signer = Agent(s, ME)
        run = signer.register_run({"request_id": "reg", "agent": {"name": "p"}})
        saver, T = InMemorySaver(), {"configurable": {"thread_id": "t"}}
        g = graph(tools, signer, run, saver)
        inv = lambda g, v: g.invoke(v, T) if mode == "sync" else asyncio.run(g.ainvoke(v, T))
        out, pauses, n = inv(g, {"messages": [HumanMessage(json.dumps(calls))]}), [], 0
        while "__interrupt__" in out and n < 6:
            if n == switch_after:
                g = graph(tools, signer, run, saver)   # another process: a new gate, the same saved state
                pauses.append("|P2|")
            v = out["__interrupt__"][0].value
            if isinstance(v, dict) and "tracekit" in v:
                pauses.append("tk")
                for a in v["tracekit"]["approvals"]:
                    if a["tool_call_id"] in approve:
                        try:
                            s.call(OTHER, "approval_decide", {"request_id": a["approval_id"] + str(n),
                                                              "approval_id": a["approval_id"], "decision": "approve"})
                        except Exception as e:
                            pass   # answered already
                out = inv(g, Command(resume={"approval_id": v["tracekit"]["approval_id"]}))
            else:
                pauses.append(v)
                out = inv(g, Command(resume="yes"))
            n += 1
        read = {m.tool_call_id: m.content.split(" (")[0][:48] for m in out["messages"] if isinstance(m, ToolMessage)}
        signer.close_run({"request_id": "close", "run_id": run["run_id"], "run_token": run["run_token"]})
        s.sweep(time.monotonic() + 5)
        ev = [r["event"] for r in s.log.storage.iter_run("default", run["run_id"])]
        pick = lambda t, f: [e["data"].get(f) or e.get(f) for e in ev if e["type"] == t]
        results = [(e.get("tool_call_id") or e["data"].get("tool_use_id"), e["data"].get("ok"), e.get("attempt"))
                   for e in ev if e["type"] == "tool.result"]
        print(f"{name} [{mode}] pauses={pauses}\n   ran={RAN}\n   model read={read}\n   results={results}"
              f"\n   decisions={[(e.get('tool_call_id'), e['data'].get('decision'), e.get('attempt')) for e in ev if e['type'] == 'policy.decision']}"
              f"\n   approval.request={len([e for e in ev if e['type'] == 'approval.request'])} "
              f"consumed={len([e for e in ev if e['type'] == 'approval.consumed'])} "
              f"refused={[(e.get('tool_call_id'), e['data'].get('rule_ids')) for e in ev if e['type'] == 'approval.refused']}"
              f"\n   gaps={[(e['data'].get('kind'), e['data'].get('tool_use_id')) for e in ev if e['type'] == 'capture.gap']}")
    finally:
        s.close()

for mode in ("sync", "async"):
    scenario("X1 single ask+own pause, P2 answers the tool", [confirmed_pay],
             [{"name": "pay", "args": {"to": "a", "cents": 1}, "id": "p1"}], mode, {"p1"}, 1)
    scenario("X2 held [pay0 ask, echo, confirm], P2 answers confirm", [pay, echo, confirm],
             [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"},
              {"name": "echo", "args": {"text": "hi"}, "id": "e"},
              {"name": "confirm", "args": {"question": "sure?"}, "id": "q"}], mode, {"p0"}, 1)
    scenario("X3 held [confirmed_pay ask, echo], P2 answers the tool", [confirmed_pay, echo],
             [{"name": "pay", "args": {"to": "a", "cents": 2}, "id": "p2"},
              {"name": "echo", "args": {"text": "hi"}, "id": "e"}], mode, {"p2"}, 1)
    scenario("X2-control all in P1", [pay, echo, confirm],
             [{"name": "pay", "args": {"to": "a", "cents": 0}, "id": "p0"},
              {"name": "echo", "args": {"text": "hi"}, "id": "e"},
              {"name": "confirm", "args": {"question": "sure?"}, "id": "q"}], mode, {"p0"}, 99)
