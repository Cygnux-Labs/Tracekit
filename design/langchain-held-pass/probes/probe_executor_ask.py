"""An executor tool whose policy asks, beside echo in one ToolNode message: does the middleware pause for it?"""
import json, sys
sys.path.insert(0, sys.argv[1] + "/tests")
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from test_contract_langchain import TOOLS
from test_integration_langchain import tool_graph
from tracekit.testing import FakeSigner
from tracekit.integrations.langchain import tracekit_tool_node
from tracekit.integrations.executor_tools import EXECUTOR

@tool
def refund(cents: int) -> str:
    """An executor action."""
    return "refunded"
refund.metadata = {EXECUTOR: True}
s = FakeSigner(lambda t, a: ("ask", ["R-REFUND"]) if t == "refund" else ("allow", []))
r = s.register_run({"request_id": "reg", "agent": {"name": "p"}})
g = tool_graph(tracekit_tool_node([*TOOLS, refund], s, r))
out = g.invoke({"messages": [HumanMessage(json.dumps([{"name": "refund", "args": {"cents": 1}, "id": "x1"},
                                                     {"name": "echo", "args": {"text": "hi"}, "id": "e1"}]))]},
               {"configurable": {"thread_id": "t"}})
ev = s.read({"run_id": r["run_id"], "run_token": r["run_token"], "limit": 100})["events"]
print("paused:", out.get("__interrupt__", [None])[0] and out["__interrupt__"][0].value,
      "| middleware approval requests:", [e["data"]["tool_call_id"] for e in ev if e["type"] == "approval.request"])
