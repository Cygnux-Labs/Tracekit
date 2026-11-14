"""Two asks in one ToolNode: approve the shown one, resume; then approve the refused one's approval and send the model's
retry of it (a new call id, same tool and arguments). Does the retry run without a pause?"""
import json
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


@tool
def pay(to: str) -> str:
    """Pay someone."""
    RAN.append(to)
    return f"paid {to}"


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
calls = [{"name": "pay", "args": {"to": "alice"}, "id": "c1"}, {"name": "pay", "args": {"to": "bob"}, "id": "c2"}]
out = a.invoke({"messages": [HumanMessage(json.dumps(calls))]}, cfg)
shown = out["__interrupt__"][0].value["tracekit"]
signer.approval_decide({"request_id": "d1", "approval_id": shown["approval_id"], "decision": "approve"})
out = a.invoke(Command(resume={"approval_id": shown["approval_id"]}), cfg)
refused = [m for m in out["messages"] if isinstance(m, ToolMessage) and "blocked" in m.content][0]
print("after resume:", RAN, "|", refused.tool_call_id, refused.content)
other_aid = refused.content.split("(approval ")[1].split(")")[0]
signer.approval_decide({"request_id": "d2", "approval_id": other_aid, "decision": "approve"})
other = next(c for c in calls if c["id"] == refused.tool_call_id)
out = a.invoke({"messages": [HumanMessage(json.dumps([dict(other, id="c3")]))]}, cfg)
print("retry:", RAN, "| paused:", "__interrupt__" in out, "|",
      [m.content for m in out["messages"] if isinstance(m, ToolMessage) and m.tool_call_id == "c3"])
if "__interrupt__" in out:
    again = out["__interrupt__"][0].value["tracekit"]
    out = a.invoke(Command(resume={"approval_id": again["approval_id"]}), cfg)
    print("after resuming the retry (its approval", again["approval_id"], "):", RAN,
          [m.content for m in out["messages"] if isinstance(m, ToolMessage) and m.tool_call_id == "c3"])
