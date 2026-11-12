"""After a tool's own pause, resume with a fresh gate (as a new process would, same checkpointer and signer): what the
model reads and what ran, for one asking call whose tool pauses, and for [pay-0 approved, confirm pausing, echo]."""
import json
import warnings

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition
from langgraph.types import Command, interrupt

from tracekit.integrations.langchain import tracekit_tool_node
from tracekit.testing import FakeSigner

warnings.simplefilter("ignore")
RAN = []


@tool
def pay(to: str, ask: bool = False) -> str:
    """Pay."""
    answer = interrupt(f"pay {to}?") if ask else "-"
    RAN.append(to)
    return f"paid {to} ({answer})"


@tool
def confirm(question: str) -> str:
    """Ask."""
    return interrupt(question)


@tool
def echo(text: str) -> str:
    """Echo."""
    RAN.append("echo")
    return text


class Model(BaseChatModel):
    def _generate(self, messages, stop=None, run_manager=None, **kw):
        msg = AIMessage("", tool_calls=json.loads(messages[-1].content)) if isinstance(messages[-1], HumanMessage) \
            else AIMessage("done")
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kw):
        return self

    @property
    def _llm_type(self):
        return "stub"


def graph(signer, run, saver):
    g = StateGraph(MessagesState)
    g.add_node("model", lambda s: {"messages": [Model().invoke(s["messages"])]})
    g.add_node("tools", tracekit_tool_node([pay, confirm, echo], signer, run))
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    return g.compile(checkpointer=saver)


for name, calls in (("one asking call, its tool pauses", [{"name": "pay", "args": {"to": "p0", "ask": True}, "id": "p0"}]),
                    ("pay-0 approved, confirm pauses, echo", [{"name": "pay", "args": {"to": "p0"}, "id": "p0"},
                                                              {"name": "confirm", "args": {"question": "sure?"}, "id": "c"},
                                                              {"name": "echo", "args": {"text": "hi"}, "id": "e"}])):
    RAN.clear()
    signer = FakeSigner(lambda t, a: ("ask", ["R-PAY"]) if t == "pay" else ("allow", []))
    run = signer.register_run({"request_id": "reg", "agent": {"name": "t"}})
    saver, cfg = InMemorySaver(), {"configurable": {"thread_id": "t"}}
    out = graph(signer, run, saver).invoke({"messages": [HumanMessage(json.dumps(calls))]}, cfg)
    shown = out["__interrupt__"][0].value["tracekit"]
    signer.approval_decide({"request_id": "d", "approval_id": shown["approval_id"], "decision": "approve"})
    out = graph(signer, run, saver).invoke(Command(resume={"approval_id": shown["approval_id"]}), cfg)
    asked = out["__interrupt__"][0].value
    before = list(RAN)
    out = graph(signer, run, saver).invoke(Command(resume="yes"), cfg)   # a new gate: the memory of a new process
    print(f"{name}: tool asked {asked!r}; ran before {before}, after {RAN};",
          {m.tool_call_id: m.content[:60] for m in out["messages"] if isinstance(m, ToolMessage)})
