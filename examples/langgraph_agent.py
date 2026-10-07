#!/usr/bin/env python3
"""LangGraph agent traced node by node (pip install langgraph). The model is a stub, so this runs offline:
plan -> tools -> report, where `tools` is LangGraph's own ToolNode running a real @tool. With nodes=True the
ledger records every node step (node:plan, node:tools, node:report) and every tool call between them."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402

from tracekit.adapters.langchain import TracekitCallbackHandler  # noqa: E402
from tracekit_sdk import Tracer  # noqa: E402


@tool
def Read(file_path: str) -> str:
    """Read a file."""
    return f"(contents of {file_path})"


def plan(state):  # a stub model that decides to read a file
    return {"messages": [AIMessage(content="", tool_calls=[{"name": "Read", "args": {"file_path": "README.md"}, "id": "c1"}])]}


def report(state):
    return {"messages": [AIMessage(content="Summary: " + state["messages"][-1].content)]}


g = StateGraph(MessagesState)
g.add_node("plan", plan)
g.add_node("tools", ToolNode([Read]))
g.add_node("report", report)
g.add_edge(START, "plan")
g.add_edge("plan", "tools")
g.add_edge("tools", "report")
g.add_edge("report", END)
graph = g.compile()

with Tracer(agent="langgraph-example") as t:
    t.prompt("Summarise the README")
    out = graph.invoke({"messages": [HumanMessage("Summarise the README")]},
                       config={"callbacks": [TracekitCallbackHandler(t, nodes=True)]})
    t.done(out["messages"][-1].content)
print("langgraph example finished; session", t.session_id)
