"""Scripted agents for the three-step quickstart (tests/test_instrument.py in this checkout, tests/test_quickstart.py
from the built wheel): each is an agent as a user already has it, offline (a mock model), plus the one line
`tracekit.instrument()`. Each prints the JSON list of what its tools returned: `ls` runs, `sudo rm -rf /` is refused
(TK-D001), or for MCP the dev policy's demo deny. AGENTS: framework -> (pip requirements, script)."""

OPENAI_AGENTS = r'''
import json, tracekit
tracekit.instrument()
from agents import Agent, Model, ModelResponse, Runner, function_tool, set_tracing_disabled
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

def call(n, command):
    return ResponseFunctionToolCall(id=f"fc_{n}", call_id=f"call-{n}", type="function_call", name="Bash",
                                    arguments=json.dumps({"command": command}), status="completed")

REPLIES = [[call(1, "ls"), call(2, "sudo rm -rf /")],
           [ResponseOutputMessage(id="m1", type="message", role="assistant", status="completed",
                                  content=[ResponseOutputText(type="output_text", annotations=[], text="done")])]]

class MockModel(Model):
    async def get_response(self, *a, **kw):
        return ModelResponse(output=REPLIES.pop(0), usage=Usage(), response_id=None)

    async def stream_response(self, *a, **kw):
        raise NotImplementedError

@function_tool(name_override="Bash")
def bash(command: str) -> str:
    """Run a shell command."""
    return f"ran {command}"

set_tracing_disabled(True)
result = Runner.run_sync(Agent(name="shell", model=MockModel(), tools=[bash]), "tidy up")
print(json.dumps([i.output for i in result.new_items if i.type == "tool_call_output_item"]))
'''

LANGGRAPH = r'''
import json, tracekit
tracekit.instrument()
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

def call(n, command):
    return {"name": "Bash", "args": {"command": command}, "id": f"call-{n}"}

MODEL = GenericFakeChatModel(messages=iter([AIMessage("", tool_calls=[call(1, "ls"), call(2, "sudo rm -rf /")]),
                                            AIMessage("done")]))

@tool("Bash")
def bash(command: str) -> str:
    """Run a shell command."""
    return f"ran {command}"

g = StateGraph(MessagesState)
g.add_node("model", lambda state: {"messages": [MODEL.invoke(state["messages"])]})
g.add_node("tools", ToolNode([bash]))
g.add_edge(START, "model")
g.add_conditional_edges("model", tools_condition)
g.add_edge("tools", "model")
out = g.compile().invoke({"messages": [("user", "tidy up")]})
print(json.dumps([m.content for m in out["messages"] if m.type == "tool"]))
'''

CLAUDE_AGENT_SDK = r'''
import asyncio, json, tracekit
tracekit.instrument()
from claude_agent_sdk import ClaudeAgentOptions, query
from claude_agent_sdk._internal.transport import Transport

class MockCLI(Transport):
    """The `claude` process and its model: two Bash calls, each through the registered hooks."""
    def __init__(self):
        self.out, self.hooks, self.waiting, self.n, self.said = asyncio.Queue(), {}, {}, 0, []

    async def connect(self): pass
    def is_ready(self): return True
    async def end_input(self): pass
    async def close(self): pass

    async def read_messages(self):
        while (m := await self.out.get()) is not None:
            yield m

    async def write(self, data):
        m = json.loads(data)
        if m["type"] == "control_request" and m["request"]["subtype"] == "initialize":
            self.hooks = m["request"]["hooks"] or {}
            await self.out.put({"type": "control_response",
                                "response": {"subtype": "success", "request_id": m["request_id"], "response": {}}})
        elif m["type"] == "control_response":
            self.waiting.pop(m["response"]["request_id"]).set_result(m["response"].get("response") or {})
        elif m["type"] == "user":
            self.task = asyncio.ensure_future(self.turn())

    async def hook(self, event, **fields):
        out = {}
        for matcher in self.hooks.get(event, []):
            for cid in matcher["hookCallbackIds"]:
                self.n += 1
                self.waiting[f"cli-{self.n}"] = asyncio.get_running_loop().create_future()
                await self.out.put({"type": "control_request", "request_id": f"cli-{self.n}", "request": {
                    "subtype": "hook_callback", "callback_id": cid, "tool_use_id": fields["tool_use_id"],
                    "input": {"hook_event_name": event, "session_id": "s1", "transcript_path": "", "cwd": "/", **fields}}})
                out.update(await self.waiting[f"cli-{self.n}"])
        return out

    async def turn(self):
        for tid, command in (("toolu_1", "ls"), ("toolu_2", "sudo rm -rf /")):
            call = {"tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": tid}
            pre = (await self.hook("PreToolUse", **call)).get("hookSpecificOutput", {})
            if pre.get("permissionDecision") == "deny":
                self.said.append(pre["permissionDecisionReason"])
                continue
            self.said.append(f"ran {command}")
            await self.hook("PostToolUse", **call, tool_response={"stdout": f"ran {command}"})
        await self.out.put({"type": "result", "subtype": "success", "duration_ms": 0, "duration_api_ms": 0,
                            "is_error": False, "num_turns": 1, "session_id": "s1"})
        await self.out.put(None)

async def prompt():
    yield {"type": "user", "message": {"role": "user", "content": "tidy up"}, "parent_tool_use_id": None,
           "session_id": ""}

async def main():
    cli = MockCLI()
    async for _ in query(prompt=prompt(), options=ClaudeAgentOptions(), transport=cli):
        pass
    return cli.said

print(json.dumps(asyncio.run(main())))
'''

MCP = r'''
import asyncio, json, tracekit
tracekit.instrument()
from mcp import Client
from mcp.server.mcpserver import MCPServer

SERVER = MCPServer("files")

@SERVER.tool()
def list_files() -> str:
    """List the files."""
    return "ran list_files"

@SERVER.tool()
def tracekit_demo_denied() -> str:
    """Denied by the dev policy's demo rule (TK-DEMO-DENY)."""
    return "should never run"

async def main():
    async with Client(SERVER) as c:
        return [(await c.session.call_tool(t, {})).content[0].text for t in ("list_files", "tracekit_demo_denied")]

print(json.dumps(asyncio.run(main())))
'''

OPENAI = r'''
import json, httpx, openai, tracekit
tracekit.instrument()

def reply(request):
    return httpx.Response(200, json={"id": "c1", "object": "chat.completion", "created": 0, "model": "gpt-5",
                                     "choices": [{"index": 0, "finish_reason": "stop",
                                                  "message": {"role": "assistant", "content": "ran nothing"}}],
                                     "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

client = openai.OpenAI(api_key="k", base_url="http://mock/v1", http_client=httpx.Client(transport=httpx.MockTransport(reply)))
out = client.chat.completions.create(model="gpt-5", messages=[{"role": "user", "content": "hi"}])
print(json.dumps([out.choices[0].message.content]))
'''

AGENTS = {
    "openai-agents": (["openai-agents>=0.23.1,<0.24"], OPENAI_AGENTS),
    "langgraph": (["langchain>=1.4,<1.5", "langgraph>=1.2,<1.3"], LANGGRAPH),
    "claude-agent-sdk": (["claude-agent-sdk>=0.2.165,<0.3"], CLAUDE_AGENT_SDK),
    "mcp": (["mcp>=2.3,<2.4"], MCP),
    "openai": (["openai>=1.0", "httpx"], OPENAI),
}
REFUSED = "blocked by policy"   # in the refused call's output; the OpenAI client makes no tool call
