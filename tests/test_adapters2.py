"""Framework adapters (#6): MCP client sessions and Vercel AI SDK telemetry spans.
python3 -m pytest tests/test_adapters2.py -q"""
import asyncio
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tracekit import otlp, otlp_wire, schema  # noqa: E402
from tracekit.adapters.mcp import tool_name, traced_session  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402
import test_otlp as O  # noqa: E402
from factories import DaemonCase  # noqa: E402

try:
    from mcp import types as mcp_types
except ImportError:
    mcp_types = None


class FakeSession:
    def __init__(self):
        self.sent = []

    async def call_tool(self, name, arguments=None, **kw):
        self.sent.append((name, arguments))
        if mcp_types is not None:
            return mcp_types.CallToolResult(content=[mcp_types.TextContent(type="text", text=f"ran {name}")], isError=name == "boom")
        return {"content": [{"type": "text", "text": f"ran {name}"}], "isError": name == "boom"}

    def other(self):
        return "passthrough"


class MCP(DaemonCase):
    policy_yaml = ("extends: default\nversion: mcp-test\ndeny:\n  - id: X-MCP-DEL\n    tool: 'mcp__github__delete_.*'\n"
                   "    pattern: '.*'\n    reason: no deletes through MCP\n")

    def test_calls_are_gated_recorded_and_errors_kept_as_results(self):
        raw = FakeSession()

        async def go(t):
            s = traced_session(raw, t, server="github")
            ok = await s.call_tool("create_issue", {"title": "x"})
            with self.assertRaises(PermissionError):
                await s.call_tool("delete_repo", {"name": "prod"})
            err = await s.call_tool("boom", {})
            return ok, err, s.other()
        with Tracer(agent="mcp-agent", session_id="m1", cwd=self.d) as t:
            ok, err, other = asyncio.run(go(t))
        self.assertEqual([n for n, _ in raw.sent], ["create_issue", "boom"], "a denied call never reaches the server")
        self.assertEqual(other, "passthrough")
        from tracekit.adapters.mcp import _is_error
        self.assertTrue(_is_error(err, err if isinstance(err, dict) else {}))
        evs = [r["event"] for r in self.records() if r["event"]["run_id"] == "m1"]
        calls = [e["data"]["name"] for e in evs if e["type"] == "tool.call"]
        self.assertEqual(calls, ["mcp__github__create_issue", "mcp__github__delete_repo", "mcp__github__boom"])
        decisions = [e["data"]["decision"] for e in evs if e["type"] == "policy.decision"]
        self.assertEqual(decisions[1], "deny")
        results = [e["data"]["ok"] for e in evs if e["type"] == "tool.result"]
        self.assertEqual(results, [True, False])

    def test_names(self):
        self.assertEqual(tool_name("my server", "do/thing"), "mcp__my_server__do_thing")


class VercelAI(unittest.TestCase):
    def test_vercel_ai_sdk_spans(self):
        calls = json.dumps([{"toolCallType": "function", "toolCallId": "call_v1", "toolName": "weather", "args": "{\"city\":\"Pune\"}"}])
        doc = O.payload(
            O.span("2222222222222222", "ai.generateText.doGenerate", {"ai.model.id": "gpt-4o-mini", "ai.model.provider": "openai.chat",
                                                                     "ai.prompt.messages": "[{\"role\":\"user\",\"content\":\"weather?\"}]",
                                                                     "ai.response.toolCalls": calls, "ai.response.finishReason": "tool-calls",
                                                                     "ai.usage.promptTokens": 50, "ai.usage.completionTokens": 9}),
            O.span("3333333333333333", "ai.toolCall", {"ai.toolCall.name": "weather", "ai.toolCall.id": "call_v1",
                                                       "ai.toolCall.args": "{\"city\":\"Pune\"}", "ai.toolCall.result": "{\"temp\":31}"}),
            O.span("1111111111111111", "ai.generateText", {"ai.model.id": "gpt-4o-mini"}, parent=None),
            service="next-app")
        items, skipped = otlp.Mapper(cwd="/").plan(otlp_wire.decode(json.dumps(doc).encode(), "application/json")[0])
        evs = [ev for _, ev, _, _ in items]
        for e in evs:
            self.assertEqual(schema.validate(e), [], e)
        self.assertEqual([e["type"] for e in evs], ["run.start", "model.exchange", "model.exchange", "tool.call", "policy.decision",
                                                    "tool.result", "run.end"])
        resp = evs[2]["data"]
        self.assertEqual((resp["model"], resp["stop_reason"], resp["tool_uses"], resp["upstream"]),
                         ("gpt-4o-mini", "tool-calls", [{"id": "call_v1", "name": "weather"}], "otel:openai.chat"))
        self.assertEqual((resp["usage"]["input_tokens"], resp["usage"]["output_tokens"]), (50, 9))
        self.assertEqual((evs[3]["data"]["tool_use_id"], evs[3]["data"]["name"]), ("call_v1", "weather"))


if __name__ == "__main__":
    unittest.main()
