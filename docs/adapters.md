# Adapters

An adapter routes a framework's real tool calls through the SDK, so each one is policy-checked **before** it runs
and its result is recorded. Anything the framework does outside the adapter is not seen.

## Any function

```python
from tracekit.agent_sdk import Tracer
from tracekit.adapters import traced

with Tracer(agent="my-agent") as tracer:
    @traced(tracer, name="Bash")          # sync or async
    def shell(command): ...
```

A denied call raises `PermissionError` and the function body never runs.

**Policy rules match on the tool name.** The default rules know `Bash`, `Write`, `Edit`, `WebFetch` and so on. If your
shell tool is called `run_command`, the shell rules will not apply to it: name it `Bash` for tracing, or add rules
for your own tool names in a policy file (`extends: default`).

## LangChain and LangGraph

```bash
pip install "tracekit-ai[langchain]"
```

```python
from tracekit.adapters.langchain import TracekitCallbackHandler
with Tracer(agent="my-graph") as tracer:
    graph.invoke(inputs, config={"callbacks": [TracekitCallbackHandler(tracer)]})
```

The handler uses LangChain's callback system, which LangGraph shares. It raises on a denied call, and LangChain
propagates the exception before the tool body executes. It is tested against `langchain-core` and a LangGraph
`ToolNode`. Model calls are not recorded by this adapter.

## MCP client sessions

```python
from tracekit.adapters.mcp import traced_session
session = traced_session(session, tracer, server="github")
await session.call_tool("create_issue", {"title": "..."})    # gated and recorded as mcp__github__create_issue
```

Names follow Claude Code's `mcp__<server>__<tool>` convention, so the default and strict policies' MCP rules apply. A
denied call raises `PermissionError` and never reaches the server. MCP tool errors (`isError`) stay results for the
caller and are recorded as failed calls.

## Model calls, onchain transactions, other harnesses

- Model calls: `tracekit_sdk.init()` (OpenAI, Anthropic, Google Gen AI) or OpenTelemetry ([otel](otel.md)).
- Onchain transactions behind a guard: `tracekit_onchain.guarded_tx` ([contrib/onchain](../contrib/onchain/README.md)).
- Codex CLI, Cursor and Gemini CLI: hooks, `tracekit init --dev --agent ...` ([coding agents](coding-agents.md)).

To add an adapter for something else: translate each tool call into `tracer.tool(name, args)` and write a test that
proves a denied call never executes.
