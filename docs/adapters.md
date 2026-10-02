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
pip install "tracekit[langchain]"
```

```python
from tracekit.adapters.langchain import TracekitCallbackHandler
with Tracer(agent="my-graph") as tracer:
    graph.invoke(inputs, config={"callbacks": [TracekitCallbackHandler(tracer)]})
```

The handler uses LangChain's callback system, which LangGraph shares. It raises on a denied call, and LangChain
propagates the exception before the tool body executes. It is tested against `langchain-core` and a LangGraph
`ToolNode`. Model calls are not recorded by this adapter.

## Not built

Codex, Cursor and Gemini CLI have their own hook formats and need their own adapters; Claude Code is covered by
the hooks and the [plugin](../plugin/README.md). To add one, read the format, translate each tool call into
`tracer.tool(name, args)`, and write a test that proves a denied call never executes.
