# LlamaIndex

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.llama_index.Tracekit` gates every tool call of a LlamaIndex agent workflow: a `FunctionAgent`,
`ReActAgent`, `CodeActAgent` or your own `BaseWorkflowAgent`, and an `AgentWorkflow` with its handoffs.
`Tracekit(run).gate(workflow)` overrides the workflow's `call_tool` step, the step every tool call runs through, the way
LlamaIndex [customises a workflow](https://developers.llamaindex.ai/python/framework/understanding/workflows/subclass/)
(a subclass that overrides a step). The signer decides each call before the tool runs (an `ask` waits for a person), and
the outcome is recorded after.

## Install

```bash
pip install tracekit-ai "llama-index-core>=0.14.25,<0.15"
```

Tested with llama-index-core 0.14.25, which needs Python 3.10+. Add your model's integration (`llama-index-llms-openai`,
`llama-index-llms-anthropic`, ...); the gate itself needs only the core package.

## Setup

```python
import asyncio
from llama_index.core.agent.workflow import AgentWorkflow, FunctionAgent
from tracekit.integrations.llama_index import Tracekit
from tracekit.sdk.client import Client

async def main(run):
    workflow = Tracekit(run).gate(AgentWorkflow(agents=[triage, billing], root_agent="triage"))
    print(await workflow.run(user_msg="close ACC-9"))

with Client().run(agent="support-agent") as run:
    asyncio.run(main(run))
```

Gate the object you call `.run()` on. An `AgentWorkflow` runs every agent's tools, the handoff tool too, in its own
`call_tool` step: gate the workflow, as above (gating only its agents gates nothing there). A single agent run on its
own: gate the agent. An agent that a tool of yours runs (an agent as a tool) is a workflow of its own: gate it too, with
the same `Tracekit`. `gate` returns the object it was given, so you can gate it where you build it. An `AsyncRunHandle`
works as well as a `RunHandle`. Then `tracekit last` exports and verifies the run. `tracekit.instrument()` doesn't wire
LlamaIndex: build the gate by hand, as above. A runnable offline example (a scripted mock model from `llama_index.core`,
no API key): [`examples/v2/llama_index`](../../examples/v2/llama_index/README.md).

## What it does

- **Overrides one step.** `gate` switches the object's class to a subclass of its own class (the same name, so
  `isinstance` and `repr` don't change) whose `call_tool` step decides the call, runs LlamaIndex's own `call_tool` and
  records the outcome. An object is gated once; gating it again raises `ValueError`.
- **Runs outermost.** A `call_tool` your agent's or workflow's own class overrides runs inside the gate: if it changes
  the call's arguments, the call runs and is recorded as `status: error`, "the call's arguments changed after the
  decision".
- **Decides the call's id and the model's arguments.** The signer decides `ToolCall.tool_id` and `tool_kwargs`, the
  arguments as LlamaIndex's model integration parsed them from the model (`{}` for none). For a function-calling model
  the id is the model's tool-call id; `ReActAgent` and `CodeActAgent` make a UUID for each call, since their model
  writes the action as text. An approval is bound to those arguments and used once. Under the [executor](../executor.md)
  (T2), a call whose approved arguments are not the model's is refused, not run with either.
- **Covers every tool the workflow runs.** Sync and async `FunctionTool`s, your own `BaseTool`s, tools from a
  `tool_retriever`, each of several parallel calls on its own, the `handoff` tool, `return_direct` tools, and
  `CodeActAgent`'s code, decided as one `execute` call with `{"code": ...}`. A tool name the agent doesn't have is
  decided too, and recorded as an error.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage under a closed fail mode and any error of Tracekit's own all skip the tool: the model reads Tracekit's reason
  as an error tool result (as for a tool the agent doesn't have) and the run goes on. A refused `return_direct` tool
  doesn't end the run, and a refused handoff hands nothing off. Under an open fail mode a call runs unrecorded during an
  outage, with a warning.
- **Records failures as failures.** LlamaIndex turns a tool's exception into an error result for the model; the call is
  recorded as `status: error` with the exception. A tool's result goes to the signer as the value it returned, in JSON
  (a model or dataclass as its fields; LlamaIndex shows the model its text), so an untrusted tool's values reach
  [provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted).
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) in the `call_tool` step; then the
  call is skipped with the approval's state, and an unanswered approval is withdrawn. So is one whose workflow is
  cancelled or times out while it waits.
- **Keeps LlamaIndex's own human in the loop.** A tool that waits for an event (`ctx.wait_for_event`) stops, and
  LlamaIndex runs its step again from the start once the event comes. The call is not completed the first time; it is
  decided again as its next `attempt` when it runs again.
- **Decides MCP calls once.** A tool from an MCP server (`llama-index-tools-mcp`) is decided under its LlamaIndex name;
  the `ClientSession` that `instrument()` wires doesn't decide it again.

## Not covered

- Only what you gate: an agent or workflow you didn't gate, an agent inside an `AgentWorkflow` you gated only by itself,
  and tools called outside an agent workflow's `call_tool` step (`llm.predict_and_call`, a router or sub-question query
  engine choosing tools) run ungated.
- The functions `CodeActAgent`'s code calls inside your `code_execute_fn` are not decided one by one: the code is
  decided as a whole, as `execute`. Run it in a sandbox.
- `ReActAgent` and `CodeActAgent` calls carry an id LlamaIndex makes, not one from the model: with model calls recorded
  (the [LLM gateway](../gateway.md), autotrace), each reads as `reconcile.fabricated`, since no model tool use has its
  id.
- A tool that waits for an event runs from its start again (LlamaIndex re-runs the step): an `ask` is asked again for
  its next attempt, and the first attempt reads as `decided_not_completed` on `run.final`. The attempt count lives in
  the `Tracekit` object, so a workflow resumed from a saved `Context` in a new process decides its calls from attempt 0
  again.
- Structured output (`output_cls`, `structured_output_fn`) runs no code the model chose and is not decided.
- An `ask` holds its step while it waits: a workflow `timeout` under 300 s cancels the wait (and withdraws the
  approval). Each signer call, and each wait, holds a thread of asyncio's default executor; many asks waiting at once
  can starve it.
- A `call_tool` step your own subclass declares with `num_workers` or a `retry_policy` runs with LlamaIndex's defaults
  once gated, and an argument change in an override of LlamaIndex's private `_call_tool` is not seen.
