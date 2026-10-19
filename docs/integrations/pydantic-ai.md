# Pydantic AI

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.pydantic_ai.Tracekit` is a Pydantic AI [capability](https://pydantic.dev/docs/ai/capabilities/overview/)
that gates every tool call an agent makes, and every output function the model calls through an output tool: its
`wrap_tool_execute` and `wrap_output_process` hooks ask the Tracekit signer for a decision before the function runs (an
`ask` waits for a person) and record the outcome after.

## Install

```bash
pip install tracekit-ai "pydantic-ai-slim[openai]>=2.57,<2.58"
```

Tested with Pydantic AI 2.57, which needs Python 3.11+. Pick the extra for your model provider (`[openai]`,
`[anthropic]`, ...); the capability itself needs none.

## Setup

```python
from pydantic_ai import Agent
from tracekit.integrations.pydantic_ai import Tracekit
from tracekit.sdk.client import Client

with Client().run(agent="support-agent") as run:
    agent = Agent("openai:gpt-5", tools=[close_account], capabilities=[Tracekit(run)])
    agent.run_sync("close ACC-9")
```

Or make `import tracekit; tracekit.instrument()` the first line: every `Agent` built after it gets the capability
(an agent given a `Tracekit` by hand keeps that one alone), and it also records the model calls the agent makes through
the OpenAI, Anthropic and Google Gen AI SDKs (autotrace). An `AsyncRunHandle` works as well as a `RunHandle`. Then
`tracekit last` exports and verifies the run.

Every agent needs the capability, a delegate agent a tool calls included: an agent built before `instrument()` or
without `Tracekit(run)` runs its tools ungated. To gate one run of an agent you don't build, pass it to the run:
`agent.run(..., capabilities=[Tracekit(run)])`. A runnable offline example (a `FunctionModel`, no API key):
[`examples/v2/pydantic_ai`](../../examples/v2/pydantic_ai/README.md).

## What it does

- **Decides the model's own arguments.** The signer decides `call.args`, the arguments as the model sent them (its JSON
  text or dict, an empty string as `{}`); the tool runs with the arguments Pydantic AI validated from them. An approval
  is bound to those arguments and used once. Under the [executor](../executor.md) (T2), a call whose approved arguments
  are not the model's is refused, not run with either.
- **Runs outermost.** The capability wraps every other one, so a capability that rewrites a call's arguments in
  `before_tool_execute` or `wrap_tool_execute` does it inside Tracekit's decision: the call runs, and is recorded as
  `status: error`, "the call's arguments changed after the decision".
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage under a closed fail mode and any error of Tracekit's own all skip the tool (`SkipToolExecution`): the model
  reads Tracekit's reason as the tool's result and the run goes on. Under an open fail mode a call runs unrecorded
  during an outage, with a warning.
- **Records failures as failures.** A tool that raises is recorded as `status: error` and its exception reaches
  Pydantic AI unchanged, so `ModelRetry` and the agent's retries work as before. A retry is a new call id and a new
  decision. A tool's result goes to the signer as the JSON the model reads (a model or dataclass as its fields, a
  `ToolReturn` as its `return_value`), so an untrusted tool's values reach
  [provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted).
- **Gates output functions.** An output function the model calls through an output tool (`output_type=ToolOutput(fn)`,
  or a function in `output_type`) is decided under that tool's name, `final_result` by default, and runs only when
  allowed; a refused one never runs and the model reads the reason as a retry prompt. When streaming, it runs once, on
  the final output (the partial outputs come back unprocessed). Its call is completed with no result: the model reads
  `Final result processed.`, not what the function returned.
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) before the call; then it is
  skipped with the approval's state, and an unanswered approval is withdrawn. So is one whose agent run is cancelled
  while it waits.
- **Decides MCP calls once.** A tool from an MCP toolset is decided by the capability under its Pydantic AI name; the
  `ClientSession` that `instrument()` wires doesn't decide it again.
- **Keeps Pydantic AI's deferred tools.** A tool that raises `ApprovalRequired` or `CallDeferred` is not completed; when
  it is resumed with `DeferredToolResults` under the same call id it is decided again as the call's next `attempt`.
  The first attempt then shows as `decided_not_completed` on `run.final`.

## What the model said

The capability records each model response (`after_model_request`): its `ThinkingPart`s (a summary, with the
provider's signature), its text, and the calls of the agent's function tools under the `tool_call_id`s they are decided
by. An output function's call and an approval-required tool's are left out of it ([limits](../limits.md#intent-reasoning-and-action-checks)).
The message itself is kept only when the signer's content vault is on; without it the record holds a commitment. A message that can't be recorded only warns. Which frameworks and providers return readable reasoning, and how to turn it on: [reasoning](../reasoning.md).

## Not covered

- An `ask` blocks the tool call while it waits. It does not use Pydantic AI's own deferred tools
  (`ApprovalRequired`, `DeferredToolRequests`): an approval given there is not the signer's and would not be recorded.
- Builtin tools the model provider runs (web search, code execution on the provider's side) never reach
  `wrap_tool_execute`; they are seen only in the model responses autotrace records.
- Plain structured output (an output type with no function) and text output functions (`TextOutput`) are not decided:
  nothing runs that the model chose. Register a function with side effects as a tool or a `ToolOutput`. Under
  autotrace the model's output tool calls (`final_result`, `final_result_<Type>` per output type) have no tool result:
  name each in the policy's `structured_output:`, or `reconcile` reports them.
- An argument rewrite in another capability's `before_tool_validate` is invisible: it happens before the validated
  arguments Tracekit compares.
- Each signer call, and an `ask`'s wait, holds a thread of asyncio's default executor; many asks waiting at once can
  starve it.
- The capability holds a live run, so it is not built from an agent spec (`Agent.from_spec`).
- A call Pydantic AI rejects before `wrap_tool_execute` (arguments that fail validation, a tool the agent doesn't have)
  is never decided. With the [LLM gateway](../gateway.md) it reads as a live `reconcile.hook_missing`, whose detail
  says the call ran with no hook gating it, though it never ran: what the model is sent for it is Pydantic AI's retry
  prompt.
- With the gateway's [verified tool results](../gateway.md#verified-tool-results), a tool returning a list reaches
  Anthropic as one text block per item, which doesn't match the list recorded: such a call reads as `result_mismatch`.
  An output function's call, completed with no result, is not checked.
