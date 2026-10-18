# Pydantic AI

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.pydantic_ai.Tracekit` is a Pydantic AI [capability](https://pydantic.dev/docs/ai/capabilities/overview/)
that gates every tool call an agent makes: its `wrap_tool_execute` hook asks the Tracekit signer for a decision before
the tool runs (an `ask` waits for a person) and records the outcome after.

## Install

```bash
pip install tracekit-ai "pydantic-ai-slim>=2.57,<2.58"
```

Tested with Pydantic AI 2.57.

## Setup

```python
from pydantic_ai import Agent
from tracekit.integrations.pydantic_ai import Tracekit
from tracekit.sdk.client import Client

with Client().run(agent="support-agent") as run:
    agent = Agent("openai:gpt-5", tools=[close_account], capabilities=[Tracekit(run)])
    agent.run_sync("close ACC-9")
```

`tracekit.instrument()` returns a run handle that works here too, and it also records the model calls the agent makes
through the OpenAI, Anthropic and Google Gen AI SDKs (autotrace): `capabilities=[Tracekit(tracekit.instrument())]`.
Then `tracekit last` exports and verifies the run. A runnable offline example (a `FunctionModel`, no API key):
[`examples/v2/pydantic_ai`](../../examples/v2/pydantic_ai/README.md).

## What it does

- **Decides the model's own arguments.** The signer decides `call.args`, the arguments as the model sent them (its JSON
  text or dict); the tool runs with the arguments Pydantic AI validated from them. An approval is bound to those
  arguments and used once.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage under a closed fail mode and any error of Tracekit's own all skip the tool (`SkipToolExecution`): the model
  reads Tracekit's reason as the tool's result and the run goes on. Under an open fail mode a call runs unrecorded
  during an outage, with a warning.
- **Records failures as failures.** A tool that raises is recorded as `status: error` and its exception reaches
  Pydantic AI unchanged, so `ModelRetry` and the agent's retries work as before. A retry is a new call id and a new
  decision.
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) before the call; then it is
  skipped with the approval's state, and an unanswered approval is withdrawn.

## Not covered

- An `ask` blocks the tool call while it waits. It does not use Pydantic AI's own deferred tools
  (`ApprovalRequired`, `DeferredToolRequests`): an approval given there is not the signer's and would not be recorded.
- Builtin tools the model provider runs (web search, code execution on the provider's side) never reach
  `wrap_tool_execute`; they are seen only in the model responses autotrace records.
- Output tools (structured output) are not tool calls here and are not decided.
- The capability holds a live run, so it is not built from an agent spec (`Agent.from_spec`).
