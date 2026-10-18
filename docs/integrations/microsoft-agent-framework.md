# Microsoft Agent Framework

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.agent_framework.Tracekit` is an Agent Framework
[function middleware](https://learn.microsoft.com/agent-framework/concepts/agents/middleware/) that gates every
function call an agent makes: its `process` asks the Tracekit signer for a decision before the function runs (an `ask`
waits for a person) and records the outcome after. Agent Framework's own code is not changed.

## Install

```bash
pip install tracekit-ai "agent-framework-core>=1.22,<1.23" agent-framework-openai
```

Tested with Agent Framework 1.22 (`agent-framework-core`), which needs Python 3.10+; other minors may change how
middleware runs and get no warning. Pick the package for your model provider (`agent-framework-openai`,
`agent-framework-anthropic`, `agent-framework-foundry`, ...); the middleware itself needs only the core.

## Setup

```python
import asyncio
from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient
from tracekit.integrations.agent_framework import Tracekit
from tracekit.sdk.client import Client

with Client().run(agent="support-agent") as run:
    agent = Agent(client=OpenAIChatClient(), tools=[close_account], middleware=[Tracekit(run)])
    print(asyncio.run(agent.run("close ACC-9")).text)
```

Build it yourself as above: `tracekit.instrument()` does not add it to agents. An `AsyncRunHandle` works as well as a
`RunHandle`. Then `tracekit last` exports and verifies the run.

The middleware can go on the agent (`Agent(middleware=[...])`), on one run (`agent.run(..., middleware=[...])`) or on
the chat client (`OpenAIChatClient(middleware=[...])`), where it gates every agent that uses that client. Put it in one
of these places, not two: each `Tracekit` decides the call. A runnable offline example (a scripted chat client, no API
key): [`examples/v2/agent_framework`](../../examples/v2/agent_framework/README.md).

## What it does

- **Decides the model's call.** The decision names the model's own call id (`context.metadata["call_id"]`) and the
  arguments Agent Framework parsed from the model's JSON and validated against the function: the ones it runs with
  (values in the parameters' types, keys the function doesn't take dropped; no arguments or an empty string are `{}`).
  An approval is bound to those arguments and used once. Under the [executor](../executor.md) (T2), a call whose
  approved arguments are not the call's is refused, not run with either.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage under a closed fail mode and any error of Tracekit's own set the call's result to Tracekit's reason without
  calling the next middleware: the function never runs, the model reads the reason as the call's result and the run
  goes on. Under an open fail mode a call runs unrecorded during an outage, with a warning.
- **Records failures as failures.** A function that raises is recorded as `status: error` and its exception reaches
  Agent Framework unchanged, so the model gets its error result and the loop's error limit counts it as before. A
  result goes to the signer as the JSON the model reads (an object a function returns arrives as its JSON text, and
  goes as that JSON), so an untrusted tool's values reach
  [provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted).
- **Follows the middleware order.** Function middleware runs in list order, the chat client's first. A middleware after
  Tracekit that rewrites `context.arguments` makes the call run with arguments the signer never decided: it is recorded
  as `status: error`, "the call's arguments changed after the decision". One before Tracekit is decided as rewritten
  (Agent Framework's own advice: argument-repair middleware before policy middleware). A middleware after Tracekit
  that ends the loop with the call's result (`MiddlewareTermination`) completes the call with that result.
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) before the call; then the call is
  refused with the approval's state, and an unanswered approval is withdrawn. So is one whose agent run is cancelled
  while it waits.
- **Decides a call sent again as its next attempt.** A call that comes again under the same call id (a model that
  reuses ids) is decided again, as that call's next `attempt`.
- **Works with Agent Framework's own approvals.** A function with `approval_mode="always_require"` is held for Agent
  Framework's approver first and the run pauses; once approved, the call is replayed and Tracekit decides it then,
  under the same call id. A call rejected there never runs and never reaches Tracekit.
- **Decides delegates and handoffs as calls.** An agent used as a tool (`agent.as_tool()`) is decided under its tool
  name with its `{"task": ...}`; a refused one never starts. Its own calls are decided only by its own middleware:
  give it `Tracekit(run)` too, or put the middleware on a chat client both use. A handoff in an
  `agent-framework-orchestrations` workflow is a call to `handoff_to_<agent>`: decided like any other, and a refused
  one keeps the conversation with the current agent.
- **Gates agents in workflows.** Each agent in a workflow runs its own middleware, so each needs `Tracekit(run)` (or a
  shared chat client that has it).
- **Decides MCP calls once.** A tool of an `MCPStdioTool`, `MCPStreamableHTTPTool` or `MCPWebsocketTool` is a function
  to Agent Framework, decided under its name there; the `ClientSession` that `instrument()` wires doesn't decide it
  again. Agent Framework 1.22's MCP tools need `mcp` 1.x.

## Not covered

- The signer decides the validated arguments, not the model's JSON text: function middleware never sees it. A value the
  model sent that the function doesn't take is not in the record; one Agent Framework converted (`"5"` for an `int`)
  is recorded converted.
- Agent Framework's own approvals are not the signer's: they are not in the bundle, and a call its approver rejects
  leaves no record. Use the policy's `ask` for approvals the bundle should hold.
- A refusal reads to the model as the call's result, not as Agent Framework's error result: middleware that doesn't
  call the next one can only set the result, and an exception would show the model only `Error: Function failed.`.
  The text starts `Tool call blocked by Tracekit`, `Tool call held by Tracekit` or `Tool call refused`.
- Tools the provider runs (hosted MCP, web and file search, code interpreter) never reach function middleware; they
  are seen only in the model responses the [gateway](../gateway.md) records. Nor do calls Agent Framework hands back to
  the caller to run (`declaration_only` functions, `additional_tools`).
- A delegate agent's or a workflow agent's calls are not gated unless that agent (or its chat client) has the
  middleware. Middleware given to a workflow wrapped as an agent (`workflow.as_agent(middleware=...)`) is not run by
  Agent Framework.
- An `ask` blocks the call while it waits, and each signer call holds a thread of asyncio's default executor; many asks
  waiting at once can starve it.
- Not wired by `tracekit.instrument()`, and tested with 1.22 only: other versions get no warning.
