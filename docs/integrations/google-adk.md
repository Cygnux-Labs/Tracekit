# Google ADK

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.google_adk.Tracekit` is a Google ADK [plugin](https://google.github.io/adk-docs/plugins/) that
gates every tool call of every agent its Runner runs, sub-agents and agents run as tools included: its
`before_tool_callback` asks the Tracekit signer for a decision before the tool runs (an `ask` waits for a person), and
its `after_tool_callback` and `on_tool_error_callback` record the outcome. ADK's own code is unchanged.

## Install

```bash
pip install tracekit-ai "google-adk>=2.12,<2.13"
```

Tested with Google ADK 2.12, which needs Python 3.11+.

## Setup

```python
from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.runners import InMemoryRunner
from tracekit.integrations.google_adk import Tracekit
from tracekit.sdk.client import Client

with Client().run(agent="support-agent") as run:
    agent = LlmAgent(name="support", model="gemini-flash-latest", tools=[close_account])
    runner = InMemoryRunner(app=App(name="support", root_agent=agent, plugins=[Tracekit(run)]))
    ...   # runner.run_async(...) as usual
```

Construct the plugin yourself: `tracekit.instrument()` doesn't add it. An `AsyncRunHandle` works as well as a
`RunHandle`. List it first in `plugins` (a warning says so when it isn't): ADK runs plugin callbacks in that order and
stops at the first that answers. Then `tracekit last` exports and verifies the run. A runnable offline example (a
scripted model, no API key): [`examples/v2/google_adk`](../../examples/v2/google_adk/README.md).

## What it does

- **Decides the model's arguments, under ADK's call id.** The signer decides the call's arguments as the model sent
  them (`{}` for none) under `tool_context.function_call_id` (the model's own id, or the `adk-...` id ADK gives a call
  without one). An approval is bound to those arguments and used once. Under the [executor](../executor.md) (T2), a
  call whose approved arguments are not the model's is refused, not run with either.
- **Decides before the agent's own callbacks.** ADK runs the plugins' `before_tool_callback` in order, then the
  agent's. One listed after Tracekit that changes the arguments in place does it after the decision: the call runs,
  and is recorded as `status: error`, "the call's arguments changed after the decision". One that answers the call
  instead of the tool (a cache) is recorded with its answer.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage under a closed fail mode and any error of Tracekit's own all answer the call with `{"error": <reason>}`, so
  ADK skips the tool (and its own tool confirmation): the model reads Tracekit's reason as the tool's result and the
  run goes on. Under an open fail mode a call runs unrecorded during an outage, with a warning.
- **Records the result the model reads.** A tool's return is recorded as the JSON ADK sends the model (a dict as it
  is, anything else as `{"result": ...}`, a model or dataclass as its fields), so an untrusted tool's values reach
  [provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted). A tool that raises is recorded as
  `status: error` and its exception reaches ADK unchanged, so `on_tool_error_callback` handlers and
  `ReflectAndRetryToolPlugin` work as before; the model's retry is a new call id and a new decision.
- **Covers every tool path ADK has.** Function tools (sync and async, parallel calls), sub-agents (and the
  `transfer_to_agent` call that hands over to one), agents run as tools (`AgentTool`: the call and the agent's own tool
  calls, since it inherits the Runner's plugins), MCP toolsets (under ADK's tool name), long-running tools, workflow
  tool nodes (under the id ADK gives each run of the node) and a tool the model made up (recorded as an error).
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) before the call; then it is
  skipped with the approval's state, and an unanswered approval is withdrawn. So is one whose agent run is cancelled
  while it waits.
- **Keeps ADK's own pauses.** A call ADK pauses for the user, for its tool confirmation (`require_confirmation`,
  `tool_context.request_confirmation()`) or for credentials (`tool_context.request_credential()`), is not completed.
  Once the user answers, ADK runs it again under the same call id and Tracekit decides it again as the call's next
  `attempt`; the first attempt shows as `decided_not_completed` on `run.final`. A call the user rejects in ADK's tool
  confirmation is recorded as `status: error`, "rejected in ADK's tool confirmation".

## Not covered

- ADK's tool confirmation is not a Tracekit approval: the signer records only its effect (the call runs again, or is
  recorded as rejected). A tool under both a Tracekit `ask` and ADK's confirmation is decided at each of its two runs,
  so a person approves it in Tracekit twice. Use one, Tracekit's `ask` for an approval in the evidence.
- The attempt count lives in the plugin: a paused call that another process resumes (a new Runner over the same
  session) is decided as attempt 0 again. An allowed call runs; one under an `ask` is refused, its approval used.
- Code the agent's `code_executor` runs, and builtin tools the model provider runs (Google Search, URL context, code
  execution on the provider's side), never reach the tool callbacks: they are not decided.
- `AgentTool(agent, include_plugins=False)` runs its agent without the Runner's plugins: that agent's tools are not
  gated.
- A long-running tool is recorded with what its function returned (its pending status): the final result your app
  sends later is not a tool run. Likewise a streaming tool in a live run (`run_live`) is recorded with the pending
  status ADK gives the model, not what it streams after.
- A plugin listed before Tracekit can change a call's arguments before the decision, answer its error (recorded as an
  `ok` result) or replace its result (the call then reads `decided_not_completed`). A result a later plugin's or the
  agent's `after_tool_callback` replaces is recorded as the tool returned it.
- A tool that changes its own arguments in place (appends to a list it was given) is recorded as changed after the
  decision.
- Each signer call, and an `ask`'s wait, holds a thread of asyncio's default executor; many asks waiting at once can
  starve it.
