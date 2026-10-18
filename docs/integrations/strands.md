# Strands Agents

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.strands.Tracekit` is a Strands Agents [hook provider](https://strandsagents.com/latest/documentation/docs/user-guide/concepts/agents/hooks/)
that gates every tool call an agent makes: its `BeforeToolCallEvent` callbacks ask the Tracekit signer for a decision
before the tool runs (an `ask` waits for a person), and its `AfterToolCallEvent` callback records the outcome. Strands
itself is not changed.

## Install

```bash
pip install tracekit-ai "strands-agents>=1.61,<1.62"
```

Tested with Strands Agents 1.61, which needs Python 3.10+. Add the extra for your model provider
(`strands-agents[openai]`, `[anthropic]`, ...); Bedrock needs none.

## Setup

```python
from strands import Agent
from tracekit.integrations.strands import Tracekit
from tracekit.sdk.client import Client

with Client().run(agent="support-agent") as run:
    agent = Agent(tools=[close_account], hooks=[Tracekit(run)])
    agent("close ACC-9")
```

Then `tracekit last` exports and verifies the run. An `AsyncRunHandle` works as well as a `RunHandle`.
`tracekit.instrument()` doesn't wire Strands: build the hook provider yourself, as above, and don't call `instrument()`
in the same process (its MCP wiring would decide each call of a Strands MCP tool a second time).

Every agent needs the hook, a sub-agent used as a tool (`agent.as_tool()`) and each agent of a `Swarm` or `Graph`
included: an agent without `hooks=[Tracekit(run)]` runs its tools ungated. One `Tracekit` can serve all of them. Given
to a `Swarm` or `Graph` itself, it raises `TypeError` (they fire no tool-call events). A runnable offline example (a
scripted model, no API key): [`examples/v2/strands`](../../examples/v2/strands/README.md).

## What it does

- **Decides the model's own call.** The first callback (`HookOrder.SDK_FIRST`, before any other hook) sends the signer
  the call's `toolUseId`, tool name and `input`: the arguments as Strands parsed them from the model, missing or empty
  ones as `{}`. An approval is bound to those arguments and used once. Under the [executor](../executor.md) (T2), a
  call whose approved arguments are not the model's is refused, not run with either.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage under a closed fail mode and any error of Tracekit's own all set `cancel_tool`: the model reads Tracekit's
  reason as an error tool result and the run goes on. Under an open fail mode a call runs unrecorded during an outage,
  with a warning.
- **Refuses a call changed after the decision.** The last callback (`HookOrder.SDK_LAST`) refuses an allowed call
  whose id, name or input another hook replaced or edited, and sets Tracekit's refusal again if a hook in between
  cleared `cancel_tool`. A call refused there, or by another hook after Tracekit allowed it, is recorded as
  `status: error`, "not run: ...".
- **Records the result the model reads.** The last `AfterToolCallEvent` callback records the result after any other
  hook rewrote it. A success is `status: ok` with its content as the model reads it: one text block as its text (a JSON
  object or array, as Strands sends a dict or model a tool returns, as that JSON), one `json` block as its value,
  several blocks as they are. So an untrusted tool's values reach
  [provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted). An error result is `status: error` with the
  tool's exception or the result's text; the tool's exception reaches Strands unchanged, as its error result.
- **Decides each run again.** A call that runs again under the same `toolUseId` (another hook's
  `AfterToolCallEvent.retry`, or a call a Strands interrupt stopped and the agent resumed) is decided again as the
  call's next `attempt`. An attempt that never ran reads as `decided_not_completed` on `run.final`.
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) before the call; then the call is
  refused with the approval's state, and an unanswered approval is withdrawn. So is one whose agent is cancelled while
  it waits, by `agent.cancel()` (checked every 0.5 s) or by cancelling its task. Calls of one model turn are decided,
  and wait, at once under Strands' default `ConcurrentToolExecutor`; agents in several threads can share one
  `Tracekit`.
- **Covers every tool path the agent runs.** Sync and async tools under either executor; direct calls
  (`agent.tool.close_account(...)`, decided under the id Strands makes for them); MCP tools, under their agent-facing
  name; a sub-agent used as a tool (the call to it, and its own calls when it has the hook); a `Swarm`'s
  `handoff_to_agent` and its agents' calls; a `Graph`'s agents' calls; the structured output tool, under the output
  model's name; and background tools (`background_tasks`), decided before they are admitted and recorded when they ran.

## Not covered

- An `ask` blocks the tool call while it waits, and each wait holds a thread of asyncio's default executor: many asks
  waiting at once can starve it. It does not raise a Strands interrupt: an interrupt's response comes from your app,
  not from an approver the signer knows, so it can't be the approval.
- An interrupt another hook raises (`event.interrupt(...)`) stops a call after Tracekit decided it: when the agent
  resumes, the call is decided again, and an `ask` asks a person again.
- A hook that runs after Tracekit's last check (registered after it at `HookOrder.SDK_LAST`, or at a higher order) can
  change the call, which then runs with arguments the signer didn't decide, or clear Tracekit's refusal. A hook that
  swaps `selected_tool` without renaming the call runs that tool under the decided name. Changes made in Strands'
  internal tool middleware are not seen.
- Strands parses the model's arguments before any hook runs: arguments that aren't JSON reach the hooks, and the tool,
  as `{}`, and the signer decides `{}`.
- With `background_tasks`, a background tool another hook asks to retry (`AfterToolCallEvent.retry`) runs again with
  no `BeforeToolCallEvent`: that run is neither decided nor recorded.
- With the gateway's [verified tool results](../gateway.md#verified-tool-results), a result of several content blocks
  is recorded as its blocks, which the gateway doesn't match to what the model is sent: such a call reads as
  `result_mismatch`.
- A remote agent (`A2AAgent`) runs its tools on its own side, out of the hooks' reach; a tool of yours that calls it is
  decided like any other. The bidirectional `BidiAgent` fires the same hooks but is not tested.
