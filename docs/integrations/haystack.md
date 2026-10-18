# Haystack

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.haystack.Tracekit` is a Haystack `Agent` hook that gates every tool call the agent makes. At
`before_tool` it asks the Tracekit signer to decide each call the model asked for, before any of them runs (an `ask`
waits for a person); at `after_tool` it records each outcome. Haystack 3 runs tools only inside an `Agent` (it has no
`ToolInvoker` component), so this covers the tool calls of a pipeline's agents too.

## Install

```bash
pip install tracekit-ai "haystack-ai>=3.4,<3.5"
```

Tested with Haystack 3.4, which needs Python 3.11+. `OpenAIChatGenerator` comes with `haystack-ai`; other model
providers come in their integration packages. The hook itself needs none.

## Setup

```python
from haystack.components.agents import Agent
from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.dataclasses import ChatMessage
from tracekit.integrations.haystack import Tracekit
from tracekit.sdk.client import Client

with Client().run(agent="support-agent") as run:
    tk = Tracekit(run)
    agent = Agent(chat_generator=OpenAIChatGenerator(), tools=[close_account],
                  hooks={"before_tool": [tk], "after_tool": [tk]})
    agent.run([ChatMessage.from_user("close ACC-9")])
```

Register the same `tk` at both hook points, last in each list. `tracekit.instrument()` doesn't wire Haystack: build the
hook yourself. In a process that calls `instrument()` (it also records the model calls made through the OpenAI,
Anthropic and Google Gen AI SDKs), pass it its handle: `Tracekit(tracekit.instrument())`. An `AsyncRunHandle` works as
well as a `RunHandle`. Then `tracekit last` exports and verifies the run.

Every agent needs the hook, a sub-agent included: the outer agent's hook decides the call to an `AgentTool`, and only
the sub-agent's own hooks decide the calls the sub-agent makes (give it the same `tk`). A runnable offline example (a
`MockChatGenerator`, no API key): [`examples/v2/haystack`](../../examples/v2/haystack/README.md).

## What it does

- **Decides the model's own arguments.** The signer decides each `ToolCall` under its `id`, with its `arguments` (the
  JSON the chat generator parsed, `{}` for none). A call without an id (some generators make them, and `ToolCall`s you
  build without one) is given one, `haystack-<hex>`, that its tool result then carries. The values Haystack adds from
  the agent's state (`inputs_from_state`, a `State` parameter) are not the model's and are not decided. An approval is
  bound to the arguments and used once; under the [executor](../executor.md) (T2), a call whose approved arguments are
  not the model's is refused, not run with either.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage under a closed fail mode and any error of Tracekit's own take the call off the step: the model reads
  Tracekit's reason as an error tool result in its place (as Haystack's `ConfirmationHook` rejects a call) and the run
  goes on. Under an open fail mode a call runs unrecorded during an outage, with a warning.
- **Records failures as failures.** A tool that raises reaches the model as Haystack's error result, as before, and is
  recorded as `status: error`. A result goes to the signer as the model reads it: Haystack sends the model a tool's
  return as text, JSON text for a dict or a list, which is parsed back, so an untrusted tool's values reach
  [provenance](../policy-v2.md#provenance-untrusted-and-from-untrusted). It records every result after the step's
  calls, wherever an `after_tool` hook listed before it moved it.
- **Decides each call on its own.** The calls of one step are decided at once, those the model gave one id one after
  the other; a call id the model uses again, in the same step or a later one, is decided as the call's next `attempt`
  and recorded with its own result.
- **Notices a later change.** A `before_tool` hook listed after Tracekit that changes a decided call's tool or
  arguments doesn't stop it running, but the call is recorded as `status: error`, "the call's tool or arguments changed
  after the decision". Hooks listed before it (Haystack's `ConfirmationHook` among them) may change the calls: it
  decides them as they leave those hooks.
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) in the hook; then the call is
  refused with the approval's state, and an unanswered approval is withdrawn. So is one whose `run_async` is cancelled
  while it waits.
- **Covers every tool Haystack runs.** `Agent.run` and `Agent.run_async`, sync and async tools, `ComponentTool`,
  `PipelineTool`, `AgentTool` and the tools of a `Toolset` all reach the same hooks.

## Not covered

- With `raise_on_tool_invocation_failure=True`, a tool that raises ends the agent run before `after_tool`: the calls of
  that step are not completed and read as `decided_not_completed` on `run.final`. Keep the default (`False`), where the
  model reads the error and the call is recorded as one. A tool output that fails to merge into the agent's state
  (`outputs_to_state`) ends the run the same way, whatever that setting.
- An `after_tool` hook listed before Tracekit that drops a result (or the whole step) leaves that call
  `decided_not_completed`.
- Tools the model provider runs itself (`OpenAIResponsesChatGenerator`'s built-in tools such as `web_search` or a
  remote `mcp` server) never reach the hooks; they show only in the model's responses, which autotrace records under
  `instrument()`.
- Values a tool writes to the agent's state (`outputs_to_state`) and a later tool reads from it (`inputs_from_state`,
  a `State` parameter) are not the model's arguments: they are not decided, so `from: untrusted` rules don't see an
  untrusted tool's values passed that way.
- A `before_tool` hook listed after Tracekit can add a call, which then runs undecided. List Tracekit last.
- A call without an id is decided under `haystack-<hex>`, which its result then carries. With the
  [LLM gateway](../gateway.md) the model's tool use has an id of the gateway's own, so the two pair only by their
  arguments (`paired_by_args`), never when two calls of a turn are alike.
- An `ask` holds its whole step: Haystack runs a step's calls once every `before_tool` hook has returned, so the
  step's allowed calls wait for the answer too.
- A refused call's error result is not sent to the agent's `streaming_callback` and not counted in
  `tool_call_counts`: Haystack streams and counts only the calls it runs.
- In a process that calls `instrument()`, which wires MCP's `ClientSession`, a tool from `mcp-haystack` is decided
  twice: by the hook under its Haystack name and by the wired session (`mcp-haystack` calls it on an event loop of its
  own, which the hook can't mark as decided).
- Each signer call, and an `ask`'s wait, holds a thread of asyncio's default executor (in a sync `Agent.run`, the hook
  runs on an event loop of its own, in a thread); many asks waiting at once can starve it.
- The hook holds a live run, so an agent or pipeline holding it can't be serialized (`to_dict`, `dumps` raise
  `SerializationError`): build it in code.
