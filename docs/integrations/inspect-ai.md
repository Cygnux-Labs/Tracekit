# Inspect AI

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.inspect_ai` gates every tool call an [Inspect AI](https://inspect.aisi.org.uk/) eval makes,
through Inspect's [approval policy](https://inspect.aisi.org.uk/approval.html): an approver asks the Tracekit signer for
a decision before each call (an `ask` waits for a person), and a hook records the outcome after the call.

## Install

```bash
pip install tracekit-ai "inspect-ai>=0.3.288,<0.4"
```

Inspect AI 0.3.288 and later need Python 3.11 or newer. Tested in CI with the newest Inspect AI 0.3.x (0.3.291 on
2026-11-20) on its `mockllm` model, against a stand-in signer (`tracekit.testing.FakeSigner`) and, for a held call's
cancelled wait, the real one. Also run by hand with a local model (Qwen3.5-4B, 4-bit, through mlx-lm's OpenAI-compatible
server) on a real signer: its `ls` call ran and was signed, its `sudo rm -rf` call was denied with the reason shown to
it, and `tracekit verify` passed on the run's bundle.

## Setup

Pass the approver in the eval's approval policy, with a run handle. One run covers the whole eval:

```python
from inspect_ai import eval
from inspect_ai.approval import ApprovalPolicy
from tracekit.integrations.inspect_ai import tracekit
from tracekit.sdk.client import Client

with Client().run(agent="my-eval") as run:
    eval(task, model="openai/gpt-5", approval=[ApprovalPolicy(tracekit(run), "*")])
```

Or pass a client and ask for one run per sample, so two samples with the same tool-call ids no longer share a run:

```python
eval(task, model="openai/gpt-5", approval=[ApprovalPolicy(tracekit(client=Client(), per_sample=True), "*")])
```

A sample's run opens on its first approved call and closes when the sample ends; a sample that makes no tool calls gets
no run. The approver tells samples apart by Inspect's own sample identity (`inspect_ai.log._samples.sample_active()`),
so this reads a private part of Inspect and is pinned to the tested inspect-ai 0.3.x in `pyproject.toml`. A call it
cannot attribute to a sample is refused.

The same policy works from `Task(approval=...)` and the `approval()` context manager. Put Tracekit's approver first, or
alone: it approves every call it allows, which ends Inspect's chain, so an approver listed after it (`human`, say)
never sees the call. To keep another approver in front, have it `escalate` what it doesn't decide.

Importing the module registers one Inspect hook for the process. It does nothing until `tracekit(run)` was called.

## What it does

- **Decides before the call runs.** The signer decides `call.function` with `call.arguments`, under Inspect's tool-call
  id. An `ask` waits up to 5 minutes for `tracekit approvals approve`; Inspect suspends the sample's token, turn and
  working-time limits while it waits, but not its wall-clock `time_limit`.
- **Rejects with the reason.** A deny, an unanswered or rejected approval, a refused consume, a signer error and an
  outage under a closed fail mode all come back as `reject`: the tool never runs and the model gets Tracekit's reason as
  a tool error of type `approval`. A call Tracekit can't decide is refused, never allowed.
- **Records what ran.** An approver never sees a call's result, so the hook completes each allowed call when Inspect
  emits its `ToolEvent`: `ok` with the result, or `error` with the event's message (a `ToolError` the tool raised, or
  an error Inspect made for the call). A refused call is never completed: its `ToolEvent` carries the `approval` error.
- **Completes a cancelled call as an error.** A call a sample limit cuts short while it runs gets a `ToolEvent` with a
  `cancelled` error and is completed as `error`. A held call whose wait a `time_limit` cancels has its approval
  withdrawn: it never ran, and no gap follows. An allowed call cut short after the approver's `approve` and before
  the tool starts gets no `ToolEvent`: it stays decided, and the signer closes the run with a `decided_not_completed`
  gap for it ([limits](../limits.md)).
- **Refuses a call whose id is open, and records changed arguments.** A call whose tool-call id is already being
  decided or still open in the run is refused, with a reason the model reads (Inspect's model cache can give two
  samples the same id). A call whose arguments changed after the decision (an in-process sentinel's `modify`) is
  completed as `error`: "the call's arguments changed after the decision".
- **Reads the shell tool as a shell.** A framework's tool name is matched ignoring case, so Inspect's `bash` is decided
  as `Bash` and its `command` is read as shell code ([limits](../limits.md#policy)).

## Not covered

- **Bridged agents.** For `agent_bridge()` and `sandbox_agent_bridge()` agents, Inspect approves the calls in each model
  response and the agent runs them itself. A decision there records that the call was *permitted*, not that it ran: no
  `ToolEvent` with a result follows, so each such call ends as a `decided_not_completed` gap. Keep bridged agents out of
  an eval that uses this approver.
- **Tools the packs don't map.** Inspect's `python`, `text_editor` and `bash_session` tools aren't in the policy
  packs' `tools:` lists. The dev and coding packs only flag them (`unknown_tools: flag`), and the server packs hold them
  for a person. A `bash_session` call's `input` is typed into a shell but isn't read as shell code, so on the dev pack
  it runs with only a flag. List them in your policy to give them a class.
- **One run per eval, or one per sample.** By default every sample and epoch records into the run you gave the
  approver, and the hook finds a call by Inspect's tool-call id, so a call whose id is still open is refused. With
  `tracekit(client=Client(), per_sample=True)` each sample gets its own run, opened on its first approved call and
  closed when the sample ends, and the hook finds a call by its run and id. A retry keeps its sample's run; each epoch
  is a separate sample execution with its own run. A call the approver cannot attribute to a sample is refused.
- **The trio backend.** With `INSPECT_ASYNC_BACKEND=trio`, the approver's asyncio calls fail, so every call is refused.
- **An escalated call.** A Tracekit `ask` is never turned into Inspect's `escalate`: the person's answer goes to
  `tracekit approvals`, not to Inspect's human approver.
- **What the model said.** Not recorded by the integration. Record the model calls with
  [`tracekit.instrument()`](../quickstart-v2.md#2-one-line-in-your-agent) or the [LLM gateway](../gateway.md); see
  [reasoning](../reasoning.md).
