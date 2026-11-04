# Inspect AI

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.inspect_ai` gates every tool call an [Inspect AI](https://inspect.aisi.org.uk/) eval makes,
through Inspect's [approval policy](https://inspect.aisi.org.uk/approval.html): an approver asks the Tracekit signer for
a decision before each call (an `ask` waits for a person), and a hook records the outcome after the call.

## Install

```bash
pip install tracekit-ai "inspect-ai>=0.3.287,<0.4"
```

Tested in CI with Inspect AI 0.3.287 on its `mockllm` model, against a stand-in signer (`tracekit.testing.FakeSigner`).

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

The same policy works from `Task(approval=...)` and the `approval()` context manager. Put Tracekit's approver first, or
alone: it approves every call it allows, which ends Inspect's chain, so an approver listed after it (`human`, say)
never sees the call. To keep another approver in front, have it `escalate` what it doesn't decide.

Importing the module registers one Inspect hook for the process. It does nothing until `tracekit(run)` was called.

## What it does

- **Decides before the call runs.** The signer decides `call.function` with `call.arguments`, under Inspect's tool-call
  id. An `ask` waits up to 5 minutes for `tracekit approvals approve`; Inspect suspends the sample's token, turn and
  working-time limits while it waits.
- **Rejects with the reason.** A deny, an unanswered or rejected approval, a refused consume, a signer error and an
  outage under a closed fail mode all come back as `reject`: the tool never runs and the model gets Tracekit's reason as
  a tool error of type `approval`. A call Tracekit can't decide is refused, never allowed.
- **Records what ran.** An approver never sees a call's result, so the hook completes each allowed call when Inspect
  emits its `ToolEvent`: `ok` with the result, or `error` with the event's message (a `ToolError` the tool raised, or
  an error Inspect made for the call). A refused call is never completed: its `ToolEvent` carries the `approval` error.
- **Leaves a cancelled call open.** A call cut short by a sample limit gets no `ToolEvent`. It stays decided and never
  completed, and the signer closes the run with a `decided_not_completed` gap for it ([limits](../limits.md)).
- **Reads the shell tool as a shell.** A framework's tool name is matched ignoring case, so Inspect's `bash` is decided
  as `Bash` and its `command` is read as shell code ([limits](../limits.md#policy)).

## Not covered

- **Bridged agents.** For `agent_bridge()` and `sandbox_agent_bridge()` agents, Inspect approves the calls in each model
  response and the agent runs them itself. A decision there records that the call was *permitted*, not that it ran: no
  `ToolEvent` with a result follows, so each such call ends as a `decided_not_completed` gap. Keep bridged agents out of
  an eval that uses this approver.
- **Tools the packs don't map.** Inspect's `python` and `text_editor` tools aren't in the policy packs' `tools:` lists.
  The coding pack only flags them (`unknown_tools: flag`), and the server packs hold them for a person. List them in
  your policy to give them a class.
- **One run per eval.** Every sample and epoch records into the run you gave the approver, and the hook finds a call by
  Inspect's tool-call id, which must not repeat across them. A run per sample is not supported yet.
- **An escalated call.** A Tracekit `ask` is never turned into Inspect's `escalate`: the person's answer goes to
  `tracekit approvals`, not to Inspect's human approver.
- **What the model said.** Not recorded by the integration. Record the model calls with
  [`tracekit.instrument()`](../quickstart-v2.md#2-one-line-in-your-agent) or the [LLM gateway](../gateway.md); see
  [reasoning](../reasoning.md).
