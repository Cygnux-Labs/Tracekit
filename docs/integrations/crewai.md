# CrewAI

`tracekit.integrations.crewai` gates every tool call a CrewAI crew makes, through CrewAI's global tool hooks: before
each call it asks the Tracekit signer for a decision (an `ask` waits for a person), and after the call it records the
outcome.

## Install

```bash
pip install tracekit-ai "crewai>=1.15.27,<1.16"
```

Tested with CrewAI 1.15.27.

## Setup

`import tracekit; tracekit.instrument()` before the crew runs registers both hooks, and records the model calls CrewAI
makes through the OpenAI, Anthropic and Google Gen AI SDKs (autotrace). By hand:

```python
from crewai.hooks import register_after_tool_call_hook, register_before_tool_call_hook
from tracekit.integrations.crewai import hooks
from tracekit.sdk.client import Client

run = Client().run(agent="support-crew")
before, after = hooks(run)
register_before_tool_call_hook(before)
register_after_tool_call_hook(after)
```

## What it does

- **Blocks by return value.** CrewAI runs a tool when a before hook raises, so the before hook never raises: it returns
  `False`, which blocks the call, on anything but an allow or an approved ask. That covers a deny, a rejected or
  unanswered approval, a refused consume, a signer refusal, an outage under a closed fail mode and any error of its
  own. Under an open fail mode, a call runs unrecorded during an outage, with a warning.
- **Tells the model why.** For a blocked call the after hook replaces CrewAI's "Tool execution blocked by hook" with
  Tracekit's reason (the rule ids, or what the approval came to).
- **Records failures as failures.** CrewAI hands the after hook a failed tool's exception as the text `Error executing
  tool: ...`; that is recorded as `status: error`. Other results are recorded as the text the model reads, and in full
  for a tool the policy lists as untrusted (provenance).
- **Waits for people.** An `ask` waits up to 5 minutes (the signer's cap for one wait) before the call; then it is
  blocked with the approval's state.

## Not covered

- CrewAI's hooks carry no tool-call id, so each call gets one of its own (`crewai-<hex>`). Under autotrace or the LLM
  gateway the reconciler pairs it with the model's tool use of the same turn by its arguments (`paired_by_args` on
  `run.final`). Two calls of the same tool with the same arguments in one turn can't be told apart: both are reported
  (`reconcile.hook_missing` and `reconcile.fabricated`).
- Delegation between agents (`delegate_work_to_coworker`, `ask_question_to_coworker`) is decided like any tool: give
  those tools a class in your policy to gate them.
- A tool that runs other than through CrewAI's tool execution (a tool calling another tool directly in Python) is not
  seen.
