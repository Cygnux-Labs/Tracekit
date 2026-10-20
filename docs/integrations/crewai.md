# CrewAI

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekit.integrations.crewai` gates every tool call a CrewAI crew makes, through CrewAI's global tool hooks: before
each call it asks the Tracekit signer for a decision (an `ask` waits for a person), and after the call it records the
outcome.

## Install

```bash
pip install tracekit-ai "crewai>=1.15.27,<1.16"
```

Tested in CI against a stand-in for CrewAI's tool hooks, not the real library. The
[case study](../case-study-oss-agents.md) ran CrewAI 1.15.27 with hand-written hook glue, not this module.

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

## What the model said

Not recorded by the integration: CrewAI's after-LLM hook sees a text answer only, never a response that asks for a
tool, and no reasoning; its tool hooks carry no call id. Record the model calls with `tracekit.instrument()` or the
[LLM gateway](../gateway.md); they pair with the calls by arguments only. Which frameworks and providers return readable reasoning, and how to turn it on: [reasoning](../reasoning.md).

## Not covered

- CrewAI's hooks carry no tool-call id, so each call gets one of its own (`crewai-<hex>`). Under autotrace or the LLM
  gateway the reconciler pairs it with the model's tool use of the same turn by its arguments (`paired_by_args` on
  `run.final`). Two calls of the same tool with the same arguments in one turn can't be told apart: both are reported
  (`reconcile.hook_missing` and `reconcile.fabricated`). So are calls whose decide lands after another agent's model
  call in the same run (async tasks, or several crews in `instrument()`'s one process run): give each its own run.
- On CrewAI's text (ReAct) path, for models without native tool calling, CrewAI retries a failing tool inside one call
  of its hooks: the retries run under that call's one decision, and only the last outcome is recorded. A failure there
  ("I encountered an error while trying to use the tool") is recorded as an error, as on the native path.
- Delegation between agents (`delegate_work_to_coworker`, `ask_question_to_coworker`) is decided like any tool: give
  those tools a class in your policy to gate them.
- A tool that runs other than through CrewAI's tool execution (a tool calling another tool directly in Python) is not
  seen.
