# Hermes Agent

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

The Tracekit plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent) (`integrations/hermes/` in this
repository) gates every tool call Hermes makes, built-in and plugin tools alike: its `pre_tool_call` hook asks the
Tracekit signer for a decision before the tool runs (an `ask` waits for a person), and its `post_tool_call` hook
records the outcome. It registers those two hooks and nothing else. The hooks are `tracekit.integrations.hermes`.

Checked against Hermes Agent v0.22.5 (commit `bf0203a794a07aac3ff764972ab9087baa4e4f4e`): tested in CI against a
stand-in for Hermes's plugin hook dispatch as that source defines it, not a running Hermes.

## Install

```bash
hermes plugins install Cygnux-Labs/Tracekit/integrations/hermes
hermes config set plugins.hook_callback_timeout 600
```

Hermes asks before it installs the plugin's dependency, `tracekit-ai`, into its own environment. At install it also
asks for `TRACEKIT_SIGNER_TOKEN`: leave it empty unless your signer is on `tcp://`.

**Raise `plugins.hook_callback_timeout` for approvals.** Hermes waits for a `pre_tool_call` hook at most that long (30 s
by default, 600 s at most) and blocks the call when the hook runs over. An `ask` waits for a person inside the hook,
until 5 s before that timeout, so with the default a person has about 25 s to approve a call. At 600 they have almost
10 minutes.

## Which signer

The plugin uses the signer Tracekit's client finds, as `tracekit.instrument()` does: with no `TRACEKIT_SIGNER` set,
the same-user dev signer, started at the first tool call if none is running; in system mode
(`/etc/tracekit/client.json`), the system signer. To use another signer, set `TRACEKIT_SIGNER` in the environment Hermes
starts with: a Unix socket path, `tcp://127.0.0.1:PORT` (its token in `TRACEKIT_SIGNER_TOKEN`, which the plugin reads
through Hermes's secret scope), or an `https://` URL (its bearer token file in `TRACEKIT_SIGNER_TOKEN_FILE`).

Each Hermes session is a run (agent `hermes`), registered at its first tool call and closed when Hermes exits. Then
`tracekit last` exports and verifies it. A run the signer closed because it was idle is replaced by a new one at the
session's next call.

## What it does

- **Decides the model's own call.** `pre_tool_call` sends the signer the call's `tool_call_id`, tool name and the
  arguments Hermes is about to run it with. A call with no `tool_call_id` is blocked: its result couldn't be bound to
  its decision.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage and any error of Tracekit's own all return Hermes's `{"action": "block", "message": ...}`: the call doesn't
  run and the model reads Tracekit's reason as the tool's error. During an outage the run's fail mode for the tool's
  class decides: closed, so the call is blocked, unless the signer's policy says `open`. When the plugin can't load
  `tracekit-ai`, it blocks every call: a plugin that failed to register would let every call run ungated.
- **Keeps approvals with the signer.** An `ask` is answered in Tracekit (`tracekit approvals`, the viewer, an
  approver the signer knows), never by Hermes's own approval prompt. An approval still unanswered when the hook's time
  is up is withdrawn, so no one approves a call that never ran.
- **Records the outcome.** `post_tool_call` completes the call against its decision with Hermes's status: `ok` with
  the result the tool returned (in full for a tool the policy lists as untrusted, for provenance; otherwise its
  digest), or `error` with Hermes's error message. A call another plugin blocked after Tracekit allowed it is recorded
  as `status: error`, "not run: ...". One whose arguments another plugin changed (with `modify`, or in place) runs and
  is recorded as `status: error`, "the call's arguments changed after the decision".

## Policy

The shipped packs name Hermes's `terminal` tool (class `shell`), so their shell rules read its `command`. Hermes's
other tools (`write_file`, `patch`, `read_file`, `web_search`, `browser_*`, `execute_code`, ...) are unknown to them:
the laptop packs flag such a call and let it run, and the server pack holds it for a person. Give them classes in your
policy's `tools:` ([file format](../policy-v2.md#file-format)).

## What the model said

Not recorded: the plugin uses only the tool hooks. Record the model calls with the [LLM gateway](../gateway.md); they
pair with the calls by the model's tool-call ids.

## Not covered

- A hold longer than Hermes's callback timeout. The hook blocks the call and withdraws the approval 5 s before
  `plugins.hook_callback_timeout` ends, so a hold can last at most about 10 minutes. A hook that runs over (a signer
  that doesn't answer in time) is blocked by Hermes itself, which then skips it, and so blocks every tool call, for
  60 s.
- Tool calls that fire no `pre_tool_call`: those another plugin makes with `ctx.dispatch_tool`, Hermes's
  `tool_search` and `tool_describe` catalog reads, and every call while Hermes runs in safe mode, which loads no
  plugins.
- A tool-execution middleware (`ctx.register_middleware`) runs between the decision and the tool: arguments it
  rewrites run undecided, and a result it returns in place of the tool's is recorded as the tool's.
- An approval with a T2 [executor](../executor.md) whose arguments aren't the call's blocks the call. Hermes's `modify`
  merges over the arguments, so it can't run the signer's copy exactly.
- Each Hermes session is its own run: a `delegate_task` subagent's calls go to its session's run, not linked to the
  parent's. The run closes at exit: a killed Hermes leaves it open until the signer's idle timeout.
- The result recorded is the one the tool returned, before a `transform_tool_result` hook rewrites what the model
  reads.
