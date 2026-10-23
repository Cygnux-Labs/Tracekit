# Hermes Agent

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

The Tracekit plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent) (`integrations/hermes/` in this
repository) gates every tool call Hermes makes, built-in and plugin tools alike: its `pre_tool_call` hook asks the
Tracekit signer for a decision before the tool runs (an `ask` waits for a person), and its `post_tool_call` hook
records the outcome. It registers those two hooks and nothing else. The hooks are `tracekit.integrations.hermes`.

Checked against Hermes Agent v0.22.5 (commit `bf0203a794a07aac3ff764972ab9087baa4e4f4e`): tested in CI against a
stand-in for the sequential path of Hermes's agent loop (`agent/tool_executor.py`) and its plugin hook dispatch, as
that source defines them, not a running Hermes.

## Install

```bash
hermes plugins install Cygnux-Labs/Tracekit/integrations/hermes
hermes config set plugins.hook_callback_timeout 600
hermes config set timeouts.tools.sequential_call 600
hermes config set timeouts.tools.concurrent_batch 600
```

The plugin needs `tracekit-ai` 1.4.2 or later, the first release with these hooks; Hermes asks before it installs it
into its own environment. At install Hermes also asks for `TRACEKIT_SIGNER_TOKEN`: leave it empty unless your signer
is on `tcp://`.

**Raise Hermes's limits for approvals.** An `ask` waits for a person inside `pre_tool_call`, and Hermes bounds that
hook twice: by `plugins.hook_callback_timeout` (30 s by default, 600 s at most), and by the call's own tool deadline
(`timeouts.tools.sequential_call`, else `timeouts.tools.concurrent_batch`, 420 s by default). The hook waits until 5 s
before the smaller of them, so with the defaults a person has about 25 s to approve a call; with all three set to 600,
almost 10 minutes. Calls the model makes together run as a concurrent batch, whose deadline counts from the batch's
start, so a call that waits for its turn there has less of it.

## Which signer

The plugin uses the signer Tracekit's client finds, as `tracekit.instrument()` does: with no `TRACEKIT_SIGNER` set,
the same-user dev signer, started at the first tool call if none is running; in system mode
(`/etc/tracekit/client.json`), the system signer. To use another signer, set `TRACEKIT_SIGNER` in the environment Hermes
starts with: a Unix socket path, `tcp://127.0.0.1:PORT` (its token in `TRACEKIT_SIGNER_TOKEN`, which the plugin reads
through Hermes's secret scope, and never from the process environment when the profile has none), or an `https://` URL
(its bearer token file in `TRACEKIT_SIGNER_TOKEN_FILE`).

Each Hermes session is a run (agent `hermes`), registered at its first tool call and closed when Hermes exits. Then
`tracekit last` exports and verifies it. A run the signer closed because it was idle is replaced by a new one at the
session's next call.

## What it does

- **Decides the model's own call.** `pre_tool_call` sends the signer the call's `tool_call_id`, tool name and
  arguments, as the model sent them: Hermes converts string arguments to the tool's schema types only after the hook.
  A call with no `tool_call_id` is blocked: its result couldn't be bound to its decision.
- **Never runs a refused call.** A deny, a rejected or unanswered approval, a refused consume, a signer refusal, an
  outage and any error of Tracekit's own all return Hermes's `{"action": "block", "message": ...}`: the call doesn't
  run and the model reads Tracekit's reason as the tool's error. During an outage the run's fail mode for the tool's
  class decides: closed, so the call is blocked, unless the signer's policy says `open`. A session whose run can't be
  registered (no signer answers at its first call) has every call blocked, whatever the fail mode. When the plugin
  can't load `tracekit-ai`, it blocks every call: a plugin that failed to register would let every call run ungated.
- **Keeps approvals with the signer.** An `ask` is answered in Tracekit (`tracekit approvals`, the viewer, an
  approver the signer knows), never by Hermes's own approval prompt. An approval still unanswered when the hook's time
  is up is withdrawn, so no one approves a call that never ran. So is one whose call Hermes stopped waiting for (its
  tool deadline, a `/stop`), answered or not: the hook sees Hermes's `post_tool_call` for it, and the call never runs.
- **Records the outcome.** `post_tool_call` completes the call against its decision with Hermes's status: `ok` with
  the result the tool returned (in full for a tool the policy lists as untrusted, for provenance; otherwise its
  digest), or `error` for Hermes's `error`, `timeout` and `cancelled`, with its message. A call another plugin blocked
  after Tracekit allowed it, or whose consume the signer refused, is recorded as `status: error`, "not run: ...". One
  whose arguments another plugin changed (with `modify`, or in place) runs and is recorded as `status: error`, "the
  call's arguments changed after the decision".

## Policy

The shipped packs name Hermes's `terminal` tool (class `shell`), so their shell rules read its `command`. Hermes's
other tools (`write_file`, `patch`, `read_file`, `web_search`, `browser_*`, `execute_code`, ...) are unknown to them,
and so are its `tool_search` and `tool_describe` catalog reads, which the hook decides too: the laptop packs flag such
a call and let it run, and the server pack holds it for a person. Give them classes in your policy's `tools:`
([file format](../policy-v2.md#file-format)).

## What the model said

Not recorded: the plugin uses only the tool hooks. Record the model calls with the [LLM gateway](../gateway.md); they
pair with the calls by the model's tool-call ids.

## Not covered

- A hold longer than Hermes's limits. The hook blocks the call and withdraws the approval 5 s before the smaller of
  `plugins.hook_callback_timeout` and the tool deadline, so a hold lasts at most about 7 minutes with the default tool
  deadline (420 s), about 10 with every limit at 600. A hook that runs over its callback timeout (a signer that doesn't
  answer in time) is blocked by Hermes itself, which then skips it, and so blocks every tool call, for 60 s.
- Tools an `execute_code` script calls: Hermes runs them with no `tool_call_id`, so the plugin blocks every one.
- Tool calls that fire no `pre_tool_call`: those another plugin makes with `ctx.dispatch_tool`, and every call while
  Hermes runs in safe mode, which loads no plugins.
- A tool-execution middleware (`ctx.register_middleware`) runs around the decision in the agent loop: the signer
  decides the arguments it passes on; one that answers in place of the tool leaves the call neither decided nor
  recorded, and a result it rewrites is recorded as rewritten.
- An approval with a T2 [executor](../executor.md) whose arguments aren't the call's blocks the call. Hermes's `modify`
  merges over the arguments, so it can't run the signer's copy exactly.
- Each Hermes session is its own run: a `delegate_task` subagent's calls go to its session's run, not linked to the
  parent's. The run closes at exit: a killed Hermes leaves it open until the signer's idle timeout.
- The result recorded is the one the tool returned, before a `transform_tool_result` hook rewrites what the model
  reads.
