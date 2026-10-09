# Claude Agent SDK (signer RPC)

`tracekit.integrations.claude_agent_sdk.tracekit_hooks` gates the tools of a Claude Agent SDK (Python) agent. Before
each tool call it asks the Tracekit signer for a policy decision; after the tool runs it records the outcome.
`TracekitSessionStore` wraps your `SessionStore` and commits every saved transcript to the signer. Both work with a
`tracekit.sdk.client.Client` or any object that implements the signer RPC (`tracekit.signer.rpc_schema.SignerAPI`),
including `tracekit.testing.FakeSigner`.

## Install

```bash
pip install tracekit-ai "claude-agent-sdk>=0.2.165,<0.3"
```

Python 3.10 or newer (the SDK's own requirement).

## Setup

```python
from claude_agent_sdk import ClaudeAgentOptions, query
from tracekit.integrations.claude_agent_sdk import TracekitSessionStore, tracekit_hooks
from tracekit.sdk.client import Client

signer = Client()
run = signer.register_run({"agent": {"name": "repo-agent"}})
options = ClaudeAgentOptions(
    hooks=tracekit_hooks(signer, run),
    session_store=TracekitSessionStore(my_store, signer, run),   # optional: only if you mirror sessions to a store
)
async for message in query(prompt="fix the failing test", options=options):
    ...
```

Register the run when the session starts; the hooks close it at `SessionEnd`. To add hooks of your own, extend the
lists in the mapping. Tools run in the CLI subprocess under their Claude Code names (`Bash`, `Edit`, `Write`, ...), so
the signer's coding packs apply to them as they do to the Claude Code hook.

## What is recorded

| When | RPC | Sent |
|---|---|---|
| PreToolUse | `decide` | `tool_use_id`, tool name, the tool input as the CLI sends it (`parsed`) |
| PreToolUse, right before it runs | `approval_consume` | the same call and arguments, and the approval id when the hook waited for one |
| PostToolUse / PostToolUseFailure | `complete` | `status` `ok` or `error`, a `sha256:` commitment to the tool response (not the response), or the error message |
| after each `SessionStore.append` | `state_write` | the transcript's digest and the digest it started from (`prev_digest`) |
| SessionEnd | `close_run` | the CLI's reason |

## Decisions

- **allow**: the tool runs.
- **deny**: the hook answers `permissionDecision: deny`. The model gets `Tool call blocked by policy: <rule ids>` as the
  tool's error result and the session goes on.
- **ask**: the hook opens an approval in the signer and holds the call until a person approves or rejects it there
  (CLI, web), for at most `APPROVAL_WAIT_S` (540 s). The PreToolUse matcher's timeout is set to `HOOK_TIMEOUT_S`
  (600 s), so the hook answers before the CLI gives up on it. A call not approved in time, or rejected, is denied.

Every call that is not denied runs only after the signer's `approval_consume` agrees: nothing the SDK holds is taken
as proof that no approval is needed. If the signer cannot be reached, the call is denied (fail closed).

The gate is the PreToolUse hook, not the `can_use_tool` permission callback: the CLI skips `can_use_tool` for calls
its permission mode or allow rules approve (`bypassPermissions`, `allowed_tools`), while PreToolUse runs for every call.
The hook returns no opinion on an allowed call, so your permission settings still apply on top.

## Session store (L1)

`TracekitSessionStore(store, signer, run)` passes every call to your store. After each `append` it sends
`state_write` with the digest of the transcript (canonical JSON of each entry, chained, so a store that reorders JSON
keys gives the same digest) and the digest the transcript had before (`prev_digest`). When a session resumes from the
store, `load` recomputes the digest from what the store gives back; if the transcript was changed in the store since
the last write, the next write starts from another digest than the signer recorded, and the signer writes a signed
`capture.gap` of kind `state_tamper`. The signer compares writes within one run: resume the session in the same run
(same `run_id` and `run_token`) for the check to apply.

## Not covered

- The hook holds a call while it waits for an approval: there is no saved state to resume in a new process, so a wait
  longer than `APPROVAL_WAIT_S` ends in a denial and the model may try again.
- The CLI gives every tool use its own `tool_use_id` and runs it once, so every call is attempt 0.
- A store that keeps an entry twice (a retried append without de-duplication by `uuid`) changes the transcript's
  digest, and the next resume records a `state_tamper`.
