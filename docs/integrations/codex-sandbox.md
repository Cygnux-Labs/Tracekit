# Codex's sandbox

Codex CLI runs each shell command inside an operating-system sandbox: Seatbelt on macOS, bubblewrap and seccomp on
Linux, a restricted token on Windows. Its `sandbox_mode` decides what a command can write (`read-only`,
`workspace-write`, or `danger-full-access`, which is no sandbox), and the network is off unless you turn it on.
Tracekit records and gates every call Codex makes, sandboxed or not. They do different jobs and work together:

| | Codex's sandbox | Tracekit |
|---|---|---|
| What it does | Limits what a shell command can write and reach while it runs | Decides each call before it runs, holds risky ones for a person, and signs a record of every call and approval |
| Where | Inside Codex, around each command | A signer outside the agent ([dev or system mode](../limits.md#dev-mode-vs-system-mode)) |
| What a third party can check later | Nothing signed; Codex keeps its own session files | A signed, hash-chained bundle, verified offline |

## Setup

Turn both on. Tracekit first (`tracekit init --dev --v2 --agent codex`, [coding agents](../coding-agents.md)), then
the sandbox in `~/.codex/config.toml`:

```toml
sandbox_mode = "workspace-write"
approval_policy = "on-request"
approvals_reviewer = "user"
```

- `workspace-write` lets a command write the workspace and temporary directories, with no network unless
  `[sandbox_workspace_write]` sets `network_access = true`. With `danger-full-access`, or
  `--dangerously-bypass-approvals-and-sandbox`, commands run with no sandbox: Tracekit still decides and records each
  call, but nothing limits what an allowed command does.
- `approval_policy = "on-request"` makes Codex ask before it runs a command the model wants outside the sandbox
  (below). For unattended runs, `"never"` makes Codex refuse every such request instead.
- `approvals_reviewer = "user"` (the default) sends those questions to you; `"auto_review"` lets a reviewer model
  answer them.
- Keep execpolicy `allow` rules (`~/.codex/rules/*.rules`) narrow. A command whose every part matches one runs without
  asking, and can run outside the sandbox. Answering "don't ask again for commands that start with …" in a Codex
  prompt adds one to `default.rules`.

## Escalation requests

Codex's shell tool (`exec_command`) lets the model ask to run a command outside the sandbox:
`sandbox_permissions: "require_escalated"`, with a `justification` that Codex shows to whoever approves. Under
`on-request` Codex asks before such a command runs; under `never` it refuses the request.

Tracekit can't hold these the way it holds Claude Code's unsandboxed retries (`TK-A003`,
[Claude Code's sandbox](claude-code-sandbox.md)): Codex's `PreToolUse` hook sends a shell call as `{"command": ...}`
only, so neither the request nor Codex's answer reaches Tracekit. What Tracekit does: its policy decides each command
before Codex's own approval step, so a command a rule denies or holds is denied or held whether or not it asked to
leave the sandbox. To keep every escalation in front of a person, use the settings above.

## CODEX_TOOL_CALL_ID

Codex puts the id of the tool call that started a command into the command's environment as `CODEX_TOOL_CALL_ID`.
It's the id Codex's hooks send as `tool_use_id`, which Tracekit records as `tool_call_id` on every record of the call:
its decision, any approval, its result ([format v2](../format-v2.md#3-events)). So a record of what a process did
that captured its environment (an OS audit log, an EDR) can be joined to the signed call that started it. Input Codex
later types into a running command keeps the first call's id.

Codex documents the label as for correlation, not authorization: the command, its shell startup files and its child
processes can change or remove it. Read a match as a pointer to the signed call, not as proof that the call caused the
effect, and a process without one as unexplained.

## What Tracekit sees and doesn't

- **Sees:** every shell command (as `Bash`), patch (`apply_patch`, as `Edit`) and MCP tool call Codex sends to its
  hooks, with its arguments and call id, the decision, any approval, and the result. Records commit to the arguments
  rather than store them ([privacy](../privacy.md)).
- **Doesn't see:** whether a command ran in the sandbox: a request to leave it, Codex's answer, or a command an `allow`
  rule let run outside it. What the sandbox blocked shows only in the command's output. In current Codex, input typed
  into a running command (`write_stdin`) runs no `PreToolUse` hook; it belongs to the command Tracekit already decided.
- **Doesn't record:** Codex's sandbox and approval settings. They aren't signed into the run, and `tracekit doctor`
  doesn't read Codex's config.

[Limits](../limits.md) lists these with what to do.
