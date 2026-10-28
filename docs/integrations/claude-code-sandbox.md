# Claude Code's sandbox

> `TK-A003` and `TK-A014` are rules in the stable coding pack, and Claude Code's hooks are stable ([support](../support.md)).
> Tested: `tracekit doctor` against settings read from a real Claude Code, and the rules against the Bash tool's
> arguments as Claude Code documents them ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

Claude Code's [sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing) runs shell commands inside an
operating-system sandbox, Anthropic's [sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (bubblewrap and
seccomp on Linux and WSL2, Seatbelt on macOS). It limits the files a command can write and the hosts it can reach.
Tracekit records and gates every call Claude makes, sandboxed or not. They do different jobs and work together:

| | Claude Code's sandbox | Tracekit |
|---|---|---|
| What it does | Limits what a shell command can write and reach while it runs | Decides each call before it runs, holds risky ones for a person, and signs a record of every call and approval |
| Where | Inside Claude Code, around each command | A signer outside the agent ([dev or system mode](../limits.md#dev-mode-vs-system-mode)) |
| What a third party can check later | Nothing: it keeps no record | A signed, hash-chained bundle, verified offline |

Using sandbox-runtime without Claude Code? Its proxy can ask Tracekit about every request it forwards:
[sandbox-runtime's proxy on its own](sandbox-runtime.md).

## Setup

Turn both on. Tracekit first (`tracekit init --dev --v2`, or the [plugin](../../plugin/README.md)), then the sandbox in
`~/.claude/settings.json` (or with `/sandbox`):

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true
  }
}
```

- `failIfUnavailable: true` makes Claude Code exit when the sandbox can't start (bubblewrap missing, an unsupported
  platform). Without it, Claude Code runs commands unsandboxed, and no hook can tell: the call looks the same.
- `allowUnsandboxedCommands` decides the unsandboxed retry (below). Leave it on and Tracekit holds each retry, or set
  it to `false` to turn retries off.
- Don't set `network.httpProxyPort` or `socksProxyPort` unless your proxy enforces an allowlist: once a port is set,
  Claude Code's `allowedDomains`, approval prompts and local-address check stop applying to that traffic. Tracekit's
  [egress observer](../egress.md) records hosts but enforces no allowlist, so it isn't a replacement for Claude Code's
  proxy.

`tracekit doctor` reads these settings and warns about both (`D-CLAUDE-SANDBOX`, [doctor](../doctor.md)).

## The unsandboxed retry (TK-A003)

When a command fails inside the sandbox, Claude may retry it with the Bash tool's `dangerouslyDisableSandbox: true`. The
retry runs with none of the sandbox's limits. Who approves it depends on Claude Code's permission mode: you in the
default mode, a classifier model in auto mode, nobody in `bypassPermissions` mode or when an allow rule such as
`Bash(curl *)` matches the command. Claude Code's own ask rule `Bash(dangerouslyDisableSandbox:true)` makes Bash
retries prompt even in auto and `bypassPermissions` mode.

The coding pack's `TK-A003` (an `ask` rule) adds what that prompt doesn't: it holds every call whose
`dangerouslyDisableSandbox` argument is `true` until a person approves it from outside the agent's session, and signs
the decision:

```text
[tracekit] waiting for approval apr-… (TK-A003): running a command outside Claude Code's sandbox. Wait for a person to approve the held call, …; a person approves it from another terminal with `tracekit approvals approve apr-…` or rejects it with `tracekit approvals reject apr-…`
tracekit approvals approve apr-…            # from another terminal
```

The approval is bound to the exact command, used once, and recorded with who approved it, like every Tracekit approval
([approvals](../approvals.md)). The signed decision names `TK-A003`, so a bundle shows which calls were unsandboxed
retries and who approved each; the command itself is committed to, not stored in the bundle
([format v2](../format-v2.md#2-hashes-over-agent-content)). To allow retries without asking, override `TK-A003` in your
own policy ([policy](../policy-v2.md)).

## Per-command allowed domains (TK-A014)

In auto mode with the sandbox on (Claude Code 2.1.271 and later), a Bash, PowerShell or Monitor call can carry an
`allowed_domains` list: the hosts it names are opened for that one command, still inside the sandbox. Claude is told
to re-run a command with a denied host listed there, and auto mode's classifier, not you, approves the re-run.

The coding pack's `TK-A014` (an `ask` rule, next to `TK-A003`) holds every call whose `allowed_domains` names a host
until a person approves it, the same way: bound to the exact command and list, used once, signed with who approved it.
An empty list opens nothing and isn't held, and neither is `blocked_domains`, which only narrows. To allow a host for
good, add it to the sandbox's own `network.allowedDomains` in your settings rather than approving each command.

## What Tracekit sees and doesn't

- **Sees:** every call Claude makes with its arguments (`dangerouslyDisableSandbox` included), the decision, any
  approval, and the result. Records commit to the arguments rather than store them ([privacy](../privacy.md)). When
  the sandbox blocks a connection, Claude Code names the denied host in the command's result, which Tracekit records
  with the result.
- **Doesn't see:** whether the sandbox actually started for a command, and what it blocked inside one beyond what
  Claude Code writes into the result. The sandbox runs inside Claude Code's process and keeps no record of its own.
  Commands matching `excludedCommands`, MCP servers and hooks run outside the sandbox. Tracekit still decides each
  excluded command and each MCP tool call, but no `dangerouslyDisableSandbox` marks them.
- **Doesn't record:** the sandbox settings themselves. They aren't signed into the run or the bundle; `tracekit doctor`
  reads them on the machine.
- **Doesn't check:** the full precedence of Claude Code's settings. `D-CLAUDE-SANDBOX` merges the files it reads key
  by key ([doctor](../doctor.md)).

[Limits](../limits.md) lists these with what to do.
