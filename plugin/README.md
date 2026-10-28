# Tracekit plugin for Claude Code

> **Experimental:** the plugin works and is tested, but may change and gets less hardening than the
> [stable core](https://github.com/Cygnux-Labs/Tracekit/wiki/Support). The same hooks wired by `tracekit init --dev --v2` are stable.

Adds Tracekit's v2 Claude Code hooks through the plugin system, plus `/tracekit-status`, `/tracekit-verify` and
`/tracekit-pending`.

```text
/plugin marketplace add Cygnux-Labs/Tracekit
/plugin install tracekit@tracekit
```

The plugin only carries the hooks. The signer and the verifier are the `tracekit` Python package:

```bash
pip install tracekit-ai==1.5.0
tracekit init --dev --v2 --no-hooks   # same-user dev signer (starts on the first hook); hooks come from the plugin
# or, for tamper resistance against the agent's own user (Linux):
sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user> --no-hooks
```

What is recorded: every tool call (the command, file path or URL in clear, file contents and outputs as hashes), the
policy's decision on it, and your prompts as hashes. In dev mode the signer also keeps each call's redacted arguments
and the result it was sent, encrypted, for 7 days, so `tracekit view --dev` can show them; `TRACEKIT_DEV_CONTENT=0`,
set before the dev signer starts, keeps none. Exported bundles hold only the hashes. Everything stays with the local
signer (dev mode: a store under your own user; system mode: the signer's own user); the plugin sends nothing off the
machine. Field by field: [privacy](https://github.com/Cygnux-Labs/Tracekit/wiki/Privacy).

## The plugin or `tracekit init`, not both

`tracekit init --dev --v2` writes the same hooks into `~/.claude/settings.json`. With both, every call is decided
twice, and every call you approve is blocked anyway: one hook uses the approval and the other is refused. So while the
plugin is enabled, `tracekit init --dev --v2` installs no hooks and says so, and `tracekit doctor` counts the
plugin's hooks (`D-HOOKS-PRESENT`) and warns when both run. In system mode, run init with `--no-hooks`.

## When a hook can't run

Each hook runs Tracekit's v2 Claude Code hook (`tracekit.integrations.claude_code`) for its event. The signer
decides: deny blocks the call, and ask holds it until someone approves it from another terminal.

- A tool call whose hook starts but can't finish is blocked.
- Any other event (a prompt, Stop, a tool's result, a session or subagent event) is never blocked. Its error shows in
  the transcript as a hook error, and the event isn't recorded. Blocking there would erase your prompt, or send Claude
  back to work at every Stop.
- **System mode** (`/etc/tracekit/client.json` exists): the hook runs only the root-owned runtime,
  `/opt/tracekit/bin/python`; `TRACEKIT_PYTHON`, `PATH` and user site-packages are ignored. If that runtime can't run
  the hook, tool calls are blocked (with `fail_mode: open` in that file they run, unrecorded, with an error shown).
  Re-run system init from a root-owned clone: `sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user>
  --no-hooks`.
- **Dev mode**: the hook runs in the first of `TRACEKIT_PYTHON`, `python3` and `python` that has the `tracekit`
  package, user site-packages included. A tracekit older than 1.2, or one whose hook won't import, blocks tool calls
  and says how to upgrade. With no tracekit at all, tool calls are blocked once Tracekit is set up for your user: the
  dev signer's data directory exists (`tracekit init --dev --v2` creates it), or `TRACEKIT_PYTHON` or
  `TRACEKIT_SIGNER` is set. Before that, every event shows a notice and runs, unrecorded.

The hooks `tracekit init --dev --v2` writes treat events the same way, but run the interpreter init ran with
(`python -I -m tracekit.integrations.claude_code <event>`) instead of searching for one.

## Upgrading from the v1 plugin

Plugin versions before 1.3 ran the v1 hook against `tracekitd`. This one runs the v2 hook, and updating the plugin
switches you over:

- **v1 dev mode** (`tracekit init --dev --no-hooks`): the next hook starts the v2 dev signer. Your v1 policy no longer
  applies (the v2 coding pack does), `tracekit pending` and `tracekit approve` no longer see held calls (use
  `tracekit approvals`), and once the v2 signer has recorded something, the v1 ledger can't be bridged into it.
- **v1 system mode** (`tracekit init --no-hooks` as root): every tool call is blocked until v2 system mode is set up. The
  hook's error says so.

Before the next Claude Code session after the update:

```bash
tracekit export --last -o last-v1-run.tkb                # each v1 run you need (--run ID)
tracekit uninstall                                         # stops tracekitd
tracekit signer bridge --v1-home ~/.tracekit-signer --dev  # only before the v2 signer records anything
tracekit init --dev --v2 --no-hooks
# system mode instead: sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user> --no-hooks
```

If the v2 signer has already recorded something, the bridge refuses and the two logs stay separate; both keep
verifying. Details: [migrating](https://github.com/Cygnux-Labs/Tracekit/wiki/Migration#laptop-v1--v2-signer).

## Platforms

The hook script is POSIX shell: macOS, Linux and WSL. On native Windows, Claude Code runs it in Git Bash when Git for
Windows is installed (untested). Without Git Bash it runs it in PowerShell, which can't, so Claude Code blocks every
tool call: there, don't install the plugin, and use `tracekit init --dev --v2`.

See the main [README](https://github.com/Cygnux-Labs/Tracekit#readme) for what Tracekit proves and what it does not.
