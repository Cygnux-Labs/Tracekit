# Tracekit plugin for Claude Code

Adds Tracekit's v2 Claude Code hooks through the plugin system, plus `/tracekit-status`, `/tracekit-verify` and
`/tracekit-pending`.

```text
/plugin marketplace add Cygnux-Labs/Tracekit
/plugin install tracekit@tracekit
```

The plugin only carries the hooks. The signer and the verifier are the `tracekit` Python package:

```bash
pip install tracekit-ai
tracekit init --dev --v2 --no-hooks      # same-user dev signer (it starts on the first hook); hooks come from the plugin
# or, for tamper resistance against the agent's own user (Linux):
sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user> --no-hooks
```

What is recorded: every tool call (the command, file path or URL in clear, file contents and outputs as hashes), the
policy's decision on it, and your prompts as hashes. It stays with the local signer (dev mode: a store under your own
user; system mode: the signer's own user); the plugin sends nothing off the machine. Field by field:
[privacy](../docs/privacy.md).

Use **either** the plugin **or** `tracekit init --dev --v2` (which writes the same hooks into `~/.claude/settings.json`),
not both, or every call is recorded twice. `tracekit doctor` reads hooks from settings files only, so with the plugin
it warns `D-HOOKS-PRESENT`. The hook script is POSIX shell (macOS, Linux, WSL); on native Windows use
`tracekit init --dev --v2`.

Each hook runs `python -I -m tracekit.integrations.claude_code <event>`, the command `tracekit init --v2` writes: the
signer decides (deny blocks the call, ask holds it until someone approves it from another terminal), and a hook that
starts but cannot finish blocks the call.

In system mode (`/etc/tracekit/client.json` exists) the hook runs only the root-owned runtime,
`/opt/tracekit/bin/python`; `TRACEKIT_PYTHON`, `PATH` and user site-packages are ignored. If that runtime cannot run
the hook the call is blocked (unless the config sets `fail_mode: open`): re-run system init from a root-owned clone,
`sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user>`.

Otherwise set `TRACEKIT_PYTHON` to pick the interpreter that has Tracekit installed. Without the package installed,
the hook prints a one-line notice and lets the call proceed; nothing is recorded until you install it. See the main
[README](../README.md) for what Tracekit proves and what it does not.
