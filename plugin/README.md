# Tracekit plugin for Claude Code

Adds Tracekit's hooks to Claude Code through the plugin system, plus `/tracekit-status`, `/tracekit-verify` and
`/tracekit-pending`.

```text
/plugin marketplace add Cygnux-Labs/Tracekit
/plugin install tracekit@tracekit
```

The plugin only carries the hooks. The signer and the verifier are the `tracekit` Python package:

```bash
pip install tracekit-ai
tracekit init --dev --no-hooks      # same-user signer, hooks come from the plugin
# or, for tamper resistance against the agent's own user (Linux):
sudo tracekit init --no-hooks
```

Use **either** the plugin **or** `tracekit init` (which writes hooks into `~/.claude/settings.json`), not both,
or every call is recorded twice. Without the package installed, the hook prints a one-line notice and lets the
call proceed; nothing is recorded until you install it. The hook script is POSIX shell (macOS, Linux, WSL);
on native Windows use `tracekit init --dev`.

Set `TRACEKIT_PYTHON` to pick the interpreter that has Tracekit installed. See the main
[README](../README.md) for what Tracekit proves and what it does not.
