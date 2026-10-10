# Claude Agent SDK agent on the v2 signer

Runs offline: a mock model, no API key, no network. `ls` is allowed, `sudo rm -rf /` is denied (TK-D001) and the agent
goes on, and `echo "unterminated` waits for an approval (TK-SHELL-PARSE: the signer can't parse the command, so a person
decides). Then the run is exported and verified.

How: `tracekit_hooks()` gates each call in the PreToolUse hook and records it in PostToolUse. A mock CLI stands in for
the `claude` process and its model; drop `transport=` to run the real one. The ask holds the call inside the hook until
it is approved.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install 'tracekit-ai[signer]' 'claude-agent-sdk>=0.2.165,<0.3'       # from a checkout: pip install '.[signer]'
python examples/v2/claude_agent_sdk/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands:

```sh
tracekit approvals show <id>
tracekit approvals approve <id>      # or: reject <id>
```

The first call starts a dev signer in the background (`tracekit down` stops it). The example writes `trust.json` and
`<run id>.tkb` to the current directory and prints the `tracekit verify` report. Read it in [the
quickstart](../../../docs/quickstarts/claude-agent-sdk.md).
