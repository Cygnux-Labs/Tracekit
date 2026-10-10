# OpenAI Agents SDK agent on the v2 signer

Runs offline: a mock model, no API key, no network. `ls` is allowed, `sudo rm -rf /` is denied (TK-D001) and the agent
goes on, and `echo "unterminated` waits for an approval (TK-SHELL-PARSE: the signer can't parse the command, so a person
decides). Then the run is exported and verified.

How: `TracekitAgents.tool()` gates the function tool; `hooks=tk` records each model response. The ask interrupts the
run; `tk.apply_decisions(state)` applies the signer's decision and the run resumes.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install 'tracekit-ai[signer]' 'openai-agents>=0.23.1,<0.24'       # from a checkout: pip install '.[signer]'
python examples/v2/openai_agents/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands:

```sh
tracekit approvals show <id>
tracekit approvals approve <id>      # or: reject <id>
```

The first call starts a dev signer in the background (`tracekit down` stops it). The example writes `trust.json` and
`<run id>.tkb` to the current directory and prints the `tracekit verify` report. Read it in [the
quickstart](../../../docs/quickstarts/openai-agents.md).
