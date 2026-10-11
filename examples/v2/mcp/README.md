# MCP client on the v2 signer

Runs offline: a mock model, no API key, no network. `list_files` is allowed, `tracekit_demo_denied` is denied
(TK-DEMO-DENY) and the client goes on, `tracekit_demo_ask` waits for an approval (TK-DEMO-ASK). Those two rules are the
dev policy's demo rules; with your own policy, any tool can be denied or held. Then the run is exported and verified.

How: `TracekitSession` wraps the client session: every `call_tool` is decided first. The server runs in process on the
mcp package's in-memory transport. `call_tool` waits for the approval itself.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai 'mcp>=2.3,<2.4'       # from a checkout: pip install .
python examples/v2/mcp/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands:

```sh
tracekit approvals show <id>
tracekit approvals approve <id>      # or: reject <id>
```

The first call starts a dev signer in the background (`tracekit down` stops it). The example writes `trust.json` and
`<run id>.tkb` to the current directory and prints the `tracekit verify` report. Read it in [the
quickstart](../../../docs/quickstarts/mcp.md).
