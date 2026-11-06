# Quickstart: Claude Agent SDK

Every tool call is decided by the v2 signer before it runs and recorded after, as a signed event. This page adds it
to the agent you have in three steps. It uses the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)).

## 1. Install

```sh
pip install tracekit-ai 'claude-agent-sdk>=0.2.165,<0.3'
```

## 2. One line in your agent

```python
import tracekit; tracekit.instrument()     # first
import anyio
from claude_agent_sdk import ClaudeAgentOptions, query

async def main():
    async for message in query(prompt="Use the Bash tool to list the files in this repo.", options=ClaudeAgentOptions()):
        print(message)

anyio.run(main)
```

Every `ClaudeAgentOptions` built after `instrument()` gets the PreToolUse and PostToolUse hooks, next to any of its
own. An `ask` holds the call inside the PreToolUse hook for up to nine minutes while a person decides
(`tracekit approvals approve <id>`). The run closes when the process exits, not at the session's end; for one run per
session, wire the hooks by hand (below).

## 3. See it verified

```sh
tracekit last
```

It exports the most recent finished run, pins the dev signer's key, verifies the bundle and says where it is
([the v2 quickstart](../quickstart-v2.md#3-see-it-verified)).

## Approvals: wire it by hand

```python
from claude_agent_sdk import ClaudeAgentOptions, query
from tracekit.integrations.claude_agent_sdk import tracekit_hooks
from tracekit.sdk.client import Client

client = Client()
run = client.register_run({"agent": {"name": "my-agent"}})
options = ClaudeAgentOptions(hooks=tracekit_hooks(client, run))
async for message in query(prompt="Use the Bash tool to list the files here.", options=options):
    ...
```

The example runs a mock CLI (`transport=`) so it needs no `claude` binary and no API key. An ask holds the call inside
the PreToolUse hook for up to nine minutes; SessionEnd closes the run.

An offline run of all this (a mock model, no API key), with an approval: `python examples/v2/claude_agent_sdk/agent.py
--scripted` from a checkout.

## Read the verify report

`tracekit last` and `tracekit verify` print a short result:

```text
VERIFIED: <n> tool calls in <m> signed records, none changed, removed or added after signing.
NOT PROOF AGAINST THE AGENT: in this setup the agent can reach the signing key, so it could have rewritten the record.
To make it proof, keep the key away from the agent: https://github.com/Cygnux-Labs/Tracekit/wiki/Deploy
NOT ANCHORED: no independent witness or anchor cosigned the log (https://github.com/Cygnux-Labs/Tracekit/wiki/Witnesses).
Pinned log key SHA-256 fingerprint: <64 hex digits>.
```

`VERIFIED` means every record was signed by the log key in `trust.json`, the run is one unbroken chain, and a
checkpoint signed by that key includes it: nothing was edited, dropped or reordered after signing. Change one byte of
the bundle and it reads `TAMPERED at event n: ...`, naming the record and what broke (`tracekit demo --server` shows
this). `NOT PROOF AGAINST THE AGENT` is dev mode: the signer runs as your own user. Add `--detail` for every check, then
the `Integrity` and `Assurance` lines; the scripted example prints that full report. `Assurance: dev` says no pinned
witness cosigned the checkpoint and the approval was a self-approval. [The v2
quickstart](../quickstart-v2.md#export-and-verify-by-hand) explains every line.

## Next steps

- **System mode** runs the signer as its own OS user, so the agent can't reach its keys, store or policy, and approvals
  come from another account: [system mode](../quickstart-v2.md#system-mode-linux-macos-experimental).
- **Witnesses** cosign the signer's checkpoints from another host, so a rolled-back or forked log shows:
  [witnesses](../witnesses.md). Pin them in the trust config and the report reads `Assurance: witnessed`.
- **Your own policy**: the dev signer uses the coding pack plus two demo rules (`tracekit/policy2/packs/dev.yaml`); a
  configured signer takes `policy:` in `signer.yaml`.
- **Reference**: [the Claude Agent SDK integration](../integrations/claude-agent-sdk.md), with every option and what it doesn't cover.
