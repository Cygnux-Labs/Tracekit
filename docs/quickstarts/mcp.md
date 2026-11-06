# Quickstart: MCP client

Every tool call is decided by the v2 signer before it runs and recorded after, as a signed event. This page adds it
to the agent you have in three steps. It uses the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)).

## 1. Install

```sh
pip install tracekit-ai 'mcp>=2.3,<2.4'
```

## 2. One line in your agent

```python
import tracekit; tracekit.instrument()     # first
import asyncio
from mcp import Client, StdioServerParameters

async def main():
    async with Client(StdioServerParameters(command="my-mcp-server")) as client:
        result = await client.call_tool("create_issue", {"title": "..."})   # recorded as mcp:<server>/create_issue
        print(result.content)

asyncio.run(main())
```

Every `ClientSession.call_tool` goes through the signer, whichever client or transport made the session. A denied
call comes back as a result with `isError: true` and the refusal as its text. An `ask` waits up to five minutes in
`call_tool` for a person to decide. The coding pack only flags MCP calls; write your own policy for real tools.

## 3. See it verified

```sh
tracekit last
```

It exports the most recent finished run, pins the dev signer's key, verifies the bundle and says where it is
([the v2 quickstart](../quickstart-v2.md#3-see-it-verified)).

## Approvals: wire it by hand

```python
from tracekit.integrations.mcp import TracekitSession
from tracekit.sdk.client import Client

client = Client()
run = client.register_run({"agent": {"name": "my-agent"}})
session = TracekitSession(session, client, run)    # an initialized ClientSession; mcp 1.x: add server="<name>"
result = await session.call_tool("create_issue", {"title": "..."})   # recorded as mcp:<server>/create_issue
```

A denied call comes back as a result with `isError: true` and the refusal as its text. The coding pack only flags MCP
calls; the example's deny and ask come from the dev policy's demo rules (TK-DEMO-DENY, TK-DEMO-ASK). Write your own
policy for real tools.

An offline run of all this (a mock model, no API key), with an approval: `python examples/v2/mcp/agent.py
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
- **Reference**: [the MCP integration](../integrations/mcp.md), with every option and what it doesn't cover.
