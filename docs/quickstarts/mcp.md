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
session = TracekitSession(session, client, run)    # an initialized ClientSession
result = await session.call_tool("create_issue", {"title": "..."})   # recorded as mcp:<server>/create_issue
```

A denied call comes back as a result with `isError: true` and the refusal as its text. The coding pack only flags MCP
calls; the example's deny and ask come from the dev policy's demo rules (TK-DEMO-DENY, TK-DEMO-ASK). Write your own
policy for real tools.

An offline run of all this (a mock model, no API key), with an approval: `python examples/v2/mcp/agent.py
--scripted` from a checkout.

## Read the verify report

```text
[PASS] checkpoint — tracekit.local/... at tree size 12, signed by its pinned log key
[PASS] witness quorum — 0 pinned cosignature(s), 0 required
[PASS] signatures — 11 record(s), keys valid at their position
[PASS] run chain — run '...' of tenant 'default', contiguous from run_seq 0
...
Integrity: VERIFIED.
Assurance: dev; records ed25519; checkpoint Ed25519 only (...); no witness cosignature; approvals: self; ...
```

`Integrity: VERIFIED` means every record was signed by the log key in `trust.json`, the run is one unbroken chain, and a
checkpoint signed by that key includes it: nothing was edited, dropped or reordered after signing. Change one byte of
the bundle and it reads `Integrity: FAILED`, naming the check (`tracekit demo --server` shows this). `Assurance: dev`
says no pinned witness cosigned the checkpoint and the approval was a self-approval. [The v2
quickstart](../quickstart-v2.md#export-and-verify-by-hand) explains every line.

## Next steps

- **System mode** runs the signer as its own OS user, so the agent can't reach its keys, store or policy, and approvals
  come from another account: [system mode](../quickstart-v2.md#system-mode-linux-macos-experimental).
- **Witnesses** cosign the signer's checkpoints from another host, so a rolled-back or forked log shows:
  [witnesses](../witnesses.md). Pin them in the trust config and the report reads `Assurance: witnessed`.
- **Your own policy**: the dev signer uses the coding pack plus two demo rules (`tracekit/policy2/packs/dev.yaml`); a
  configured signer takes `policy:` in `signer.yaml`.
