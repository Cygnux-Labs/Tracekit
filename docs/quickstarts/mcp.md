# Quickstart: MCP client

Every tool call is decided by the v2 signer before it runs and recorded after, as a signed event. This page runs the
example in [examples/v2/mcp](../../examples/v2/mcp/) offline (a mock model, no API key), then reads the report of its
verified bundle. It uses the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)).

## 1. Install

```sh
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install 'tracekit-ai[signer]' 'mcp>=2.3,<2.4'
```

## 2. Run the example

```sh
python examples/v2/mcp/agent.py --scripted
```

The first call starts a dev signer in the background. One call is allowed, one is denied and the agent goes on, one is
held until it is approved. `--scripted` approves it from a second process; without it, approve it yourself from another
terminal with `tracekit approvals approve <id>` (`tracekit approvals show <id>` shows the signer's copy of the arguments
first). The example then pins the signer's key (`tracekit signer trust -o trust.json`), exports the run (`tracekit
export --v2 --run <id>`) once the signer has finalised it, and verifies it.

## 3. Wire it into your agent

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

## 4. Read the verify report

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
quickstart](../quickstart-v2.md#4-export-and-verify) explains every line.

## Next steps

- **System mode** runs the signer as its own OS user, so the agent can't reach its keys, store or policy, and approvals
  come from another account: [system mode](../quickstart-v2.md#system-mode-linux-macos-experimental).
- **Witnesses** cosign the signer's checkpoints from another host, so a rolled-back or forked log shows:
  [witnesses](../witnesses.md). Pin them in the trust config and the report reads `Assurance: witnessed`.
- **Your own policy**: the dev signer uses the coding pack plus two demo rules (`tracekit/policy2/packs/dev.yaml`); a
  configured signer takes `policy:` in `signer.yaml`.
