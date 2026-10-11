# Quickstart: OpenAI Agents SDK

Every tool call is decided by the v2 signer before it runs and recorded after, as a signed event. This page adds it
to the agent you have in three steps. It uses the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)).

## 1. Install

```sh
pip install tracekit-ai 'openai-agents>=0.23.1,<0.24'
```

## 2. One line in your agent

```python
import tracekit; tracekit.instrument()     # first
from agents import Agent, Runner, function_tool

@function_tool
def transfer_funds(to: str, cents: int) -> str:
    """Send money."""
    return f"sent {cents} to {to}"

agent = Agent(name="payer", model="gpt-5", tools=[transfer_funds])
print(Runner.run_sync(agent, "pay acct-42 $15").final_output)
```

The tools of every `Agent` built after `instrument()` are gated: function tools, ShellTool with a local executor,
LocalShellTool and ApplyPatchTool. Hosted tools, ComputerTool and handoffs are recorded only in the signed model
responses. An `ask` interrupts the run (`result.interruptions`); to resume it once a person decided, wire the adapter by
hand (below).

## 3. See it verified

```sh
tracekit last
```

It exports the most recent finished run, pins the dev signer's key, verifies the bundle and says where it is
([the v2 quickstart](../quickstart-v2.md#3-see-it-verified)).

## Approvals: wire it by hand

```python
from tracekit.integrations.openai_agents import TracekitAgents
from tracekit.sdk.client import Client

client = Client()
tk = TracekitAgents(client, client.register_run({"agent": {"name": "my-agent"}}))
agent = Agent(name="payer", model="gpt-5", tools=[tk.tool(transfer_funds)])
result = await Runner.run(agent, "pay acct-42 $15", context={}, hooks=tk)   # the context must be a dict
while result.interruptions:                       # an ask: once a person decided in the signer
    state = result.to_state()
    await tk.apply_decisions(state)
    result = await Runner.run(agent, state, hooks=tk)
```

Function tools, ShellTool with a local executor, LocalShellTool and ApplyPatchTool are gated. Hosted tools, ComputerTool
and handoffs are recorded only inside the signed model responses.

An offline run of all this (a mock model, no API key), with an approval: `python examples/v2/openai_agents/agent.py
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
