# Quickstart: OpenAI Agents SDK

Every tool call is decided by the v2 signer before it runs and recorded after, as a signed event. This page adds it
to the agent you have in three steps. It uses the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)).

## Try it first, with no API key

```sh
git clone --depth 1 https://github.com/Cygnux-Labs/Tracekit && cd Tracekit
python3 -m venv .venv && . .venv/bin/activate
pip install . 'openai-agents>=0.23.1,<0.24'
python examples/v2/openai_agents/agent.py --scripted
```

A mock model drives a real `Runner`: `ls` is allowed, `sudo rm -rf /` is denied and the agent goes on, and `echo
"unterminated` is held until a second process approves it. Then the run is exported and verified.

## 1. Install

```sh
pip install tracekit-ai 'openai-agents>=0.23.1,<0.24'
export OPENAI_API_KEY=...        # the agent below calls OpenAI's gpt-5
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
responses. An `ask` interrupts the run: `Runner.run_sync` returns at once with `final_output` None and
`result.interruptions`, and at exit the process prints each held approval's id with its approve and reject commands.
To resume it once a person decided, see the next section.

## 3. See it verified

```sh
tracekit last
```

It exports the most recent finished run, pins the dev signer's key, verifies the bundle and says where it is
([the v2 quickstart](../quickstart-v2.md#3-see-it-verified)).

## Resume a held call under `instrument()`

`instrument()` returns the run handle, and `run.openai_agents` is the adapter it wired into every `Agent`:

```python
import asyncio, time, tracekit
from agents import Runner

run = tracekit.instrument()
...
result = Runner.run_sync(agent, "pay acct-42 $15")
while result.interruptions:             # an ask; approve it in another terminal: tracekit approvals approve <id>
    state = result.to_state()
    if asyncio.run(run.openai_agents.apply_decisions(state)):   # calls nobody has decided yet
        time.sleep(2)
        continue
    result = Runner.run_sync(agent, state, hooks=run.openai_agents)
print(result.final_output)
```

In async code, `await run.openai_agents.apply_decisions(state)` and `await Runner.run(agent, state,
hooks=run.openai_agents)`. A process that exits with a call still held leaves the run open for another process to
resume (a `RunState` saved with `state.to_string()`, resumed with `RunState.from_string`).

## Approvals: wire it by hand

```python
from tracekit.integrations.openai_agents import TracekitAgents
from tracekit.sdk.client import Client

client = Client()
tk = TracekitAgents(client, client.register_run({"agent": {"name": "my-agent"}}))
agent = Agent(name="payer", model="gpt-5", tools=[tk.tool(transfer_funds)])
result = await Runner.run(agent, "pay acct-42 $15", context={}, hooks=tk)   # any run context works
while result.interruptions:                       # an ask: once a person decided in the signer
    state = result.to_state()
    await tk.apply_decisions(state)
    result = await Runner.run(agent, state, hooks=tk)
```

Function tools, ShellTool with a local executor, LocalShellTool and ApplyPatchTool are gated. Hosted tools, ComputerTool
and handoffs are recorded only inside the signed model responses.

The no-key example at the top of this page wires it this way, with an approval.

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
- **Your own policy**: the dev signer runs `tracekit/policy2/packs/dev.yaml` (the coding, browser, data, network,
  cloud, comms and core packs, two demo rules, unmapped tools flagged) and can't take another. To run yours, start
  `tracekit signer serve --config signer.yaml` with `policy:` set and point the agent at it with `TRACEKIT_SIGNER`:
  [run your own policy on your machine](../policy-guide.md#run-your-own-policy-on-your-machine).
- **Reference**: [the OpenAI Agents integration](../integrations/openai-agents.md), with every option and what it doesn't cover.
