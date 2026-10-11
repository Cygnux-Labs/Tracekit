# Quickstart: LangChain and LangGraph

Every tool call is decided by the v2 signer before it runs and recorded after, as a signed event. This page adds it
to the agent you have in three steps. It uses the dev signer, which runs as your own user (see [what dev assurance
means](../quickstart-v2.md#what-dev-assurance-means)).

## 1. Install

```sh
pip install tracekit-ai 'langchain>=1.4,<1.5' 'langgraph>=1.2,<1.3'
```

## 2. One line in your agent

```python
import tracekit; tracekit.instrument()     # first
from langchain.agents import create_agent
from langchain_core.tools import tool

@tool
def bash(command: str) -> str:
    """Run a shell command."""
    return f"ran {command}"

agent = create_agent("openai:gpt-5", [bash])
print(agent.invoke({"messages": [("user", "tidy up")]})["messages"][-1].content)
```

Every `ToolNode` built after `instrument()` gates its calls, the one `create_agent` builds included, after any
middleware's own `wrap_tool_call`. An `ask` pauses the graph with `interrupt()`, which needs a checkpointer; without one
the call is denied. For approvals and the checkpointer commitments, wire the adapter by hand (below).

## 3. See it verified

```sh
tracekit last
```

It exports the most recent finished run, pins the dev signer's key, verifies the bundle and says where it is
([the v2 quickstart](../quickstart-v2.md#3-see-it-verified)).

## Approvals: wire it by hand

```python
from tracekit.integrations.langchain import TracekitCheckpointer, TracekitMiddleware, tracekit_tool_node
from tracekit.sdk.client import Client

client = Client()
run = client.register_run({"agent": {"name": "my-agent"}})
# a graph of your own: its ToolNode, gated
graph.add_node("tools", tracekit_tool_node(tools, client, run))
app = graph.compile(checkpointer=TracekitCheckpointer(InMemorySaver(), client, run))
# or create_agent: the middleware, last in the list
agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                     middleware=[TracekitMiddleware(client, run["run_id"], run["run_token"], run.get("fail_modes"))])
```

An ask needs a checkpointer: the graph pauses with `interrupt()` and resumes with `Command(resume={"approval_id":
...})`. Without one the call is denied.

An offline run of all this (a mock model, no API key), with an approval: `python examples/v2/langchain/agent.py
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
