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
the call is denied. The pause gets through the node's `handle_tool_errors`, whatever it is set to, and through
`.with_fallbacks()`. For approvals and the checkpointer commitments, wire the adapter by hand (below).

## 3. See it verified

```sh
tracekit last
```

It exports the most recent finished run, pins the dev signer's key, verifies the bundle and says where it is
([the v2 quickstart](../quickstart-v2.md#3-see-it-verified)).

## Approvals: wire it by hand

```python
from tracekit.autotrace import init as record_model_calls
from tracekit.integrations.langchain import TracekitCheckpointer, TracekitMiddleware, tracekit_tool_node
from tracekit.sdk.client import Client

client = Client()
handle = client.run("my-agent")   # registers the run
run = handle.registered
record_model_calls(run=handle)    # model calls through the OpenAI, Anthropic and Google Gen AI SDKs, into this run
# a graph of your own: its ToolNode, gated
graph.add_node("tools", tracekit_tool_node(tools, client, run))
app = graph.compile(checkpointer=TracekitCheckpointer(InMemorySaver(), client, run))
# or create_agent: the middleware, last in the list
agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                     middleware=[TracekitMiddleware(client, run["run_id"], run["run_token"], run.get("fail_modes"))])
```

The gate and the checkpointer record tool calls and checkpoints only; without the `record_model_calls(run=handle)` line the
run holds no model calls, and verify reports `(L3 absent)`. `handle.close()` ends the run.

An ask needs a checkpointer: the graph pauses with `interrupt()` and resumes with `Command(resume={"approval_id":
...})`. Without one the call is denied. The pause gets through the node's `handle_tool_errors` (any setting; a
handler whose annotation names no exception type fails when the gated node is built, not at the tool's
first error) and through `.with_fallbacks()`, as LangGraph's customer-support tutorial wraps its ToolNodes
(`tracekit_tool_node(tools, client, run).with_fallbacks([...], exception_key="error")`). Code of your own that catches
exceptions around the node ends the pause: the call doesn't run and its approval expires
([limits](../limits.md#approvals)).

An offline run of all this (a mock model, no API key), with an approval: `python examples/v2/langchain/agent.py
--scripted` from a checkout.

## Routing between assistants (handoffs)

A graph whose assistants hand over with tool schemas that no ToolNode runs, as LangGraph's customer-support tutorial
does (`ToFlightBookingAssistant`, `ToBookCarRental`, `CompleteOrEscalate`: a conditional edge sends each to a node that
answers it), never has those calls decided, so each one the model asks for is a `reconcile.hook_missing` in the report.
Name them in your policy's `handoffs:` ([policy](../policy-v2.md#file-format)), by their exact names:

```yaml
handoffs: [ToFlightBookingAssistant, ToBookCarRental, ToHotelBookingAssistant, ToBookExcursion, CompleteOrEscalate]
```

A tool a node calls from its own code, outside any ToolNode (the tutorial's `user_info` node fetching the passenger's
flights), is neither gated nor recorded: put it in a ToolNode to have it decided.

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

## Find why it did something

A recorded thread can be replayed from its own checkpoints to test which input caused an action: `tracekit why
attribute --langgraph myapp:graph_factory --thread T --target tool=send_email`, where `graph_factory()` returns your
compiled graph over its checkpointer. Each trial forks the checkpoint where a suspect entered, with and without it,
on a scratch copy of the graph, and serves every ToolNode call from the thread, so those tools don't run for real; a
tool called outside a ToolNode would, and stops the replay ([limits](../limits.md#investigation-tracekit-why)). `python examples/v2/langchain/injection.py`
runs it on a page with a planted instruction. How it works: [fork replay](../why.md#how-causality-is-tested).

## Next steps

- **System mode** runs the signer as its own OS user, so the agent can't reach its keys, store or policy, and approvals
  come from another account: [system mode](../quickstart-v2.md#system-mode-linux-macos-experimental).
- **Witnesses** cosign the signer's checkpoints from another host, so a rolled-back or forked log shows:
  [witnesses](../witnesses.md). Pin them in the trust config and the report reads `Assurance: witnessed`.
- **Your own policy**: the dev signer uses the coding pack plus two demo rules (`tracekit/policy2/packs/dev.yaml`); a
  configured signer takes `policy:` in `signer.yaml`.
- **Reference**: [the LangChain integration](../integrations/langchain.md), with every option and what it doesn't cover.
