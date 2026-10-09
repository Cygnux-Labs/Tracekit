# LangChain v1 (signer RPC)

`tracekit.integrations.langchain.TracekitMiddleware` is a LangChain v1 `AgentMiddleware`. Before each tool call it
asks the Tracekit signer for a policy decision; after the tool runs it records the outcome. It works with any object
that implements the signer RPC (`tracekit.signer.rpc_schema.SignerAPI`), including `tracekit.testing.FakeSigner`.

The older callback adapter in `tracekit.adapters.langchain` ([adapters.md](../adapters.md)) is unchanged.

## Install

```bash
pip install tracekit-ai "langchain>=1.4"
pip install langgraph-checkpoint-sqlite   # optional: a durable checkpointer for approvals
```

Python 3.10 or newer (LangChain v1's own requirement).

## Setup

```python
from tracekit.integrations.langchain import TracekitCheckpointer, TracekitMiddleware

run = signer.register_run({"request_id": "run-start-1", "agent": {"name": "billing-agent"}})
agent = create_agent(model, tools, checkpointer=TracekitCheckpointer(InMemorySaver(), signer, run),
                     middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"])])
```

A resumed run (another process, after a restart) builds the middleware with the same `run_id` and `run_token`.
`TracekitCheckpointer` is optional; see [Checkpoint commitments](#checkpoint-commitments-l1).

### Graphs built on `ToolNode`

A graph that runs its tools with `ToolNode` directly, without `create_agent`, uses `tracekit_tool_node`. It applies
the same gate as the middleware (decisions, approvals, results), so everything below holds for it too:

```python
from tracekit.integrations.langchain import TracekitCheckpointer, tracekit_tool_node

graph = StateGraph(MessagesState)
graph.add_node("model", call_model)
graph.add_node("tools", tracekit_tool_node(tools, signer, run))   # other keyword arguments go to ToolNode
graph.add_edge(START, "model")
graph.add_conditional_edges("model", tools_condition)
graph.add_edge("tools", "model")
app = graph.compile(checkpointer=TracekitCheckpointer(InMemorySaver(), signer, run))
```

## What is recorded

| When | RPC | Sent |
|---|---|---|
| before the tool runs | `decide` | `tool_call_id`, `attempt` (0), tool name, the args as LangChain decoded them (`args_source: parsed`) |
| after the tool runs | `complete` | `status` `ok` or `error`, a `sha256:` commitment to the ToolMessage content (not the content), or the exception type and message |

The signer classifies the tool and computes the args digest itself; nothing the middleware sends is trusted for that.

## Decisions

- **allow**: the tool runs.
- **deny**: the tool does not run. The model gets an error ToolMessage, `Tool call blocked by policy: <reason or rule
  ids>`, and the agent run goes on.
- **ask**: the middleware opens an approval and pauses the run with LangGraph `interrupt()`. The interrupt payload is
  `{"tracekit": {"approval_id", "tool_call_id", "tool", "rule_ids"}}`. A person approves or rejects in the signer;
  then the app resumes the thread:

  ```python
  agent.invoke(Command(resume={"approval_id": approval_id}), config)
  ```

  On resume LangGraph re-runs the tool node, so the middleware asks the signer again, this time naming the approval.
  The signer, not the saved state, decides: the call runs only if that approval was granted for this exact call and
  these exact args, and was not used before. Otherwise the call is denied as above. The `approval_id` in the resume
  value is only a hint; leaving it out does not skip the check.

Exceptions raised by the tool are recorded and re-raised unchanged.

## Approvals need a checkpointer

`interrupt()` can only hold a run that LangGraph can save. Without a checkpointer, an `ask` is answered with a deny
(`approval required, and the agent has no checkpointer to wait for it`) and no approval is opened. Use `InMemorySaver`
for a single process, or a durable saver such as `SqliteSaver` / `PostgresSaver` when the resume may happen in
another process.

## Checkpoint commitments (L1)

`TracekitCheckpointer(saver, signer, run)` wraps any LangGraph `BaseCheckpointSaver`, sync or async. Each time the
saver writes a checkpoint or its pending writes, the wrapper reads back what the saver now holds and sends the signer a
`state_write` with its digest, under the key `langgraph:<thread_id>` (`langgraph:<thread_id>/<checkpoint_ns>` in a
subgraph). Each write names the digest the signer last recorded for that key (`prev_digest`).

When a run loads a checkpoint to resume and it differs from the one last committed, the next write starts from the
changed digest, and the signer records a signed `capture.gap` of kind `state_tamper`. This catches a stored checkpoint
edited between a pause and its resume, even in another process. A tool call edited that way is also refused when it
runs: its args no longer match the approval (`TK-APPROVAL-MISMATCH`).

The digest (`checkpoint_digest`) is a `sha256:` over canonical JSON of the hashes of the checkpoint's serialised parts
(LangGraph's msgpack serialiser):

- the checkpoint's own fields (`id`, `ts`, `channel_versions`, `versions_seen`, ...);
- every channel value, `messages` and `__pregel_tasks` among them. `__pregel_tasks` holds the pending tool calls a
  resumed `create_agent` run actually executes, so covering only `messages` would miss an edit to them;
- every pending write: results of tasks that finished, interrupts, resume values.

Not covered: the checkpoint's `metadata` and `parent_config`. Each part is hashed on its own, so a saver that returns
channels or writes in another order gives the same digest.

Resuming from an older checkpoint in a new process (time travel, replaying a snapshot) also differs from the last one
committed and is recorded as `state_tamper`.

A commitment that fails (signer unreachable) is a warning, never an exception: the saver has already written, and
raising would fail the run after it. The next commitment starts from the last digest the signer recorded, so a lost one
is not read as tampering; the signer records it as a `client_counter_gap`.
