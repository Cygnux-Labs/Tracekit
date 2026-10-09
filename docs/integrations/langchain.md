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
from tracekit.integrations.langchain import TracekitMiddleware

run = signer.register_run({"request_id": "run-start-1", "agent": {"name": "billing-agent"}})
agent = create_agent(model, tools, checkpointer=InMemorySaver(),
                     middleware=[TracekitMiddleware(signer, run["run_id"], run["run_token"])])
```

A resumed run (another process, after a restart) builds the middleware with the same `run_id` and `run_token`.

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
