# OpenAI Agents SDK (signer RPC)

`tracekit.integrations.openai_agents.TracekitAgents` gates the tools of an OpenAI Agents SDK (Python) agent. Before
each tool call it asks the Tracekit signer for a policy decision; after the tool runs it records the outcome. It works
with any object that implements the signer RPC (`tracekit.signer.rpc_schema.SignerAPI`), including
`tracekit.testing.FakeSigner`.

## Install

```bash
pip install tracekit-ai "openai-agents>=0.23.1,<0.24"
```

Python 3.10 or newer (the SDK's own requirement).

## Setup

```python
from agents import Agent, Runner, function_tool
from tracekit.integrations.openai_agents import TracekitAgents

@function_tool
def transfer_funds(to: str, amount_cents: int) -> str:
    """Move money."""
    ...

run = signer.register_run({"request_id": "run-start-1", "agent": {"name": "billing-agent"}})
tk = TracekitAgents(signer, run)
agent = Agent(name="billing-agent", model="gpt-5", tools=[tk.tool(transfer_funds)])
result = await Runner.run(agent, "pay acct-42 $15", context={}, hooks=tk)
```

- Wrap every tool with `tk.tool(...)`: a plain function, a `FunctionTool`, a `ShellTool` with a local executor, a
  `LocalShellTool` or an `ApplyPatchTool`. The signer's policy decides approvals, so a tool's own `needs_approval` is
  replaced.
- The run context must be a dict (`context={}`, or your own dict): the approval hint is kept in it.
- `hooks=tk` records each model response (below).

A resumed run (another process, after a restart) builds `TracekitAgents` with the same `run_id` and `run_token`.

## What is recorded

| When | RPC | Sent |
|---|---|---|
| before the tool runs | `decide` | `tool_call_id`, tool name, the arguments as the SDK decoded them (`parsed`); after a resume in another process, the model's raw string |
| right before it runs | `approval_consume` | the same call, the arguments (for function tools the model's raw string), and the approval id the run state carries as a hint |
| after the tool runs | `complete` | `status` `ok` or `error`, a `sha256:` commitment to the result (not the result), or the exception type and message |
| after each model response | `model_event` | a `sha256:` commitment to the whole response output, every tool call in it (`tool_uses`; hosted ones as `executed_by: provider`), and token usage |

The signer classifies the tool and computes the args digest itself; nothing the adapter sends is trusted for that.

## Decisions

- **allow**: the tool runs.
- **deny**: the tool does not run. The model gets `Tool call blocked by policy: <rule ids>` as the tool output and the
  run goes on.
- **ask**: the run stops with an interruption (`result.interruptions`), and the adapter opens an approval in the signer.
  Save the run state, let a person decide in the signer, then resume:

  ```python
  saved = result.to_state().to_string()          # keep it in your database
  # ... a person approves or rejects in the signer (CLI, web) ...
  state = await RunState.from_string(agent, saved)
  waiting = await tk.apply_decisions(state)      # approves or rejects each paused call as the signer says
  if not waiting:
      result = await Runner.run(agent, state, hooks=tk)
  ```

  `apply_decisions` is the one place approvals are applied: it reads them from the signer, not from the saved state.
  A rejected call reaches the model as `Tool call rejected in Tracekit`.

The saved run state is not authenticated (the SDK says so), so it carries the approval id only as a hint, in
`context["tracekit"]["approvals"]`. The SDK does not call `needs_approval` again on resume; the adapter's tool input
guardrail asks the signer on every execution, with the model's raw arguments string. The call runs only if the
signer's approval for this exact call and these exact arguments was granted and not used before. Editing the saved
state (the arguments, the call id, the hint, or approving the call in the state directly) gets the call refused, and
the signer records why. Exceptions raised by a tool are recorded, then handled by the tool's own failure policy as
without Tracekit.

## Not covered

- **Hosted tools** (web search, file search, code interpreter, image generation, hosted MCP, a hosted `ShellTool`),
  **`ComputerTool`** and **handoffs** run outside the hooks Tracekit can gate. `tk.tool(...)` refuses hosted tools
  with a `TypeError`. They appear only as `tool_uses` in the signed model exchange recorded for each model response (T3: what the
  agent process reported, not checked by Tracekit).
- **`LocalShellTool` and `ApplyPatchTool` cannot wait for an approval**: the SDK has no approval hook for the first and
  does not tell the editor the call id of the second, so an `ask` for them is refused. Allow and deny work as above.
- The SDK runs each tool call id once, so every call is attempt 0.
