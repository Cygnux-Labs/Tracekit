# MCP client (signer RPC)

`tracekit.integrations.mcp.TracekitSession` gates the tool calls an agent makes through an MCP `ClientSession` (the
Python `mcp` package). Before each `call_tool` it asks the Tracekit signer for a policy decision; after the server
answers it records the outcome. It works with any object that implements the signer RPC
(`tracekit.signer.rpc_schema.SignerAPI`), including `tracekit.testing.FakeSigner`.

## Install

```bash
pip install tracekit-ai "mcp>=2.3,<2.4"
```

Python 3.10 or newer (the `mcp` package's own requirement).

## Setup

```python
from mcp import ClientSession
from tracekit.integrations.mcp import TracekitSession

run = signer.register_run({"request_id": "run-start-1", "agent": {"name": "triage-agent"}})
async with ClientSession(read, write) as session:
    await session.initialize()
    session = TracekitSession(session, signer, run)
    result = await session.call_tool("create_issue", {"title": "..."})
```

Every other attribute is the wrapped session's. Only calls made through the wrapped session are seen.

## What is recorded

| When | RPC | Sent |
|---|---|---|
| before the call is sent | `decide` | a fresh `tool_call_id`, the tool as `mcp:<server>/<tool>`, `tool_class_hint: mcp`, the arguments as given (`parsed`) |
| right before it is sent | `approval_consume` | the same call and arguments, and the approval id when the call waited for one |
| after the server answers | `complete` | `status` `ok`, or `error` for a result with `isError: true`; a `sha256:` commitment to the result (not the result), or the exception type and message |

`<server>` is the name in the server's initialize result, with every character outside `A-Za-z0-9_.-` replaced by `_`
(`unknown` when the server gave none). The policy's `tools` map should map `mcp:*/*` to the `mcp` class (the coding
pack does), so rules can match the `server`, `tool` and `args` fields. A class hint that disagrees with the policy is
recorded as a `capture.gap` and the stricter decision applies.

## Decisions

- **allow**: the call is sent to the server.
- **deny**: the call is not sent. `call_tool` returns a `CallToolResult` with `isError: true` and the text
  `Tool call blocked by policy: <rule ids>`, and the run goes on.
- **ask**: the adapter opens an approval in the signer and holds the call while it waits, up to `approval_wait_s`
  seconds (default 300), for a person to decide (CLI, web). Approved, the call is sent; rejected, expired or still
  undecided at the deadline, it is refused as for a deny. `TracekitSession(session, signer, run, approval_wait_s=0)`
  is for a caller that cannot wait: an `ask` is then refused without opening an approval.

Every call that is not denied is sent only after the signer's `approval_consume` agrees for this exact call and these
exact arguments. A result with `isError: true` is returned unchanged; an exception from the session (a protocol error,
a lost connection) propagates unchanged. Both are recorded as `error`.

## Not covered

- MCP calls carry no call id, so every `call_tool` is a call of its own (attempt 0); a retry is a new decision.
- There is no saved state: a call waiting for an approval does not survive the process.
- Servers the agent reaches without this session (another client, a hosted MCP tool of a model provider) are not seen.
