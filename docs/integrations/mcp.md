# MCP client (signer RPC)

> **Stable:** tested with [`tests/adapter_contract.py`](../../tests/adapter_contract.py) against the pinned library on every push to main
> and every pull request ([what's stable](../support.md)).

`tracekit.integrations.mcp.TracekitSession` gates the tool calls and prompt fetches an agent makes through an MCP
`ClientSession` (the Python `mcp` package). Before each `call_tool` or `get_prompt` it asks the Tracekit signer for a
policy decision; after the server answers it records the outcome. It works with any object that implements the signer
RPC (`tracekit.signer.rpc_schema.SignerAPI`), including `tracekit.testing.FakeSigner`.

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
| before the call is sent | `decide` | a fresh `tool_call_id`, the tool as `mcp:<server>/<tool>` (`mcp:<server>/prompt:<name>` for `get_prompt`), `tool_class_hint: mcp`, the arguments as given (`parsed`) |
| right before it is sent | `approval_consume` | the same call and arguments, and the approval id when the call waited for one |
| after the server answers | `complete` | `status` `ok`, or `error` for a result with `isError: true`; a `sha256:` commitment to the result (not the result), or the exception type and message |
| after `read_resource` answers | `observe` | `source` `mcp:<server>/resource`, `trust: untrusted` and the result as `value` (recorded as its commitment and indexed for provenance; a result over half the signer's 1 MiB frame as its `sha256:` digest; withheld if the signer cannot record it, unless the run fails open for `mcp` and the signer is unreachable, when it warns and returns the result; a refusal is withheld either way) |

`list_tools`, `list_resources` and `list_prompts` are recorded as untrusted observed input (`observe`, source `mcp:<server>/tools`, `/resources` or `/prompts`): the model reads the descriptions the server wrote, and the page the caller asked for is what is recorded (a page over half the signer's 1 MiB frame as its `sha256:` digest, as the [MCP gateway](../mcp-gateway.md) records one). The list mcp's `call_tool` makes itself, to check a result against the tool's output schema, never reaches the model and isn't recorded. A page the signer cannot record is withheld, unless the run fails open for `mcp`, when an unreachable signer returns it with a warning; a refusal is withheld either way. A tool call or prompt that returns an `InputRequiredResult` (MCP 2.3) records each round's input requests as untrusted observed input (`observe`, source `mcp:<server>/input_required`). When the server provides a `request_state` and the decision is `allow`, it is decided and completed once, under its initial decision, when the terminal result arrives. A round continues the call its own asyncio task left waiting, as `mcp.Client.call_tool` drives the rounds, so concurrent calls never share a decision even when the server returns the same `request_state` to both; a waiting call whose task calls a tool or gets a prompt on the session first is never completed ([not covered](#not-covered)). Rounds from a server that returns no `request_state`, or under a decision that isn't `allow` (a flag, or an ask, whose approval the signer consumes only once), are decided and completed as separate calls per round.

`<server>` is the name in the server's initialize result, with every character outside `A-Za-z0-9_.-` replaced by `_`
(`unknown` when the server gave none). The policy's `tools` map should map `mcp:*/*` to the `mcp` class (the coding
pack does), so rules can match the `server`, `tool` and `args` fields. A class hint that disagrees with the policy is
recorded as a `capture.gap` and the stricter decision applies.

## Decisions

- **allow**: the call is sent to the server.
- **deny**: the call is not sent. `call_tool` returns a `CallToolResult` with `isError: true` and the text
  `Tool call blocked by policy: <rule ids>`, and the run goes on; `get_prompt` raises `RuntimeError` with that text.
- **ask**: the adapter opens an approval in the signer and holds the call while it waits, up to `approval_wait_s`
  seconds (default 300), for a person to decide (CLI, web). Approved, the call is sent; rejected, expired or still
  undecided at the deadline, it is refused as for a deny, and an undecided approval is withdrawn
  (`approval.abandoned`), as it is when the caller cancels the waiting `call_tool`.
  `TracekitSession(session, signer, run, approval_wait_s=0)` is for a caller that cannot wait: an `ask` is then refused
  without opening an approval.

Every call that is not denied is sent only after the signer's `approval_consume` agrees for this exact call and these
exact arguments. A result with `isError: true` is returned unchanged; an exception from the session (a protocol error,
a lost connection) propagates unchanged. Both are recorded as `error`.

## Not covered

- MCP calls carry no call id, so every `call_tool` is a call of its own (attempt 0); multi-round input-required calls reuse their decision across rounds, while an independent retry is a new decision. A call whose later rounds never reach the session (the elicitation callback fails, mcp's `input_required_max_rounds` runs out, both inside `mcp.Client`, or the task driving it ends or makes another call on the session first) stays decided and is never completed; at run close the signer records it as a signed `decided_not_completed` gap. Rounds you drive yourself from different tasks are decided as calls of their own, so each round of an allowed call before its last is such a gap ([limits](../limits.md#approvals)).
- The input responses a round sends the server (elicitation answers, a sampling callback's output, the client's roots, or `input_responses` you pass) are neither decided nor recorded: a round is decided on its tool and arguments alone, an allowed call's later rounds under its first decision, and only the server's input requests are recorded. Check what leaves in your own callbacks, or give a client of a server you don't trust none of them ([limits](../limits.md#approvals)).
- There is no saved state: a call waiting for an approval does not survive the process.
- Servers the agent reaches without this session (another client, a hosted MCP tool of a model provider) are not seen.
- The server's name in `mcp:<server>/<tool>` is the one the server gives. An mcp 1.x session doesn't keep it:
  `instrument()` takes it from the session's `initialize()` when that runs after `instrument()`; by hand, pass
  `TracekitSession(session, client, run, server="github")`. Without a name the calls are recorded as `mcp:unknown/<tool>`,
  with a warning, and rules written for the server's name don't match them.
- The LLM gateway's verified tool results don't check MCP calls: this integration decides each under an id of its own, not the model's tool call id ([gateway](../gateway.md#verified-tool-results)).
