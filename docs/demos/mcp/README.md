# MCP tools, gated and recorded

An MCP client calls three tools of an in-process MCP server (the mcp package's in-memory transport). Every
`call_tool` goes to the signer first: `list_files` runs, `tracekit_demo_denied` is denied (TK-DEMO-DENY) and the
client gets an error result and goes on, and `tracekit_demo_ask` waits inside `call_tool` until it is approved.

```sh
python examples/v2/mcp/agent.py --scripted   # needs mcp
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** Each tool as `mcp:files/<tool>` with a signed `policy.decision` (flag, deny, ask); an
`approval.request`, `approval` and `approval.consumed` for the held one; a `tool.result` only for the two that ran.
[verify.txt](verify.txt): `Integrity: VERIFIED`, `Assurance: dev; ... approvals: self`, as on any dev signer.

**Why it matters.** MCP servers are third-party code the agent reaches by name. The same policy and the same signed
evidence cover them as the agent's own tools, with no change to the server; the dev policy's two demo rules stand in
for your own rules on any MCP tool.

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/mcp/agent.py) ·
[quickstart](../../quickstarts/mcp.md)
