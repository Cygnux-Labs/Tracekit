# Integrations

Causeway and onchain transaction guards are separate packages: [contrib/causeway](../contrib/causeway/README.md),
[contrib/onchain](../contrib/onchain/README.md).

## MCP clients

`tracekit.adapters.mcp.traced_session(session, tracer, server="github")` wraps an MCP `ClientSession`: each
`call_tool` passes the policy gate as `mcp__<server>__<tool>` before it is sent, and its result is recorded. MCP tool
errors stay results for the caller (as the protocol intends) and are recorded as failed calls.

## Vercel AI SDK

With `experimental_telemetry` enabled, the AI SDK's spans go to `tracekit otel serve --experimental` unchanged: provider calls
(`ai.*.doGenerate`, `ai.*.doStream`) become model exchanges with the tool calls they requested and token usage, and
`ai.toolCall` spans become tool calls with their arguments and results.
