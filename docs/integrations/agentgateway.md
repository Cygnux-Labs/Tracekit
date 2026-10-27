# agentgateway

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> It is tested against the protocol and the span attributes in agentgateway's source, not against a running agentgateway.

[agentgateway](https://agentgateway.dev) (a Linux Foundation project) is a proxy for MCP, A2A and LLM traffic. Tracekit
works with it in two ways, which you can use together:

Both cover MCP. For A2A, Tracekit's own [A2A gateway](../a2a.md) decides and records each message; agentgateway's A2A traffic is not decided or recorded by Tracekit.

| | The `ext_mcp` processor | The OTLP import |
|---|---|---|
| What it does | Decides each MCP `tools/call` in the signer before agentgateway forwards it, holds an `ask` for a person, and records the result | Records each MCP `tools/call` agentgateway traced, after it ran |
| Gates calls | Yes, and fails closed | No |
| Arguments and results | Committed to by the signer | Not in agentgateway's spans |
| Evidence | `source: gateway`, tier T2, when the agent reaches its MCP servers only through agentgateway | `source: import`, tier T3: the spans were received |

## The ext_mcp processor

agentgateway's `mcpGuardrails` policy can call a remote processor over gRPC (`agentgateway.dev.ext_mcp.ExtMcp`) before
it forwards an MCP request and again with the result. `tracekit ext-mcp serve` is that processor. It needs `grpcio`
and a v2 signer, and listens on loopback only, so run it next to agentgateway, in its pod or on its host:

```bash
pip install 'tracekit-ai[grpc]'
TRACEKIT_SIGNER=https://signer.internal:8443 TRACEKIT_SIGNER_CERT=tls/ext-mcp.pem TRACEKIT_SIGNER_KEY=tls/ext-mcp.key \
  tracekit ext-mcp serve --listen 127.0.0.1:9091
```

It reaches the signer as itself (`TRACEKIT_SIGNER_TOKEN_FILE` or `TRACEKIT_SIGNER_CERT`/`_KEY`). In `signer.yaml`, list
it under `gateways` and grant it the calls it makes for the agents:

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-ext-mcp"]
authorize: {"mtls:spiffe://acme.org/tracekit-ext-mcp": [decide, complete, approval_request, approval_wait, approval_consume]}
```

In agentgateway's config, add the processor to the MCP route's policies:

```yaml
binds:
- port: 3000
  listeners:
  - routes:
    - policies:
        mcpGuardrails:
          processors:
          - kind: remote
            host: 127.0.0.1:9091
            methods: {"tools/call": full}       # request and response
            failureMode: failClosed             # agentgateway's default: the processor unreachable denies the call
            metadata:
              caller: '"mtls:" + source.spiffeId'          # who agentgateway authenticated, as the signer names them
              tracekit_call: 'mcpGuardrails.tracekit_call'  # carries the call's id to the response
      backends:
      - mcp:
          targets:
          - name: everything
            stdio: {cmd: npx, args: ["-y", "@modelcontextprotocol/server-everything"]}
```

- `caller` must be the identity the agent's run token was issued to (`scheme:subject`). Build it from what
  agentgateway authenticated: `source.spiffeId` with client certificates, `jwt.sub` with JWT authentication. Never
  build it from a header the agent sets.
- The agent registers its run with the signer and sends `X-Tracekit-Run: <run_id>.<run_token>` on every MCP request
  to agentgateway, as it would to Tracekit's [MCP gateway](../mcp-gateway.md#connecting). agentgateway forwards the
  request's headers to the processor (unless `requestHeaders` filters them out), and to HTTP MCP servers too, except
  on a `tools/call` the processor passes: its answer has agentgateway remove `X-Tracekit-Run` first. Other methods
  (`tools/list`, resources) don't reach the processor and still carry it. A run token is bound to the agent's
  identity, so it is no use to a server without the agent's credentials.

### What happens to a tools/call

- **Decided** as `mcp:<target>/<tool>`, with its arguments, for `caller` under the agent's run token. That is the name
  the MCP gateway and the MCP adapter use, so one policy covers all three. The target and tool names are agentgateway's
  native ones (`everything`, `echo`), not its multiplexed `everything_echo`.
- **Allowed:** the processor passes the call and agentgateway forwards it. agentgateway then sends the processor the
  result, which completes the call (an `isError` result as an error).
- **Refused:** a deny, a rejected or expired approval, the signer unreachable, no run or caller, or params that don't
  parse. The processor answers `PERMISSION_DENIED` with the reason, which agentgateway returns to the agent as a tool
  error. The MCP server never sees the call.
- **Ask:** agentgateway gives a processor 10 seconds, so the processor can't hold a call for a person. It asks for
  approval and refuses the call at once with `approval requested; make the same call again once a person approves
  it`: a worker waiting on a person would hold up the other agents' calls. Approve it (`tracekit approvals approve apr-…`); the same call again, with the same run, caller, tool
  and arguments, then passes and uses up the approval. A call with other arguments asks again.
- **Other methods** pass undecided. List only `tools/call` in `methods`.

agentgateway's response hook carries neither the request nor a call id. So when the processor passes a call, it
returns the call's id as processor metadata `tracekit_call`, which agentgateway keeps with the request
(`mcpGuardrails.tracekit_call` in CEL); the `tracekit_call` metadata entry above sends it back with the result. The
processor could instead write the id into the request's `_meta`, but that reaches the MCP server, not the response
hook.

### What Tracekit records and can't see

- **Records:** a `policy.decision` for each tools/call, committing to its arguments, naming the processor (`via`) and
  the agent (`caller`); approval records; a `tool.result` committing to the redacted result. All `source: gateway`,
  tier T2, as for the [MCP gateway](../mcp-gateway.md#what-is-recorded).
- **T2 holds only if** the agent reaches its MCP servers only through agentgateway and can't connect to the processor.
  The processor takes whoever calls it for agentgateway, with its `caller` and its results.
- **Doesn't see errors:** agentgateway sends a JSON-RPC error (an upstream failure, a timeout) to the agent without
  calling the response hook. Such a call has a decision and no result; when its run ends the signer waits
  `gateway_wait_s` and then writes a `held_call_unresolved` gap: the call may have run. So does a result over 64 MiB,
  which the processor refuses (`RESOURCE_EXHAUSTED`) and agentgateway's `failClosed` turns into an error.
- **Doesn't check** how agentgateway authenticated the agent. The signer checks that the run token was issued to
  `caller`.
- **Decides only tools/call:** `resources/read` and `prompts/get` go through agentgateway unrecorded.
- **Forgets on restart:** the processor keeps pending asks and the calls awaiting their results in memory, up to
  10,000 each. After a restart a retried call asks again, and the result of a call passed before it isn't recorded
  (the run ends with a `held_call_unresolved` gap for it).

## The OTLP import

agentgateway exports one span per request. Point its tracing at the signer's
[OTLP import](../otel.md#receiving-traces-tier-t3-import) (an `otlp` section in `signer.yaml`, and the `otlp_import`
grant for agentgateway's identity):

```yaml
frontendPolicies:
  tracing:
    host: signer.internal:8443
    protocol: http
    path: /v1/traces
    randomSampling: true
    parentNotSampled: "true"   # trace a request even when its traceparent says not to
    policies:
      backendTLS: {root: tls/tracekit-ca.pem, cert: tls/agentgateway.pem, key: tls/agentgateway.key}
```

- **Recorded:** each request span whose `mcp.method.name` is `tools/call` becomes a `tool.call` and a `tool.result`,
  named `mcp:<mcp.target>/<gen_ai.tool.name>` like the processor's records. It failed when the span's status is an
  error or it carries `mcp.error.code`. The outbound and guardrail spans under it (`agentgateway.outbound.*`) and
  other methods are skipped, so each call is recorded once.
- **One run per trace.** Unless the agent sends `traceparent`, each request is its own trace, so its own run,
  closed as its span arrives. With `traceparent` the request span has a parent agentgateway doesn't export, so the
  run stays open until `idle_s` and counts against agentgateway's `open_runs` (100 by default) meanwhile.
- **No arguments or results:** agentgateway's spans carry the tool's name and outcome. Its tracing `attributes` can add
  CEL values (`mcp.tool.arguments`, `mcp.tool.result`) as `gen_ai.tool.call.arguments` and `gen_ai.tool.call.result`,
  which the import reads.
- **T3:** the import proves the spans were received, nothing about completeness, and gates nothing. Only sampled
  requests are exported.

[Limits](../limits.md#custody-12) lists these with what to do.
