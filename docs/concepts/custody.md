# Custody

Capture inside the agent's process records what the agent says it did. Custody moves the action itself out of the
agent's process: a service the signer trusts holds the credentials, runs the call, and records what actually crossed
the boundary. These services are tier T2 evidence ([capture and completeness](capture-and-completeness.md)). All four
are experimental ([what's stable](../support.md)).

| Service | Holds | Records | Example port |
|---|---|---|---|
| [Tool executor](#the-tool-executor) | API credentials for your tools | Every call it runs | 8090 |
| [MCP gateway](#the-mcp-gateway) | Credentials for MCP servers | Every MCP tool call, prompt and resource | 8091 |
| [LLM gateway](#the-llm-gateway) | The model provider key | Every model request and response | 8080 |
| [Egress observer](#the-egress-observer) | Nothing | Which hosts each run talked to | 3128 |

Each service is listed in the signer's config and is the only kind of caller allowed to act on a run's behalf. The
agent passes its run id and token in a header, and the signer checks the token against the agent's identity.

## The tool executor

The executor runs tool calls with credentials the agent never sees. You declare each action: its HTTP method, a URL
template, headers that come from secret files, and a JSON Schema for its arguments. The agent asks the executor to run
an action; the executor asks the signer to decide, runs the call if allowed, and records the result.

- A path argument must be one plain segment, and redirects are never followed.
- Secret header values are cut from responses and records, in raw, JSON, URL and HTML encodings.
- For a held call, the executor runs the signer's own copy of the approved arguments
  ([approvals](approvals.md#in-process-and-executor-approvals)).
- The agent can't complete, consume or abandon the executor's calls.
- If the signer can't be reached, the executor refuses: it always fails closed.

Setup: [executor](../executor.md).

## The MCP gateway

The MCP gateway sits in front of MCP servers (stdio or Streamable HTTP) whose credentials stay in the gateway. Tool
calls are decided as `mcp:<server>/<tool>`. Resources, prompts and list pages the agent reads are recorded as observed
content, untrusted unless the server is marked trusted, which feeds [provenance](provenance-and-why.md). It always
fails closed. Docker's MCP Gateway and Wassette can sit behind it as upstreams. Setup: [MCP gateway](../mcp-gateway.md).

## The LLM gateway

The LLM gateway is an OpenAI-compatible endpoint (chat completions, responses and messages, streamed or not) between
the agent and the model provider. It holds the provider key, never forwards the agent's own auth headers, and records
each exchange as `model.exchange`, before and after the model answers.

Because it sees what the model asked the agent to do, it is the strongest source for [reconciliation](capture-and-completeness.md#reconciliation).
With `gateway_mandatory: true` and network rules that stop the agent reaching the provider directly:

- a tool use the model asked for, with no decision requested, is `reconcile.hook_missing`;
- a decision no model call asked for is `reconcile.fabricated`.

**Verified tool results** (experimental). An agent can change what a tool returned before the model reads it. With
`verify_tool_results: record` (or `refuse`) in the signer's config, the gateway sends digests of each tool result in a
model request, the signer compares them with the results it recorded, and an edited result, or one sent before its call
completed, becomes a signed `reconcile.result_mismatch`. `refuse` also answers the agent 403 for an edited result and
doesn't send the request. A result past the newest 512, or past 1 MiB of results, isn't compared and is a
`result_unchecked` gap. Some integrations record a result in a form the model isn't sent, so run `record` on honest
runs before `refuse` ([verified tool results](../gateway.md#verified-tool-results)).

The gateway can also ask the provider for a readable summary of the model's reasoning when the request turned reasoning
on without one, and records which fields it changed (format 1.4's `ext.amended`;
[readable reasoning](../gateway.md#readable-reasoning)). It can refuse requests that declare provider-run tools, and it
stops forwarding a quarantined run's requests. If the signer is down, the run's fail mode for model calls decides.
Setup: [gateway](../gateway.md).

## The egress observer

The egress observer is a forward proxy for the agent's outbound traffic. It never decrypts TLS. It attributes each
connection to a run (by the run's token, or by the caller's identity) and refuses common ways to slip past it:

- a CONNECT whose TLS server name doesn't match the requested host;
- raw IP addresses, in any notation;
- public DNS-over-HTTPS endpoints;
- names that resolve to private addresses.

It also takes SOCKS5 on the same port, which is how [E2B](../integrations/e2b.md) and
[microsandbox](../integrations/microsandbox.md) send a sandbox's outbound traffic to it from the host. Every minute it
reports the hosts each run reached, and the signer records them. A host no recorded call explains
becomes `reconcile.unexplained_effect`. A policy's `explains` entries list hosts a tool's own dependencies reach (a
package index for an install command, for example). If the observer stops reporting for 90 seconds, the signer writes
`observer_lost`. On Linux system mode, `tracekit init --v2 --user AGENT --egress`, run as root, adds a firewall rule so the
agent's user can only reach the network through the observer. Setup: [egress](../egress.md).

## Choosing what to deploy

| You want | Deploy |
|---|---|
| Calls to your APIs to run exactly as approved, with keys the agent never sees | Tool executor |
| The same for MCP servers | MCP gateway |
| To catch an agent that skips its hook or invents calls | LLM gateway with `gateway_mandatory: true` |
| To see where an agent's traffic goes | Egress observer |
| To catch an agent that edits a tool's result before the model reads it | LLM gateway with `verify_tool_results` |
| Model calls, tool calls and network all marked `enforced` in the coverage matrix | LLM gateway and egress observer together, with the matching posture |
| To see the processes, connections and file writes beneath each call | A kernel sensor import ([capture](capture-and-completeness.md#kernel-sensors-and-sandboxes)) |

Third-party gateways and sandbox proxies can ask the signer the same way, so the calls they pass are decided and
recorded outside the agent: agentgateway, LiteLLM, NVIDIA OpenShell and sandbox-runtime's proxy
([integrations](integrations.md#sandboxes-gateways-and-sensors)).

## Reference

[Executor](../executor.md) · [MCP gateway](../mcp-gateway.md) · [gateway](../gateway.md) · [egress](../egress.md) ·
code: [`tracekit/executor.py`](../../tracekit/executor.py), [`tracekit/mcp_gateway.py`](../../tracekit/mcp_gateway.py),
[`tracekit/gateway.py`](../../tracekit/gateway.py), [`tracekit/egress.py`](../../tracekit/egress.py)

---

Previous: [Capture and completeness](capture-and-completeness.md) · [All concepts](README.md) · Next:
[Provenance and `tracekit why`](provenance-and-why.md)
