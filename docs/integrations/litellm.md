# LiteLLM

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> It is tested against LiteLLM's guardrail interface as its source defines it, not against a running LiteLLM proxy.

[LiteLLM](https://github.com/BerriAI/litellm)'s proxy is an LLM gateway that can also serve MCP: agents call MCP tools
through it, and it runs them against the MCP servers you configure, with credentials the agents never see.
`tracekit.integrations.litellm.TracekitGuardrail` is a LiteLLM guardrail that brings those calls under Tracekit:

| | LiteLLM | Tracekit |
|---|---|---|
| What it does | Authenticates the agent's key, runs each MCP tool call against the upstream server | Decides each call before LiteLLM runs it, holds risky ones for a person, and signs the decision and the result |
| Where | The LiteLLM proxy, as a `pre_mcp_call` guardrail | A signer outside the agent and the proxy |
| What a third party can check later | LiteLLM's own logs | A signed, hash-chained bundle, verified offline |

LiteLLM runs the call, so the guardrail acts as a gateway in Tracekit's terms, like the [MCP gateway](../mcp-gateway.md):
its records are `source: gateway`, tier T2, and an agent that reaches its MCP servers only through LiteLLM can't run a
tool without the signer seeing it.

It covers MCP tool calls only. Tool calls the model returns through LiteLLM's chat, responses or messages endpoints are
run by the agent, not by LiteLLM: decide those where they run (a framework integration), and record the model
exchanges with the [LLM gateway](../gateway.md).

## Setup

**1. The signer.** List the LiteLLM proxy's identity under `gateways`, and grant it, and each agent identity it acts
for, the calls it makes (`signer.yaml`):

```yaml
gateways: ["mtls:spiffe://acme.org/litellm"]
authorize:
  "mtls:spiffe://acme.org/litellm": [decide, complete, approval_request, approval_wait, approval_consume]
  "k8s_sa:system:serviceaccount:acme:support-agent": [register_run, close_run, decide, complete, approval_request, approval_wait, approval_consume]
```

**2. The proxy.** Install Tracekit in the LiteLLM proxy's environment (`pip install tracekit-ai`) and give the proxy its
signer identity in the environment: `TRACEKIT_SIGNER=https://signer.internal:8443` and `TRACEKIT_SIGNER_CERT` /
`TRACEKIT_SIGNER_KEY` (or `TRACEKIT_SIGNER_TOKEN_FILE`), as for any [remote client](../remote-ingest.md). Then add the
guardrail to the proxy's `config.yaml`:

```yaml
mcp_servers:
  notes:
    transport: http
    url: https://notes.internal/mcp

guardrails:
  - guardrail_name: tracekit
    litellm_params:
      guardrail: tracekit.integrations.litellm.TracekitGuardrail
      mode: pre_mcp_call             # the only mode it takes; LiteLLM refuses another at startup
      default_on: true               # every key's MCP calls; a key opts out only through its admin metadata
      approval_wait_s: 300           # how long a call the policy asks about waits for a person
```

List it after any other `pre_mcp_call` guardrail that rewrites arguments: what the signer decides is what runs.

**3. Each agent's key.** Set `tracekit_caller` in the metadata of the LiteLLM key the agent uses, to the Tracekit
identity the agent registers its runs as:

```bash
curl -X POST https://litellm.internal/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
  -d '{"key_alias": "support-agent", "metadata": {"tracekit_caller": "k8s_sa:system:serviceaccount:acme:support-agent"}}'
```

**4. Each run.** The agent registers its run with the signer and sends it with every MCP request to LiteLLM, next to
its LiteLLM key: `X-Tracekit-Run: <run_id>.<run_token>`. The value changes with every run, so the code that registers
the run sets the header:

```python
from tracekit.sdk.client import Client

run = Client().run("support-agent")
headers = {"Authorization": f"Bearer {litellm_key}", "X-Tracekit-Run": f"{run.run_id}.{run.run_token}"}
```

## Which run, which caller

Nothing the agent sends is trusted as who it is:

- **The caller** is `tracekit_caller` in the metadata of the LiteLLM key that authenticated the request, read from the
  key LiteLLM verified, not from the request. LiteLLM itself trusts the same metadata for guardrail opt-outs
  (`disable_global_guardrails`, `opted_out_global_guardrails`), so whoever can edit a key's metadata can already turn
  guardrails off for it. Keep agents' keys away from LiteLLM's key management routes.
- **The run** is the `X-Tracekit-Run` header. The signer accepts the run token only from the identity it was issued
  to, so a token presented through a key whose `tracekit_caller` is another identity is refused (`run_token_invalid`).

A request with no run, or through a key with no `tracekit_caller`, doesn't run.

## What is recorded

For each MCP `tools/call` LiteLLM runs:

| When | Recorded |
|---|---|
| before LiteLLM calls the upstream | `policy.decision` for `mcp:<server>/<tool>` and its arguments, `caller` the agent, `via` the proxy (source `gateway`, tier T2); on `ask`, the approval |
| when LiteLLM logs the result | `tool.result` (tier T2): the result the agent gets, redacted and committed to by the signer; an `isError` result as an error |
| when the call raised | `tool.result` as an error, with the exception's message |

`<server>` is the server's `alias` in LiteLLM's MCP configuration, else its name; `<tool>` is the upstream's own tool
name, so one policy covers this, the [MCP gateway](../mcp-gateway.md) and the [MCP client](mcp.md).

## Decisions

- **allow**: LiteLLM runs the call with the arguments the signer consumed.
- **deny**: the call doesn't run; LiteLLM answers the agent with an error, `Tool call blocked by Tracekit: denied by
  policy: <rule ids>`.
- **ask**: the request waits up to `approval_wait_s` for a person (`tracekit approvals`, the viewer). Approved, the
  call runs; an approval with a T2 executor makes the consume return the signer's copy of the arguments, and that is
  what runs. Rejected or unanswered, it is refused as for a deny.
- **signer unreachable, or a refusal**: the call doesn't run, whatever the run's fail modes.

## What Tracekit sees and doesn't

- **Sees:** each MCP tool call LiteLLM runs for a key the guardrail covers, its arguments as they go upstream, the
  decision, any approval, and the result the agent gets.
- **Doesn't see:** tool calls the model returns through LiteLLM's LLM endpoints (the agent runs those), MCP tool
  listings, resources and prompts, and calls the agent makes around LiteLLM.
- **Doesn't record:** a result LiteLLM doesn't hand its callbacks: a call LiteLLM answers with an interim
  input-required result, or one that raised in a request sent with LiteLLM's `no-log`. The decision stays open and its
  run ends with a signed `held_call_unresolved` gap for it.
- **Logs:** LiteLLM passes request headers, `X-Tracekit-Run` included, to its logging callbacks. The run token is
  usable only by the identity it was issued to.

[Limits](../limits.md) lists these with what to do.
