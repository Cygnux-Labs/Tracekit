# LLM gateway

`tracekit gateway serve` is a reverse proxy between your agents and an OpenAI-compatible model API. It records every
model exchange in the v2 signer as `source: gateway` (tier T2): what the model asked to run, read from the response by
the gateway, not reported by the agent. The signer reconciles those tool uses against the agent's decides, so a tool
call the model asked for that ran with no decide shows up as `reconcile.hook_missing` in the run.

Served: `POST /v1/chat/completions`, `POST /v1/responses` and `POST /v1/messages` (Anthropic Messages), streamed or
not. Anything else is answered 404.

## Configure

`gateway.yaml` (relative paths are from the file):

```yaml
http:                                  # the same section, and identity plugins, as the signer's https listener
  listen: 0.0.0.0:8080
  cert: tls/gateway.pem
  key: tls/gateway.key
  client_ca: {acme.org: tls/acme-ca.pem}
  authenticators: [mtls, k8s_sa, token]
upstream: https://api.openai.com
api_key_file: secrets/provider.key     # the provider credential
api_key_header: authorization          # sent as "Bearer <key>"; x-api-key (Anthropic) sends the key as is
signer: https://signer.internal:8443
max_body: 33554432                     # bytes, for request bodies and non-streamed responses
```

The gateway reaches the signer as itself, with the `TRACEKIT_SIGNER_TOKEN_FILE` or `TRACEKIT_SIGNER_CERT`/`_KEY`
environment variables of the Python client. In `signer.yaml`, list it and let it record model events:

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-gateway"]
authorize: {"mtls:spiffe://acme.org/tracekit-gateway": [model_event]}
gateway_mandatory: true                # optional, see Reconciliation
```

Only an identity in `gateways` may record an exchange for another identity's run; the signer refuses `caller` from
anyone else.

## Calling it

Each request needs two things:

- **An identity** the `authenticators` accept: a client certificate, a Kubernetes service account token or the bearer
  token, exactly as on the signer.
- **The run**: `X-Tracekit-Run: <run_id>.<run_token>`, from `register_run`. A client authenticated by certificate may
  send that value as `Authorization: Bearer` instead, which is what an OpenAI SDK's `api_key` sets.

The signer checks the run token against the identity the gateway authenticated. No identity or no run: 401. A run
that doesn't exist, or a token issued for another run, identity or tenant: 403. The gateway never attributes a request
by source address or service name.

```python
import httpx
from openai import OpenAI
client = OpenAI(base_url="https://gateway.internal:8080/v1", api_key="unused",
                default_headers={"X-Tracekit-Run": f"{run_id}.{run_token}"},
                http_client=httpx.Client(cert=("agent.pem", "agent.key")))
```

The client's `Authorization`, `x-api-key` and `X-Tracekit-Run` headers are never forwarded: the gateway sends its own
provider credential. Agents never hold the provider key, so in a deployment whose network policy lets only the gateway
reach the provider, an agent can't call the model around it.

## What is recorded

Before forwarding a request: `model.exchange` phase `request`, with a digest of the body and the tool results the
request sends back. After the response completes: phase `response`, with the tool uses the model asked for (name,
args commitment, `executed_by`), usage, the stop reason and any error. A non-streamed response reaches the client only
after it is recorded; a streamed one passes through as it arrives and its last chunk is held until it is recorded.

Errors are never a clean end:

- An upstream error status is passed through and recorded as an error.
- A stream that breaks, sends an error event or ends before its terminal event (`[DONE]`, `response.completed`,
  `message_stop`) is recorded as an error, and the client gets an SSE `error` event followed by a cut connection.
- A request body over `max_body` is answered 413 and never forwarded; a non-streamed response over it is answered 502
  and recorded as an error.

If the signer can't be reached, the run's fail mode for class `model` applies (the `fail_modes` in `signer.yaml`;
closed by default): closed answers 503 and forwards nothing. Open forwards only for a run, token and identity the
signer has already accepted through this gateway.

## Reconciliation

Gateway tool uses are L3 and take precedence over agent-reported L3 (autotrace) for the same tool call id. With
`gateway_mandatory: true`, only gateway L3 counts: a decide the gateway never saw is `reconcile.fabricated` and a
gateway tool use with no decide is `reconcile.hook_missing`, whatever the agent reported. Use it when every model call
must go through the gateway.
