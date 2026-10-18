# LLM gateway

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

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
environment variables of the Python client. In `signer.yaml`, list it and let it record model events and say where a
run's stream ended (`close_run`, see [what is recorded](#what-is-recorded)):

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-gateway"]
authorize: {"mtls:spiffe://acme.org/tracekit-gateway": [model_event, close_run]}
gateway_mandatory: true                # optional, see Reconciliation
```

Only an identity in `gateways` may record an exchange for another identity's run; the signer refuses `caller` from
anyone else.

To keep exchanges in the signer's [content vault](privacy.md#the-content-vault), turn the vault on in `signer.yaml`
and also grant the gateway `status`: `[model_event, close_run, status]`. The gateway asks the signer's status once,
and from then on each `model_event` carries the exchange's `body`. Restart the gateway after you turn the vault on or
off.

Your agents reach the signer too (`register_run`, the tool decisions, autotrace), each as its own identity. Over the
signer's HTTPS listener (or `http://127.0.0.1:PORT` with `insecure_loopback: true`, for a local trial: the Python
client speaks plain HTTP to a loopback address only), a token, certificate or service-account identity may call no
method until `authorize` grants it; a call it isn't granted is refused `forbidden: token:NAME is not authorized for
status`. Grant every RPC the agent makes. An agent on the Python SDK with `tracekit.instrument()`, an adapter that
waits for approvals and the checkpoint commitments makes these:

```yaml
authorize:
  "token:agent": [status, register_run, decide, complete, observe, model_event, state_write, approval_request,
                  approval_wait, approval_consume, approval_abandon, approval_list, close_run]
```

The person who answers approvals needs `approval_list`, `approval_get` and `approval_decide` under an identity of
their own ([approvals](approvals.md#who-may-answer)).

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
after it is recorded; a streamed one passes through as it arrives, except the chunk with its terminal event, held
until the response is recorded. With the signer's content vault on, each record also carries the body: the request as
the client sent it, the response as the upstream sent it (a stream: assembled), when it fits the vault's
`max_record_bytes` and half the signer's 1 MiB frame. The signer redacts it, commits to the redacted form as the
record's `content_digest` and keeps it encrypted. Without the vault, the digest covers the raw bytes and no body leaves
the gateway. If the signer refuses the record (the run closed, its quota is used up), the client
gets an error whatever the fail mode.

Errors are never a clean end:

- An upstream error status is passed through and recorded as an error.
- An upstream redirect is never followed (it would carry the provider credential): 502, recorded as an error.
- A stream that breaks, sends an error event or ends before its terminal event (`[DONE]`, `response.completed`,
  `message_stop`) is recorded as an error, and the client gets an SSE `error` event followed by a cut connection.
- A request body over `max_body` is answered 413 and never forwarded; a non-streamed response over it is answered 502
  and recorded as an error.

If the signer can't be reached, the run's fail mode for class `model` applies (the `fail_modes` in `signer.yaml`;
closed by default): closed answers 503 and forwards nothing. Open forwards only for a run, token and identity the
signer has already accepted through this gateway.
Each run's records from one gateway share a stream and counter, so exchanges forwarded while the signer was
down show as a signed `client_counter_gap` once a later exchange of that run is recorded. **(1.2)** When the gateway
drops a run from memory (it keeps the last 10,000) or stops (SIGTERM, as systemd, Docker and Kubernetes send, or
Ctrl-C), it tells the signer where the stream of each run with unrecorded exchanges ended (`close_run` with `caller`
and `last_client_seq`), so those become a gap too; the run stays as it is, and for a run already final the gap goes in
the tenant's signer run, naming it. The gateway's identity needs the `close_run` grant next to `model_event`; without
it the gateway logs the refusal on stderr, saying so.

### Provider-run tools (1.2)

Tools the provider runs itself (Anthropic `server_tool_use` and `mcp_tool_use`, OpenAI `web_search_call`,
`file_search_call`, `code_interpreter_call`, `mcp_call`, hosted shell and server tool search) are recorded with
`executed_by: provider` and, where the provider returns their input (a search's query, the code, the MCP arguments),
an args commitment of it. No decide covers them, so reconciliation counts them (`provider_executed` on `run.final`)
and never reports one as `fabricated`.

They run mid-response, so no policy can hold one. To keep them out, refuse the requests that declare them:

```yaml
provider_tools: {deny: [web_search_preview, code_interpreter, mcp_servers]}   # or allow: [...], refusing the rest
```

Names are those `tracekit why` uses: an Anthropic typed tool the client doesn't run by its `name` (`web_search`,
`code_execution`), `mcp_servers` and `container`; an OpenAI tool by its type (`web_search_preview`,
`code_interpreter`, `mcp:<server_label>`; an entry `mcp` covers every server label), and `web_search_options`. The
OpenAI types the client runs (`function`, `custom`, `local_shell`, `apply_patch`, `computer_use_preview`) are never
refused; `shell` and `tool_search` count, since the provider may host them: with `allow`, list them if your client runs
them. A refused request is answered 403 `provider tool(s) ... not allowed by this gateway's provider_tools` and never
reaches the provider or the signer.

## Replay runs

`tracekit why` replays a recorded run's model calls through the gateway
([attribution on signed runs](why.md#attribution-on-signed-runs)). Each arm of a test is a run the investigator
registers with `replay_of: <run id>` and the investigation id (an identity in signer.yaml `analyzers`), then calls the
gateway exactly as an agent does: its own identity and `X-Tracekit-Run`. Its exchanges are recorded like any other,
source `gateway`, in the replay run, never in the run it replays. No tool the client runs is executed: the investigator
answers tool uses from the recorded run itself, so a replay run has model exchanges and no decisions, and is not
reconciled. A tool the provider runs itself would run again, so the investigator refuses, before sending anything, a
call whose request enables one (OpenAI Responses tools other than function and custom, Anthropic typed server tools,
`mcp_servers`, `container`, chat `web_search_options`); see [why](why.md#attribution-on-signed-runs).

## Verified tool results

> **Experimental (1.3):** this works and is tested, but may change and gets less hardening than the
> [stable core](support.md).

An agent can change what a tool returned before the model reads it. The gateway sees what goes to the model; the
signer holds what the tool returned (each `tool.result`'s commitment). With `verify_tool_results` in signer.yaml, the
signer compares the two on every request through the gateway:

```yaml
verify_tool_results: record    # or refuse
```

It catches two things, each a signed `reconcile.result_mismatch` (once per call) that `tracekit verify` and run.final's
coverage count with the run's unreconciled calls:

- a tool result (an OpenAI chat `role: tool` message, a Responses `*_output` item, an Anthropic `tool_result` block)
  for a call the signer already completed, whose content is not what was completed: the agent edited it;
- a tool result sent for a call the run allowed before its result was recorded. The shipped integrations complete a
  call before the next model request; a client of your own that completes later is flagged here too. This one is
  recorded, never refused: a complete that was lost (a client gives up after its retries) would otherwise stop the
  run for good, since every later request sends the result again.

`record` forwards the request; `refuse` answers the agent `403` for an edited result of a completed call and doesn't
send the request to the model (the exchange's response is recorded with that error). How it works: for each tool result
a request sends (the newest 512, newest first while their JSON stays within 1 MiB), the gateway sends digests of the
values it may have been recorded as (the content as sent, the text of a list of text blocks, the value of a JSON string
or of that text; for no content, `None`, `""` and `[]` alike; a value canonical JSON can't encode, such as one with a
lone surrogate, as its JSON text, as `result_field` records it); the signer computes their commitments under that
result's salt (only it can) and compares. No content leaves the gateway. A result the run's previous request sent too
reuses its digests, and a digest that matched or failed once isn't computed again. A tool_call_id used again in a run
matches any of its last 8 results.

It does not catch:

- text the agent adds anywhere else: a user turn, the system prompt, an assistant message;
- a tool call the agent writes into the history itself, with its result. Reconciliation flags it at run.final
  (`result_without_call`, or `fabricated` under `gateway_mandatory`), unless the agent also records a decide, a result
  and a model report for it and `gateway_mandatory` is off;
- results past a request's newest 512, or past 1 MiB of them as JSON (newest first; one the run's previous request also
  sent counts for nothing), so any one result over 1 MiB: the agent chooses which those are, since it can add results
  of its own. The gateway digests results in pure Python before it forwards the request; the cap bounds that work, and
  a result `complete` carries fits one 1 MiB frame anyway;
- a request under another run's token: the agent can register a run of its own and send its requests in that run,
  which has no results to compare;
- a result sent again later is checked again, but one the API doesn't resend (OpenAI Responses with
  `previous_response_id`) is checked once, when it is first sent;
- a model call that doesn't go through the gateway; and, with the signer unreachable and the run's `model` class
  failing open, a request the gateway forwards unchecked;
- a call that completed with no result, an error result, and a result whose content redaction changed (its commitment
  is over the redacted value);
- calls decided under ids of the client's own, not the model's: the MCP integration and the MCP gateway's calls are
  unchecked.

It is off unless set. A match needs the value your client completed the call with to be the value the model is sent
(or its digest). It can't be used with the Claude Code hooks (they record a digest of the tool's raw output, not what
the model is sent) or the Claude Agent SDK integration (it records the structured tool response): every result would
mismatch. These mismatch too: in Pydantic AI, a tool returning a list to Anthropic (one text block per item); in Google
ADK under `AnthropicLlm`, every result but a dict (and a dict with a `content` key or only `result`), under `LiteLlm` a
model or dataclass return (ADK sends its Python repr); a result of several content blocks (Agent Framework, Strands).
Gemini requests (ADK's default model) don't pass through the gateway, so nothing is checked. A Pydantic AI output
function's call is completed with no result (the model reads `Final result processed.`): unchecked. Run with `record`
first, and set `refuse` only once `tracekit verify` shows no `result_mismatch` on honest runs of your own agent, model
and tools. When the signer doesn't check, its answers say so and the gateway stops sending digests. A gateway older
than 1.3 sends none.

## Reconciliation

Gateway tool uses are L3 and take precedence over agent-reported L3 (autotrace) for the same tool call id. **(1.2)** A
gateway request that sends back the result of a gateway tool use no decide covers is recorded as
`reconcile.hook_missing` at once, mid-run, so whatever watches the signed records sees it before the run ends. With
`gateway_mandatory: true`, only gateway L3 counts: a decide the gateway never saw is `reconcile.fabricated` and a
gateway tool use with no decide is `reconcile.hook_missing`, whatever the agent reported. Use it when every model call
must go through the gateway.

**(1.2)** An adapter whose framework hands it no tool-call id (CrewAI's hooks) decides each call under an id of its
own. The reconciler pairs such a decide with the model's tool use when both are in the same model turn, name the same
tool with the same arguments, and no other unpaired call of that turn does: they count as reconciled, and `run.final`
says how many were paired so (`paired_by_args`; the verifier's coverage line names them). Anything less certain stays
`reconcile.hook_missing` and `reconcile.fabricated`.

A framework that asks the model for its actions as structured output rather than tool calls (Browser Use) leaves the
gateway no tool use to match: name those tools in the policy's `structured_output:` and reconciliation compares them
with nothing, in either direction ([policy](policy-v2.md#file-format)). The browser pack names Browser Use's actions
(`browser_use:*`); the output tool Browser Use uses with Anthropic models (`AgentOutput`) is the deployment's to name
([Browser Use](integrations/browser-use.md#the-browser-policy-pack)). Such a tool gets no L3 cross-check: its decides
show what the signer allowed, not that the model asked for it, and the model asking for it needs no decide, so name
only tools whose name no other tool of yours uses. Only the operator's policy can name them; nothing the agent sends
at run time can.
