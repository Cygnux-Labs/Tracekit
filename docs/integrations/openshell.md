# NVIDIA OpenShell

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Tested: a gRPC client plays OpenShell's gateway and supervisor against the middleware and a real signer, with messages built from OpenShell's protocol file; not yet run against a released OpenShell ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

[OpenShell](https://github.com/NVIDIA/OpenShell) runs agents in sandboxes. Each sandbox's supervisor allows or blocks
the agent's connections by network policy, injects provider credentials at the endpoints the policy approves, and calls
[supervisor middleware](https://github.com/NVIDIA/OpenShell/blob/main/docs/extensibility/supervisor-middleware/index.mdx)
on the HTTP traffic it allows. `tracekit openshell-middleware` is such a middleware: a gRPC service that decides each
request in the Tracekit signer and records each request and its response. They do different jobs and work together:

| | OpenShell | Tracekit |
|---|---|---|
| What it does | Runs the agent in a sandbox, allows or blocks each connection by network policy, and injects credentials | Decides each HTTP request OpenShell allows, holds risky ones for a person, and signs a record of each request, decision, approval and response |
| Where | The sandbox supervisor, around the agent | A middleware service the supervisor calls, and the signer behind it, both outside the sandbox |
| What a third party can check later | OpenShell's [OCSF event logs](https://github.com/NVIDIA/OpenShell/blob/main/docs/observability/ocsf-json-export.mdx) | A signed, hash-chained bundle per sandbox run, verified offline |

The supervisor calls the middleware after its network policy allows a request and before it injects credentials, so
Tracekit never sees the credentials, and again with the response before the sandbox gets it. A denial from the
middleware blocks the request whatever the policy entry's `on_error`; the external service never sees it.

## Requirements

- OpenShell 0.1.0 or newer: supervisor-middleware protocol 1.0. The middleware answers OpenShell's `Describe` only for
  protocol 1.0 with the `openshell.supervisor-middleware.contract` capability, and refuses any other version, so the
  OpenShell gateway doesn't start against a middleware that doesn't speak its protocol. OpenShell marks the middleware
  API as still evolving: a new protocol version needs a Tracekit release that knows it.
- NemoClaw pins OpenShell 0.0.116 (`min_openshell_version` and `max_openshell_version` in its blueprint, October
  2026). That release predates protocol negotiation: its gateway calls `Describe` with no protocol metadata, and its
  middleware contract has no response phase. The middleware refuses it, so NemoClaw sandboxes can't use it until
  NemoClaw moves to OpenShell 0.1.0 or newer.
- grpcio: `pip install 'tracekit-ai[grpc]'`.
- A v2 signer ([quickstart](../quickstart-v2.md)).

## Setup

**1. The signer.** The middleware reaches the signer as its own identity, registers one run per sandbox and acts for
each sandbox as `openshell:<sandbox id>`. In `signer.yaml`, list it under `gateways` and grant both:

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-openshell"]
authorize:
  "mtls:spiffe://acme.org/tracekit-openshell": [register_run, delegate_run, decide, complete, approval_request,
                                                approval_wait, approval_consume]
  "openshell:*": [decide, complete, approval_request, approval_wait, approval_consume]
```

The policy decides each request as tool `http_request`. The server pack (`server.yaml`) maps it to the `http` class:
internal addresses and names are denied, data sent to a host outside its allowlist is denied, and data sent to a host
only fetched content named is held ([policy](../policy-v2.md#packs-shipped)). Under the dev policy it is an unknown
tool, allowed and flagged.

**2. The middleware.** `openshell-middleware.yaml` (relative paths are from the file):

```yaml
listen: 10.0.0.12:50051                    # internal: only the OpenShell gateway and the sandbox supervisors reach it
tls: {cert: tls/mw.pem, key: tls/mw.key}   # required: OpenShell sends its caller token only over TLS
gateway_jwt:                               # who may call it: see below
  gateway_id: openshell                    # the gateway's [openshell.gateway.gateway_jwt] gateway_id
  public_key: jwt/public.pem               # a copy of its public_key_path
  audience: "urn:openshell:extension:middleware:tracekit"   # the registration's audience (its default for "tracekit")
signer: https://signer.internal:8443       # its identity: $TRACEKIT_SIGNER_CERT/_KEY or _TOKEN_FILE
```

Bind `listen` to an address only the OpenShell gateway and the sandbox supervisors reach, and never allow that address
in a sandbox's network policy: the middleware decides and records each request it gets in the run of the sandbox the
request names. Keep TLS on, and configure OpenShell's `gateway_jwt` so each call carries a token OpenShell mints for
the middleware's audience, which the middleware's `gateway_jwt` checks; OpenShell doesn't support client certificates
for middleware.

```bash
tracekit openshell-middleware serve --config openshell-middleware.yaml
```

Start it before the OpenShell gateway: the gateway calls `Describe` at startup and doesn't start without it.

**3. The OpenShell gateway.** Register the service in the gateway's TOML and restart the gateway:

```toml
[[openshell.supervisor.middleware]]
name = "tracekit"
grpc_endpoint = "https://tracekit-openshell.internal:50051"
tls_ca_cert_path = "/etc/openshell/tracekit-ca.pem"
max_payload_bytes = 4194304
timeout = "10s"
```

The middleware makes four signer calls for a sandbox's first request (register, delegate, decide, consume) and two
for each later one. `timeout` bounds each call OpenShell makes to the middleware, and OpenShell's default of 500 ms
leaves little room for a remote signer. For local development only, on a machine and network no one else
reaches, use an `http://` endpoint with `allow_insecure_transport = true`, and leave `tls` and `gateway_jwt` out of
`openshell-middleware.yaml`: OpenShell then sends no caller token, and the middleware listens on a loopback address
only (`listen: 127.0.0.1:50051`), unless you set `allow_unauthenticated: true`.

### Who may call it

With JWT signing configured, OpenShell sends a short-lived token with every call to the middleware
([Authenticating Extensions](https://github.com/NVIDIA/OpenShell/blob/main/docs/extensibility/overview.mdx#authenticating-extensions)).
With `gateway_jwt` the middleware checks it on each call: `typ` `openshell-ext+jwt`, an EdDSA signature under the
gateway's key, issuer `openshell-gateway:<gateway_id>`, the audience, not expired. A request or a response needs a
sandbox supervisor's token for the sandbox it names, so one sandbox (or anything else on the network) can't send
requests or responses in another's name. A request without a valid token is denied (`tracekit_unauthenticated`);
`Describe`, `ValidateConfig` and a response stream are refused (`UNAUTHENTICATED`). `gateway_jwt` needs `tls`:
OpenShell sends its tokens to `https://` endpoints only.

Without `gateway_jwt`, any peer that reaches the address is taken for OpenShell, so the middleware refuses to listen
beyond loopback unless `allow_unauthenticated: true` says the network already authenticates its callers.

**4. The sandbox policy.** Attach it to the hosts whose traffic you want decided and recorded:

```yaml
network_middlewares:
  tracekit:
    middleware: tracekit
    on_error: fail_closed
    endpoints:
      include: ["api.github.com", "*.api.example.com"]
```

Never list the middleware's own address in a sandbox's network policy: without `gateway_jwt`, a sandbox that reaches
it can send requests in any sandbox's name. Leave `config` out: the middleware takes none, and refuses a policy that sets one. Keep `on_error: fail_closed` (the
default): with `fail_open`, OpenShell skips the middleware when it fails, and that traffic goes unrecorded.

## What the agent sees

An allowed request goes through unchanged. A refused one never leaves: the sandbox gets OpenShell's denial, with the
middleware's reason code and none of its text:

```json
{"error": "middleware_denied", "detail": "Request rejected by configured middleware", "policy": "api-policy",
 "middleware": "tracekit", "reason_code": "tracekit_approval_required"}
```

| `reason_code` | When |
|---|---|
| `tracekit_denied` | the policy denied the request, or the signer refused to let an approved one run (a held or quarantined run) |
| `tracekit_approval_required` | the policy asks: a person must approve it, then the agent sends the same request again |
| `tracekit_approval_pending` | the same request again before anyone answered |
| `tracekit_approval_rejected`, `_expired`, `_consumed` | the approval was rejected, expired or already used; the next same request is decided anew |
| `tracekit_signer_unreachable` | the signer can't be reached: nothing is sent, whatever the run's fail modes |
| `tracekit_signer_refused` | the signer refused the middleware's call (a missing grant, a quota) |
| `tracekit_malformed_request` | OpenShell's message didn't decode |
| `tracekit_unauthenticated` | with `gateway_jwt`, the call came without a valid token for the request's sandbox |

The middleware prints each refusal and each held request on stderr, with the reason OpenShell doesn't pass on (a
held request's URL without its query string, which may carry a secret).

## Held requests

OpenShell waits for a middleware's answer at most its `timeout`, 30 seconds at most, which is too short for a person.
So when the policy asks, the middleware requests the approval and denies the request at once:

```text
tracekit openshell-middleware: sandbox demo: POST https://api.example.com/v1/transfer waits for approval apr-… (TK-P003): tracekit approvals approve apr-…
tracekit approvals approve apr-…            # from a terminal outside the sandbox
```

When the agent sends the same request again (same method, URL, headers and body), the middleware consumes the approval
and lets it through, once. The approval is bound to that exact request by the signer, like every Tracekit approval
([approvals](../approvals.md)): a request with another body, URL or header asks again. An agent that retries on its
own gets `tracekit_approval_pending` until someone answers.

## What Tracekit records

- **One run per sandbox**, `openshell-<sandbox id>-<8 hex>`, agent `openshell sandbox <name>`, registered by the
  middleware on the sandbox's first request, for `openshell:<sandbox id>`: each sandbox's runs, approval waits and
  events count against the signer's quotas (`limits`) on their own, not against one budget for every sandbox. The
  run token stays in the middleware; the agent never holds it. When the
  signer closes the run after `idle_s` without calls, the sandbox's next request starts a new run, and so does a
  restart of the middleware.
- **Each request** as tool `http_request` with arguments `method`, `url`, `headers` (the headers OpenShell passes, in
  wire order) and `body` (its text; the digest and size of a binary body or one too large for a signer frame). The
  `policy.decision` is source `gateway`, tier T2, and names the sandbox (`caller: openshell:<sandbox id>`) and the
  middleware (`via`). On `ask`, the `approval.request` and, once answered, the approval and its consume.
- **Each response** completes the call: a `tool.result`, source `gateway`, tier T2, with the status, headers and body,
  `ok` unless the status is 400 or above. The middleware reads the body as OpenShell streams it, passing each piece
  through unchanged. When the policy lists `http_request` as untrusted (the server pack does), a UTF-8 body under
  512 KiB is sent itself, so the signer indexes the hosts it names for provenance; otherwise the result's digest is.

Records commit to the arguments and results rather than store them ([privacy](../privacy.md)). `tracekit verify`
counts the calls under `tiers` as T2.

## What Tracekit sees and doesn't

- **Sees:** every HTTP request OpenShell allows to a host the policy entry includes, before credentials are added,
  and its response.
- **Doesn't see:** traffic to hosts the entry doesn't include, traffic OpenShell doesn't pass to middleware as HTTP
  (such as an endpoint with `tls: skip`, which an entry that fails closed can't select), and what OpenShell itself
  decided: its network policy's denials and the credentials it injects. WebSocket messages aren't sent to the middleware: it doesn't take them, so the
  upgrade request is decided and recorded and the messages aren't. Which process in the sandbox made a request isn't
  recorded: OpenShell doesn't send it today.
- **Doesn't read:** a response body OpenShell doesn't offer to middleware (compressed, partial, bodyless or
  `no-transform`); such a call completes with the digest of its status and headers.
- **Doesn't check without `gateway_jwt`:** who calls it. Any caller that reaches its address is taken for OpenShell
  ([who may call it](#who-may-call-it)).
- **Doesn't take more than 64 responses at once:** each response stream holds a thread, and the threads that decide
  requests stay free; one more response is refused, which OpenShell handles by the entry's `on_error`, and its call
  ends as a `held_call_unresolved` gap.
- **Doesn't import:** OpenShell's OCSF events. OpenShell exports them as OpenTelemetry log records over gRPC, and the
  signer's OpenTelemetry import takes traces only.

## Limits

[Limits](../limits.md#custody-12) lists these with what to do.
