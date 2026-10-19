# NVIDIA OpenShell

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Tested: a gRPC client plays OpenShell's gateway and supervisor against the middleware and a real signer, with messages built from OpenShell's protocol file; not yet run against a released OpenShell ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

## What you get

If you run agents in [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandboxes, Tracekit gives each sandbox one
tamper-evident record of what its agent did on the network and what OpenShell did about it:

- **Each HTTP request, decided and signed by Tracekit.** For the hosts you choose, every request the sandbox makes that
  OpenShell's network policy allows goes to Tracekit before OpenShell adds credentials. Tracekit's policy allows it,
  denies it, or holds it until a person approves that exact request. The request, the decision, any approval and the
  response are signed records.
- **OpenShell's own events, signed into the same record.** The connections OpenShell's policy allowed and blocked
  (with the program that tried), the start of the sandbox's agent process, and every change of the sandbox's policy or
  configuration OpenShell reports (a draft rule approved, a policy loaded, a reload that failed), taken from
  OpenShell's OCSF export.
- **Losses on the record.** When OpenShell drops OCSF events, or its export stops while the sandbox keeps making
  requests, the record says so in a signed gap; it doesn't go quiet.
- **Verifiable offline by anyone.** Records are hash-chained and Ed25519-signed by a Tracekit signer outside the
  sandbox, which the agent can't control. A run exports as a bundle that `tracekit verify` or the browser verifier
  checks on another machine, with no access to OpenShell, the agent or the signer.

Two parts, each optional: the **middleware** (the first point) and the **OCSF import** (the second and third). One
process, `tracekit openshell-middleware`, serves both on one port.

| | OpenShell | Tracekit |
|---|---|---|
| What it does | Runs the agent in a sandbox, allows or blocks each connection by network policy, and injects credentials | Decides each HTTP request OpenShell allows, holds risky ones for a person, signs a record of each request, decision, approval and response, and signs OpenShell's own events into the same run |
| Where | The sandbox supervisor, around the agent, and the OpenShell gateway | A middleware service the supervisor calls and OpenShell exports to, and the signer behind it, all outside the sandbox |
| What a third party can check later | OpenShell's [OCSF event logs](https://github.com/NVIDIA/OpenShell/blob/main/docs/observability/ocsf-json-export.mdx), best-effort and unsigned | A signed, hash-chained bundle per sandbox run, holding both, verified offline |

## How it works

[OpenShell](https://github.com/NVIDIA/OpenShell) runs agents in sandboxes. Each sandbox's supervisor allows or blocks
the agent's connections by network policy, injects provider credentials at the endpoints the policy approves, and calls
[supervisor middleware](https://github.com/NVIDIA/OpenShell/blob/main/docs/extensibility/supervisor-middleware/index.mdx)
on the HTTP traffic it allows. `tracekit openshell-middleware` is such a middleware: a gRPC service that decides each
request in the Tracekit signer and records each request and its response. OpenShell's gateway and supervisors also
export their [OCSF](https://ocsf.io) security events as OpenTelemetry log records over gRPC
([OCSF log export](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/gateways/configuration.mdx#ocsf-log-export));
the middleware takes them on the same port and records them in the sandbox's run.

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
- For the OCSF import: an OpenShell with OCSF log export (`[openshell.gateway.otlp.ocsf]`). It speaks OTLP over gRPC
  only, which is what the middleware serves.
- grpcio: `pip install 'tracekit-ai[grpc]'`.
- A v2 signer ([quickstart](../quickstart-v2.md)).

Tested against: OpenShell source at commit `55bf786` (17 October 2026), with OpenTelemetry log batches built as its
exporter writes them; not yet run against a released OpenShell
([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

## Setup

**1. The signer.** The middleware reaches the signer as its own identity, registers one run per sandbox and acts for
each sandbox as `openshell:<sandbox id>`. In `signer.yaml`, list it under `gateways` and grant both; `observe_effect`
is for the OCSF import (leave it out without one):

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-openshell"]
authorize:
  "mtls:spiffe://acme.org/tracekit-openshell": [register_run, delegate_run, decide, complete, approval_request,
                                                approval_wait, approval_consume, observe_effect]
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
ocsf:                                      # take OpenShell's OCSF export on this port too (leave out: middleware only)
  token_file: ocsf.token                   # the bearer token OpenShell's OCSF export sends: see step 3
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

**3. The OpenShell gateway.** Register the service in the gateway's TOML, point its OCSF export at the same address,
and restart the gateway:

```toml
[[openshell.supervisor.middleware]]
name = "tracekit"
grpc_endpoint = "https://tracekit-openshell.internal:50051"
tls_ca_cert_path = "/etc/openshell/tracekit-ca.pem"
max_payload_bytes = 4194304
timeout = "10s"

[openshell.gateway.otlp.ocsf]          # the OCSF import; leave it out for the middleware only
enabled  = true
endpoint = "https://tracekit-openshell.internal:50051"
```

and in the gateway's environment, the token from `ocsf.token`, percent-encoded as OpenTelemetry headers are:

```bash
OTEL_EXPORTER_OTLP_LOGS_HEADERS="authorization=Bearer%20<the token>"
```

The gateway exports its own OCSF events there and passes the endpoint and the header to every sandbox supervisor it
starts, which export theirs directly
([OCSF log export](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/gateways/configuration.mdx#ocsf-log-export)).
Leave `schema_version` unset: a downgrade to OCSF 1.1 or 1.3 drops the sandbox's name from each event (its id stays).
OpenShell checks the OCSF endpoint's certificate against its usual trust roots (the system's), not `tls_ca_cert_path`:
the middleware's certificate must chain to a CA the gateway and the supervisors trust.

The middleware makes four signer calls for a sandbox's first request (register, delegate, decide, consume) and two
for each later one. `timeout` bounds each call OpenShell makes to the middleware, and OpenShell's default of 500 ms
leaves little room for a remote signer. For local development only, on a machine and network no one else
reaches, use an `http://` endpoint with `allow_insecure_transport = true` (and an `http://` OCSF `endpoint`), and
leave `tls` and `gateway_jwt` out of `openshell-middleware.yaml` (and `ocsf` as `ocsf: {}`, no token): OpenShell then
sends no caller token, and the middleware listens on a loopback address
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

OpenShell sends no extension token with its OCSF export, only the collector headers its gateway is configured with.
With `ocsf.token_file`, an export without `authorization: Bearer <that token>` is refused (`UNAUTHENTICATED`) and
nothing of it is recorded. `token_file` needs `tls`. The gateway hands the header to each supervisor with its launch
credentials, never through the sandbox's environment, so the agent doesn't hold it; but it is one token for the
gateway and every supervisor, so an event's sandbox is the one the sending OpenShell component names. Without
`token_file` the middleware takes OCSF events from any peer, so `ocsf` then needs a loopback `listen` or
`allow_unauthenticated: true`.

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
| `tracekit_body_unreadable` | the request's body isn't UTF-8 text (compressed or binary) or is over 512 KiB: the policy can't read it, so it isn't decided without it |
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
  middleware on the sandbox's first request or OCSF event, for `openshell:<sandbox id>`: each sandbox's runs,
  approval waits and events count against the signer's quotas (`limits`) on their own, not against one budget for
  every sandbox. The run token stays in the middleware; the agent never holds it. When the signer closes the run after
  `idle_s` without calls, the sandbox's next request starts a new run, and so does a restart of the middleware.
- **Each request** as tool `http_request` with arguments `method`, `url`, `headers` (the headers OpenShell passes, in
  wire order) and `body` (its text: a body that isn't UTF-8 or is over 512 KiB is denied unrecorded). The
  `policy.decision` is source `gateway`, tier T2, and names the sandbox (`caller: openshell:<sandbox id>`) and the
  middleware (`via`). On `ask`, the `approval.request` and, once answered, the approval and its consume.
- **Each response** completes the call: a `tool.result`, source `gateway`, tier T2, with the status, headers and body,
  `ok` unless the status is 400 or above. The middleware reads the body as OpenShell streams it, passing each piece
  through unchanged. When the policy lists `http_request` as untrusted (the server pack does), a UTF-8 body under
  512 KiB is sent itself, so the signer indexes the hosts it names for provenance; otherwise the result's digest is.

Records commit to the arguments and results rather than store them ([privacy](../privacy.md)). `tracekit verify`
counts the calls under `tiers` as T2.

### OpenShell's OCSF events

With `ocsf`, each event OpenShell exports goes into the run of the sandbox it names (the record's
`openshell.sandbox.id`, else the supervisor's), as the middleware's observation: `effect.observed` with `sensor:
openshell` and `observer` the middleware's identity, written by the signer, OpenShell's assertion and no more. The
import names the middleware's own identity as its one caller, so it covers only the runs the middleware registered:
the signer records an event it attributes to any other run as an `effect_outside_run` gap, never in that run. A
gap OpenShell or the middleware reports names `sensor: openshell`.

| OpenShell's OCSF event | Recorded as |
|---|---|
| Network Activity (4001) or HTTP Activity (4002) that OpenShell's policy allowed or denied | `effect.observed{kind: connect, host, port, pid, binary}` (the program OpenShell names), with `denied: true` when OpenShell blocked it |
| Process Activity (1007): a launch | `kind: exec`, the process OpenShell started (the sandbox's entrypoint) |
| Process Activity (1007): a termination | `kind: exit`, with its exit code |
| Device Config State Change (5019): a policy or configuration change | an `ext` record `openshell.policy`: OpenShell's name for the change (`approved`, `merged`, `loaded`, `failed`, ...), its `policy_hash`, who made it (`by`, its `actor` as OpenShell writes it, which may be a person's email: a signed record can't be edited later), and a commitment to its message, never the message itself |
| Detection Finding (2004) of traffic OpenShell let past a middleware under `fail_open` (`openshell.middleware.failure` naming the middleware, `.traffic_uninspectable` or `.body_unavailable` with disposition `fail_open`, `.http_response_fail_open`) | a `capture.gap{observer_lost}` in the sandbox's run: a request or response that may have no record |
| OpenShell's gap record (`openshell.ocsf.gap`: records it dropped before export) | a `capture.gap{observer_lost}` in that sandbox's run, or in every run the import covers when OpenShell's gateway dropped them (they may be of any sandbox) |

OpenShell's own records of the middleware's decisions are skipped: those requests are the run's calls already. An
event delivered twice (OpenShell retries a batch) is recorded once, by its `ocsf.metadata.uid`. A batch the signer
can't take is refused, so OpenShell sends it again; once OpenShell gives up, its next batch carries the gap record.

OpenShell records each request the middleware decides as an OCSF event of the sandbox. When none arrives from a
sandbox for 60 s after the middleware decided one of its requests, its export stopped or doesn't reach the middleware:
the run gets a `capture.gap{observer_lost}` saying so, once, until the sandbox's events arrive again. The import also
calls the signer at least every 30 s; if it stops, each open run it covers gets the signer's own `observer_lost` gap
after 90 s, as for any [observer](../egress.md).

`tracekit verify` reads the policy changes on a line of their own: `openshell policy: OpenShell changed the sandbox
policy or configuration 2 time(s) (approved: 1, loaded: 1), as OpenShell reported it`. A verifier before 1.4 can't
verify such a bundle (`UNVERIFIABLE (needs tracekit >= 1.4.0)`); a 1.4 verifier that didn't know the name would still
verify it and say `not interpreted`. `tracekit view` shows each block as `BLOCKED BY OPENSHELL · connect host:port`
and each change as `OPENSHELL POLICY · <change>` on the run's tape.

## What Tracekit sees and doesn't

- **Sees:** every HTTP request OpenShell allows to a host the policy entry includes, before credentials are added,
  and its response. With `ocsf`: what OpenShell's OCSF export reports of each sandbox's connections to any host
  (allowed and blocked), its entrypoint's start and its policy changes.
- **Doesn't see:** the credentials OpenShell injects. Without `ocsf`: traffic to hosts the entry doesn't include,
  traffic OpenShell doesn't pass to middleware as HTTP (such as an endpoint with `tls: skip`, which an entry that fails
  closed can't select), and OpenShell's own decisions. WebSocket messages aren't sent to the middleware: it doesn't
  take them, so the upgrade request is decided and recorded and the messages aren't. The middleware's records don't
  name the process that made a request; OpenShell's connection events do.
- **Doesn't import:** OCSF events of other kinds (SSH, authentication, detection findings other than a `fail_open`
  bypass, application lifecycle, base events, and network events that neither allow nor deny), events that name no
  sandbox (the gateway's own), and processes other than the ones OpenShell reports (it reports the entrypoint, not each process the agent starts: a
  [kernel sensor](tetragon.md) sees those). The middleware counts each kind it skips and prints the counts on stderr.
- **Doesn't read:** a response body OpenShell doesn't offer to middleware (compressed, partial, bodyless or
  `no-transform`); such a call completes with the digest of its status and headers. A request body that isn't UTF-8
  text or is over 512 KiB isn't read either, so the request is denied (`tracekit_body_unreadable`).
- **Doesn't check without `gateway_jwt`:** who calls it. Any caller that reaches its address is taken for OpenShell
  ([who may call it](#who-may-call-it)).
- **Doesn't take more than 64 responses at once:** each response stream holds a thread, and the threads that decide
  requests stay free; one more response is refused, which OpenShell handles by the entry's `on_error`, and its call
  ends as a `held_call_unresolved` gap.
## Limits

[Limits](../limits.md#custody-12) lists these with what to do.
