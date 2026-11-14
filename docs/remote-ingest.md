# Remote clients

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

An agent on another machine (a CI runner, a batch worker, a framework running elsewhere) talks to a v2 signer over its
HTTPS transport: each call is one `POST /v2/rpc`, authenticated again on every request. The signer signs, chains and
checkpoints as it does for a local caller; the client holds no key.

## On the signer host

`signer.yaml`, the `http` section (see `tracekit/transport/http.py`):

```yaml
http:
  listen: 0.0.0.0:8443
  cert: tls/fullchain.pem
  key: tls/privkey.pem
  authenticators: [token]      # also k8s_sa, mtls
  tokens: tokens.json          # named tokens, managed below
authorize:   # + approval_list for the TypeScript OpenAI Agents and Vercel AI adapters
  "token:*": [register_run, decide, approval_consume, complete, close_run, model_event, approval_request, approval_wait,
              state_write, status, read, observe, constraint_add, approval_get]   # observe, constraint_add: the coding-agent hooks
  # approval_get: the Claude Code hook, to run an approved command the model retried with a new description
tenants:
  "token:build-agent": acme    # or give the token a tenant with --tenant
```

```bash
tracekit signer token add build-agent --ttl 30d --config signer.yaml   # prints the token once
tracekit signer token list --config signer.yaml                         # names, tenants, created, expires, revoked
tracekit signer token revoke build-agent --config signer.yaml
tracekit signer serve --config signer.yaml
```

- A token is the identity `token:<name>`. Names are 1-64 of `a-z 0-9 _ -` (never `:`, never `dev` or `http`); a name is
  never reused, so a new token always gets a new name.
- The tokens file keeps a salted hash of each token with its created and expiry times, never the token. Every token
  expires (`--ttl`, default 30 days); an expired or revoked token is refused from its next request. The signer reads the
  file on every request: adding, revoking or rotating a token needs no restart.
- What a token may call comes from `authorize`; its tenant from `tenants`, else the token's `--tenant`, else `tenant`.
- Failed authentications are limited per source address and in total. Past an address's limit its requests are refused
  before their credential is looked at; past the total limit failures are refused as over it, but a valid credential
  still gets in. `tracekit_signer_auth_failures_total` on the metrics port counts them. A refusal carries the
  error only: no sequence number, hash or run id.

## On the agent's machine

```bash
echo "$TOKEN" > /etc/tracekit/token
tracekit init --remote https://tracekit.example:8443 --v2 --token-file /etc/tracekit/token --ca signer-ca.pem
```

This wires the v2 Claude Code hooks to the remote signer and prints the environment SDK clients need:
`TRACEKIT_SIGNER` (the URL), `TRACEKIT_SIGNER_TOKEN_FILE` (read on every call: rotate by rewriting the file) and
`TRACEKIT_SIGNER_CA` (the CA the signer's certificate must chain to). The hooks record each prompt (`observe`) and send
the live constraints it states (`constraint_add`): without both grants the hook reports an error at each prompt,
records none and holds no constraint. Claude Code's hook also reads an answered approval (`approval_get`) when the model
retries a held command with a new description: without the grant the retry is held again.

Without a token file, the Python and TypeScript clients take the token itself from `TRACEKIT_API_KEY`:

```bash
export TRACEKIT_SIGNER=https://tracekit.example:8443 TRACEKIT_API_KEY="$TOKEN"
```

Both read it on every call. A token file wins when both are set: it is read on every call too, so a rotated token is
picked up, and a key left in the environment never replaces it. The Python client's `token_file=` argument wins over both. The agent's own commands
inherit the environment, so one that prints it (`env`) puts the key in its transcript; give agents the file.

## Calling the signer over HTTP

Each call is one `POST /v2/rpc` with a JSON frame, `{"method": ..., ...}`, and the answer is one JSON frame:

```bash
curl -si https://tracekit.example:8443/v2/rpc -H "Authorization: Bearer $TRACEKIT_API_KEY" \
  -H 'Tracekit-Errors: http-status' -d '{"method": "status"}'
```

A refusal is an error frame, `{"error": {"code", "message", "retry_after_ms"?}}`. With the header
`Tracekit-Errors: http-status`, for curl and other HTTP clients, it comes with its HTTP status; without it, with 200,
as it always has, for clients that read errors from the body only. The frame is the same either way. The SDKs read
the body and don't send the header, so a proxy in front of the signer sees 200 for their refusals and acts on none of
them (it never retries a 503 or ejects the signer). A decision is an answer, not an error: `decide` returns allow,
deny or ask with 200.

| Error code | Status |
|---|---|
| `invalid_request` | 400 |
| `unauthenticated` | 401, with `WWW-Authenticate: Bearer` |
| `forbidden`, `run_token_invalid` | 403 |
| `unknown_run`, `unknown_tool_call`, `unknown_decision`, `unknown_approval`, `unknown_incident` | 404 |
| `run_exists`, `run_closed`, `conflict`, `client_seq_reused`, `args_mismatch`, `approval_not_pending` | 409 |
| `quota_exceeded` with `retry_after_ms` (a rate or count limit) | 429, with `Retry-After` |
| `quota_exceeded` without it (a size limit: the same request never fits) | 413 |
| `unavailable` | 503, with `Retry-After` when the signer gives `retry_after_ms` |

`Retry-After` is `retry_after_ms` rounded up to whole seconds; the frame keeps the milliseconds. Every answer carries a
`Request-Id` header (`req_` and 24 hex digits) of its own, not the `request_id` a call sends: the signer logs one line
per answer at INFO on the `tracekit.transport.http` logger with that id, the status, method, identity, error code and
time taken.

The SDKs send an event call (`decide`, `complete`, `observe`, `state_write`, `model_event`) again after `unavailable`
or a `quota_exceeded` with `retry_after_ms`, at most three tries within the call's timeout: they wait
`retry_after_ms`, or longer (100 ms doubled for each try, at most 2 s, with jitter). The retry is the same request,
its `request_id`, `stream` and `client_seq`. The signer refuses a `client_seq` it has already recorded before it writes
anything, and rebuilds that from the records after a restart or a disk error, so a retry is recorded once or refused
(`client_seq_reused`: a try the signer answered `unavailable` was written after all). Then the SDK raises that first
`unavailable`, as it did before it retried, so the caller takes its outage path (the run's fail mode). Refusals that
run out are the signer's error, as before; lost connections are counted apart, three tries of their own, and end in
`SignerUnavailable`. No other call is sent again: its `request_id` is remembered in memory only and forgotten with a
write that failed, so a retry after `unavailable` could be recorded twice. Don't let a proxy in front of the signer
retry its requests either.

## Downloading a run

Whoever owns a tenant's runs can download one as a `.tkb` bundle over the same API, with no access to the signer's
host. The operator grants `export_run` to an identity of that tenant, best one of its own rather than the agent's:

```yaml
authorize:
  "token:acme-audit": [export_run]
tenants:
  "token:acme-audit": acme    # or give the token a tenant with --tenant
```

```bash
(umask 077 && echo "$TOKEN" > /etc/tracekit/audit-token)   # owner-only, as every token file
export TRACEKIT_SIGNER=https://tracekit.example:8443 TRACEKIT_SIGNER_TOKEN_FILE=/etc/tracekit/audit-token
export TRACEKIT_SIGNER_CA=signer-ca.pem
tracekit export --v2 --run <run id> -o run.tkb
tracekit verify run.tkb --trust trust.json   # the trust config the signer's operator gives you
```

- The file is the one the operator's `tracekit export --v2 --config signer.yaml --run <run id>` writes from the same
  checkpoint, byte for byte: the run's records (commitments, not the content vault's content), the signer's key records
  (public keys), inclusion proofs, the checkpoint note, and the compiled policy where the run's records cite one. No
  verification code. Of the rest of the signer it shows what every bundle of it does: the log's size and the run's
  place in it, and the signer's one policy.
- With a [record-key issuer](issuer.md) whose certificates name more tenants than the caller's, the signer refuses the
  download (`forbidden`): every bundle's key records carry the certificates, so they would name the other tenants. The
  operator exports such runs.
- The tenant is the caller's own: `tenants`' entry for the identity, or the tenant its token was issued for, never the
  signer's default tenant. An identity with neither is refused, and the signer doesn't start when `authorize` grants
  `export_run` to an identity that can carry no tenant and `tenants` names none. Another tenant's run is refused as
  `unknown_run`, as a run that doesn't exist is.
- No identity has `export_run` unless `authorize` lists it, the dev signer's included, and only with calls that write
  nothing (`status`, `read`, `approval_get`, `approval_list`, `grant_list`, `incident_list`, `incident_show`), so no
  identity an agent writes through downloads runs: the signer doesn't start when one entry grants it with any other
  call, and refuses an identity its entries together grant one. An identity with it can download any run of its
  tenant.
- The signer builds a bundle at a time per tenant, two at once in all, at a limited rate per identity and per tenant,
  and keeps the bundles it built in memory for their later chunks, with a share per tenant. When it is busy it answers
  `unavailable` with a time to ask again, which the client follows until its timeout.
- A run still open is exported up to the latest checkpoint. When no checkpoint covers the run yet, the signer writes one
  and the client asks again a second later, until its timeout.
- Verify against a trust config you got from the operator or your own sources, not from the signer that sent the bundle.
- One run per download; `--run-set`, `--with-findings` and `--otel` stay with the operator's export. From Python,
  `Client().export_bundle(run_id)` returns the bundle's bytes. Limits: [deployment](limits.md#deployment).

## What changes in the evidence

| Property | Local caller | Remote caller |
|---|---|---|
| Signed, chained, checkpointed by the signer | yes | yes |
| Identity in `run.registered` | `uid:<n>` | `token:<name>` (or `k8s_sa:`, `mtls:`) |
| `signer_isolation` | `same-user` / `separate-user` | `remote`, set by the signer from the transport |
| Run access | the run's capability token | the same: a run token is bound to the identity that registered the run, so one remote client cannot write another's runs |
| Trust in the content | what the agent chose to send | the same |

A compromised remote agent can lie in the calls it sends and nothing proves it sent all of them; it cannot write
another identity's runs, forge signer records (gaps, tamper, checkpoints, approvals) or read records outside its scope.

## Migrating from `tracekit ingest`

`tracekit ingest` (the v1 ingest gateway) is deprecated and is removed in tracekit 0.5; it prints a warning when run.

| v1 | v2 |
|---|---|
| `tracekit ingest token NAME --home H` | `tracekit signer token add NAME --config signer.yaml` |
| tokens never expire | `--ttl`, default 30 days; `token revoke` |
| `tracekit ingest serve ...` | the signer's `http` section; no separate gateway |
| `tracekit init --remote URL --token-file F` | the same with `--v2` (and `--ca`) |
| runs `remote:<client>:<run>`, source `sdk` | runs registered by the identity `token:<name>`, isolation `remote` |
| `POST /v1/rpc`, `/v1/traces` | `POST /v2/rpc`; OTLP on `/v1/traces` with `otlp` configured (docs/otel.md) |

Steps: add the `http` section and one token per client to the signer, run `tracekit init --remote ... --v2` on each
client machine, move SDK code to `tracekit.sdk.client` (the v2 client), then stop `tracekit ingest serve`. Bundles of
runs already ingested by the v1 gateway keep verifying.
