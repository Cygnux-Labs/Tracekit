# Remote clients

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
authorize:
  "token:*": [register_run, decide, complete, state_write, model_event, close_run, status, read]
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
- Failed authentications are limited per source address and in total; past the limit a request is refused before its
  credential is looked at. `tracekit_signer_auth_failures_total` on the metrics port counts them. A refusal carries the
  error only: no sequence number, hash or run id.

## On the agent's machine

```bash
echo "$TOKEN" > /etc/tracekit/token
tracekit init --remote https://tracekit.example:8443 --v2 --token-file /etc/tracekit/token --ca signer-ca.pem
```

This wires the v2 Claude Code hooks to the remote signer and prints the environment SDK clients need:
`TRACEKIT_SIGNER` (the URL), `TRACEKIT_SIGNER_TOKEN_FILE` (read on every call: rotate by rewriting the file) and
`TRACEKIT_SIGNER_CA` (the CA the signer's certificate must chain to).

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
