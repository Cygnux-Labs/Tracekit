# Remote ingestion

Lets an SDK agent on another machine write to this signer's ledger over HTTPS. It exists for custom agents (CI
runners, batch workers, a framework running elsewhere). It is not a way to collect Claude Code hooks from other
machines: run a signer on each machine for that.

> **Experimental.** The ingest gateway (`tracekit ingest serve`) is off by default and being rebuilt: it runs only with `--experimental` and prints a
> warning when it starts. `tracekit init` never starts it.

```bash
# on the signer host
tracekit ingest token build-agent --home /var/lib/tracekit          # prints the token once; only its hash is stored
tracekit ingest serve --experimental --home /var/lib/tracekit --host 0.0.0.0 --port 8443 --cert fullchain.pem --key privkey.pem

# on the agent's machine
echo "$TOKEN" > token.txt
tracekit init --remote https://tracekit.example:8443 --token-file token.txt
python my_agent.py        # uses tracekit_sdk.Tracer as usual
```

## What changes in the evidence

| Property | Local SDK | Remote SDK |
|---|---|---|
| Signed, chained, checkpointed by the signer | yes | yes |
| Event source | `sdk` | `sdk`, always |
| Run id | as chosen | `remote:<client>:<run>`, so one client cannot write into another's run or a local one |
| `host` in `run.start` | the client's own claim | `remote:<client>@<address>` (set by the gateway) |
| `signer_isolation` | the signer's | the signer's real value, not the client's claim |
| Event types accepted | all client sources | `run.start`, `user.prompt`, `tool.call`, `policy.decision`, `tool.result`, `model.message`, `run.end` |
| Policy `ask` (human approval) | works | refused: the call is not run |
| Trust in the content | what the agent chose to send | the same |

The gateway holds no key. It authenticates, validates, rewrites, and forwards to the signer. A compromised
**remote agent** can lie in the events it sends (and nothing proves it sent everything); it cannot forge hook,
proxy, transcript, checkpoint, gap or tamper evidence, and cannot read or change existing records. A compromised
**gateway host** is a compromised signer host unless the gateway runs on a different machine from the signer and
reaches it over the local socket only; the supported layout is gateway and signer on one host.

## Operating it

- TLS is required unless the gateway binds loopback. `--insecure-http` exists for a reverse proxy that terminates
  TLS in front of it.
- Tokens live as SHA-256 hashes in `ingest-tokens.json` (mode 0600) in the signer home. Revoke by deleting the
  client's entry; the next request is refused. There is no expiry.
- Limits: 1 MiB per request, 100 events per second per client with a burst of 300, then HTTP 429 (the client
  treats it as retryable).
- The client keeps its counters as for local use, so lost or replayed events show up as `capture.gap` events.
- A signer outage makes the gateway answer 503; the SDK's fail-open or fail-closed setting applies as usual.
