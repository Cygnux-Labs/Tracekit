# Migrating

Two moves: from the v1 signer (`tracekitd`, `tracekit init --dev`) to the v2 signer on the same laptop, and from a
laptop signer to one on a server. Neither rewrites evidence: every bundle you already have keeps verifying with the
key or trust config it verified with before (I8 in the [threat model](threat-model-server.md#invariants)).

## Laptop: v1 → v2 signer

### What changes

| | v1 (`tracekit init --dev`) | v2 (`tracekit init --dev --v2`) |
|---|---|---|
| Signer | `tracekitd`, home `~/.tracekit-signer` | `tracekit signer serve --dev`, started by the first client ([quickstart](quickstart-v2.md)) |
| Claude Code hook | `tracekit.hook`; the hook evaluates the policy | `tracekit.integrations.claude_code`; the signer evaluates the policy over the raw arguments ([policy](policy-v2.md)) |
| Policy | `tracekit/policy/default.yaml` | the coding pack, `tracekit/policy2/packs/` |
| Approvals | `tracekit pending`, `tracekit approve` | `tracekit approvals list`, `tracekit approvals approve <id>`, bound to the exact arguments ([approvals](approvals.md)) |
| Export | `tracekit export --last -o run.tkb` | `tracekit export --v2 --run <run id> -o run.tkb` |
| Verify | `tracekit verify run.tkb --key signer.pub` (or `--witness`) | `tracekit verify run.tkb --trust trust.json` ([verdicts](verdicts.md)) |
| Bundle | v1 `.tkb`: one hash chain over the whole ledger | [format v2](format-v2.md): a per-run chain with inclusion proofs into a checkpointed Merkle tree |

### Steps

Export the v1 runs you will need as bundles while tracekitd is still set up:

```sh
tracekit export --last -o last-v1-run.tkb          # repeat with --run ID for each run you need
tracekit uninstall                                  # removes the v1 hooks and stops tracekitd
tracekit down                                       # if a v2 dev signer is running
tracekit signer bridge --v1-home ~/.tracekit-signer --dev
tracekit init --dev --v2                            # the v2 Claude Code hooks
tracekit doctor
```

`tracekit signer bridge` continues the v1 ledger in the v2 log ([format v2 §12](format-v2.md#12-v1--v2-bridge)): it
appends a `format_upgrade` gap and the v1 key's retirement to the v1 ledger, makes them the first record of the v2
log, and overwrites and deletes the v1 signing key (`signer.pub` stays). Run it as the owner of the v1 home, with no
tracekitd running on it. It must be the v2 log's **first** record: if the dev signer has already recorded something,
the bridge refuses, and the two logs simply stay separate.

A v2 bundle can then prove it continues that v1 ledger:

```sh
tracekit signer trust -o trust.json
tracekit export --v2 --run <run id> -o run.tkb
tracekit verify run.tkb --trust trust.json \
    --v1-ledger ~/.tracekit-signer/ledger/ledger.jsonl --v1-key ~/.tracekit-signer/ledger/signer.pub
```

The report's `format bridge` line passes when the v1 chain verifies up to the bridge, ends in the retirement of the
v1 key, and has no record after it.

### Old v1 bundles

They don't change. Verify them as before with the frozen v1 verifier:
`tracekit verify last-v1-run.tkb --key ~/.tracekit-signer/ledger/signer.pub`. Keep `signer.pub` (and any witness
clone) with them.

## Laptop → server

A signer's log can't be moved, merged or re-signed: the server signer starts a **new log** with its own keys, and the
laptop's log stays what it was. What moves is your agents' configuration.

1. **Export what you need from the laptop signer**, and keep its trust config:
   `tracekit signer trust -o laptop-trust.json`, then `tracekit export --v2 --run <id>` per run (or
   `--run-set` for a tenant's whole run-set). Its bundles keep verifying against `laptop-trust.json` for good, at the
   assurance they had (`dev` for a dev signer).
2. **Deploy the server signer** in one of the modes of the [deployment guide](deploy.md): sidecar, central or compose.
3. **Keys.** Let the server signer make its own. Never copy a laptop key to the server: in dev mode the agent's user
   could read it, so nothing it signs later proves anything. For a central signer, put the log key in a KMS
   (`log_key: {aws_kms: {key_id, region}}`) and certify short-lived record keys with the
   [issuer](issuer.md); a sidecar keeps file keys on its own volume ([Kubernetes](deploy-kubernetes.md)).
4. **Witnesses.** Add at least one witness the operator doesn't run (`witnesses:` in signer.yaml,
   [witnesses](witnesses.md#v2-c2sp-tlog-witnesses)), and for `witnessed+monitored` a [monitor](monitor.md) on a host
   the operator doesn't control.
5. **Trust configs.** Write the new one with `tracekit signer trust -o server-trust.json`. An auditor builds theirs
   from independent sources instead ([auditor guide](auditor-guide.md#2-build-the-trust-config-from-independent-sources)).
   A trust config pins a list of logs, so one file can hold both the laptop's and the server's log keys; the laptop's
   bundles still read `Assurance: dev`.
6. **Point the agents at it.** The code doesn't change: set `TRACEKIT_SIGNER` to the socket (sidecar) or the HTTPS URL
   (central, compose), with `TRACEKIT_SIGNER_TOKEN_FILE` and `TRACEKIT_SIGNER_CA` for token identity. For Claude Code:
   `tracekit init --remote https://signer.example:8443 --v2 --token-file /etc/tracekit/token --ca signer-ca.pem`
   ([remote clients](remote-ingest.md)).
7. **Check it.** `tracekit doctor --config signer.yaml` on the signer host (and `tracekit doctor --k8s` in a pod),
   then export and verify one run against `server-trust.json`.

### Which bundle verifies with what

| Bundle | Verify with |
|---|---|
| v1, from tracekitd | `tracekit verify run.tkb --key signer.pub` (or `--witness`), the frozen v1 verifier |
| v2, laptop log | `tracekit verify run.tkb --trust laptop-trust.json` |
| v2, laptop log bridged from v1 | the same, plus `--v1-ledger ledger.jsonl --v1-key signer.pub` to check the bridge |
| v2, server log | `tracekit verify run.tkb --trust server-trust.json` (plus `--monitor-report`, `--revocations` with an issuer) |
