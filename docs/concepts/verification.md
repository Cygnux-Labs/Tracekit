# Verification and assurance

Anyone with a bundle can check it offline: no network, no access to the signer, no trust in whoever ran the agent.
The verifier answers two separate questions. **Integrity:** are these exactly the records the signer signed, complete
and in order? **Assurance:** who, besides the signer's own key, vouches for the checkpoint that covers them?

## The trust config

The person verifying decides what to trust and writes it in a trust config. It is never inside a bundle.

| Key | What it pins |
|---|---|
| `logs` | Each log's origin and log key |
| `algs` | The signature algorithms accepted |
| `witnesses` | Witness keys, each with a class: `public`, `customer`, `tracekit` or `operator` |
| `witnesses_required` | How many cosignatures a checkpoint needs |
| `rekor`, `monitors`, `issuers` | Optional: Rekor's trusted root, monitor keys, record-key issuers |

`tracekit signer trust -o trust.json` writes one for a signer you run, and `tracekit last` writes one next to the
bundle it exports. An auditor should build theirs from keys obtained independently, not from the operator's bundle.

## What `tracekit verify` checks

In order:

1. **Trust config** parses strictly.
2. **Bundle readable**: the zip layout, the format, and the minimum verifier version.
3. **Manifest**: the files and their hashes match exactly.
4. **Checkpoint**: signed by a pinned log key for its origin; its size matches the proofs.
5. **Witness quorum**: enough cosignatures from pinned witnesses.
6. **Rekor anchor** and **monitor report**, when pinned or given.
7. **Keys**: every key record is in the tree, its id matches its public key, certificates check against pinned
   issuers, and retirements are respected.
8. **Signatures**: every record verifies under a key valid at its position.
9. **Run chain**: contiguous, linked, one run per chain, nothing after `run.final`.
10. **Inclusion**: each run's first and last record are in the checkpointed tree.
11. **Policy snapshots**: each file is named by its own SHA-256.
12. **Run-set**: complete or incomplete, when the bundle carries one.
13. **Incidents, agent approvals and findings**: recomputed from the records and the bundled policies.

It then reports, without failing on them: gaps, capture coverage, the coverage matrix, the tier of each call,
how arguments were obtained, the isolation the signer measured, fail-open classes and how keys were assured.

## Verdicts and exit codes

| Verdict | Exit | Meaning |
|---|---|---|
| `VERIFIED` | 0 | Every check passed and every run ended in `run.final` |
| `VERIFIED TO HEAD n (open)` | 0 | The run hasn't finished; everything up to record n checks out |
| `FAILED` | 1 | A check failed: something was changed, removed, reordered or forged |
| `UNUSABLE BUNDLE` | 2 | The trust config or the zip can't be read |
| `UNVERIFIABLE (...)` | 2 | The verifier can't judge: it needs a newer version, a key was revoked, or (TypeScript) a feature it doesn't check |
| any of the above with a warning, under `--strict` | 3 | Fail CI on gaps or other warnings |

Line by line: [reading a verify report](../verdicts.md).

## Assurance levels

Assurance says who vouches for the checkpoint. It is independent of isolation (who could reach the signer's keys),
which the report states separately.

| Level | When | What it means |
|---|---|---|
| `dev` | No pinned cosignature or anchor, or any self-approval in the run | Only the signer's own key vouches |
| `local` | Only `operator`-class witnesses | The operator's own infrastructure vouches |
| `witnessed` | At least `max(1, witnesses_required)` cosignatures or anchors from non-operator witnesses | Someone the operator doesn't control saw this checkpoint |
| `witnessed+monitored` | Witnessed, plus a fresh, conflict-free report from a pinned independent monitor | An independent party also read the log and found it consistent |

A run in system mode with no independent witness still verifies at `dev`: isolation stops the agent rewriting the
log, but only a witness stops the operator.

## Two independent verifiers

The TypeScript verifier was written from [format v2](../format-v2.md), not from the Python code. It has its own
canonical JSON, zip reader, schema checks and Merkle and checkpoint code, uses only Web Crypto, and runs in Node and in
browsers. Tests require both verifiers to give the same verdict, assurance, exit code and check lines on every golden
bundle and on about 45 deliberately tampered ones. A bug in one verifier therefore can't decide an audit on its own.

The TypeScript verifier doesn't check SLH-DSA lines, Rekor anchors, issuer certificates or why findings; a bundle that
relies on them is `UNVERIFIABLE` there, never `VERIFIED`.

## Verifying in CI

The repository's GitHub Action verifies a v1 bundle in a workflow (`uses: Cygnux-Labs/Tracekit@main`, with `bundle:`
and `key:` or `witness:`); an unanchored bundle fails the step unless `require-anchor: "false"`. For v2 bundles, run
`tracekit verify --strict` in the job.

## Reference

[Reading a verify report](../verdicts.md) · [auditor guide](../auditor-guide.md) · the verifier:
[`tracekit/verify/v2.py`](../../tracekit/verify/v2.py) · the TypeScript verifier:
[`sdk/typescript/src/verify/`](../../sdk/typescript/src/verify)

---

Previous: [The evidence format](evidence-format.md) · [All concepts](README.md) · Next:
[Witnesses and monitoring](witnesses-and-monitoring.md)
