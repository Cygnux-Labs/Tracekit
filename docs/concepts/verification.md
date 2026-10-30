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
| `analyzers` | Optional: the identities whose signed findings count as independent |

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
13. **Incidents, agent approvals and why findings**: recomputed from the records and the bundled policies.
14. **Signed findings** (`tracekit analyze --v2`): each one's citations must be records of the analysed run, with
    those hashes; a made-up or edited citation fails.
15. **Live constraints**: a call held by one must be an ask that comes after its `constraint.added`.
16. **Ext names**: those it knows get lines of their own (`gateway amendments`, `openshell policy`); any other gets a
    `not interpreted` warning.

It then reports, without failing on them: gaps, capture coverage (an edited tool result,
`reconcile.result_mismatch`, counts as unreconciled), the coverage matrix, observers or kernel sensors that lost
events, the tier of each call, how arguments were obtained, the isolation the signer measured, fail-open classes and
how keys were assured.

When the bundle holds signed findings, a third summary line, `Findings:`, counts them by severity and by who wrote
them: `independent` only when the trust config's `analyzers` pins the author, `self-asserted` when the agent could
have written them. Findings are an opinion of the run, never part of its integrity
([what was asked, said and done](provenance-and-why.md#what-was-asked-said-and-done)).

## Verdicts and exit codes

| Verdict | Exit | Meaning |
|---|---|---|
| `VERIFIED` | 0 | Every check passed and every run ended in `run.final` |
| `VERIFIED TO HEAD n (open)` | 0 | The run hasn't finished, or was cut back (records dropped from its end, which the bundle can't show): everything up to record n checks out. For audits require `VERIFIED` |
| `VERIFIED (k run(s) open)` | 0 | A run-set bundle in which k runs haven't finished |
| `FAILED` | 1 | A check failed: something was changed, removed, reordered or forged |
| `UNUSABLE BUNDLE` | 2 | The zip can't be read (a damaged file says so) or isn't a v2 bundle |
| `UNVERIFIABLE (...)` | 2 | The verifier can't judge: your trust file can't be used (its line says why), it needs a newer version (the report prints the commands that verify it), a key was revoked, (TypeScript) a feature it doesn't check, or (the browser page) no trust file was given |
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
bundle, on 55 deliberately broken ones, and on tampered copies of bundles from a real signer. A bug in one verifier
therefore can't decide an audit on its own.

The TypeScript verifier doesn't check SLH-DSA lines, Rekor anchors, record-key certificates or `tracekit why` findings
and their replay runs; a bundle that relies on them is `UNVERIFIABLE` there, never `VERIFIED`. It checks signed
findings, live constraints and both ext names like the Python one. Monitor reports and revocation lists are inputs
only the Python verifier takes.

## Verifying in a browser

`verify.html`, a release asset also served at https://cygnux-labs.github.io/Tracekit/verify/, is the TypeScript
verifier as one page: nothing to install. Drop the bundle on it with the trust file the sender gave you. Its Content
Security Policy lets it load and send nothing, so the files never leave the browser. It shows the verdict with what it
means and what it doesn't, what to do next, a summary of the run, and every check line exactly as `tracekit verify`
prints it.

Without a trust file it still checks everything that needs no pinned key: a changed, missing or reordered record
fails, but an intact bundle is `UNVERIFIABLE (no trust config: ...)`, because anyone can sign a bundle with keys of
their own. It doesn't check v1 bundles. For evidence, use a copy you checked against the release
(`gh attestation verify verify.html --repo Cygnux-Labs/Tracekit`). Tests check the page prints the TypeScript command
line's report and loads and sends nothing, and `scripts/verify_page_check.py` compares it in a real browser with both
command-line verifiers ([reading a verify report](../verdicts.md#verify-in-your-browser)).

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
