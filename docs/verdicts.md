# Reading a v2 verify report

`tracekit verify bundle.tkb --trust trust.json` prints one line per check, then two summary lines:

```text
[PASS] manifest — every file is listed with its SHA-256 and nothing else is in the bundle
[PASS] checkpoint — tracekit.example.org/log/1 at tree size 42, signed by its pinned log key
...
Integrity: VERIFIED.
Assurance: witnessed; records ed25519; checkpoint Ed25519 only (tracekit.example.org/log/1); cosigned ed25519 by ...
```

Each line is `PASS`, `WARN` or `FAIL`. `--json` prints the same as `{"exit_code", "checks", "failures", "warnings",
"integrity", "assurance", "notes"}`. The algorithm behind each line is in [format v2](format-v2.md#11-verification-algorithm);
this page says what each one means, and what it does not. The v1 report is described in [signing](signing.md).

## Exit codes

| Code | When |
|---|---|
| 0 | no line failed |
| 1 | at least one line failed: `Integrity: FAILED` |
| 2 | the trust config or the bundle could not be used at all (`UNUSABLE BUNDLE`, `UNVERIFIABLE`), or the flags were wrong |
| 3 | `--strict` and no line failed but at least one is a warning |

Use `--strict` in CI or an audit when a warning should stop the pipeline: every `WARN` line below makes it exit 3.

## Integrity

| Verdict | Means |
|---|---|
| `VERIFIED` | every check passed and every run in the bundle ends in its `run.final` |
| `VERIFIED TO HEAD n (open)` | the bundle's one run has no `run.final` yet; its records up to `run_seq` n verify. Records after n may exist |
| `VERIFIED (k run(s) open)` | a run-set bundle in which k runs have no `run.final` yet |
| `FAILED` | at least one check failed; the failed lines say which |
| `UNUSABLE BUNDLE` | the trust config or the zip could not be read, or the manifest is not `tracekit.bundle.v2` |
| `UNVERIFIABLE (needs tracekit >= x)` | the bundle asks for a newer verifier (`verifier_min_version`) |
| `UNVERIFIABLE (key revoked)` | records signed by a record key whose certificate a passed `--revocations` file revokes ([issuer.md](issuer.md)) |

`VERIFIED` means: the records were signed by keys the log declared and had not retired; they form one unbroken run
chain; the run's first and last records are in a tree whose checkpoint the pinned log key signed; nothing was edited,
dropped, reordered or added after signing. It does **not** mean the run did everything the agent did (see coverage and
tiers), that a tool result is true, or that the signer was out of the agent's reach (see isolation and assurance).

## Assurance

The first word is the level; the rest lists what it rests on.

| Level | When |
|---|---|
| `dev` | no pinned witness cosigned the checkpoint and no pinned anchor verified, **or** the bundle holds a self-approval |
| `local` | only `operator`-class witnesses or anchors vouch for the checkpoint |
| `witnessed` | at least `max(1, witnesses_required)` independent (non-`operator`) cosignatures or anchors |

Then the algorithms each conclusion rests on: `records <algs>`; `checkpoint Ed25519 only (<origin>)`, or `checkpoint
Ed25519 + SLH-DSA-SHA2-128s (<origin>)` when your trust config pins the log's hybrid key ([format v2](format-v2.md#hybrid-checkpoint-signature));
each pinned cosignature (Ed25519) with its witness class and time (or `no witness cosignature`); each Rekor anchor
with its class, time and algorithms (ECDSA P-256 entry, RFC 3161 time); `earliest independent anchor <time>`, the earliest time a
non-`operator` witness or anchor vouches the checkpoint existed; `approvals: self` when a run holds a self-approval; and
`key retirements not proven complete` (see `keys`).

The level describes who vouches for the checkpoint, not how the signer was isolated: a same-user dev signer whose
checkpoints a public witness cosigns verifies as `witnessed`. A witness proves the log was not rolled back or forked
after it cosigned. Witness classes come from **your** trust config, never from the bundle. `witnessed+monitored`
is `witnessed` plus a fresh, conflict-free report of a monitor your trust config pins, passed with `--monitor-report`
([monitor.md](monitor.md)).

## Lines

### Integrity checks (a `FAIL` here fails the bundle)

| Line | Pass means | On failure |
|---|---|---|
| `trust config` | — | the trust config is malformed (exit 2) |
| `bundle readable` | — | not a zip, unsafe entries, no manifest, or too new (exit 2) |
| `manifest` | the files are exactly those listed, with those hashes | a file was added, removed or changed after export |
| `checkpoint` | the note is signed by the pinned log key named after its origin (and by its pinned hybrid SLH-DSA key, if any), and is of the proofs' tree size | wrong key, wrong origin, edited note, a pinned hybrid line missing or bad |
| `witness quorum` | at least `witnesses_required` pinned cosignatures (any class) | too few |
| `rekor anchor` | the checkpoint is in Rekor, timestamped by a pinned TSA. Only when the trust config pins `rekor` and the bundle has an anchor | a bad anchor fails the bundle |
| `keys` | the key records are in the checkpointed tree, in order, and every declared key matches its SPKI | a key record is missing from the tree, out of order, or retires an unknown key; a `key.retire` the registry has is withheld |
| `signatures` | every record verifies under a key valid at its position | names the record; "after its key.retire" when signed by a retired key |
| `run chain` | each run is contiguous from `run_seq` 0, one tenant and run, increasing seq, nothing after `run.final` | a record deleted, swapped, spliced from another run, or appended after `run.final` |
| `inclusion` | each run's first and last record is in the checkpointed tree | the run was rebuilt or the proofs are for another tree |
| `policy snapshot` | the snapshot file is named by its own SHA-256 | the snapshot was edited |
| `run-set` | `COMPLETE, registry a..b (r runs registered, f final, o open)` | `INCOMPLETE`: a leaf is missing or points elsewhere, a final run's records are missing, a second `run.final`, an unrelated run, or records after `log.closed` |
| `format bridge` | the v1 ledger verifies up to the bridge and ends in its key retirement (only with `--v1-ledger`) | a v1 record after the bridge, wrong key, broken v1 chain |
| `bundle structure` | — | the bundle is malformed in a way no other line covers |

### Warnings (`--strict` exits 3)

| Line | Means | Does not mean |
|---|---|---|
| `keys` (second line) `retirements not proven complete` | no run-set from registry size 0 reaches the bundle's last record, so a withheld `key.retire` would not show | that a key was retired |
| `tenant-level gaps` | the run-set range holds signer gaps that concern every tenant (witness failures, clock skew, startup without a witness, rollbacks), counted by kind | that the runs in the range lost records |
| `log tail` | records after the checkpoint are unproven: the range has no `log.closed` at the checkpoint's last record | that records were hidden |
| `policy` | a tool call ran against a deny, or an `ask` with no consumed approval, and the signer recorded it as `capture.gap{executed_against_policy}` | that the call did harm |
| `coverage` | the signer's reconciliation found calls it could not match across capture layers (`unreconciled: hook_missing 1, ...`) | that the agent hid a call; a layer may simply not have reported |
| `break-glass approvals` | an approval was answered under the break-glass role, with its approver and reason | that the approval was wrong |

### Informational lines (always `PASS`)

| Line | Shows | Read it as |
|---|---|---|
| `coverage` (no unreconciled calls) | the capture layers that reported (`L1`–`L6`; `(L3 absent)` when no model calls were seen) and the number of calls reconciled | completeness is only as good as the layers listed |
| `tiers` | tool calls by evidence tier: `T1` adapter, `T2` gateway or executor, `T3` import; `untiered` when no record names one | T3 (OTLP import) proves receipt only |
| `args source` | records by `args_source`: `raw` (the exact bytes the model produced), `parsed`, `coerced` (after the framework changed them) | coerced arguments can't be matched to the model's call byte for byte |
| `isolation` | the `signer_isolation` the signer measured for each run: `same-user`, `separate-user`, `remote`, `unknown` | `signer-reported`: the signer's own measurement of its caller, never the client's claim |
| `fail-open classes` | tool classes the signer's config lets run when the signer is down | calls of these classes may have run unrecorded during an outage |
| `key assurance` | `asserted`: the log declares its own record keys; nothing attests them yet | trust in the keys is trust in the pinned log key |

## Approvals in the report

A run with a self-approval (the approver was the requester or the run's owner: the dev signer, or `self_approval: allow`) caps assurance at
`dev` and adds `approvals: self`. Break-glass answers are a warning line. Approvals themselves are records in the run;
see [approvals](approvals.md).

## Signed gaps

Gaps inside a run (`capture.gap` with kinds such as `client_counter_gap`, `signer_unavailable`, `decision_flip`,
`class_mismatch`) are signed records of the run, visible in the bundle; only `executed_against_policy` and the
reconciliation kinds have report lines of their own. Tenant-level gaps show on the run-set line.
