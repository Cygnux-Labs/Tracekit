# Reading a v2 verify report

`tracekit verify bundle.tkb --trust trust.json` prints one line per check, then two summary lines, and a third when
the bundle holds signed findings:

```text
[PASS] manifest — every file is listed with its SHA-256 and nothing else is in the bundle
[PASS] checkpoint — tracekit.example.org/log/1 at tree size 42, signed by its pinned log key
...
Integrity: VERIFIED.
Assurance: witnessed; records ed25519; checkpoint Ed25519 only (tracekit.example.org/log/1); cosigned ed25519 by ...
Findings: 2 finding(s) (1 high, 1 medium) and 1 coverage review(s); 3 independent (an opinion of the run, not its integrity).
```

Each line is `PASS`, `WARN` or `FAIL`. `--json` prints the same as `{"exit_code", "checks", "failures", "warnings",
"integrity", "assurance", "notes"}`, with `"findings"` when there is a Findings line. The algorithm behind each line is in [format v2](format-v2.md#11-verification-algorithm);
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
| `VERIFIED` | every check this verifier implements passed and every run in the bundle ends in its `run.final`. Records carrying an ext name it doesn't interpret verified like every other; what the name says is on a `not interpreted` warning |
| `VERIFIED TO HEAD n (open)` | the bundle's one run has no `run.final` yet; its records up to `run_seq` n verify. Records after n may exist |
| `VERIFIED (k run(s) open)` | a run-set bundle in which k runs have no `run.final` yet |
| `FAILED` | at least one check failed; the failed lines say which |
| `UNUSABLE BUNDLE` | the trust config or the zip could not be read, or the manifest is not `tracekit.bundle.v2` |
| `UNVERIFIABLE (needs tracekit >= x)` | the bundle asks for a newer verifier (`verifier_min_version`); nothing failed. The `bundle readable` line lists the commands that verify it ([below](#a-bundle-that-needs-a-newer-verifier)) |
| `UNVERIFIABLE (key revoked)` | records signed by a record key whose certificate a passed `--revocations` file revokes ([issuer.md](issuer.md)) |

`VERIFIED` means: the records were signed by keys the log declared and had not retired; they form one unbroken run
chain; the run's first and last records are in a tree whose checkpoint the pinned log key signed; nothing was edited,
dropped, reordered or added after signing. It does **not** mean the run did everything the agent did (see coverage and
tiers), that a tool result is true, or that the signer was out of the agent's reach (see isolation and assurance).

## A bundle that needs a newer verifier

`UNVERIFIABLE (needs tracekit >= x)` means the bundle uses something your verifier doesn't know; nothing failed.
Verify it with a newer one. From 1.4.0 the `bundle readable` line prints these with your own paths (1.3 and earlier
print only the verdict):

```text
[FAIL] bundle readable — UNVERIFIABLE (needs tracekit >= 1.4.0)
        uvx --from "tracekit-ai>=1.4.0" tracekit verify run.tkb --trust trust.json
        npx -y @cygnuxlabs/tracekit@latest verify run.tkb --trust trust.json
        or open https://cygnux-labs.github.io/Tracekit/verify/ and choose both files: the page verifies them in your browser and sends nothing
```

`uvx` (from [uv](https://docs.astral.sh/uv/)) runs the Python verifier of that version without installing it; `npx`
runs the TypeScript one (Node ≥ 20.12), which lists itself first. The page is the TypeScript verifier too: its Content
Security Policy lets it load and send nothing, so the bundle never leaves your browser. For evidence, use a copy you
checked against the release (`gh attestation verify verify.html --repo Cygnux-Labs/Tracekit`, [releasing](RELEASING.md#verifying-a-release)).

From 1.4.0, what an older verifier can leave unread is non-critical (`ext`, [format v2](format-v2.md#9-bundle-layout)):
a 1.4.0 verifier verifies a later bundle and names each ext name it did not interpret on a `not interpreted` warning,
with the version that checks it.

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
non-`operator` witness or anchor vouches the checkpoint existed; `capped by the run-set's registry notes (<level>)`
when a run-set's registry notes, judged by the same rule from their own cosignatures, earn a lower level than the
checkpoint (the level shown is then theirs); `approvals: self` when a run holds a self-approval; and `key retirements
not proven complete` when no run-set from registry size 0 reaches the bundle's last record, so a withheld `key.retire`
would not show (a `keys` warning too when the bundle's key records show a retired key).

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
| `bundle readable` | — | not a zip, unsafe entries, no manifest, or too new (exit 2): then it lists the commands that verify the bundle ([above](#a-bundle-that-needs-a-newer-verifier)) |
| `manifest` | the files are exactly those listed, with those hashes | a file was added, removed or changed after export |
| `checkpoint` | the note is signed by the pinned log key named after its origin (and by its pinned hybrid SLH-DSA key, if any), and is of the proofs' tree size | wrong key, wrong origin, edited note, a pinned hybrid line missing or bad |
| `witness quorum` | at least `witnesses_required` pinned cosignatures (any class) | too few |
| `rekor anchor` | the checkpoint is in Rekor, timestamped by a pinned TSA. Only when the trust config pins `rekor` and the bundle has an anchor | a bad anchor fails the bundle |
| `keys` | the key records are in the checkpointed tree, in order, and every declared key matches its SPKI | a key record is missing from the tree, out of order, or retires an unknown key; a `key.retire` the registry has is withheld |
| `signatures` | every record verifies under a key valid at its position | names the record; "after its key.retire" when signed by a retired key |
| `run chain` | each run is contiguous from `run_seq` 0, one tenant and run, increasing seq, nothing after `run.final` | a record deleted, swapped, spliced from another run, or appended after `run.final` |
| `inclusion` | each run's first and last record is in the checkpointed tree | the run was rebuilt or the proofs are for another tree |
| `policy snapshot` | the snapshot file is named by its own SHA-256 | the snapshot was edited |
| `run-set` | `COMPLETE, registry a..b of tenant 't' (r runs registered, f final, o open)` | `INCOMPLETE`: a registry note without `witnesses_required` pinned cosignatures, a leaf is missing or points elsewhere, a final run's records are missing, a second `run.final`, an unrelated run or a run of another tenant, or records after `log.closed` |
| `format bridge` | the v1 ledger verifies up to the bridge and ends in its key retirement (only with `--v1-ledger`) | a v1 record after the bridge, wrong key, broken v1 chain |
| `bundle structure` | — | the bundle is malformed in a way no other line covers |

### Warnings (`--strict` exits 3)

| Line | Means | Does not mean |
|---|---|---|
| `keys` (second line) `retirements not proven complete` | the bundle's key records show a retired key (a `key.retire`, or more than one record key), and no run-set from registry size 0 reaches the bundle's last record, so another withheld `key.retire` would not show. With one key never retired, only the assurance line says so | that a key was retired |
| `gaps` | the runs hold signer-written records a person should read: a `capture.gap` of a kind listed under [signed gaps](#signed-gaps) as a warning, an `approval.binding_mismatch` (a consume with other arguments than the approved ones, e.g. a checkpoint edited between pause and resume) or a `trace.tamper`; counted by kind, each listed with its reason | that the agent did something wrong: a gap can be an outage |
| `fail-open classes` | the run declares tool classes that run when the signer is down (`fail_modes`), so calls the agent classed as one of those may have run unrecorded (the class is the agent's own reading of the tool, [FAQ](faq.md#what-happens-when-the-signer-is-down)). An outage the client recovered from is a `client_counter_gap` (`gaps`); one it never recovered from leaves no record | that any call ran unrecorded |
| `tenant-level gaps` | the run-set range holds signer gaps that concern every tenant (witness failures, clock skew, startup without a witness, rollbacks), counted by kind | that the runs in the range lost records |
| `log tail` | records after the checkpoint are unproven: the range has no `log.closed` at the checkpoint's last record | that records were hidden |
| `policy` | a tool call ran against a deny, or an `ask` with no consumed approval, and the signer recorded it as `capture.gap{executed_against_policy}` | that the call did harm |
| `coverage` | the signer's reconciliation found calls it could not match across capture layers (`unreconciled: hook_missing 1, ...`), or a host an [egress observer](egress.md) saw the run reach that no http or model call nor `explains` entry covers (`unexplained_effect 1`) | that the agent hid a call; a layer may simply not have reported, and an unexplained host may be a tool's own dependency the policy's `explains` doesn't list yet |
| `observers` | an egress observer covering the run went silent or restarted while the run was open, and the signer wrote a `capture.gap{observer_lost}`: the run's traffic after that (on a restart, what the old process had not reported) was not observed. A [kernel sensor's import](integrations/tetragon.md) writes the same gap when it goes silent, restarts or reports lost events | that the run sent anything unobserved, or ran anything unrecorded |
| `break-glass approvals` | an approval was answered under the break-glass role, with its approver and reason | that the approval was wrong |
| `held calls` | the signer wrote a `held_call_unresolved` gap: a call the executor or a gateway decided and may have run got no result before its run ended (after `gateway_wait_s`) | that the call ran, or did harm |
| `tiers` (`decided and completed by different capture paths`) | a tool call's decision and result records name different `source` or `tier`, for example a call a gateway decided (T2) completed by the agent, which a current signer refuses; each such call is listed and counted at the weaker tier | which record is false, or that the call didn't run |
| `gateway amendments` | `ext.amended` is on a record other than an LLM gateway's model request, or isn't a list of JSON pointers: the signer never writes that. It passes otherwise: `gateway amended n request(s) to show reasoning (/thinking/display: n)`, the requests the [gateway](gateway.md#readable-reasoning) sent with a field changed so the provider shows reasoning, each record committing to the request as sent | that the records are false: they verified like every other |
| `not interpreted` | records carry an ext name (format 1.4's non-critical slot) this verifier doesn't check, one line per name: `n record(s) carry ext.<name>`. They verified like every record (signature, chain, inclusion); what the name says is not checked. `tracekit >= x checks it` names a verifier that does (from the manifest, advisory) | that anything is wrong: a later Tracekit wrote something this verifier doesn't read |
| `external decisions` | another policy system's imported decision (`policy.external`) disagreed with the signer's for the same call (or named another tool, or a call the signer never decided), recorded as `capture.gap{decision_mismatch}`; the line also counts imports by system and by verified signature | that either decision was wrong: the signer's decision is the one that applied |

### Informational lines (always `PASS`)

| Line | Shows | Read it as |
|---|---|---|
| `coverage` (no unreconciled calls) | the capture layers that reported (`L1`–`L6`; `(L3 absent)` when no model calls were seen) and the number of calls reconciled | completeness is only as good as the layers listed |
| `coverage matrix` | per action class, how the run was covered: `model calls enforced (gateway, asserted), tool calls reported (adapter), network observed (egress), processes not covered, services not covered`. `enforced`: custody, the only way to act records it; `observed`: an observer outside the agent saw it and the signer reconciled it; `reported`: only the agent's own process reported it; `not covered`: nothing did. The layers behind each, and `asserted` where it rests on the operator's [posture](egress.md#posture); across several runs, each class's weakest | never that a run is complete: `reported` and `not covered` classes are where the agent could act unseen |
| `tiers` (each call decided and completed by one capture path) | tool calls by evidence tier: `T1` adapter, `T2` gateway or executor, `T3` import; `untiered` when no record names one. A call whose records disagree counts at the weakest (untiered < T3 < T1 < T2), its decision or result naming none counting as untiered | T3 (OTLP import) proves receipt only |
| `args source` | records by `args_source`: `raw` (the exact bytes the model produced), `parsed`, `coerced` (after the framework changed them) | coerced arguments can't be matched to the model's call byte for byte |
| `isolation` | the `signer_isolation` the signer measured for each run: `same-user`, `separate-user`, `remote`, `unknown` | `signer-reported`: the signer's own measurement of its caller, never the client's claim |
| `fail-open classes` (`none`) | no tool class runs when the signer is down | every call needed the signer |
| `key assurance` | `asserted`: the log declares its own record keys; `certified: n of m` when a pinned [issuer](issuer.md) certifies them | with `asserted`, trust in the keys is trust in the pinned log key |

## Approvals in the report

A run with a self-approval (the approver was the requester or the run's owner: the dev signer, or `self_approval: allow`) caps assurance at
`dev` and adds `approvals: self`. Break-glass answers are a warning line. Approvals themselves are records in the run;
see [approvals](approvals.md).

When a bundle holds an approval an agent gave, approvals are counted on separate lines (both verifiers; a bundle
without one keeps the report it always had):

| Line | Pass means | Warning / failure |
|---|---|---|
| `approvals by people` | `n approval(s) answered by people` (always `PASS`) | — |
| `approvals by agents` | for each approval an [agent approver](approvals.md#agent-approvers) gave (model output): its run holds the `approval.request` and `policy.decision` it answered; the request is agent-eligible (`agent.eligible: true`) and no `approval.escalated` or `approval.revoked` of it comes before the approval; the decision has no `provenance` and `provenance_state: complete` (or none, as the signer writes a decision with nothing untrusted); the approval needs no passkey; the agent is neither the requester nor the run's owner; and with the policy snapshot of the decision's `policy_hash` in the bundle, every rule the call was held by (flags aside) is an ask rule with `approval.agent` and no passkey | **warn** `agent approval bounds unchecked`: the bundle has no snapshot of that policy. **fail**: any check above, naming the approval |

The argument bounds themselves are not checkable offline: the records hold the arguments as salted commitments, so the
line says so in its detail. To audit one approval, `tracekit signer reveal --record <seq>` prints the salt of that
record and an auditor holding the arguments recomputes the commitment ([privacy](privacy.md#the-v2-signer)).

## Reviews

A signed finding is what `tracekit analyze --v2` found in a run, signed by the signer in a findings run of the
analyzer's own ([findings](findings.md), [format v2](format-v2.md#3-events)). It holds a rule, a severity, the rule's
fixed title and citations of the records it rests on, never text of the run. When a bundle holds `review` records,
both verifiers add:

| Line | Pass means | Warning / failure |
|---|---|---|
| `reviews` | `n review(s): 2 independent, 1 imported`: the reviews counted by label (below), and each citation of a signed finding is a record of the analysed run, in the bundle, with that `run_seq` and hash, and its verdict has a signed finding's shape | **warn** when a finding is `self-asserted`, naming its findings run and why. **fail** when a citation names a record the analysed run doesn't have, or one with another hash (the records are intact; the finding misstates them), a signed finding is outside a findings run, or its verdict holds a value no signer of its format signs (an alignment, reason code, model family or window outside what `review_finding` allows) |
| `reviews counted` | — | **warn**: a findings run is in the bundle without the run it analyses, so its citations are not counted. Export the analysed run with `tracekit export --v2 --run <run> --with-findings` |

The label says who wrote a finding: its author, the identity the signer measured when the findings run registered.
Only `independent` vouches for the author; read every other label as the analyzer's word:

| Label | Means |
|---|---|
| `independent` | your trust config's `analyzers` lists the author ([format v2](format-v2.md#10-the-trust-config)), and the author is not the analysed run's identity |
| `unpinned author <id>` | the author is not the analysed run's identity, but your trust config doesn't list it. If you trust that identity to analyse runs, add it to `analyzers` |
| `self-asserted` | the agent could have written the finding about itself: the author is the analysed run's own identity, or a run's `signer_isolation` is `same-user` (the signer runs as its client's user, which can then use its keys). Every finding of the dev signer reads this |
| `author not checked` | the analysed run is not in the bundle |
| `imported` | a review without citations, such as a v1 judge verdict carried over; never checked |

A finding says that a check fired on these records, not that the agent did wrong. A bundle with signed findings needs
`verifier_min_version` 1.4.0: an older verifier reports `UNVERIFIABLE (needs tracekit >= 1.4.0)`.

The `Findings:` line, after `Integrity` and `Assurance`, sums them up: how many findings by severity, the coverage
reviews, and the author labels. It is kept apart on purpose. Integrity depends only on the cryptographic and structural
checks; a finding is someone's opinion of the run and never changes it. Only a citation that doesn't match fails the
bundle (`reviews`), because then the analyzer misstated the evidence or the evidence changed.

## Live constraints

A [live constraint](policy-v2.md#live-constraints) is what the person's request said not to do in the rest of a run
(`constraint.added`); the signer held each later call that broke one for a person's approval (`TK-CONSTRAINT`). When a
bundle holds either, both verifiers add:

| Line | Pass means | Failure |
|---|---|---|
| `constraints` | `n live constraint(s) added; m call(s) held by them`: each decision held by `TK-CONSTRAINT` is an `ask` that comes after a `constraint.added` in its run | a decision held by `TK-CONSTRAINT` before any constraint in its run, or one that is not an `ask`: the signer never writes either |

The line counts holds, not breaches: a held call ran only if a person approved it (`approvals by people`). A
constraint holds a file's commitment, never its name; the person's prompt it came from is in the content vault.

## Signed gaps

Gaps inside a run (`capture.gap`, written by the signer only) are signed records of the run, visible in the bundle.
Every kind is a warning except the informational ones below, which say nothing against the run's own records:

| Kind | Report line |
|---|---|
| `executed_against_policy` | `policy` (warning) |
| `held_call_unresolved` | `held calls` (warning) |
| `decision_mismatch` | `external decisions` (warning) |
| `observer_lost` | `observers` (warning) |
| `state_tamper`, `client_counter_gap`, `signer_unavailable`, `tailer_lost`, `decision_flip`, `class_mismatch`, `log_closed`, `quota_refused`, `identity_refused`, `policy_timeout`, `retry_conflict`, `run_abandoned`, `rollback`, `key_revoked`, and any kind not listed here | `gaps` (warning), with `approval.binding_mismatch` and `trace.tamper` records |
| `witness_late`, `witness_failed`, `degraded_unanchored`, `clock_skew` | informational: the witness and checkpoint lines judge cosignatures themselves |
| `format_upgrade`, `key_retired` | informational: the format bridge and `keys` lines check them |
| `args_coerced` | informational: `args source` counts coerced arguments |
| `approval_expired` | informational: an approval no one answered in time is not a missing record |

Tenant-level gaps, `effect_outside_run` (an observation no open run held) among them, show on the run-set line
(`tenant-level gaps`, a warning). Reconciliation records (`reconcile.*`) are on the `coverage` line.
