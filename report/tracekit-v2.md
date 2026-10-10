---
title: "Tracekit v2: tamper-evident records of what AI agents did"
subtitle: "Technical report: evidence format v2, capture-layer reconciliation and the E-series evaluation"
---

# Abstract

AI agents run tools with their operators' permissions, and the record of what they did is usually a log the agent, or
whoever runs it, can edit. Tracekit records each tool call through a signer the agent cannot control: the signer
decides the call against its own policy, signs the event into a per-run hash chain inside an RFC 6962 Merkle tree,
checkpoints the tree as a C2SP signed note, and has independent witnesses cosign it. Runs export as `.tkb` bundles
that a third party verifies offline against a trust configuration it pins itself. This report describes evidence
format v2 (canonical JSON, domain-separated signatures, positional key validity, registry logs that prove which runs
exist), the capture layers whose reports the signer reconciles so that a missing or fabricated call becomes a signed
record rather than silence, and the verifier's split of the result into *integrity* and *assurance*. The evaluation
covers seeded faults, insider attacks, throughput and latency on file and Postgres storage, reconciliation, tampering
with agent state, tenant isolation, outages, crash durability and the deployment checker. Every number in the
evaluation tables is generated from the committed results files by `report/tables.py`, and a test fails when the
report and the results disagree. The claim is detection, not prevention, and it is only as strong as the witnesses
the operator does not control.

# 1. Problem and threat model

## 1.1 The claim

> Tracekit proves what its capture path recorded, and that the record has not changed since it was signed and
> checkpointed.

It does not prove intent, that every action was captured, or that a reported tool result is true. Two properties are
pursued separately:

- **Integrity.** A recorded event can't be changed, deleted, reordered or forged without detection: by the agent
  always; by the operator and whoever exports a bundle only when an independent witness has seen the log.
- **Completeness.** Actions are captured at several independent layers, and disagreements between layers are written
  as signed gap records. Completeness is reported, not proven (section 5).

## 1.2 Adversaries

The server threat model ([docs/threat-model-server.md](../docs/threat-model-server.md)) names six adversaries; the
laptop model ([docs/threat-model-laptop.md](../docs/threat-model-laptop.md)) maps onto them.

| Id | Adversary | Reach | Detected or stopped | Not detected |
|---|---|---|---|---|
| S1 | Prompt-injected or misaligned agent | the framework's tools, with the agent's identity | forged records; changes to the policy the signer decides with; self-approval; running calls unrecorded by stopping the signer (fail-closed classes) | anything in dev mode, where the agent's user owns the signer's files: there the policy's tripwires are all that stand in the way |
| S2 | Compromised application code or dependency | inside the agent's process, holds the run token | forged, reordered or deleted records; forged gap records; reuse of an approval; skipped or invented calls, when another capture layer saw the model ask for them | calls it skips when no layer outside the process saw them; false tool results |
| S3 | Insider with deploy or database rights | edits or restores the store, restarts the signer | edited records (background `fsck`), rollback below a cosigned checkpoint (at startup), edited bundles | a rewrite, by a key holder, of records no independent witness has cosigned yet |
| S4 | The operator, including the bundle exporter | chooses what to export; can fork or re-sign its log | edited bundles; missing, spliced or doubly-finalised runs and withheld key retirements, against a run-set; forks after an independent witness or anchor saw the log | a log never shown to an independent witness; two forks shown to two verifiers without a monitor |
| S5 | Another tenant or local user | the signer's RPC with its own identity | writing into another run; reading or answering another tenant's approvals; reading other tenants' registry leaves | - |
| S6 | Cloud provider | hosts and storage | out of scope | - |

The invariants every change is checked against (I0 to I10, mapped to tests in
[tests/INVARIANTS.md](../tests/INVARIANTS.md)) say what the design relies on: the agent's identity can't reach the
store, keys or policy (I0, which dev mode breaks and reports); no signing key or sequence assignment in the agent's
process (I1); the signer decides policy over the raw arguments (I2); approvals bind to exact arguments and are
consumed once (I3); runs are registered before their first action and closed by a signed `run.final` (I4); identity
proves the workload, not the tenant (I5); gaps are signed, never silent (I6); keys and time (I7); old evidence stays
verifiable (I8); the verifier and its trust come from someone other than the party verified (I9); canonical JSON is
unambiguous (I10).

# 2. Design

## 2.1 Signer service

The signer (`tracekit signer serve`) is the only process that holds signing keys, assigns sequence numbers and
writes records. Agents reach it over an RPC (Unix socket, or HTTPS with mTLS, Kubernetes service account or token
identity) through a Python or TypeScript client and framework adapters. A tool call is `decide` (the signer evaluates
the raw arguments with its own policy and classes, and returns allow, deny or ask) and then `complete` (the result).
The signer runs in three deployments: **dev** (same OS user as the agent, auto-spawned; every report says
`isolation: same-user`), **laptop system mode** (its own OS user under a hardened service unit) and **another host**
(file or Postgres storage, optionally a KMS-held log key). Fail modes are per tool class and come from the signer's configuration:
a closed class is blocked while the signer is unreachable; an open class runs, and the client's next call makes the
signer write a signed `client_counter_gap` covering the missed calls. Records are acknowledged after the write
(`ack-on-write`, with background sync) or after `fsync` (`ack-on-fsync`).

## 2.2 Evidence format v2

The format is specified in [docs/format-v2.md](../docs/format-v2.md), precisely enough for an independent verifier,
with normative test vectors. Its parts:

- **Canonical JSON.** Everything hashed or signed is JCS (RFC 8785) [10]. Input is parsed strictly first: invalid
  UTF-8, duplicate keys, non-finite numbers, integers beyond 2^53 - 1 and lone surrogates are rejected, because JCS
  implementations in different languages would hash them differently.
- **Commitments, not hashes, of agent content.** Arguments and results are published as an HMAC under a per-record
  salt derived from a signer secret, so a holder of the bundle can't test guesses against them; one revealed salt
  opens one record.
- **Records and domain-separated signatures.** A record is `{v, event, hash, alg, kid, sig}`. The signature covers
  the JCS of the record's position fields (log, seq, previous hash, tenant, run, run_seq, previous run hash), its
  `hash`, `alg` and `kid` (the SHA-256 of the key's DER SubjectPublicKeyInfo, which binds the algorithm), and a
  domain tag `"t": "tracekit.record.v2"`. Each purpose (record, checkpoint, approval, certificate, retirement, export)
  has its own tag, so a signature made for one never verifies as another. Ed25519 [9] is verified under strict rules
  (canonical `S`, no small-order keys, cofactorless equation) so every backend accepts the same signatures, and `alg`
  must be both pinned and the key's own algorithm.
- **Positional key validity.** Record keys are declared in the log itself by `signer.epoch` records and retired by
  `key.retire{kid, last_seq}`. A record is valid only under a key valid at its own sequence number; a record signed
  with a retired key after its `last_seq` fails. No clock is involved.
- **Certified record keys.** Optionally, short-lived record keys are certified by a separate issuer that holds the
  CA key; each certificate is a leaf of the issuer's own witnessed issuance log and is returned only after a witness
  cosigned it, so a certificate issued in secret does not verify ([docs/issuer.md](../docs/issuer.md)).
- **RFC 6962 trees and tiles.** Each log is an RFC 6962 / RFC 9162 Merkle tree [1, 2] whose leaves are record hashes;
  bundles carry inclusion proofs. The signer stores tree hashes as tlog-tiles [6]; tiles are storage, not evidence.
- **C2SP checkpoints and witnesses.** A checkpoint is a C2SP signed note in the tlog-checkpoint format [5], signed by
  a stable log key that signs nothing else, and cosigned by witnesses per tlog-cosignature (C2SP tlog-witness
  protocol) [7]. A witness that has cosigned size *n* refuses a later checkpoint inconsistent with it, so a rewrite or
  fork after that point shows. Witness classes (`public`, `customer`, `tracekit`, `operator`) come from the
  verifier's trust config, never from the bundle.
- **Rekor and RFC 3161 anchors.** The signer can also anchor checkpoints in Rekor v2 [4], with an RFC 3161 [11]
  timestamp that gives the anchor its time; the verifier checks both offline against a pinned Sigstore trusted root.
- **Hybrid SLH-DSA.** Stored notes can carry a second log signature by an SLH-DSA-SHA2-128s key (FIPS 205 [12],
  stateless and hash-based). Records stay Ed25519 and are covered long-term through the tree root the SLH-DSA line
  signs. A verifier that pins the hybrid key requires both lines; one that doesn't ignores the line. The line is not
  sent to witnesses or Rekor, whose request limits it exceeds.
- **Registry logs and run-sets.** Each tenant has a second tree, the registry log, with one fixed-width leaf per
  `run.registered`, `run.final`, `log.closed`, `key.retire` and tenant-level gap. Run ids are hashed under a
  per-tenant salt, and the registry's origin is derived from the salt, so neither names the tenant. A **run-set** is
  the leaf range between two registry checkpoints with a consistency proof: it shows which runs were registered and
  finalised in that window, so a deleted run, a second `run.final` or a withheld key retirement is a missing or extra
  leaf.

A bundle is a zip with a manifest (an index, never trusted: the files must be exactly those listed), one run's records
or a run-set's runs, the key records, inclusion proofs, the checkpoint note, any Rekor entry and timestamp, and the
policy snapshots. It carries no code and no trust configuration.

## 2.3 The verifier and its verdicts

`tracekit verify bundle.tkb --trust trust.json` checks, in order: the trust config; the zip's limits; the manifest;
the checkpoint against the pinned log key (both lines when a hybrid key is pinned), the witness quorum and any Rekor
anchor; the key records; every run's signatures, chain and inclusion; the run-set; the v1 bridge when given; the
policy snapshots. It reports two separate results ([docs/verdicts.md](../docs/verdicts.md)):

- **Integrity:** `VERIFIED`, `VERIFIED TO HEAD n (open)` for a run without `run.final`, `VERIFIED (k run(s) open)`,
  `FAILED`, `UNUSABLE BUNDLE` or `UNVERIFIABLE`. A malformed bundle is a failed line, never a crash.
- **Assurance:** who vouches for the checkpoint. `dev` when no pinned witness or anchor does, or a run holds a
  self-approval; `local` when only operator-class witnesses do; `witnessed` with at least one independent
  cosignature or anchor; `witnessed+monitored` adding a fresh, conflict-free report from a pinned monitor that reads
  every record.

Informational lines say what integrity rests on: capture layers that reported and unreconciled calls, evidence tiers,
argument sources, the isolation the signer measured for each run, fail-open classes and key assurance. `--strict`
turns warnings (unproven key retirements, tenant-level gaps, an unproven log tail, calls run against policy,
unreconciled calls, break-glass approvals) into a non-zero exit.

# 3. Capture layers and reconciliation

The signer can only sign what reaches it. Tracekit therefore captures the same activity at several layers and
compares them.

| Layer | What it records | Where | Can see | Cannot see |
|---|---|---|---|---|
| L1 agent state | writes to transcripts, framework checkpoints, session stores | in-process store wrappers (LangGraph checkpointer, Claude Agent SDK session store); a signer-side transcript tailer on laptop and sidecar | the agent contradicting state it already committed (`state_tamper`); a tailed file edited, truncated, replaced or swapped (`tailer_lost`) | state the agent never wrote through a wrapper; the wrapper is agent-reported and S2 can bypass it |
| L2 tool calls | call, argument commitment, decision, approval, result | the adapter's `decide` and `complete` | what the agent process reported, gated by the signer | calls the process does not report |
| L3 model calls | tool uses the model requested (id, name, argument digest, executor) | in-process autotrace (agent-reported), or the LLM gateway (T2, outside the agent) | a call the model asked for with no `decide`, a `decide` no model call asked for, other arguments | with autotrace only, nothing S2 suppresses in the same process; provider-executed tools are excluded |
| L4-L6 | tool gateway, execution, side effects | out of process | specified, not shipped | - |

**Tiers** say who captured a record: T1 adapter (what the agent reported), T2 gateway or executor (what crossed a
boundary outside the agent), T3 OTLP import (receipt only, never counted towards integrity).

**Reconciliation** (`tracekit/signer/reconcile.py`) indexes each run's reports by tool call id and attempt and compares
the tool name and argument digest unless one side is labelled coerced. Within a grace window before `run.final` it
writes signed records: `reconcile.hook_missing` (the model requested a call that has no decide),
`reconcile.fabricated` (a decide no model call requested), `reconcile.args_mismatch`, `reconcile.args_unparseable`
and `reconcile.result_without_call`. `run.final` lists the layers that reported, so a run with no L3 says so.

**Gateway.** `tracekit gateway serve` is a reverse proxy in front of an OpenAI-compatible or Anthropic Messages API
([docs/gateway.md](../docs/gateway.md)). It holds the provider credential, so agents don't; it records each exchange
as `source: gateway` (T2) before the client receives the end of the response. With `gateway_mandatory: true` only gateway L3
counts, so in a deployment whose network policy lets only the gateway reach the provider, a call the agent hides from
L2 is `reconcile.hook_missing` whatever the agent reports.

# 4. Evaluation

The experiments are small, synthetic and written by the authors. They show how the mechanisms behave, not how
Tracekit performs across real agents and projects. Each writes `eval/results/<name>.json` and records its platform;
every table below is generated from those files by `report/tables.py` (`python3 report/tables.py` rewrites them,
`tests/test_report.py` fails when they differ). Section 7 lists the commands.

## 4.1 Integrity and seeded faults (E1, E4)

E1 mutates signed v1 ledgers. "Ledger only" checks the hash chain and signatures; "plus witness" adds
checkpoints taken before the attack.

<!-- table e1 -->
Ledgers of 120 records.

| Mutation | Ledger only | Plus witness |
|---|---|---|
| edit field | 60/60 | 60/60 |
| delete record | 60/60 | 60/60 |
| swap adjacent | 60/60 | 60/60 |
| insert forged | 60/60 | 60/60 |
| truncate tail | 0/60 | 60/60 |
| rechain no key | 60/60 | 60/60 |
| rechain with key | 0/60 | 60/60 |
| torn write | 60/60 | 60/60 |
<!-- /table -->

The ledger alone can't see its own tail cut off or a history re-signed by the key holder; only a copy of the head held
elsewhere catches those. Against a key holder who edits one record at a random position and re-signs the rest, the
checkpoint interval bounds the window left open:

<!-- table e1-interval -->
| Checkpoint every n records | Detection rate |
|---|---|
| 1 | 1.00 |
| 5 | 1.00 |
| 10 | 1.00 |
| 25 | 0.90 |
| 50 | 0.82 |
| 100 | 0.82 |
| 120 | 1.00 |
<!-- /table -->

E4 corrupts real bundles and runs the offline verifier on each copy; the attacker edits the zip directly and repairs
the manifest hashes. On v1 bundles:

<!-- table e4 -->
| Fault (v1 bundle) | Bundle alone | Witness | Witness + strict |
|---|---|---|---|
| edit a record | 30/30 | 30/30 | 30/30 |
| delete a record | 30/30 | 30/30 | 30/30 |
| swap two records | 30/30 | 30/30 | 30/30 |
| append a forged record (valid hash, random signature) | 30/30 | 30/30 | 30/30 |
| edit then re-chain, without the key | 30/30 | 30/30 | 30/30 |
| truncate the tail, without the key | 30/30 | 30/30 | 30/30 |
| replace the signer: re-sign everything with an attacker key | 0/30 | 30/30 | 30/30 |
| replace signer.pub only | 30/30 | 30/30 | 30/30 |
| remove a deny rule from the policy snapshot | 30/30 | 30/30 | 30/30 |
| narrow the manifest's seq range | 30/30 | 30/30 | 30/30 |
| add a file the manifest does not list | 30/30 | 30/30 | 30/30 |
| delete the bundle's own checkpoints | 0/30 | 0/30 | 30/30 |
| edit then re-chain and re-sign, WITH the real key | 0/30 | 30/30 | 30/30 |
| truncate the tail and re-sign, WITH the real key | 0/30 | 20/30 | 30/30 |
| truncate the zip file at a random byte | 30/30 | 30/30 | - |

Untampered control exit codes: 0 alone, 0 with witness. Verifier crashes: 0.
<!-- /table -->

The v1 misses with a witness are a key holder cutting the tail exactly at a witnessed checkpoint, which leaves a
valid prefix whose only sign is the missing `run.end` (a warning, so `--strict` fails it). In format v2 such a run
verifies only as `VERIFIED TO HEAD n (open)`, and against a run-set its missing `run.final` is a missing leaf. On v2 bundles (runs with an approval, a run-set from registry size 0, a checkpoint cosigned
by a pinned and required witness):

<!-- table e4-v2 -->
| Fault (v2 bundle) | Detected | First failing check |
|---|---|---|
| edit record bytes (any record file) | 30/30 | signatures 14, bundle structure 9, keys 6, run-set 1 |
| flip a bit of a record signature | 30/30 | signatures 17, keys 8, run-set 5 |
| break a chain link (prev_hash, run_prev_hash, run_seq; hash recomputed) | 30/30 | signatures 23, run-set 7 |
| flip a bit of an inclusion proof (record tree or registry tree) | 30/30 | run-set 30 |
| edit a checkpoint note's body or signature lines (record or registry note) | 30/30 | run-set 16, checkpoint 14 |
| flip a bit of a registry leaf | 30/30 | run-set 30 |
| edit the run-set (range end, tenant salt, drop or swap leaves) | 30/30 | run-set 30 |
| edit the manifest without the files (hash, drop, phantom, unlisted file) | 30/30 | manifest 30 |
| drop a record of the run | 30/30 | run chain 27, run-set 3 |
| reorder two records of the run | 30/30 | run chain 22, run-set 8 |
| duplicate a record of the run | 30/30 | run chain 29, run-set 1 |
| re-sign an edited record with a foreign key | 30/30 | keys 14, signatures 13, run-set 3 |
| remove the run's run.final | 30/30 | run-set 30 |
| truncate the zip file at a random byte | 30/30 | - |

Untampered control: exit 0, VERIFIED. Verifier crashes: 0. Platform: darwin, Python 3.11.15.
<!-- /table -->

E4 v2 has no fault class for an attacker holding the real signing key; what a witness adds against one is measured
on v1 only.

## 4.2 Insider attacks (E8)

E8 attacks the path that feeds the log rather than a finished log: real unprivileged OS users (the agent's user and
a second local user) against a system-mode signer with a registered harness. E8 v2 runs the same attacks, plus
self-approval, against the v2 signer in system mode; it needs root on Linux.

<!-- table e8-v2 -->
_No `eval/results/e8_insider_v2.json` committed: run `eval/e8_insider_v2.py` (see its docstring)._
<!-- /table -->

The committed results are those of E8 on the v0.3 laptop signer, which the CI job "E8 insider attacks (Linux system
mode)" runs on every pull request as a merge gate:

<!-- table e8 -->
| Case | Caught | Verdict or outcome |
|---|---|---|
| E8.1 decoy redirect | yes | VERIFIED |
| E8.2 redirect + counter restore | yes | VERIFIED WITH GAPS (capture gaps) |
| E8.3 cross-user injection | yes | VERIFIED WITH GAPS (rejected writes) |
| E8.4 signer down | yes | hook exit 2 (2 = blocked; 0 = ran unrecorded) |
| E8.5 policy swap | yes | hook exit 2 (2 = still denied by the real policy) |
| E8.6 fabricated run, outside the harness | yes | UNUSABLE BUNDLE |
| E8.7 fabricated run, inside a live session | yes | VERIFIED WITH GAPS (capture gaps) |
| E8.8 write into a live run from outside the session | yes | VERIFIED WITH GAPS (capture gaps, rejected writes) |

Gates: gate_0.2.1 passed, gate_0.3 passed.
<!-- /table -->

"Caught" means the attack was refused, recorded as a gap, or blocked. E8 does not cover events fabricated into the
live run from inside the harness session; only cross-layer reconciliation catches those.

## 4.3 Throughput and latency (E9)

E9 runs `tracekit signer serve` as its own process and drives it with the Python client over the Unix socket, so
every number includes the client, the socket and the writer. Latency is one client calling `decide` and `complete`
in sequence; throughput is several client processes calling as fast as they can. The design's gates (p99 at most
5 ms per tool call at ack-on-write, at least 1,000 events per second) apply to full runs on Linux; the table states
the machine and run length of each committed result, and marks a result informational when no gate applied.

<!-- table e9 -->
| Storage | Machine | Run | ack-on-write p50 / p99 ms | events/s | ack-on-fsync p50 / p99 ms | Gates |
|---|---|---|---|---|---|---|
| file | darwin, 12 CPUs, Python 3.11.15 | quick | 0.448 / 0.91 (1000 calls) | 5356 (4 workers, 5 s) | 7.115 / 9.99 (200 calls) | events_per_s_ge_1000 yes, p99_ms_at_ack_on_write_le_5 yes (informational) |
| postgres | darwin, 12 CPUs, Python 3.11.15 | quick | 0.587 / 5.169 (1000 calls) | 3954 (4 workers, 5 s) | 0.662 / 0.861 (200 calls) | events_per_s_ge_1000 yes, p99_ms_at_ack_on_write_le_5 **no** (informational) |
<!-- /table -->

## 4.4 Reconciliation (E10)

E10 scripts runs against an in-process signer for each combination of capture layers: clean runs, including the hard clean cases
(coerced arguments that differ from the model's, a provider-executed tool, an L3 report that arrives late inside the
grace window), and runs with one seeded discrepancy each. Without L3 nothing can be compared, and no run may be
flagged.

<!-- table e10 -->
| Scenario | Flagged (L2) | Flagged (L2+L3) | Flagged (L1+L2+L3) | As expected |
|---|---|---|---|---|
| clean | none | none | none | yes |
| clean: coerced args | none | none | none | yes |
| clean: provider-executed tool | none | none | none | yes |
| clean: late L3 inside grace | none | none | none | yes |
| hook_missing | none | hook_missing | hook_missing | yes |
| fabricated | none | fabricated | fabricated | yes |
| args_mismatch: tool | none | args_mismatch | args_mismatch | yes |
| args_mismatch: args | none | args_mismatch | args_mismatch | yes |
| args_unparseable | none | args_unparseable | args_unparseable | yes |
| result_without_call | none | result_without_call | result_without_call | yes |

30 runs; seeded discrepancies flagged: 12/12; false positives: 0.
<!-- /table -->

The L2 column is the limitation in numbers: with one layer, a hidden or invented call is invisible.

## 4.5 Tampering with agent state (E11)

E11 runs a short session through each L1 source, then tampers with the saved state (in-place edits keep
the file's size). A case is detected when the run holds the signer-written gap.

<!-- table e11 -->
| Tampering | claude agent sdk | langgraph | tailer |
|---|---|---|---|
| delete | yes | yes | yes |
| edit | yes | yes | yes |
| pending tool call | yes | yes | yes |
| reorder | yes | yes | yes |
| replace | yes | yes | yes |
| symlink | yes | yes | yes |
| truncate | yes | yes | yes |
| untampered control: gaps | 0 | 0 | 0 |
| gap expected | `state_tamper` | `state_tamper` | `tailer_lost` |

Skipped sources: none. Platform: darwin, Python 3.11.15.
<!-- /table -->

The wrappers detect tampering when the resumed session next writes; they compare the store with what the same
process committed, so they catch a store changed underneath the agent, not an agent process that lies consistently.

## 4.6 Tenant isolation (E12)

Two tenants share one signer. Tenant b's identity attacks tenant a's run (with a pending approval and an imported
trace); every attempt must be refused or reach nothing of a's. Then concurrent tasks and threads, each in its own run,
check that the client's per-run context never leaks a call into another run.

<!-- table e12 -->
| Attack | Attempts | All refused |
|---|---|---|
| approvals | 5 | yes |
| delegate run | 2 | yes |
| guessed id | 3 | yes |
| observability | 3 | yes |
| otlp import | 2 | yes |
| run set | 3 | yes |
| run token | 10 | yes |
| control: own identity, own run | 1 | went through |
| python asyncio tasks: 8 x 20 calls, calls in another run / runs missing calls | 0 / 0 | - |
| python threads: 8 x 20 calls, calls in another run / runs missing calls | 0 / 0 | - |

Skipped: node async local storage. Platform: darwin, Python 3.11.15.
<!-- /table -->

## 4.7 Outage behaviour (E14)

E14 breaks one part at a time with fail modes `{default: closed, fs: open}`: (a) signer down, closed class; (b)
signer down, open class; (c) signer killed and restarted mid-run with an approval pending; (d) a network partition
that silently drops traffic to an HTTPS signer; (e) the only witness unreachable; (f) storage refusing writes; (g)
cases a and b through the TypeScript client. Every store must pass `tracekit signer fsck`.

<!-- table e14 -->
| Scenario | Passed | Measured |
|---|---|---|
| a fail closed | yes | blocked 20; calls while down 20 |
| b fail open | yes | calls while down 20; ran 20; fsck problems 0 |
| c restart | yes | approval after restart approved; asked ask; decide after allow; decide before allow; completed; consumed; fsck problems 0 |
| d partition | yes | client timeout ms 1000.0; fs ran unrecorded 20; shell blocked 20; fsck problems 0 |
| e witness unreachable | yes | answered 40; calls while down 40; degraded unanchored gaps 1; witness failed gaps 2; cosigned after recovery; fsck problems 0 |
| f storage unavailable | yes | acknowledged 41; acknowledged lost 0; signer unavailable gaps 1; fsck problems 0 |
| g typescript | yes | back allow; blocked 20; calls while down 40; ran 20; up allow; fsck problems 0 |

Run: full. Platform: darwin, Python 3.11.15.
<!-- /table -->

Latency of a tool call under the partition (scenario d):

<!-- table e14-partition -->
| Phase | Calls | p50 ms | p95 ms | added p50 ms | added p99 ms |
|---|---|---|---|---|---|
| baseline | 200 | 1.85 | 2.23 | - | - |
| during | 40 | 1003.18 | 1003.32 | 1001.32 | 1001.58 |
| after | 200 | 1.8 | 2.04 | -0.06 | 0.57 |

Client timeout: 1000.0 ms.
<!-- /table -->

During a partition each call costs the client timeout, then takes its class's fail mode; open-class calls run
unrecorded and are covered afterwards by a signed counter gap, never silently.

## 4.8 Durability (E15)

E15 runs the signer as its own process under concurrent clients and `kill -9`s it at random points, restarting it
each time. Clients don't retry: a failed call's counter value is used up. Afterwards every acknowledged call must be
in the store with the position it was acknowledged with, and every unacknowledged call must be in the store or
inside a signed `client_counter_gap`; anything else is a silent drop.

<!-- table e15 -->
| Durability | kill -9 rounds x clients | Acknowledged | Acknowledged lost | Not acknowledged | of which in the store | of which in a signed gap | Silent drops | fsck problems |
|---|---|---|---|---|---|---|---|---|
| ack-on-fsync | 30 x 8 | 7938 | 0 | 6986 | 141 | 6845 | 0 | 0 |
| ack-on-write | 30 x 8 | 41040 | 0 | 10876 | 38 | 10838 | 0 | 0 |

Gates: ack_on_fsync_zero_acknowledged_lost yes, fsck_clean yes, zero_silent_drops yes. Platform: darwin, Python 3.11.15.
<!-- /table -->

`kill -9` keeps the operating system's page cache, so ack-on-write losing nothing here says nothing about power loss:
there, records acknowledged within the last background sync interval can be lost. That window is not exercised.

## 4.9 Deployment checker (E16)

`tracekit doctor` should flag a misconfigured signer. E16 builds a clean layout, breaks one thing per case, and
expects the named check to fail or warn; the clean layout must pass. Without root, root-only cases are skipped.

<!-- table e16 -->
| Suite | Broken layouts | Flagged | Skipped | Clean layout passes | Checks exercised |
|---|---|---|---|---|---|
| system mode layout | 30 | 29 | 1 | yes | D-AGENT-PRIV, D-AGENT-PROBE, D-CLOCK-SKEW, D-CODE-TRUST, D-CONFIG, D-DATA-FS, D-DURABILITY, D-FAIL-MODES, D-HOOKS-PRESENT, D-HOOKS-TIMEOUT, D-HOOKS-VENV, D-KEY-HYGIENE, D-KEYS-DISTINCT, D-KEYS-MODE, D-POLICY-ENGINE, D-POLICY-TRUST, D-PROCESS-BOUNDARY, D-SIGNER-ENV, D-UNIT-HARDENING, D-WITNESS-CONFIGURED, D-WITNESS-FRESH, D-WITNESS-OWNERSHIP |
| Kubernetes manifests | 19 | 19 | 0 | yes | D-K8S-HOST-ACCESS, D-K8S-RUN-AS-USER, D-K8S-SA-TOKEN, D-K8S-SECURITY-CONTEXT, D-K8S-SHARED-VOLUME, D-K8S-SIGNER-DATA, D-K8S-WORKLOAD-IDENTITY, D-K8S-WORKLOADS |
| Postgres roles | 5 | 5 | 0 | yes | D-PG-READER-ROLES, D-PG-SIGNER-ROLE |
<!-- /table -->

Doctor checks only the misconfigurations it was written for. Its output is advice, not evidence.

# 5. Limitations

- **Same-user modes give no isolation.** In dev mode, and in any deployment where the agent's identity can reach the
  signer's files, the agent can read the keys, stop the signer and rewrite and re-sign the store. Every such report
  says `isolation: same-user` and, without an independent witness, `Assurance: dev`. Policy rules that deny the
  obvious attempts are tripwires, not a boundary. Windows supports dev mode only.
- **What harness binding doesn't stop.** On Linux system mode, harness binding refuses runs and events from programs
  that are not the registered harness. It does not stop a process the agent starts from inside its own harness session
  (a descendant of the real harness), or a new instance of the harness program that the agent's user starts on its
  own terms. Events fabricated from inside the session are caught only by cross-layer reconciliation, and only when
  a layer outside the agent (the gateway) saw the model's requests.
- **Completeness is not proven.** An action that crosses no capture layer can't be recorded. L1 wrappers and in-process
  autotrace are agent-reported, so compromised application code can suppress them along with L2. The out-of-process
  tool gateway, execution and side-effect layers (L4 to L6) are specified but not shipped. Tool results are whatever
  the agent reported. The coverage line says which layers reported; it is a statement of what was compared, not of
  what happened.
- **Operator trust without independent witnesses.** Whoever holds the signing key can rewrite and re-sign any history
  no independent witness has cosigned (E1, E4). A log never shown to such a witness is `Assurance: dev` or `local`, and
  the verifier says so. Two different forks shown to two verifiers are detected only by a monitor or a witness that
  sees both. Detection is all the design offers: nothing prevents a rewrite.
- **Monitor reports cover one view.** A monitor sees the log the signer serves it; a bundle checkpoint smaller than the
  report's tree is not proven consistent with it.
- **The evaluation's reach.** The experiments are synthetic, written by the authors, and mostly run on one developer
  machine; several gates hold on Linux only. No experiment measures adversarial models trying to bypass capture, real
  production traffic, or an external review. E8 v2 results are not yet committed.

# 6. Related work

**Tamper-evident logging.** Haber and Stornetta [13] linked timestamped documents into a hash chain so that
back-dating needs collusion. Schneier and Kelsey [14] protected audit logs on an untrusted machine with evolving MAC
keys, so an attacker who compromises the machine can't alter entries written before; Ma and Tsudik [15] gave
forward-secure aggregate signatures for the same setting with public verification. Crosby and Wallach [16] used
history trees to give logarithmic proofs that one version of a log is a prefix of another, the basis of what
transparency logs call consistency proofs. Tracekit's per-run chains, positional key retirement and witnessed tree
heads follow this line; the difference is the setting. The logging party in these schemes is a host that may be
compromised later; in Tracekit the party whose actions are logged (the agent) is never given the key at all, and the
logging party (the operator) is treated as a separate adversary.

**Certificate Transparency and transparency logs.** Certificate Transparency [1, 2] publishes certificates in
append-only Merkle trees whose signed tree heads are checked by monitors and auditors, so a mis-issued certificate
can't be hidden. Tracekit reuses its tree, proofs and the separation of logger, witness and monitor, and applies them
to agent events: the operator is the log, independent witnesses check consistency, and `tracekit monitor` reads every
record for semantic violations a witness can't see (a second `run.final`, an unannounced key). Tracekit's per-tenant
registry logs add run-set proofs, which show which runs exist in a window without revealing other tenants' run ids.

**Sigstore and Rekor.** Sigstore [3] makes software signing usable with short-lived certificates bound to an identity
and recorded in the Rekor transparency log [4]. Tracekit's optional record-key issuer follows the same pattern
(short-lived keys, every certificate published before use), and Tracekit anchors its checkpoints in Rekor v2 with an
RFC 3161 timestamp, which gives a public, independently witnessed time for each anchored tree.

**C2SP witnesses.** The C2SP specifications for signed notes, checkpoints, tlog-tiles and the witness protocol
[5, 6, 7, 8] standardise how a log publishes its head and how independent witnesses cosign it after checking
consistency. Tracekit's checkpoints follow them exactly, so standard witnesses (omniwitness, litewitness) can cosign
Tracekit logs without knowing anything about agents.

**Agent observability.** Tracing tools for LLM applications, including LangSmith, Langfuse, Arize Phoenix and
exporters following the OpenTelemetry semantic conventions for generative AI [17], record prompts, model calls and
tool calls for debugging and evaluation. Their stores are operated by the same party that runs the agent, and their
records are not, as far as we know, signed or independently witnessed, so they are evidence only for someone who trusts that party. Tracekit imports
OTLP traces as tier T3 (proof of receipt, nothing more) and exports its own records as OTel spans carrying their entry
hashes, so it complements these tools rather than replacing them. Policy gates and sandboxes for agents decide or
contain actions; Tracekit's signer gates too, but its contribution is the evidence that the gate ran and what it saw.

# 7. Reproducing

```bash
make eval                                            # E1-E4 (v1 and v2), E6, E10, E11, E12, E14 --quick, E16; E9 --quick on Linux
python3 eval/e9_signer_perf.py                       # E9 full run (gated on Linux)
python3 eval/e9_signer_perf.py --storage postgres --dsn DSN
python3 eval/e15_durability.py                       # E15, POSIX
sudo /opt/tracekit/bin/python eval/e8_insider_v2.py --require-harness   # E8 v2, Linux system mode (see the docstring)
python3 report/tables.py                             # regenerate this report's tables from eval/results/
make -C report                                       # check the tables and links; render a PDF when pandoc is installed
```

# References

1. B. Laurie, A. Langley, E. Kasper. *Certificate Transparency.* RFC 6962, 2013. <https://www.rfc-editor.org/rfc/rfc6962>
2. B. Laurie, E. Messeri, R. Stradling. *Certificate Transparency Version 2.0.* RFC 9162, 2021.
   <https://www.rfc-editor.org/rfc/rfc9162>
3. Z. Newman, J. S. Meyers, S. Torres-Arias. *Sigstore: Software Signing for Everybody.* ACM CCS 2022.
   <https://doi.org/10.1145/3548606.3560596>
4. Sigstore. *Rekor transparency log.* <https://github.com/sigstore/rekor-tiles>
5. C2SP. *Signed note* and *tlog-checkpoint.* <https://c2sp.org/signed-note>, <https://c2sp.org/tlog-checkpoint>
6. C2SP. *tlog-tiles.* <https://c2sp.org/tlog-tiles>
7. C2SP. *tlog-cosignature* and *tlog-witness.* <https://c2sp.org/tlog-cosignature>, <https://c2sp.org/tlog-witness>
8. Transparency.dev. *Witness network (omniwitness).* <https://github.com/transparency-dev/witness>
9. S. Josefsson, I. Liusvaara. *Edwards-Curve Digital Signature Algorithm (EdDSA).* RFC 8032, 2017.
   <https://www.rfc-editor.org/rfc/rfc8032>
10. A. Rundgren, B. Jordan, S. Erdtman. *JSON Canonicalization Scheme (JCS).* RFC 8785, 2020.
    <https://www.rfc-editor.org/rfc/rfc8785>
11. C. Adams, P. Cain, D. Pinkas, R. Zuccherato. *Internet X.509 PKI Time-Stamp Protocol (TSP).* RFC 3161, 2001.
    <https://www.rfc-editor.org/rfc/rfc3161>
12. NIST. *Stateless Hash-Based Digital Signature Standard.* FIPS 205, 2024. <https://csrc.nist.gov/pubs/fips/205/final>
13. S. Haber, W. S. Stornetta. *How to Time-Stamp a Digital Document.* Journal of Cryptology 3(2), 1991.
14. B. Schneier, J. Kelsey. *Secure Audit Logs to Support Computer Forensics.* ACM TISSEC 2(2), 1999.
15. D. Ma, G. Tsudik. *A New Approach to Secure Logging.* ACM Transactions on Storage 5(1), 2009.
16. S. A. Crosby, D. S. Wallach. *Efficient Data Structures for Tamper-Evident Logging.* USENIX Security 2009.
17. OpenTelemetry. *Semantic conventions for generative AI systems.*
    <https://opentelemetry.io/docs/specs/semconv/gen-ai/>
