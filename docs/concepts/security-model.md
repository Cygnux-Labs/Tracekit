# Security model

This page brings the other concepts together from an attacker's point of view: who Tracekit defends against, the
rules the code keeps so those defences hold, the questions a security engineer asks, and the design decisions behind
the answers. The full threat models, attack by attack, are the [laptop](../threat-model-laptop.md) and
[server](../threat-model-server.md) threat models.

## The claim

Tracekit proves what its capture path recorded, and that the record has not changed since it was signed and
checkpointed. It doesn't prove intent, completeness, or that a reported result is true, and it detects tampering
rather than preventing it ([overview](overview.md#what-a-verified-run-proves)).

## Adversaries

| Adversary | Can | Stopped or detected by |
|---|---|---|
| The agent itself (prompt-injected or misaligned) | Run tools as its OS user, call the signer with its run token | The signer's isolation; signer-side policy; signed gaps; reconciliation against layers outside its process |
| Compromised code in the agent's process | Skip the adapter, report false results, edit a tool's result before the model reads it | Reconciliation against the LLM gateway, which also compares tool results with the recorded ones; custody through the executor and MCP gateway |
| Another local user or tenant | Connect to the signer, guess run ids | Run tokens bound to identity and tenant; per-tenant registries; refused and recorded writes |
| An insider with database or deploy rights | Edit or roll back the store | Background fsck (`trace.tamper{edited}`), witness rollback checks (`trace.tamper{rollback}`) |
| The operator running the signer | Rewrite or fork the log with its own key | Independent witnesses and a monitor; run-sets for omitted runs. Not detectable without them |
| The cloud provider | Everything below the operating system | Out of scope |

## Invariants

The code keeps these rules, each mapped to tests ([tests/INVARIANTS.md](../../tests/INVARIANTS.md)):

- The agent can't reach the signer's store, keys, witnesses, code, config or policy (except in dev mode, which says so).
- The agent never holds a signing key or a chain head, and never assigns sequence numbers.
- Policy runs on the raw arguments, with the signer's own tool classes, deterministically.
- Approvals bind to exact arguments and are used once.
- Runs are registered before their first action and end with a signed `run.final`.
- Gaps are signed, never silent; clients can't forge gap or tamper records.
- Signatures name their algorithm and key and are domain-separated; key retirement is positional.
- Verifiers are frozen per format, and their test bundles are never regenerated.
- The verifier and its trust config never come from the party being verified; bundles contain no verification code.
- Canonical JSON is strict: no number overflow, non-finite numbers, duplicate keys or lone surrogates.

## Hard questions

**Who watches the signer?** Witnesses the operator doesn't control, a monitor run elsewhere, and Rekor anchors. They
detect a dishonest signer after the fact. Preventing one would need attested hardware, which Tracekit doesn't claim.

**What if the operator is malicious?** Whoever holds the log key can rewrite or fork the log; records after the last
cosigned checkpoint are unproven. Detection needs an independent witness and a monitor, plus run-sets to show which runs
exist. Without them, an operator rewriting its own log is expected behaviour, not a vulnerability
([SECURITY.md](../../SECURITY.md)).

**Can the agent forge events?** With its run token, it can report well-formed calls that never happened, and the signer
can't tell them from real ones. Only a record kept outside the agent's process catches them (`reconcile.fabricated` from
the LLM gateway).

**What if the agent never calls the hook?** Nothing records the call. The answer is a layer it must go through: a
mandatory LLM gateway, the executor or MCP gateway holding credentials, or the egress observer
([capture and completeness](capture-and-completeness.md)). A kernel sensor import records what the hidden action did
on the machine, and `tracekit analyze --v2` reports effects no call explains; the sensor's records are its word, and
a root user on the node can change the sensor.

**Isn't a regex gate weak?** As prevention, yes: a determined agent can reword a command. On calls written blind to the
rules (E21), the server pack stops or holds about half the harmful ones. It is deterministic, so a verifier can
recompute every decision, which a model-based judge doesn't allow. Tracekit's contribution is evidence that the gate ran
and what it saw. Pair it with a sandbox to prevent effects.

**Can the timestamps be trusted?** Record times come from the signer host's clock. Independent time comes from witness
cosignatures and the RFC 3161 timestamps on Rekor anchors. Clock skew is a signed gap.

**What leaks?** Arguments and results are commitments, but timing, sizes, counts and checkpoint cadence still show,
Rekor entries are public and permanent, and redaction is pattern-based ([privacy](../privacy.md)).

**Has it been reviewed?** Not externally yet ([review packet](../review-packet.md)), and the experiments are small,
synthetic and written by the project.

## Design decisions

| Decision | Reason |
|---|---|
| A separate signer process | Who can rewrite the log decides what a run is worth; only the signer holds keys, sequence numbers and chain heads |
| Certificate Transparency's design and C2SP formats | A proven design, existing witness software, and a format precise enough for an independent verifier |
| Keyed commitments instead of plain hashes | Short values can't be guessed, and one record can be opened on its own |
| Deterministic rules instead of a model judge | The same policy, engine and arguments always give the same decision, so it can be recomputed |
| Fail closed by default | An early insider test showed an agent could stop the signer and act unrecorded (fixed in 0.2.1) |
| No verifier inside a bundle | The party being checked must not supply the checker or the trust |
| Frozen verifiers and a version gate | Evidence must stay checkable for years; an old verifier says "needs newer", never "failed" |
| Run tokens instead of keys | A capability for one run, in a key domain apart from evidence signatures |
| A chain per run and one for the log | The log chain orders everything; the run chain makes one run's bundle provable with two inclusion proofs |

## Evidence for the design

| Experiment | Result |
|---|---|
| Tamper detection, 8 attacks × 60 trials (E1) | 6 of 8 caught by the signed log alone; truncation and re-signing with the key need a witness; 8 of 8 with one |
| Insider attacks as real users against Linux system mode (E8) | 8 of 8 caught on the v1 signer, 6 of 6 on the v2 signer (including self-approval); both run on every pull request |
| Reconciliation (E10) | 12 of 12 seeded discrepancies flagged, 0 false positives |
| Saved-state tampering (E11) | 21 of 21 caught |
| Tenant isolation (E12) | Every attack refused, no leaks under concurrency |
| Policy packs on the project's corpus (E17) | 699 of 699 harmful calls stopped, 1 false alarm in 797 |
| Policy packs on calls written blind to the rules (E21) | Server pack: 211 of 420 harmful calls stopped or held on the only blind run; 245 with rules added since (the pool is no longer blind); 18 false alarms in 432 |
| Agent approvers (E18) | 7 of 7 attacks caught |
| Unrequested edits behind cover text, checked by `tracekit analyze --v2` (E20, synthetic; the blind pool v3, scored once) | Caught under every cover; after a "don't touch X", 79 to 100% by cover (67 to 92% held before the edit ran); 5 false findings and 1 held call in 1,812 honest calls |
| The v1 regex gate on a rougher set (E3) | 11 of 16 caught: rules are tripwires |

Every experiment and what isn't measured: [evaluation](../evaluation.md).

## Not done yet

- An external review of the threat models.
- A deployed public witness, so independent witnessing needs no setup.
- Capture of services, and of processes beyond the experimental kernel sensor import (Linux, tested against events
  shaped as Tetragon's and Falco's source writes them, not a live sensor).
- Adversarial evaluation with real models, beyond the scripted attacks.
- System mode validated on macOS and Windows, and performance numbers for separate-user and HTTPS signers on Linux.

Every known limit, with what to do about it: [limits](../limits.md).

## Reference

[Threat model (laptop)](../threat-model-laptop.md) · [threat model (server)](../threat-model-server.md) ·
[security checklist](../security-checklist.md) · [SECURITY.md](../../SECURITY.md) · [evaluation](../evaluation.md)

---

Previous: [Integrations](integrations.md) · [All concepts](README.md)
