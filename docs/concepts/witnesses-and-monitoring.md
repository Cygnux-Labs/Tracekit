# Witnesses and monitoring

A signed log can prove a lot about itself, but not everything. Two attacks can't be seen from inside: cutting off the
end of the log, and rewriting it with the signing key. Both need someone outside who saw an earlier state. Tracekit
uses the same design as Certificate Transparency for this: independent **witnesses** that cosign checkpoints, and a
**monitor** that reads the log. Both are experimental in 1.2.

## Why a log needs outside help

In the tamper experiment ([E1](../evaluation.md#e1-tamper-detection)), the signed log on its own catches edits,
deletions, swaps, forged insertions, re-chaining without the key and torn lines in 60 of 60 trials each. It catches
**truncating the tail** and **re-signing with the key** in 0 of 60: a shorter log still checks out, and whoever holds the
key can rebuild a consistent one. With a witness holding checkpoints taken every 10 records, all eight attacks are
caught in 60 of 60.

How often you checkpoint matters. Against an attacker who holds the key and edits one record, then re-signs everything
after it, a witness catches the edit every time at checkpoints every 1, 5 or 10 records, 90% of the time every 25, and
82% every 50 or 100: records after the last witnessed checkpoint are the window an attacker can still use.

## What a witness does

The signer sends each new checkpoint to its witnesses using the C2SP tlog-witness protocol, with a **consistency
proof** from the tree size the witness last cosigned.

1. The witness checks the checkpoint's signature with the log key it registered.
2. It checks the consistency proof: the new tree must extend the one it saw before.
3. If both hold, it returns a cosignature with its own timestamp, and stores the new size.

A witness never sees records, only sizes and root hashes, so it learns nothing about what agents did. It never cosigns
a fork or a rollback, because neither extends the tree it already holds. If a witness is behind or doesn't know the
log, the signer resends from the witness's size or registers first. Witnesses that stop answering for five minutes
become a signed `witness_failed` gap.

## Rollback detection

At startup the signer asks each witness for the last size it cosigned. If the local log is shorter than what a witness
has seen, someone rolled the log back: the signer writes `trace.tamper{rollback}` and refuses client writes until an
operator acknowledges it.

## Witness classes

| Class | Who runs it | Counts toward `witnessed` |
|---|---|---|
| `operator` | The party running the signer | No: raises assurance to `local` only |
| `customer` | The customer or auditor | Yes |
| `tracekit` | The Tracekit project | Yes |
| `public` | A public witness | Yes |

The class is set in the verifier's trust config, not by the witness. A public witness server is written (open
registration with rate limits) but not deployed yet, so today independent witnessing means running or arranging one.
Setup: [witnesses](../witnesses.md).

## Rekor and timestamp anchors

At most once an hour, the signer can also anchor a checkpoint in Sigstore's public Rekor log, with an RFC 3161
timestamp. A verifier checks the anchor offline against Sigstore's trusted root. An anchor counts as an independent
cosignature and gives an independent time: the verify report shows the earliest independent anchor. Rekor entries are
public and permanent.

## The monitor

Witnesses check that the tree only grows; they don't read it. `tracekit monitor` does. It follows the log's public tiles
and checks:

- no rollbacks and no forks;
- both chains are intact and the tree rebuilds to the signed root;
- each run has exactly one `run.registered` and one `run.final`, and nothing after it;
- no key appears without being announced;
- registry entries and Rekor anchors match the log.

It signs a report with the size and root it checked, the rules it ran and any conflicts. A verifier given a fresh,
conflict-free report from a pinned independent monitor reaches `witnessed+monitored`. The monitor catches one thing
witnesses can't: an operator showing two different forks to two different verifiers. Setup: [monitor](../monitor.md).

## Not a blockchain

There is no consensus, no token and no mining. It is transparency logging: one writer, a Merkle tree, signed
checkpoints, and independent witnesses and monitors, as in Certificate Transparency and Sigstore. The difference in
Tracekit is that the party being logged (the agent) never holds the key, and the operator running the signer is treated
as a separate adversary that witnesses and monitors keep honest.

## Reference

[Witnesses](../witnesses.md) · [monitor](../monitor.md) · the witness client:
[`tracekit/tlog_witness.py`](../../tracekit/tlog_witness.py) · anchors: [`tracekit/anchor/`](../../tracekit/anchor)

---

Previous: [Verification and assurance](verification.md) · [All concepts](README.md) · Next: [Policy](policy.md)
