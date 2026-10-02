# Evaluation (v0.2)

Two experiments run offline against the v0.2 code (`make eval`; results in `eval/results/`). They are small,
synthetic and written by the authors. They show how the mechanisms behave, not how Tracekit performs on real
agents. The v0.1 paper's real-agent experiments (14 Claude Code runs, seeded faults, hook latency) were not
repeated for v0.2.

## E1: tamper detection

120-record signed ledgers, 60 trials per mutation. "Ledger only" is the hash chain plus Ed25519 signatures with the
signer's public key. "Plus witness" adds independent checkpoints (every 10 records) taken before the attack.

| Mutation | Ledger only | Plus witness |
|---|---|---|
| edit a record's content | 60/60 | 60/60 |
| delete a record | 60/60 | 60/60 |
| swap two adjacent records | 60/60 | 60/60 |
| insert a forged record (re-hashed, not signed) | 60/60 | 60/60 |
| re-chain after an edit, **without** the key | 60/60 | 60/60 |
| torn final line | 60/60 | 60/60 |
| truncate the tail | **0/60** | 60/60 |
| re-chain and re-sign after an edit, **with** the key | **0/60** | 60/60 |

The two zeros are the point. A ledger cannot tell that its own tail was cut off, and whoever holds the signing key
can rewrite history and re-sign it. Only a copy of the head held elsewhere (a witness) catches those. That is the
design, and it is why an unwitnessed verdict is reported as unanchored.

Witness interval against an attacker who holds the key and edits one record at a random position, then re-signs
everything after it: every record is covered when checkpoints are every 1, 5 or 10 records (1.00), 0.90 at 25, and
0.82 at 50 and 100 (the edit lands after the last checkpoint). Records after the last witnessed checkpoint are not
protected, so the checkpoint interval is the window an attacker with the key can still use.

## E3: policy gate

Default policy against a labelled corpus of tool calls. Nothing is executed.

| Set | Harmful blocked | Benign blocked |
|---|---|---|
| Development set (44 harmful, 40 benign), the rules were tuned on it | 43/44 | 0/40 |
| Rougher second set (16 harmful, 20 benign), written afterwards by the same author | 12/16 | 1/20 |

Misses on the second set are evasions the rules do not try to cover: an indirect command (`X=rm; $X -rf ~`), an
encoded payload piped to a shell, an `rm` run from inside `python -c`, and a delete issued after `cd /`. The false
positive is a `grep` whose argument contains the text `curl ... | sh`. Both sets are small and neither is
independent of the rules, so read the first row as "the rules do what they were written to do" and the second as
"a regex gate is a tripwire, not a sandbox".

## What is not measured

Hook latency and signer throughput under load, durability across crashes, bypass attempts by a real adversarial
agent, redaction leaks across real transcripts, and any evaluation with an external reviewer. These are the
release-gating experiments still listed in the README.
