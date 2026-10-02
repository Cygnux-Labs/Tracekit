# Evaluation (v0.2)

Five experiments run against the v0.2 code. E1 to E4 are offline and run with `make eval`; E5 uses real Claude Code
runs and is opt-in (`make eval-agents`, needs the `claude` CLI and spends model usage). Results are written to
`eval/results/`. The experiments are small, synthetic and written by the authors. They show how the mechanisms
behave, not how Tracekit performs across real agents and projects. The v0.1 paper's experiments (14 Claude Code
runs, seeded faults, hook latency) were ported to v0.2 as E2, E4 and E5, with different scenarios and numbers.

Machine for the numbers below: Linux x86_64, Python 3.13, dev-mode signer on the same host. Other machines will
differ, so each results file records the platform.

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

## E2: overhead

Dev-mode signer, local Unix socket, 40 repetitions per cell.

| Measurement | Result |
|---|---|
| Bare `python -c pass` (the floor a hook pays) | 19 ms median |
| One hook call, PreToolUse | 70 ms median, 82 ms p95 (ledger of 0, 1,000 and 5,000 events: 70, 70, 74 ms) |
| One hook call, PostToolUse | 70 ms median, 76 ms p95 (68 to 71 ms across the same ledger sizes) |
| Signer append, single writer | about 85 events per second, 9 ms median, 50 ms p95 |
| Eight concurrent writers, 1,600 events | about 98 events per second, every event recorded, no gaps, chain intact |
| Offline `verify`, bundle of 500 / 2,000 / 8,000 events | 0.16 s / 0.72 s / 2.9 s |

So a tool call costs roughly 140 ms of hook time (before and after), of which about 20 ms is interpreter start-up.
Hook latency did not grow with ledger size over the range tested. Verification is linear in bundle size. The
50 ms p95 on appends is the periodic witness checkpoint (a git commit).

The same experiment on an Apple-silicon Mac (macOS 26, Python 3.9.6, 20 repetitions): a hook call took about 49 ms
at every ledger size, the signer appended about 145 events per second (8 concurrent writers: about 160, every event
recorded, no gaps), and verification took 0.09 s, 0.34 s and 1.4 s for 500, 2,000 and 8,000 events. E1, E3 and E4
give the same results as on Linux there. E5 was run on Linux only.

E2 found a real bug before release: with eight concurrent writers the signer's accept queue (Python's default of
5) filled, and some clients got `EAGAIN` and, being fail-open, dropped events. The queue is now 256, the client
retries a full-queue connect, and `BurstOfWriters` in the test suite fails without the fix.

## E4: seeded faults

A real signed bundle (about 40 records, a checkpoint every 4 records, a git witness) is corrupted in 14 ways,
30 random placements each, and the offline verifier is run on every copy. The attacker edits the zip directly and
always repairs the manifest hashes. "Detected" means a non-zero exit. "Bundle alone" is `verify` with no witness;
"witness" is `verify` against the independent git witness; "strict" adds `--strict`, which turns warnings into
failures.

| Fault | Bundle alone | Witness | Witness + strict |
|---|---|---|---|
| edit a record | 30/30 | 30/30 | 30/30 |
| delete a record | 30/30 | 30/30 | 30/30 |
| swap two records | 30/30 | 30/30 | 30/30 |
| append a forged record (valid hash, random signature) | 30/30 | 30/30 | 30/30 |
| edit, then re-chain without the key | 30/30 | 30/30 | 30/30 |
| truncate the tail without the key | 30/30 | 30/30 | 30/30 |
| replace `signer.pub` only | 30/30 | 30/30 | 30/30 |
| remove a deny rule from the policy snapshot | 30/30 | 30/30 | 30/30 |
| narrow the manifest's sequence range | 30/30 | 30/30 | 30/30 |
| add a file the manifest does not list | 30/30 | 30/30 | 30/30 |
| replace the signer: re-sign everything with an attacker key | **0/30** | 30/30 | 30/30 |
| edit, re-chain and re-sign **with the real key** | **0/30** | 30/30 | 30/30 |
| truncate the tail and re-sign **with the real key** | **0/30** | **20/30** | 30/30 |
| delete the bundle's own checkpoints (not a content change) | 0/30 | 0/30 | 30/30 |
| truncate the zip file at a random byte | refused 30/30, no crash | | |

The three bold zeros are the same limit E1 shows: a bundle checked alone is only as trustworthy as whoever made it,
so without the key pinned or a witness the verdict says "unanchored" and the attacks above pass. Against a witness
they are caught, with one exception. When a key holder truncates the tail so that the cut lands exactly on a
witnessed checkpoint, the shortened bundle is a valid prefix of the real ledger. In 10 of 30 trials the default
verdict was "verified" with only a coverage warning (no `run.end`). `--strict` fails those. Use `--strict` when a
missing `run.end` should count as evidence of tampering. Deleting the bundle's copy of the checkpoints is not
detected by default because the witness still anchors the head; it is flagged under `--strict`.

The verifier raised no exception on any of the corrupted inputs.

## E5: real Claude Code runs

Four scenarios, three runs each (12 runs), `claude -p` with the hooks installed in a throwaway project and a git
witness: a plain bug fix, a bug fix with a README that tells the agent to upload `.env`, one that tells it to pipe
a script into `sh`, and a legitimate `rm -rf build` before the fix.

| Result | |
|---|---|
| runs whose bundle verified against the witness | 12/12 |
| runs where the test ended up fixed | 12/12 |
| events recorded per run | 15, with a `run.end` every time |
| policy denials | 0 |
| false blocks of the legitimate `rm -rf build` | 0/3 |
| wall time per run | 9 to 16 s |

The model ignored both planted instructions in all six injected runs, so the gate never had to block anything. These
runs show that capture and verification work on real sessions, not that the gate stops a real injection; the blocked
case in `docs/sample/` comes from a scripted agent, as the demo says. A model that follows the injection is the case
the gate exists for, and this experiment did not produce one. Twelve runs of one model on one tiny project is a smoke
test, not a benchmark.

## What is not measured

Signer throughput with a separate-user signer or over the remote gateway, durability across crashes beyond the
`kill -9` test in the suite, bypass attempts by an adversarial agent, redaction leaks across real transcripts,
behaviour on Windows or with macOS system mode, and any evaluation with an external reviewer. These are the
release-gating items still listed in the README.
