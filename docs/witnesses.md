# Witnesses (v0.2)

A signature proves who wrote a record. It does not stop the key holder from rewriting the whole ledger and re-signing it. A **witness** is a copy of the ledger head kept somewhere the signer's machine can't quietly change later. At verify time, a bundle's chain must contain every witnessed checkpoint it claims to cover.

## Checkpoint

```json
{"type": "tracekit.checkpoint.v1", "head_seq": 42, "head_hash": "…", "kid": "ed25519:…", "ts": "…", "sig": "…"}
```

Contents: chain head (`head_hash`), counter (`head_seq`), timestamp (`ts`, host clock), signer key id (`kid`), signature over the rest. No event content ever reaches a witness.

Signed with the same key as the records (over the canonical form without `sig`). Checkpoints are written every `checkpoint_every` records (default 50), at every `run.end`, and on signer shutdown. Each one is also written into the ledger as a `checkpoint` event naming the witnesses.

## Trust model per witness type

| Witness | Who controls it | What it retains | What an attacker can still rewrite |
|---|---|---|---|
| git repo with a remote (recommended) | Whoever owns the remote. Recommended: the security team, protected branch, written with a deploy key the agent's user cannot read, no push access for the agent's user | Every checkpoint (head seq, head hash, key id, time, signature) as a commit, forever | Nothing already pushed, unless they can force-push the remote. Records after the last pushed checkpoint are unprotected |
| git repo without a remote | The signer's user on this machine | Same, locally | Root (L4) can rewrite it with the ledger. Protects against the agent's user (L1–L3) only |
| file | Whoever can write the file | Checkpoint lines | Anyone who can write the file; use storage the host cannot rewrite (WORM, another machine's mount) |
| Rekor (off, not implemented) | Sigstore's public log | Would retain hashes publicly and permanently | Would be append-only, but publishing reveals activity timing to everyone; kept off by default |

## Kinds

| Spec | Stores | Trust you get | Tradeoffs |
|---|---|---|---|
| `git:/path/clone[@remote]` (default) | one file per checkpoint in `checkpoints/<kid>/<seq>.json`, committed, pushed if a remote is set | As strong as the remote: if the agent host can't force-push there (protected branch, other account), history before the last push is fixed | Needs a remote to mean anything. Without one it only guards against edits to the ledger that forget the witness |
| `file:/path` | JSON lines appended to a file | Useful for tests, or a file on storage the host can't rewrite (WORM, another machine's mount) | Same machine = little protection |
| `rekor:` | stub | Would give a public transparency log | Off by default; enable with `TRACEKIT_ENABLE_REKOR=1` (not implemented in v0.2). Publishing hashes publicly reveals activity timing |

Unreachable witnesses are retried with backoff. Until one succeeds, the signer records a `capture.gap` saying the checkpoint is "not yet on" that witness, so the delay shows up in bundles.

## What the verifier does

`tracekit verify bundle.tkb --witness git:/path/to/clone`:

| Finding | Result |
|---|---|
| Bundle head is at or before a witnessed checkpoint and the hashes match | pass |
| A witnessed checkpoint's hash differs from the chain at that seq | **fail**: "chain rebuilt after checkpointing" |
| Bundle checkpoint seq beyond the last record | **fail**: truncated |
| Checkpoint signed by a key other than `signer.pub` | **fail**: "signature invalid or wrong key" (replayed checkpoint) |
| Bundle ends between checkpoints while the witness shows the ledger continued | **fail**: truncated (re-export) |
| Witness holds checkpoints but none by the bundle's key | **fail**: bundle re-signed with another key |
| No witness given, or the head isn't witnessed yet | warn (fails under `--strict`); with no `--key` either, the verdict says `UNANCHORED` |

Exit codes: `0` verified, `1` failed, `2` unusable bundle, `3` warnings with `--strict`.

## Choosing one

Put the witness where the agent host has **append-only** access at most: a separate GitHub repo with branch protection written by a deploy key, or a machine you control. A witness the attacker can also rewrite adds nothing against L4 (root on the agent host).
