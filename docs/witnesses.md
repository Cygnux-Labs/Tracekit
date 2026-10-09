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
| git repo without a remote | The signer's user on this machine | Same, locally | Root (A4) can rewrite it with the ledger. In system mode it protects against the agent's user (A1–A3); in dev mode the agent's user owns it and can rewrite it too. Not off-machine |
| file | Whoever can write the file | Checkpoint lines | Anyone who can write the file; use storage the host cannot rewrite (WORM, another machine's mount) |
| Rekor (experimental) | Sigstore's public log | Retains each signed checkpoint publicly and permanently | Append-only and not controlled by the host, but publishing reveals activity timing to everyone; off by default |
| witness service (`tracekit witness serve`) | Whoever runs it: the security team, or a third party | Every checkpoint in an append-only RFC 6962 Merkle log with signed tree heads | Nothing logged, without detection: a second history for a logged sequence number is refused (fork), and readers with a pinned witness key check inclusion proofs. A reader that also keeps a `state=` file checks each new tree head is consistent with the last one it saw, so the operator cannot drop or rewrite entries that reader has already seen. Without `state=`, a rewrite is not detected |

## Witness service

```bash
# on the witness host
tracekit witness init  --home /srv/tkw          # creates the witness key; give witness.pub to signers and verifiers
tracekit witness token box-1 --home /srv/tkw --signer-pub signer.pub     # prints a token once; binds it to that signer key
tracekit witness serve --home /srv/tkw --host 0.0.0.0 --port 8444 --cert c.pem --key k.pem

# signer: publish to it
tracekit init ... --witness 'https://witness.example:8444#token=/var/lib/tracekit/witness.token&key=/var/lib/tracekit/witness.pub'
# verifier: read from it (the witness key must be pinned; state= remembers the last tree head for consistency checks)
tracekit verify run.tkb --witness 'https://witness.example:8444#key=witness.pub&state=~/.tkw-sth.json'
```

| Endpoint | |
|---|---|
| `POST /v1/checkpoints` | token-authenticated; the checkpoint must be signed by the key registered for the token. Returns the index, a signed tree head and an inclusion proof. Same checkpoint again: the same receipt. Different head for a logged sequence number: `409` and a conflict record |
| `GET /v1/checkpoints?after=N` | entries with inclusion proofs against the current signed tree head |
| `GET /v1/sth`, `/v1/consistency?first=&second=` | signed tree head; RFC 6962 consistency proof between two sizes |
| `GET /v1/conflicts`, `/v1/key` | refused forks; the witness public key |

The witness holds checkpoints only (sequence numbers, hashes, key ids, timestamps), never ledger content.

## Kinds

| Spec | Stores | Trust you get | Tradeoffs |
|---|---|---|---|
| `git:/path/clone[@remote]` (default) | one file per checkpoint in `checkpoints/<kid>/<seq>.json`, committed, pushed if a remote is set | As strong as the remote: if the agent host can't force-push there (protected branch, other account), history before the last push is fixed | Needs a remote to mean anything. Without one it only guards against edits to the ledger that forget the witness |
| `file:/path` | JSON lines appended to a file | Useful for tests, or a file on storage the host can't rewrite (WORM, another machine's mount) | Same machine = little protection |
| `rekor:https://rekor.sigstore.dev` | one `rekord` entry per checkpoint (the canonical checkpoint, its Ed25519 signature and the signer's public key) | A public, append-only log the agent host cannot rewrite | Experimental, off unless `TRACEKIT_ENABLE_REKOR=1`. Publishing reveals activity timing. See below |

Unreachable witnesses are retried with backoff. Until one succeeds, the signer records a `capture.gap` saying the checkpoint is "not yet on" that witness, so the delay shows up in bundles.

## Rekor (experimental)

```bash
export TRACEKIT_ENABLE_REKOR=1
curl https://rekor.sigstore.dev/api/v1/log/publicKey > rekor.pem       # pin it once, out of band
export TRACEKIT_REKOR_PUBKEY=$PWD/rekor.pem
tracekit init --dev --witness rekor:https://rekor.sigstore.dev
tracekit verify run.tkb --witness rekor:https://rekor.sigstore.dev
```

Reading is strict: Tracekit finds the signer's entries by public key and accepts one only if it carries a valid
RFC 6962 inclusion proof **and** a signed entry timestamp that verifies against the Rekor key you pinned. With no
pinned key, `verify` refuses rather than trust an unauthenticated response. The Merkle, signature and encoding code
is tested offline against logs generated in the test suite; it has not been run against the live service from the
build environment, so treat the first real run as validation. Entries are public and permanent, and the signer's
public key links all of a signer's checkpoints together.

## What the verifier does

`tracekit verify bundle.tkb --witness git:/path/to/clone`:

| Finding | Result |
|---|---|
| Bundle head is at or before a witnessed checkpoint and the hashes match | pass |
| A witnessed checkpoint's hash differs from the chain at that seq | **fail**: "chain rebuilt after checkpointing" |
| Bundle checkpoint seq beyond the last record | **fail**: truncated |
| Checkpoint signed by a key other than `signer.pub` | **fail**: "signature invalid or wrong key" (replayed checkpoint) |
| Bundle ends between checkpoints while the witness shows the ledger continued | **fail**: truncated (re-export) |
| Bundle ends at its own signed checkpoint after `run.end` that the witness does not hold, while the witness holds a later one | warn: "checkpoint not on the witness" (a missed publish) |
| Witness holds checkpoints but none by the bundle's key | **fail**: bundle re-signed with another key |
| No witness given, or the head isn't witnessed yet | warn (fails under `--strict`); with no `--key` either, the verdict says `UNANCHORED` |

Exit codes: `0` verified, `1` failed, `2` unusable bundle, `3` warnings with `--strict`.

## Choosing one

Put the witness where the agent host has **append-only** access at most: a separate GitHub repo with branch protection written by a deploy key, or a machine you control. A witness the attacker can also rewrite adds nothing against A4 (root on the agent host).
