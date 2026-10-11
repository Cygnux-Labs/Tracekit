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
| v1 witness log (HTTP, `https://` spec) | Whoever runs it | Every checkpoint in an append-only RFC 6962 Merkle log with signed tree heads | Nothing logged, without detection, for a reader that pins the witness key and keeps a `state=` file. Tracekit no longer ships this server: new deployments use the v2 C2SP witness below |

## v1 witness logs

`tracekit verify run.tkb --witness 'https://witness.example:8444#key=witness.pub&state=~/.tkw-sth.json'` still reads an
existing v1 witness log: every entry needs an inclusion proof against a tree head signed by the pinned key, and with
`state=` each new tree head must be consistent with the last one seen. The v1 witness server itself is gone; the v2
signer's witness is a C2SP tlog-witness (below), and the compose stack ships one (docs/deploy-compose.md).

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

## v2: C2SP tlog-witnesses

The v2 signer (`tracekit signer serve`) signs C2SP checkpoint notes of its record log and of each tenant's registry
log, and publishes every new note to the witnesses in signer.yaml with the [tlog-witness](https://c2sp.org/tlog-witness)
`add-checkpoint` call. Each witness's cosignature line is verified and added to the stored note (the note's body never
changes), so bundles exported afterwards carry it.

```yaml
# signer.yaml
witnesses:
  - {url: "https://witness.example.org", vkey: "witness.example.org/w1+1234abcd+BA...", class: customer}
contact: ops@example.org              # the contact line of the logs list
metrics: {listen: 0.0.0.0:9464, allow_remote: true}   # serves GET /logs/v0 to the witness host
```

- `vkey` is the witness's cosignature (type 0x04) verifier key; its name names the witness in metrics and gaps.
  `class` (`public`, `customer`, `tracekit` or `operator`) is copied into the trust config by `tracekit signer trust`.
- Witnesses get the note text and the log's Ed25519 signature only, in at most 10 KiB. A `409` makes the signer resend
  from the witness's size. Failures are retried with backoff, and the retry state is kept in the store
  (`witness-queue.json`), so a restart resumes it. A log a witness has not cosigned for 5 minutes gets one signed
  `capture.gap{kind: witness_failed}` per outage. Metrics: `tracekit_signer_witness_lag_records`,
  `tracekit_signer_witness_publish_failures_total` (docs/observability.md).
- At startup the signer asks each witness for the size it last cosigned; a local log behind it is a rollback.
- The signer's logs list, in the witness network's `logs/v0` format (vkey, qpd, contact per log), is at
  `GET /logs/v0` on the metrics port. A new tenant adds a registry log to it.

**omniwitness** (shipped: the compose stack builds it from a pinned commit, `deploy/compose/witness/Dockerfile`, see
docs/deploy-compose.md; `tests/test_witness_publish.py` runs it when the binary is on PATH; Apache-2.0,
github.com/transparency-dev/witness). Its key file
is a note signing key, `PRIVATE+KEY+<name>+<key id>+<base64(0x01 ‖ Ed25519 seed)>`; it registers the signer's logs by
polling the list:

```bash
omniwitness --listen=:8080 --private_key_path=/etc/omniwitness/key --db_file=/var/lib/omniwitness/w.db \
  --public_witness_config_url=http://signer.internal:9464/logs/v0 --public_witness_config_poll_interval=1m \
  --rate_limit=10
```

**litewitness** (supported, and the compose stack's alternative build; BSD-3-Clause, `go install filippo.io/torchwood/cmd/litewitness@v0.10.0`). Its key lives in
an ssh-agent on a dedicated socket. Register the logs from the list with `witnessctl pull-logs` (from cron, so new
tenants' registry logs are added):

```bash
litewitness -ssh-agent /run/litewitness/agent.sock -key SHA256:<key fingerprint> -name witness.example.org/w1 \
  -db /var/lib/litewitness/w.db -listen :7380
witnessctl pull-logs -db /var/lib/litewitness/w.db -source http://signer.internal:9464/logs/v0
```

litewitness refuses bodies over 10 KiB; omniwitness accepts 16 KiB. Verify with a trust config that pins the witness:
`tracekit signer trust -o trust.json` pins every configured witness with its class, and `tracekit verify` reports
`Assurance: witnessed` once a non-`operator` pinned witness has cosigned the bundle's checkpoint. A signature line from
a key the trust config does not pin is ignored; a pinned witness's bad cosignature fails the bundle.

v2 assurance levels (`dev`, `local`, `witnessed`) describe checkpoint cosigning only, not signer isolation: a same-user
dev signer with a witness verifies as `witnessed`. The witness shows the log was not rolled back or forked after it
cosigned; whether the agent could reach the signer is each run's `signer_isolation` (`same-user`, `separate-user`).

## The public witness

Cygnux runs a free public C2SP tlog-witness, so a team gets `Assurance: witnessed` without running or finding one.

```yaml
# signer.yaml
witnesses: [public]          # or, with your own witnesses: [public, {url: ..., vkey: ..., class: customer}]
```

or `sudo tracekit init --v2 --user AGENT --public-witness` (v2 system mode). `public` expands to the witness's URL and
cosignature vkey from `tracekit/public_witness.py`, with class `public`; until those are set (the witness is not
deployed yet) the signer and `init` refuse it and say so. Off by default.

- **First use.** The witness does not know a new log: it answers `404`, and the signer registers the log (its origin
  and log vkey, proved by a checkpoint signed with that key), then resends. The record log and each tenant's registry
  log register separately. Failures are retried like any witness failure. One key per origin, the first registered:
  a log with a new log key needs a new `origin` in signer.yaml.
- **Pinning.** `tracekit signer trust` pins the witness's vkey with class `public`.
- **What it sees.** Checkpoints only: each log's origin and log vkey, tree sizes and root hashes, the log's signature,
  and when they arrive, so how often and how fast each log grows (docs/privacy.md). Never records or content. It
  keeps, per origin, the key, the latest cosigned size and root and the last cosigning time; `GET /stats` publishes
  only counts (distinct origins cosigned in the last 7 days and per ISO week), which is how Cygnux counts adoption.
- **What it proves.** That the log was not rolled back or forked after the witness cosigned it, independently of the
  signer's operator: the witness never cosigns a tree that is not an extension of the one it last cosigned. It is not
  independent of Cygnux: whoever controls the witness key could cosign anything. For assurance that depends on no
  single party, add a witness you or a partner run (above) and raise `witnesses_required` in the trust config.
- **Limits.** 30 checkpoints per log a minute (a busier log is cosigned at that rate, always its newest note), 100
  registrations per client network (an IPv4 address or IPv6 /64) a day, and a cap on logs in total (docs/limits.md).

Running it: `tracekit public-witness init|serve` and deploy/public-witness/README.md.

## v2: Rekor v2 anchors and RFC 3161 timestamps

The v2 signer can also anchor its record log's checkpoint notes in [Rekor v2](https://blog.sigstore.dev/rekor-v2-ga),
Sigstore's public transparency log, at most once an hour. Each anchor is a `hashedrekord` v0.0.2 entry over the note
bytes (the note text and the log's signature line), signed with a P-256 publishing key (`keys/rekor.key`; Rekor v2
does not accept plain Ed25519), plus an RFC 3161 timestamp of the same bytes from the Sigstore TSA: Rekor v2 entries
carry no time, so the anchor's time is the timestamp's. Rekor's own checkpoint comes back cosigned by public witnesses.

```yaml
# signer.yaml
anchors:
  rekor:
    signing_config: sigstage-signing_config.json   # Sigstore TUF signing_config: the Rekor v2 and TSA write URLs
    trusted_root: sigstage-trusted_root.json       # Sigstore TUF trusted_root: the Rekor shard keys and TSA chains
    every_s: 3600                                  # at least 3600 (at most 24 anchors a day)
```

- **Staging first.** Copy `signing_config.v0.2.json` and `trusted_root.json` from the staging TUF repository
  (`tuf-repo-cdn.sigstage.dev`): its signing config lists the Rekor v2 write URL. Switch to production
  (`tuf-repo-cdn.sigstore.dev`) once its signing config lists a Rekor v2 log (`majorApiVersion: 2`); until then the
  signer refuses to start with it. URLs always come from the signing config, never from Tracekit. The files are pinned
  local copies, not fetched through TUF yet: refresh them when Sigstore rotates a shard (yearly). Entries are public
  and permanent, and the publishing key links all of a signer's anchors.
- Anchoring runs in its own worker, named `rekor`, with the witnesses' retry queue and backoff (`witness-queue.json`,
  so the hourly cadence holds across restarts) and their signed `capture.gap{kind: witness_failed}` when Rekor or the
  TSA fails for 5 minutes. Each answer is verified before it is stored (`anchors.jsonl` in the store). Metric:
  `tracekit_signer_anchor_lag_records`.
- `tracekit export --v2 --run` uses the newest anchored note that covers the run, so the bundle carries its Rekor entry
  (`rekor/<size>.json`) and timestamp (`tsa/<size>.tsr`).
- `tracekit signer trust` adds `"rekor": {"trusted_root", "publishing_key", "class": "public"}` to the trust config.
  `tracekit verify` then checks the anchor offline: the timestamp against the trusted root's TSA certificates, the
  entry binding the exact note bytes and the pinned publishing key, its inclusion proof, and Rekor's checkpoint under
  the key of the shard (found by log id, valid at the timestamp's time) that wrote it. A pinned anchor that does not
  verify fails the bundle; with no `rekor` in the trust config, anchors are ignored. A verified anchor counts toward
  `Assurance: witnessed` unless its class is `operator`, and the report gives its time.

To check a timestamp by hand, use OpenSSL 3 (`openssl ts -verify -data note.bin -in 42.tsr -CAfile tsa-root.pem
-untrusted tsa-leaf.pem`) or `tracekit verify`. The system `openssl` on macOS is LibreSSL, which cannot verify these
tokens (it fails on their ESSCertIDv2 attribute).
