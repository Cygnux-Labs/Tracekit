# Storage, durability and performance

The signer sits in the path of every tool call, so it has to be fast, and its log has to survive crashes without
losing what it acknowledged or hiding what it lost. This page explains how records are written and stored, what each
durability mode guarantees, and what the signer costs per call.

## The single writer

Every record goes through one writer thread. It takes up to 512 queued requests at a time and, for each one inside an
undo log, assigns sequence numbers, computes hashes, signs, and appends the records and their Merkle leaves to storage
in one batch. A refused request leaves no partial state behind. If storage fails mid-batch (a disk error, a full disk),
the whole batch rolls back and callers get `unavailable`; when storage recovers, the signer writes a signed
`signer_unavailable` gap. One writer is what lets the signer, not the agent, decide the order of everything.

## Storage backends

| Backend | Layout | Single writer enforced by |
|---|---|---|
| File store | `records.jsonl`, the registry, checkpoints, Merkle tiles and periodic snapshots in the signer's data directory | A lock file |
| Postgres (14 or newer) | Tables for records, registry, notes, tiles and snapshots, written by a role that can only insert | A session advisory lock; each batch is one transaction |

Network filesystems (NFS, SMB, FUSE and the like) aren't supported for the data directory, because file locking and
fsync can't be trusted there; `tracekit doctor` flags one (`D-DATA-FS`).

## Durability modes

| Mode | A call returns after | Risk |
|---|---|---|
| `ack-on-write` (default) | The record is written; the file store syncs within a few milliseconds, Postgres commits asynchronously | A power loss can lose the last acknowledged records |
| `ack-on-fsync` | The record is synced to disk (or the WAL is flushed) | Slower per call |

`tracekit doctor` warns when a production signer uses `ack-on-write`.

## Checks at rest

`tracekit signer fsck` checks every line, hash, both chains, every signature, the registry, checkpoints and tiles. The
signer also runs it in the background once a day; a problem it finds becomes a signed `trace.tamper{edited}`, and client
writes stop until a restart. Every time the store is opened, the last 1,024 signatures are re-verified.

## Crashes and outages

| Experiment | Result |
|---|---|
| `kill -9` of the signer, 30 rounds under 8 concurrent clients (E15) | No acknowledged record lost in either mode; every unacknowledged call either reached the store or is covered by a signed gap. Power loss isn't tested: `kill -9` keeps the operating system's cache |
| Signer down, closed tool class (E14) | 20 of 20 calls blocked |
| Signer down, open tool class (E14) | 20 calls ran, then one signed gap covering them |
| Network partition to an HTTPS signer (E14) | Each call waits the client timeout (one second), then follows its fail mode; afterwards latency returns to normal |
| Disk full (E14) | 41 calls acknowledged, none lost, one `signer_unavailable` gap |
| Witness down (E14) | Signed gaps while it's down; checkpoints cosigned after it recovers |

## Performance

| Measurement | Result |
|---|---|
| v2 signer, file storage, one client calling decide and complete | 0.45 ms median, 0.91 ms p99 per call |
| v2 signer, file storage, throughput with 4 clients | 5,356 events a second |
| v2 signer, Postgres | 0.59 ms median, 5.17 ms p99 per call |
| v2 signer, file storage, `ack-on-fsync` | about 7 ms median, 10 ms p99 per call |
| v1 coding-agent hooks | about 70 ms per hook on Linux, mostly starting Python |
| A real agent app with Tracekit added | 1.6% more wall time |

The signer figures are a short run on one macOS machine and are informational. The design's targets (p99 at most 5 ms
per call, at least 1,000 events a second) are enforced on Linux in CI; on that run Postgres's p99 is just over the
target. Full tables: [evaluation](../evaluation.md) and the [technical report](../../report/tracekit-v2.md).

Default quotas per caller identity: 200 events a second (bursts of 400), 100 open runs, 100 pending approvals, 8
approval waits at once, and 64 event streams per run. Calls a gateway makes for its clients count per gateway and
client, so one agent behind a shared gateway can't use up every other agent's budget. A refusal is
`quota_exceeded` with a retry time, and the refusals of a window are folded into one signed `refusal.summary`.

## Reference

[Deployment: storage and durability](../deploy.md) · [doctor](../doctor.md) · the writer:
[`tracekit/signer/pipeline.py`](../../tracekit/signer/pipeline.py) · storage: [`tracekit/storage/`](../../tracekit/storage)

---

Previous: [Deployment and isolation](deployment.md) · [All concepts](README.md) · Next: [Integrations](integrations.md)
