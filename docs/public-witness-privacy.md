# What the public witness sees

The public witness is a free server Cygnux runs. It countersigns each log's size and fingerprint, so that nobody can
rewrite or cut a log unseen afterwards, not even the key holder. This page lists what it receives, what it keeps, what
it publishes, and what it never gets. The code is `tracekit/public_witness_server.py`; on the signer's side,
`tracekit/tlog_witness.py`.

It is not deployed yet. Until it is, no signer sends it anything ([deploying it](public-witness.md)).

## What it receives

A signer sends it two kinds of request, over HTTPS.

**Registration**, once per log, the first time the witness doesn't know it. The body is JSON with three fields:

- `origin`: the log's name. By default `tracekit.local/<log id>`, where the log id is 32 random hex digits.
- `vkey`: the log's public key, named after the origin. It is a public key; the private key never leaves the signer.
- `checkpoint`: a checkpoint of the log, signed with that key, as proof the signer holds the key.

**Checkpoints**, each time the log grows. The body is plain text:

- `old <n>`: the size the witness last countersigned.
- Up to 63 hashes: the proof that the new log extends the old one.
- The checkpoint: the origin, the log's size (how many records it holds), its root hash, and the log's signature.

A growing log sends a new checkpoint about every 10 seconds, and when a run ends, at most once a second. An idle log
sends nothing. Each time the signer starts, it also sends its empty checkpoint, to learn how far the witness has
countersigned.

Each tenant of a signer has a second log, its registry, named `<origin>/registry/<32 hex digits>`. The hex digits come
from a keyed hash of the tenant's name, never the name. A registry log gets a record when a run starts and when it
ends, so its size counts runs. A dev signer has one tenant, so it sends two logs.

The network adds the rest: the signer's IP address, the time of each request, its size, and standard HTTP headers,
among them `User-Agent: Python-urllib/<Python version>`.

## What it keeps

One row per log, in its database:

- the origin and the log's public key;
- the latest size and root hash it countersigned;
- when it registered the log, when it last countersigned, and the week of that.

And one count per week: how many logs it countersigned that week.

It keeps nothing else. It writes no request log. It counts IP addresses in memory for its rate limits, for the current
minute or day only, and never writes them to disk. A log not countersigned for 90 days is deleted, and one never
countersigned within a day of registering.

Caddy, the TLS proxy in front of it, is set up with no access log. Its error log, kept by Docker, can name a client's
address when a request fails at the proxy.

## What it publishes

`GET /stats` returns two counts: how many logs it countersigned in the last 7 days, and how many in each week. It names
no log.

Its other answers go to whoever sends a request. Two of them tell a stranger something:

- Anyone can learn whether a given origin is registered.
- Anyone holding one of a log's signed checkpoints (from a bundle you shared, say) can learn the log's current size.

Verifying a bundle never contacts the witness. `tracekit verify` checks its countersignature offline, against the
witness key in your trust file.

## What it never gets

- Records, tool names, arguments, results, prompts, file paths or any other content.
- Run ids, tenant names, user names, agent names or host names.
- Any private key, your policy, or your signer's `contact` line.

The hashes it gets are Merkle hashes over record hashes. They can't be turned back into records.

## What it can still work out

From what it receives, Cygnux can see:

- **How fast each log grows, and when.** The size and time of every checkpoint show when your agents work and how many
  records they write. A registry log shows how many runs start and end.
- **Which logs belong together.** A signer's logs share one public key, and they come from one IP address.
- **Your name, if the origin carries it.** An origin such as `acme.com/agents` says whose log it is. The signer warns at
  start when it sends a chosen origin to the public witness. Leave `origin` unset on a new log: the default is random.

The hosting company's network sits in front of the witness. It sees your IP address and the timing and size of each
request, and it may keep its own network logs. Tracekit doesn't control them. To hide your address, give the signer an
`HTTPS_PROXY`, or run your own witness.

To send nothing at all, opt out with `--no-witness` (`tracekit init --v2`, `tracekit up`). Then whoever holds the
signing key can rewrite the log unseen, and its bundles verify as `NOT ANCHORED`. [Witnesses](witnesses.md) explains how
to run your own instead.

The limits on this page are rows in [limits](limits.md#privacy).
