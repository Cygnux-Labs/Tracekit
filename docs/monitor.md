# Log monitor (`tracekit monitor`)

Witnesses check that a log only grows. They don't read its records, so they can't see a run finalised twice, a record
after a `run.final`, a second registration of a run id, or a key retired that nobody announced. A **monitor** reads
every record and checks those rules, then publishes a signed report. A verifier that pins the monitor uses a fresh,
conflict-free report to raise `witnessed` to `witnessed+monitored`.

## Run it

The signer serves its logs read-only on the metrics port. The record log's entries are every tenant's records (run
ids, tool names, commitments), so the signer serves them only with `serve_records: true`; checkpoints, hash tiles and
the salted registry logs are always served. Keep that port private to the monitor (`metrics: {listen: ...,
serve_records: true}` in signer.yaml; `allow_remote: true` to serve a monitor on another host):

```bash
tracekit signer vkey --config signer.yaml > log.vkey
tracekit monitor --log http://signer.internal:9464 --log-key "$(cat log.vkey)" --state /var/lib/tracekit-monitor
# with Rekor anchors: the same trusted_root the signer uses, and its publishing key (data_dir/rekor.pub)
tracekit monitor ... --rekor trusted_root.json --publishing-key "$(cat rekor.pub)"
```

The monitor polls every 60 s (`--every S`, or `--once`: exit 0 when clean, 1 with conflicts, 2 when the poll could
not finish). Its key is `DIR/monitor.key`, created on first use (`--key FILE` to bring one); `DIR/monitor.vkey` is
the key a verifier pins. Run it somewhere the signer's operator can't change: a monitor they control vouches for
nothing.

`--allow KID` (repeatable) names a record key the log may declare in a later `signer.epoch` or retire with
`key.retire`. Keys of the log's first record are always allowed. Anything else is a conflict.

## What it checks

Each poll reads the record log's checkpoint, checks its signature, and checks it against the last one seen. A smaller
tree is a **rollback**. A tree that does not extend the last one (another root at its size) is a **fork**. Both are conflicts and keep both
signed notes as evidence. The monitor then fetches the new records, rebuilds the tree and checks it matches the
checkpoint. Each tenant's registry log in `/logs/v0` is read the same way. Then, over every record seen so far:

| Rule | Conflict |
|---|---|
| log chain | a `seq` or `prev_hash` that does not continue the log; a record whose hash is not its event's |
| run chain | a `run_seq` or `run_prev_hash` that does not continue its run |
| one run.registered per run | a second `run.registered` for a run id |
| one run.final per run, nothing after it | a second `run.final`; any record after a run's `run.final` |
| run.final head | a `run.final` whose head is not the run's last record |
| key announcements | a `signer.epoch` key or `key.retire` for a kid not passed with `--allow` |
| registry leaves | a leaf that points to no record of that type and hash, or two leaves for one record in a registry, or two run hashes for one run; a `run.registered` or `run.final` still without a leaf one poll after it was seen |
| rekor anchors (with `--rekor`) | an anchor the signer serves that doesn't verify or isn't of the log; an entry under the publishing key, in the Rekor shards the anchors are in, that matches no anchor one poll after it was seen |

Conflicts stay in the report once found. State (`DIR/state.json`, the trees in `DIR/tiles/`) is saved after each poll,
so a restarted monitor carries on from where it stopped.

A Rekor entry the signer wrote but never got a reply for (a timeout after the write) matches no stored anchor, so it
shows up as a conflict too. Check the signer's `witness_failed` gaps for that Rekor outage before treating it as
misbehaviour.

## The report

`DIR/report.json`, rewritten each poll:

```json
{"report": {"format": "tracekit.monitor.report.v1", "origin": "tracekit.example.org/log/1", "checked_size": 1042,
            "checked_root": "<base64>", "time": "2026-10-10T12:00:00Z", "conflicts": [{"rule": "...", "detail": "..."}],
            "rules_checked": ["checkpoint consistency", "..."]},
 "sig": "<base64 Ed25519 over 'tracekit monitor report v1\n' + JCS(report)>"}
```

Serve it as a static file (for example `python3 -m http.server --directory DIR`) so auditors can fetch it.

## Verifying with it

Pin the monitor in the verifier's trust config. Reports come from the verifier's side, never from a bundle:

```json
{"logs": ["..."], "algs": ["ed25519"], "witnesses": [...],
 "monitors": [{"vkey": "tracekit-monitor+1a2b3c4d+AQ...", "class": "customer", "max_age_s": 3600}]}
```

```bash
tracekit verify run.tkb --trust trust.json --monitor-report report.json
```

A report counts when a pinned monitor signed it, it is no older than `max_age_s`, it is for the bundle's origin, it
was checked to at least the checkpoint's size, it lists no conflicts, and its monitor is not classed `operator`. A counting report raises `witnessed` to
`witnessed+monitored`. It never raises `dev` or `local`. If a pinned monitor reports conflicts for the origin, or a
different root at the checkpoint's size, `monitor` fails and the conflicts are listed. A stale, unpinned or
not-yet-covering report is a warning and is ignored.

## Signer endpoints

On the metrics port, read-only, in the C2SP tlog-tiles layout:

| Path | |
|---|---|
| `/checkpoint` | the record log's latest note, with cosignatures |
| `/tile/<L>/<N>[.p/<W>]` | hash tiles |
| `/tile/entries/<N>[.p/<W>]` | records, as JSON lines, one per line (a record can be longer than C2SP's uint16 length prefix) |
| `/registry/<id>/checkpoint`, `/registry/<id>/tile/...` | each tenant's registry log (origin `<origin>/registry/<id>`); entry bundles are C2SP's |
| `/anchors` | the stored Rekor anchors, as JSON lines |
| `/logs/v0` | the logs list (record log and registries) |

The records hold tenant names, run ids, tool names and keyed digests of arguments, never the arguments themselves
([privacy.md](privacy.md)). Expose the port only to the monitor.
