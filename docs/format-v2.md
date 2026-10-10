# Evidence format v2

This page specifies `tracekit.bundle.v2` and the records, trees and checkpoints inside it. It aims to be precise enough
to write an independent verifier. The reference implementation is `tracekit/format/`, `tracekit/merkle/`,
`tracekit/bundle_v2.py` and `tracekit/verify/v2.py`; where this page and the code disagree, the code is right and
this page has a bug. v1 bundles (`tracekit.bundle.v1`) keep their own frozen format and verifier
([signing](signing.md)); nothing here changes how they verify.

Normative test vectors:

| Vectors | What they pin |
|---|---|
| `tests/vectors/jcs.jsonl` | canonical JSON: input, canonical bytes, SHA-256 |
| `tests/vectors/sig_v2.jsonl` | records (event, signature message, signed record) and the Ed25519 acceptance rules |
| `tests/vectors/c2sp_checkpoint.json` | a checkpoint note, its log signature and a witness cosignature |
| `tests/vectors/slh_dsa_note.json` | a hybrid checkpoint note: Ed25519 and SLH-DSA-SHA2-128s lines, keys, key ids |
| `tests/golden/v2/` | bundles (closed, open, approval, run-set) with `trust.json` and the expected report |
| `tests/golden/negative/` | one bundle per rejection, with the expected report in `expected.json` |

Every worked example on this page is checked against the code by `tests/test_format_doc_vectors.py`.

## 1. Canonical JSON

Everything hashed or signed is canonical JSON: [JCS, RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (keys sorted by
UTF-16 code units, no whitespace, ECMAScript number serialisation, minimal string escapes, UTF-8 output). Example:

```text
{"b":1,"a":[1.0,"é",1e21]}  →  {"a":[1,"é",1e+21],"b":1}
```

Every JSON text a verifier reads from a bundle or trust config, and the raw arguments a client sends, are parsed by a
strict parser (`format.canon.loads_strict`) that rejects input JCS could hash differently in different languages:

| Rejected | Error code |
|---|---|
| bytes that are not UTF-8 | `invalid_utf8` |
| anything that is not one JSON text | `syntax` |
| a key twice in one object | `duplicate_key` |
| `NaN`, `Infinity`, `-Infinity`, or a number that overflows to them | `non_finite` |
| an integer token (no `.` or exponent) above 2^53 − 1 in magnitude, or longer than 16 digits | `int_range` |
| a string or key with a lone UTF-16 surrogate (`"\ud800"`) | `lone_surrogate` |

Send larger integers as strings. A tool call whose raw arguments fail strict parsing is denied with rule
`TK-ARGS-INVALID` and gets no `args_commitment` ([policy](policy-v2.md)).

## 2. Hashes over agent content

The signer never publishes a plain hash of something the agent sent. It publishes a **commitment**, an HMAC that only
someone holding the record's salt can test a guess against.

- **Arguments digest:** `"sha256:" + hex(SHA-256(JCS({"tool": <tool name>, "args": <arguments>})))`, over the arguments
  as parsed (raw arguments are parsed strictly first).
- **Content digest:** `"sha256:" + hex(SHA-256(JCS(value)))` of a result, model exchange or state write, after the
  signer's redaction ([privacy](privacy.md)).
- **Salt:** `HMAC-SHA256(args_salt.key, label)`, where `args_salt.key` is the signer's secret (`keys/args_salt.key`) and
  `label` is fixed per record: `<type>:<salt_id>` when the record's `data` has a `salt_id` (current records), else
  the older labels in `pipeline.salt_label` (the `decision_id` for `policy.decision`, `"result:" + decision_id` for
  `tool.result`).
- **Commitment:** `"hmac-sha256:" + hex(HMAC-SHA256(salt, UTF-8 bytes of the digest string))`.

Worked example (salt = bytes `00 01 02 … 1f`):

```text
tool  Bash
args  {"command":"ls -la"}
JCS   {"args":{"command":"ls -la"},"tool":"Bash"}
digest      sha256:b7c38435fe712f5634b07e925ba451b8281b9c1480a7df201a2855d9ab409f64
commitment  hmac-sha256:b0793fcab9cccb7a6ae4a79f07a4b2d324f04e9fe51df1bd38fdeb0ff4e98d99
```

`tracekit signer reveal --record SEQ` prints the salt of one record ([auditor guide](auditor-guide.md)). One salt opens
one record's commitments and nothing else.

## 3. Events

An event is a `tracekit.event.v2` object, validated by `tracekit/schema/tracekit.event.v2.json` (JSON Schema 2020-12;
patterns are full-match ASCII; every string and array is bounded). It adds to v1:

| Field | Set by | Meaning |
|---|---|---|
| `log_id` | signer | the record log, 32 hex |
| `seq`, `prev_hash` | signer | position in the log and the previous record's `hash` (`sha256:` + 64 zeros at seq 0) |
| `tenant`, `run_id` | signer | the run; signer-level records use tenant `tracekit`, run `tracekit/signer` |
| `run_seq`, `run_prev_hash` | signer | position in the run and the run's previous record hash (zeros at run_seq 0) |
| `tenant_attested`, `principal`, `principal_attested` | signer | whether tenant and principal came from the caller's verified identity |
| `request_id`, `stream`, `client_seq` | client | idempotency key and per-stream counter; a skipped `client_seq` becomes a signer gap |
| `tool_call_id`, `attempt` | client | the call a record is about |
| `tier` | signer | `T1`/`T2`/`T3` evidence tier, when known; OTLP imports are `T3` |
| `step`, `capture_layer` | — | defined by the schema; the signer does not write them yet |
| `args_commitment`, `args_source` | signer | the commitment (§2) and whether arguments were `raw`, `parsed` or `coerced` |
| `engine` | signer | the policy engine `id@version` |
| `span_id` | signer | the OTel span an imported record came from |

`source` is `hook`, `proxy`, `transcript`, `signer`, `sdk`, `migrated` or `import`. Gap and tamper records
(`capture.gap`, `trace.tamper`) are written only with `source: signer`; the `kind`s are listed in the schema's
`capture_gap` and `trace_tamper` definitions. A gap marked `tenant_level: true` (`witness_failed`, `witness_late`,
`clock_skew`, `degraded_unanchored`, and rollback tamper records) concerns every tenant (§7).

Lifecycle records: `run.registered` (agent, the caller identity, `signer_isolation` and `fail_modes` from the signer's
own measurement and config), `run.closing`, the run's `reconcile.*` records, then `run.final{head_run_seq, head_hash,
coverage}`. Key records: `signer.epoch{keys: [{kid, alg, spki, cert?}], bridge?}` (`cert`: the key's issuance entry from a
record-key issuer, [issuer.md](issuer.md)) and `key.retire{kid, last_seq}`. The log's
last record, if it is ever closed: `log.closed{final_seq}`.

## 4. Records and the signature message

A record is one line of JSON:

```text
{"v": 2, "event": <event>, "hash": "sha256:<hex>", "alg": "ed25519", "kid": "sha256:<hex>", "sig": "<base64>"}
```

- exactly these six keys; `v` is the integer 2;
- `hash` = `"sha256:" + hex(SHA-256(JCS(event)))`;
- `kid` = `"sha256:" + hex(SHA-256(DER SubjectPublicKeyInfo))`, so it binds the key's algorithm too;
- `sig` = standard base64 of the signature over the **signature message**.

The signature message is JCS of an object holding the record's position fields, its `alg`, `kid` and `hash`, and the
domain tag `"t"`:

```text
JCS({alg, kid, log_id, seq, prev_hash, tenant, run_id, run_seq, run_prev_hash, hash, "t": "tracekit.record.v2"})
```

Each signature purpose has its own tag, so a signature made for one purpose never verifies as another. Only `record`
is used today; the others are reserved:

```text
{"t":"tracekit.record.v2"}
{"t":"tracekit.checkpoint.v2"}
{"t":"tracekit.approval.v2"}
{"t":"tracekit.cert.v2"}
{"t":"tracekit.retire.v2"}
{"t":"tracekit.export.v2"}
```

Worked example: the first record of `tests/vectors/sig_v2.jsonl` (`record-signer-epoch`) has the signature message

```text
{"alg":"ed25519","hash":"sha256:db5045e1f08ce84b3f4af68706546c4db460adbef48568a7206ba5cc73f73dc6","kid":"sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9","log_id":"0123456789abcdef0123456789abcdef","prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","run_id":"run-1","run_prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","run_seq":0,"seq":0,"t":"tracekit.record.v2","tenant":"acme"}
```

**Algorithms.** `alg` must be in the verifier's pinned allow-list (`algs` in the trust config) **and** be the key's own
algorithm (`ed25519` for an Ed25519 SPKI); a mismatch is algorithm confusion and fails. Ed25519 is verified under strict
rules, identical on every backend: `S < L`, a canonically encoded public key that is not of small order, and the
cofactorless equation `[S]B = R + [k]A` (`crypto.verify_v2`; vectors `ed25519-*` in `sig_v2.jsonl`).

**Key epochs and positional retirement.** Record keys are declared by `signer.epoch` records in the log itself. A key
is valid from the seq of the `signer.epoch` that declares it up to `last_seq` of a later `key.retire{kid, last_seq}`
for it, inclusive; with no retirement, from then on. A record is valid only under a key valid at its own `seq`. A record
signed by a retired key after its `last_seq` fails, and the report names the retired key. The signer writes one
`signer.epoch` as the log's first record; with a record-key issuer, a `signer.epoch` and the previous key's
`key.retire` (`last_seq`: the record before the epoch) at every start and before the certificate expires
([issuer.md](issuer.md)).

## 5. Trees and tiles

Each log is an [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) / RFC 9162 Merkle tree (`tracekit/merkle`):

```text
leaf hash  = SHA-256(0x00 ‖ data)
node hash  = SHA-256(0x01 ‖ left ‖ right)
empty tree = SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The **record tree**'s leaf `seq` has as data the 32 raw bytes of record `seq`'s `hash`. For `record-signer-epoch`:

```text
leaf hash = SHA-256(0x00 ‖ db5045e1…3dc6) = 252e000747132185f241d03274ef087f1eccb5d708dc18b49c9d990f21059060
```

Inclusion and consistency proofs are verified as in RFC 9162 §2.1.3.2 and §2.1.4.2.

The signer stores tree hashes as tiles, in the [tlog-tiles](https://c2sp.org/tlog-tiles) layout: tile (level L,
index N, width w ≤ 256) holds w consecutive hashes at tree height 8·L, starting at hash 256·N, as concatenated
32-byte hashes, at `<level>/<index>.<width>` (`merkle/tiles.py`). Full tiles never change. Tiles are storage, not
evidence: a bundle carries proofs, not tiles.

## 6. Checkpoints

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note) in the
[tlog-checkpoint](https://c2sp.org/tlog-checkpoint) format, cosigned per
[tlog-cosignature](https://c2sp.org/tlog-cosignature) (all v1.1.0; `format/checkpoint.py`):

```text
<origin>\n<tree size>\n<base64 root hash>\n\n— <key name> <base64(key id ‖ signature)>\n...
```

- The **log key** (`keys/log.key`, Ed25519, stable, signs notes only) is named after the origin (default
  `tracekit.local/<log_id>`). Its line is type 0x01: Ed25519 over the note text (everything up to and including the
  newline after the root).
- A **witness** cosigns with type 0x04: `8-byte big-endian timestamp ‖ Ed25519("cosignature/v1\ntime <t>\n" + text)`.
- **Key id** = first 4 bytes of `SHA-256(name ‖ 0x0A ‖ type ‖ public key)`. Keys are pinned as **vkeys**:
  `<name>+<hex key id>+<base64(type ‖ public key)>`.
- A verifier ignores signature lines of keys it does not pin (unknown types too) and rejects the note when a pinned
  key's signature fails, when one key signs twice, or when no pinned log key named after the origin signed it.
  Limits: 1 MiB note, 64 signature lines, canonical base64, tree size without leading zeros.

Worked example (`tests/vectors/c2sp_checkpoint.json`): note text

```text
tracekit.example.org/log/0190f3a0-test
13
Mi7CJiZLruMIePTlzHPx4mYt0B1o8dZ+0VjPECnCnOY=
```

signed by `tracekit.example.org/log/0190f3a0-test+070965d6+AZsfhHkc/HZjBFhU04netcqVRJ2HXydqg4QLBgqznPxx` (key id
`070965d6`) and cosigned by `witness.example.org/w1+257cc7f1+BGG3op9v3HIXXDPBmFc/0CioJHhGCXc+pyvvFPlBZdYO`.

The signer signs a record-tree note after each `run.final`, on `checkpoint_nudge`, every 10 s while the tree grows and
on close, then one note per tenant registry that grew. How witnesses are run and pinned: [witnesses](witnesses.md).

### Hybrid checkpoint signature

With `log_key: {slh_dsa: {file: keys/log-slh.key}}` in signer.yaml, every stored note (record tree and registries)
carries a second log line after the Ed25519 one, from a stateless hash-based key: SLH-DSA-SHA2-128s
([FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)), pure mode, empty context, over the same note text
(`format/slh_dsa.py`, pure Python, no native dependency). Records stay Ed25519; a record is covered long-term through
the tree root the SLH-DSA line signs.

- The line has type **0xff** and the same key name as the log line. Its "public key" is
  `"tracekit/slh-dsa-sha2-128s" ‖ PK.seed ‖ PK.root` (26 + 32 bytes), so the key id is
  `SHA-256(origin ‖ 0x0A ‖ 0xff ‖ "tracekit/slh-dsa-sha2-128s" ‖ pub)[:4]` and the vkey
  `<origin>+<hex key id>+<base64(0xff ‖ "tracekit/slh-dsa-sha2-128s" ‖ pub)>`. The signature is 7856 bytes (a line of
  about 10.5 KB).
- **Never sent to witnesses** (litewitness caps requests at 10 KiB, omniwitness at 16 KiB) or to Rekor: they get the
  note text and the Ed25519 line only. It is in the stored note and in bundles.
- A verifier that does not pin the hybrid key ignores the line, so old verifiers read new notes. One that pins it
  (`tracekit signer trust` pins both keys, `tracekit signer vkey` prints both) requires **both** a valid Ed25519 line and
  a valid SLH-DSA line from the origin's pinned keys; a note without the line, or with either line bad, fails
  `checkpoint`. Notes signed before the key was configured have no line and fail against a trust config that pins it.
- Cost: signing takes about 1 s of CPU per note (pure Python; about 0.8 s on an Apple M-series core), once per tree that
  grew, at most once per second per tree; verifying takes about 1 ms. The signer signs notes off the writer thread.

Worked example (`tests/vectors/slh_dsa_note.json`): the note text above, signed by the Ed25519 key above and by
`tracekit.example.org/log/0190f3a0-test+b412f80c+/3RyYWNla2l0L3NsaC1kc2Etc2hhMi0xMjhzP2n4dHiz4830nh9Ilj+5EtFbGqwUwJGvStS72PP3Q7g=` (key id `b412f80c`).

## 7. Registry logs and run-sets

Each tenant has a **registry log**, a second tree whose leaves are fixed-width (89 bytes, `format/registry.py`):

```text
type u8 ‖ H(tenant_salt ‖ run_id) 32B ‖ record log_id 16B ‖ seq u64 big-endian ‖ record hash 32B
```

| type | record |
|---|---|
| 1 | `run.registered` |
| 2 | `run.final` |
| 3 | `log.closed` |
| 4 | `key.retire` |
| 5 | `capture.gap` (tenant-level only) |
| 6 | `trace.tamper` (tenant-level only) |

`run.registered` and `run.final` get a leaf in their run's tenant's registry; `log.closed`, `key.retire` and
tenant-level gaps get one in every tenant's registry. `tenant_salt = HMAC-SHA256(registry salt, tenant)`, `H` is
SHA-256. The registry's checkpoint origin is `<record log origin>/registry/<first 32 hex of SHA-256("registry " ‖
tenant_salt)>`, signed by the same log key, so the origin never carries the tenant's name. Worked example (registry
salt = 32 zero bytes, tenant `acme`, log origin `tracekit.example.org/log/1`):

```text
tenant_salt        c9a7e476bacbbf87e60c30ba2612595b5a1a0bd1dcb1ba8dbd37c30be1fec8a8
H(salt ‖ "run-1")  34bc0067fd0081b5c0324ba1e799cd769f8542cd42b0b2c699751ce63fb9d00f
registry origin    tracekit.example.org/log/1/registry/62d28187e34b4d26bb63c6d6f490e8b3
```

A **run-set** is the range of registry leaves `a..b−1` between two registry checkpoints. It proves which runs of the
tenant were registered and finalised in that window: a run deleted, a second `run.final`, or a withheld `key.retire`
shows as a missing or extra leaf. A bundle with a run-set carries the tenant salt, so its holder can test guessed run
ids against this tenant's leaves; other tenants' leaves stay opaque.

## 8. Anchors

With `anchors.rekor` configured, the signer anchors record-tree notes in Rekor v2 at most once an hour: a
`hashedrekord` v0.0.2 entry over the note text and the log's signature line, signed with a P-256 publishing key
(`keys/rekor.key`), plus an RFC 3161 timestamp of the same bytes, which gives the anchor its time. The verifier checks
it offline against a pinned Sigstore `trusted_root` and publishing key (`tracekit.anchor.rekor2`). Setup:
[witnesses](witnesses.md#v2-rekor-v2-anchors-and-rfc-3161-timestamps).

## 9. Bundle layout

A bundle is a zip. The manifest is an index and is never trusted: every file it lists must hash as listed, and the
bundle may hold nothing else.

```text
manifest.json             {"format": "tracekit.bundle.v2", "verifier_min_version": "0.4.0", "files": {name: sha256 hex}}
runs/<id>.jsonl           one run's records in run_seq order; id = first 32 hex of SHA-256("<tenant>/<run_id>")
keys/records.jsonl        every signer.epoch and key.retire record the checkpoint covers
proofs/records.json       {"checkpoint": "checkpoints/<size>.note", "tree_size": n,
                           "inclusion": {"<seq>": [base64 hash, ...]}}: inclusion of each run's first and last record,
                           every key record, and every record a registry leaf points to
checkpoints/<size>.note   the record-tree note the proofs are against
rekor/<size>.json         its Rekor v2 TransparencyLogEntry, when anchored
tsa/<size>.tsr            its RFC 3161 timestamp response, when anchored
policies/<sha256>.json    policy snapshots, named by the SHA-256 of their bytes
```

A run-set bundle adds:

```text
registry/run-set.json     {"tenant_salt": base64, "from": a, "to": b, "consistency": [base64 hash, ...],
                           "leaves": [{"leaf": base64, "inclusion": [base64 hash, ...]}, ...]}
registry/records.jsonl    the record each leaf points to, in leaf order
checkpoints/registry-<n>.note   the registry notes at a (none when a = 0) and b
runs/                     every run whose run.final is in the range, and the selected run, if any
```

JSON lines files end in a newline, one strict JSON text (§1) per line, each line at most 1 MiB. Zip limits: at most
10,000 entries, 64 MiB per entry, 512 MiB in total; entry names match `[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*`
with no `.` or `..` segment; no symlinks; no duplicate names. A bundle carries no code and no trust configuration.

## 10. The trust config

The verifier pins its own trust, never the bundle's (`verify.v2.load_trust`):

```json
{"logs": ["<log vkey>", "<hybrid SLH-DSA log vkey, optional>"],
 "witnesses": [{"vkey": "<cosignature vkey>", "class": "public|customer|tracekit|operator"}],
 "algs": ["ed25519"],
 "witnesses_required": 0,
 "rekor": {"trusted_root": {}, "publishing_key": "<base64 SPKI>", "class": "public"}}
```

`logs` and `algs` are required and non-empty; `witnesses`, `witnesses_required` (default 0) and `rekor` are optional.
No other key is allowed. `tracekit signer trust -o trust.json` writes one for a signer; an auditor should build theirs
from independent sources ([auditor guide](auditor-guide.md)).

## 11. Verification algorithm

`tracekit verify bundle.tkb --trust trust.json` (`verify.v2.verify`). Each step adds report lines; the meaning of each
line and verdict is in [verdicts](verdicts.md).

1. **Trust config.** Parse strictly; check the keys and types of §10; parse every vkey. Failure: exit 2.
2. **Read the zip** under the limits of §9. Parse `manifest.json`; `format` must be `tracekit.bundle.v2` and
   `verifier_min_version` a version number not above the verifier's own, else `UNVERIFIABLE (needs tracekit >= x)`.
   Failure: `UNUSABLE BUNDLE`, exit 2.
3. **Manifest.** The listed files and hashes must equal the files present, exactly (`manifest`).
4. **Checkpoint.** Open the note named by `proofs/records.json` (§6) with the pinned log keys (both lines when a hybrid
   key is pinned) and witness keys; its tree size must equal `tree_size` (`checkpoint`). Count the pinned cosignatures
   against `witnesses_required` (`witness quorum`). If the trust config pins `rekor` and the bundle has `rekor/<size>.json`, verify the anchor
   (`rekor anchor`).
5. **Keys.** Walk `keys/records.jsonl` in increasing seq: each must be a `signer.epoch` or `key.retire` record included
   in the checkpointed tree; each declared key's `kid` and `alg` must match its SPKI; each record must verify (§4)
   under the keys valid at its seq; a `key.retire` must name a declared key and sets its `last_seq`. All records must
   share the first key record's `log_id`. A key with `cert` is declared only if its certificate verifies under a
   pinned issuer, for that key and `log_id`, in the issuer's cosigned issuance log ([issuer.md](issuer.md)).
6. **Runs.** A bundle holds exactly one `runs/` file, or any number with a run-set. For each run, every record must:
   verify under the keys valid at its seq (§4); be a schema-valid `tracekit.event.v2` event of this `log_id`; have
   `run_seq` = its index, `run_prev_hash` = the previous record's `hash` (zeros first), the first record's tenant and
   run_id, a seq above the previous record's; and follow no `run.final`. The run's first and last records must be
   included in the checkpointed tree.
7. **Run-set** (with `registry/run-set.json`). Open the registry notes at `a` and `b` with the pinned log key renamed
   to the registry origin of §7; check consistency `a → b`; require `b > 0` and exactly `b − a` leaves, each included
   in the registry tree at `b`, each pointing to a record in `registry/records.jsonl` with that hash, seq, type,
   log_id and run hash, included in the record tree. One `run.final` per run; every run final in the range present in
   the bundle from its `run.registered` (when in the range) to that `run.final`; every bundled run but one the target
   of a leaf. Every `key.retire` leaf in the range must be among the key records. A `log.closed` in the range must be
   the checkpoint's last record, or later records were added after the log closed.
8. **Format bridge** (with `--v1-ledger`/`--v1-key`, §12).
9. **Policy snapshots.** Each `policies/` file is named by its own SHA-256.
10. **Verdict.** Any failed line: `FAILED`, exit 1. Otherwise `VERIFIED`, `VERIFIED TO HEAD n (open)` for one open
    run, or `VERIFIED (k run(s) open)`. Then the informational lines (policy, coverage, tiers, args source, isolation,
    fail-open classes, key assurance, break-glass approvals) and the assurance level. Exit 0, or 3 with `--strict`
    when any line is a warning.

A malformed bundle never crashes the verifier: anything unexpected is a failed `bundle structure` line.

## 12. v1 → v2 bridge

`tracekit signer bridge` continues a v1 ledger in a v2 log without rewriting either (`signer/format_bridge.py`):

1. The v1 ledger gets two last records, signed with the v1 key: `capture.gap{kind: format_upgrade}`, then the key's
   retirement as a v1-valid `capture.gap{kind: key_retire, reason: "key.retire kid=<v1 kid> last_seq=<its seq>"}`.
2. The v2 log's first record is `signer.epoch{bridge: {v1_kid, v1_last_seq, v1_head}}`, where `v1_head` is the hash
   of step 1's last record.
3. The v1 signing key is overwritten and deleted.

`tracekit verify bundle.tkb --trust trust.json --v1-ledger ledger.jsonl --v1-key signer.pub` then checks that the v1
chain verifies by v1 rules up to `v1_last_seq`, that its last record is the retirement of `v1_kid` with hash `v1_head`,
and that no v1 record follows it. The frozen v1 verifier sees the two bridge records as ordinary signer gaps and can't
tell a later v1 record from a genuine one; only this check reports it.
