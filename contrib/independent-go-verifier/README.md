# Tracekit issue #260: independent Go verifier

> **Experimental:** this verifier is not part of the stable core and has not had a production security audit.

This dependency-free Go implementation reads evidence offline without invoking either existing verifier. Its development consulted the Python verifier and golden corpus, so it does not establish whether the specification alone is sufficient to write a verifier. The embedded event schemas are public format data copied from the repository schemas.

## Current coverage

- Strict JSON parser: UTF-8, duplicate keys, lone surrogates, nesting limit, unsafe integer tokens, nonfinite numbers and trailing data.
- RFC 8785 JCS: UTF-16 key ordering, ECMAScript binary64 formatting, minimal string escapes.
- Record envelopes and SHA-256 event hashes; SHA-256 SPKI key IDs; domain-separated Ed25519 messages; cofactorless Ed25519 verification and rejection of noncanonical/small-order keys.
- RFC 6962 / RFC 9162 record Merkle leaf, node and inclusion proof verification.
- C2SP signed checkpoint notes, log vkeys, witness cosignatures, duplicate signature-key rejection, one witness per key and per name (a trust config pinning one witness key under two names, two keys under one name, or one key with two classes is refused) and witness quorum.
- Rigid ZIP layout and limits, manifest file hashes and only the file names format-v2 §9 allows, record-key epochs and retirement positions, per-run hash chains, multi-part run concatenation and first/last/key-record inclusion proofs.
- CLI input caps: bundles and v1 witness files are limited to 512 MiB; trust and v1 public-key files are limited to 1 MiB.
- Cryptographic registry run-set checks: derived-origin signed checkpoints, RFC 9162 consistency proofs, per-leaf inclusion proofs, fixed-width leaf contents, record signatures, run-final uniqueness and selected-run limits. These are *necessary* checks, not sufficient to establish the complete run-set semantics.

- Event schema validation for both generations: embedded public schemas, conditional payload checks, local references, required and additional properties, enums, constants, patterns and size/numeric bounds.
- V1 chain and elided-record signatures, checkpoints, file witnesses, independent key pins, policy snapshots/rule citations, completeness warnings and signer-isolation assurance.
- V2 policy snapshot digests and live constraints; unsupported security-sensitive semantics fail closed.
- Offline Rekor v2 anchors: RFC 3161 CMS signed attributes and data imprint, pinned TSA certificate validity, P-256 publishing signatures, hashedrekord binding, shard validity, inclusion proofs and signed Rekor checkpoints. The Rekor entry is checked against the exact verified checkpoint note selected by the bundle and the matching log signature line in that note. TSA trust comes from the auditor-pinned trusted root; certificates carried by the token do not establish trust.
- Integrity/exit/assurance reporting, including witness classes/timestamps, self-approval, open runs, registry assurance caps and key-retirement completeness.

The CLI can report `VERIFIED` for supported evidence after all applicable implemented checks pass. **Golden parity is not complete format coverage or a production security audit.** Unsupported features fail closed: hybrid SLH-DSA log pins, record-key issuer certificates/revocations, monitor/analyzer trust, v1-to-v2 bridges, signed reviews/findings/replays, agent approvals and containment incidents. Ext names (format-v2 §9's non-critical slot) are verified like any record and not interpreted: each gets a `not interpreted` warning and the bundle verifies. V1 supports file witnesses only; its stricter JSON/schema handling may reject historical inputs the original verifier accepts. The CLI does not implement strict-warning mode, and it reports the checks that warn or fail, not those that pass.

## Known differences

A check that warns or fails carries the Python verifier's name for it: a failure names the check it fails
(`signatures`, `run chain`, `inclusion`, `chain intact`, ...), and the warnings Go performs (`gaps`, `keys`,
`trust root`, `run completeness`, ...) are named as Python names them. Go's v2 verifier stops at its first failure,
so on a v2 bundle that fails it names that one check and no warning, where Python names every check that fails; the
differential gate requires Go's one failed check to be among Python's. The v1 verifier reports every check it performs.

**Verdict-only checks.** Go doesn't perform these on evidence it accepts, so it can't name them, and where Python
reports them, with that status, the gate compares the verdict only (`KNOWN_GAPS` in
`scripts/differential_golden.py`):

- v1: `counter has no gaps` (Go's chain check reports a missing record under `chain intact` instead), the warning of
  `head matches a witness checkpoint` when the selected records run past the last checkpoint (Go names this check's
  failures), `signing key`, `policy unchanged during run`, `capture sources`, `harness attribution`, `approvals`,
  `coverage` and `opt-in content capture`.
- v2: `coverage` (including `reconcile.*` records), `tiers` (including split capture paths), `fail-open classes`,
  `break-glass approvals` and `log tail`.

Each is a warning in the Python verifier, except `counter has no gaps`, which fails only together with `chain intact`,
so none of them decides a verdict alone. Evidence Go doesn't support fails closed, so its verdict differs from Python's
whatever the names, and its checks are not compared: agent approvals, incidents, signed findings, reviews and replays,
a format bridge in the key records and v1 signed findings are `UNVERIFIABLE` (exit 2); a trust config that pins
issuers, monitors or analyzers can't be used (exit 2, `trust config`; an empty list pins nothing); a record key with
an issuer certificate, or of an algorithm other than Ed25519, fails `keys` (exit 1), as the reference fails one whose
certificate no pinned issuer signed.

An invalid `signer.pub` stops the v1 verifier at `signatures valid` (exit 1, as Python's verdict). Python goes on: it
also reports the checks that don't need the key, and fails every bundled checkpoint under `head matches a witness
checkpoint`.

The Go verifier rejects some inputs accepted by Python: a run with a findings companion, two log keys, v2 numeric spellings `run_seq: -0` or `tree_size: 18.0`, noncanonical base64 signatures or inclusion nodes, checkpoint filenames outside its constraints, v1 ZIP archives with more than 10,000 entries, and v1 ZIP members whose name or extra field contains a crafted ambiguous local-header signature. An open run whose run-set range contains a second `run.registered` leaf gets `FAILED` from Go and `VERIFIED TO HEAD (open)` from Python. A v1 manifest whose `seq_range` end is written as a float (`22.0`) fails Go's `manifest range`. These are false rejections and remain verdict differences if present in the golden corpus.

A manifest's `verifier_min_version` is compared with 1.4.0, the newest row of the format's version table (`VERSIONS` in `tracekit/bundle_v2.py`) Go implements (`formatVersion` in `verify.go`): above it a bundle may use entries Go doesn't know, so Go reports it `UNVERIFIABLE (needs tracekit >= x)`, as Python and TypeScript do for one above their own release version. Between the two (from 1.4.1 up to that release) the verdicts differ. The exporter declares only versions of that table, so only an edited manifest falls between them. Raise `formatVersion` when Go implements a new row.

The conformance kit (`tests/kit`, format-v2 §13) has a case for each difference, with the section that decides it:
`tests/test_go_verifier.py` scores tkverify against it as a verifier of format 1.4.0 (`KIT_KNOWN` lists the cases
it answers otherwise: two pinned log keys). Its `proposed` cases hold the rules this verifier already applies and
the format text doesn't state yet: integer tokens and canonical base64 in every bundle file, and a run other than
a tenant's signer run (`tracekit/signer`, which holds no `run.registered`) starting with its `run.registered`.

## Run

```sh
cd contrib/independent-go-verifier
go build -o tkverify ./cmd/tkverify
./tkverify -bundle ../../tests/golden/v2/closed.tkb -trust ../../tests/golden/v2/trust.json
./tkverify -bundle ../../tests/golden/v1/demo-run.tkb -key ../../tests/golden/v1/signer.pub -json
```

The exit code is the reference CLI's: 0 verified, 1 failed, 2 unusable or unverifiable. Run the built binary when the
exit code matters: `go run` exits 1 for any non-zero exit of the program (it prints `exit status 2`).

The CLI reads a bundle's format from its manifest, as the reference CLI does: a v2 bundle needs `-trust`, and without
it the CLI says so (exit 2).

The text report prints a line per check that warns or fails, under the reference verifier's name for it (a failure's
line gives its reason), then the `Integrity:` and `Assurance:` lines, as the reference CLI does; a reason no check
names, such as an unsupported feature, is printed on its own line. A failed bundle's printed assurance reads
`not rated`.

Signed capture gaps, tampering, binding mismatches and policy violations are exposed as structured warning checks and as `[WARN]` lines in text output. They describe the recorded run while the integrity verdict describes whether its evidence is intact.

V1 key pins may be a raw/base64 public-key file or an `ed25519:` key ID. Use `-witness file:/path/to/checkpoints.jsonl` for an independently selected v1 witness copy. A v1 bundle without an independent key or a valid witness checkpoint agreeing with its ledger is explicitly reported as unanchored. An empty witness file never establishes trust, intentionally tightening the reference verifier’s behavior outside the golden corpus.

## Tests

```sh
cd contrib/independent-go-verifier
go test ./... -count=1
go vet ./...
go build ./cmd/tkverify
```

`TestEmbeddedSchemasAreTheRepositorys` fails when an embedded event schema differs from `tracekit/schema/`: copy the file again after a schema change. The suite includes directly embedded published checkpoint, record and eight small-order Ed25519 key vectors, deterministic ZIP fixtures, mutation tests, synthetic signed registry and multipart bundles, consistency proofs across all sizes up to 16 leaves, strict JSON tests and RFC 6962 tree sizes 1 through 5. In a full Tracekit checkout, `TestRepositoryJCSVectors` and `TestRepositorySignatureVectors` additionally execute **all** the published JSONL vectors. They skip explicitly when the upstream files are absent; check the test log for `SKIP` before treating them as covered.

Security regressions additionally exercise authenticated schema-invalid events, unsupported semantic features, malformed trust/DER, invalid live constraints, modified TSA/Rekor signatures and proofs, unpinned TSAs, wrong publishing keys, expired shards, and v1 key/signature/checkpoint/policy mutations. Run the differential gate below separately: standalone Go unit tests do not substitute for corpus parity. The main repository’s full pytest and TypeScript suites are not covered by this module’s test result.

## Maintainer-required golden differential gate

With a complete upstream checkout and the Python verifier's dependencies installed:

```sh
python contrib/independent-go-verifier/scripts/differential_golden.py --report golden-parity.json
```

With `--ts sdk/typescript/bin/tracekit.mjs` (after `make test-ts` builds it) the TypeScript verifier is a third: on
each v2 case it must give the reference's verdict and check names, or `UNVERIFIABLE (not checked by this verifier:
...)` for an add-on it doesn't implement.

The gate enumerates the repository's v1, v2, negative and multipart `.tkb`
fixtures, including the trust variants listed in the published case manifests.
It fails if a bundle is not covered by a case. **Verdict parity is the exact
three-field tuple `(exit_code, integrity, assurance)`** from the machine-readable
reports of the two processes. The gate compares warning and failed check names separately. A difference outside the verdict-only checks listed above fails it; on a v2 bundle that fails, Go's one failed check must be one of Python's, and Go may name no check Python doesn't. Differences in verdict-only checks are recorded separately in the report as known gaps. For v2, the Python verifier runs in a separate
subprocess via `tracekit.verify.v2.verify` (matching `tests/test_golden.py`),
not the auto-detecting CLI: deliberately malformed v2 bundles can otherwise
be misrouted to v1 and produce a non-JSON argument error. V1 cases use the
Python CLI. Every verdict mismatch and every unexpected check-name difference fails the gate and is captured in the optional JSON report.

The gate compares exit code, integrity, assurance, and the names of warning and failed checks outside the verdict-only ones. It is an executable acceptance test, not a substitute for reviewing unsupported features. Rerun it against the checkout being reviewed; report files are generated on demand and are not committed.

## Mutated bundles

`tests/test_go_verifier.py` builds `tkverify` and gives it the mutated bundles the TypeScript verifier is held to:
every structural mutation of the golden closed bundle, run-set and run in parts (`tests/test_bounded.py`) and the
mutated copies of the real signer's bundles (`tests/test_ts_verifier.py`). Each must get Python's exit code and
integrity. It skips without Go on `PATH`; CI's go-verifier job runs it and fails if it skips.

```sh
PYTHONPATH=$PWD python -m pytest -q tests/test_go_verifier.py
```

It compares the verdict only. On a few mutations both fail, but Go stops sooner, at `bundle structure` (a run file
without its final newline, a run file under a name that isn't a run's, an integer written as a float), where Python
names the checks it fails later (`manifest`, `run chain`, `run parts`, `signatures`, ...); and the JSON assurance of a
failed bundle can differ. Both CLIs print a failed bundle's assurance as `not rated`.
