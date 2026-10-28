# Tracekit issue #260: independent Go verifier

> **Experimental:** this verifier is not part of the stable core and has not had a production security audit.

This dependency-free Go implementation reads evidence offline without invoking either existing verifier. Its development consulted the Python verifier and golden corpus, so it does not establish whether the specification alone is sufficient to write a verifier. The embedded event schemas are public format data copied from the repository schemas.

## Current coverage

- Strict JSON parser: UTF-8, duplicate keys, lone surrogates, nesting limit, unsafe integer tokens, nonfinite numbers and trailing data.
- RFC 8785 JCS: UTF-16 key ordering, ECMAScript binary64 formatting, minimal string escapes.
- Record envelopes and SHA-256 event hashes; SHA-256 SPKI key IDs; domain-separated Ed25519 messages; cofactorless Ed25519 verification and rejection of noncanonical/small-order keys.
- RFC 6962 / RFC 9162 record Merkle leaf, node and inclusion proof verification.
- C2SP signed checkpoint notes, log vkeys, witness cosignatures, duplicate signature-key rejection and witness quorum.
- Rigid ZIP layout and limits, manifest file hashes, record-key epochs and retirement positions, per-run hash chains, multi-part run concatenation and first/last/key-record inclusion proofs.
- CLI input caps: bundles and v1 witness files are limited to 512 MiB; trust and v1 public-key files are limited to 1 MiB.
- Cryptographic registry run-set checks: derived-origin signed checkpoints, RFC 9162 consistency proofs, per-leaf inclusion proofs, fixed-width leaf contents, record signatures, run-final uniqueness and selected-run limits. These are *necessary* checks, not sufficient to establish the complete run-set semantics.

- Event schema validation for both generations: embedded public schemas, conditional payload checks, local references, required and additional properties, enums, constants, patterns and size/numeric bounds.
- V1 chain and elided-record signatures, checkpoints, file witnesses, independent key pins, policy snapshots/rule citations, completeness warnings and signer-isolation assurance.
- V2 policy snapshot digests and live constraints; unsupported security-sensitive semantics fail closed.
- Offline Rekor v2 anchors: RFC 3161 CMS signed attributes and data imprint, pinned TSA certificate validity, P-256 publishing signatures, hashedrekord binding, shard validity, inclusion proofs and signed Rekor checkpoints. The Rekor entry is checked against the exact verified checkpoint note selected by the bundle and the matching log signature line in that note. TSA trust comes from the auditor-pinned trusted root; certificates carried by the token do not establish trust.
- Integrity/exit/assurance reporting, including witness classes/timestamps, self-approval, open runs, registry assurance caps and key-retirement completeness.

The CLI can report `VERIFIED` for supported evidence after all applicable implemented checks pass. **Golden parity is not complete format coverage or a production security audit.** Unsupported features fail closed: hybrid SLH-DSA log pins, record-key issuer certificates/revocations, monitor/analyzer trust, v1-to-v2 bridges, signed reviews/findings/replays, agent approvals, containment incidents and extensions. V1 supports file witnesses only; its stricter JSON/schema handling may reject historical inputs the original verifier accepts. The CLI does not implement strict-warning mode or the reference verifier's full per-check report.

## Known differences

The differential gate compares check names as a separate parity requirement. Known V1 reporting omissions include Python's `run completeness`, `run boundaries`, `run tail witnessed`, `head matches a witness checkpoint`, `trust root`, `signing key`, `policy unchanged during run`, `capture sources`, `harness attribution`, `approvals`, `coverage`, `opt-in content capture`, and `chain intact` checks. Known V2 warning/failure-check omissions include `gateway amendments`, `openshell policy`, `revocations`, `coverage` (including `reconcile.*` records), `tiers` (including split capture paths), `fail-open classes`, `break-glass approvals`, `approvals by agents`, `incident policies`, `findings counted`, `replay runs`, `reviews counted`, `reviews`, `keys`, `log tail`, `monitor`, `not interpreted`, `policy snapshot`, `manifest`, `inclusion`, `witness quorum`, `run chain`, `bundle structure`, `checkpoint`, `signatures`, `bundle readable`, `run-set`, and `run parts`. These are check-reporting gaps; the differential report records them separately as known gaps. The `coverage` gap includes `reconcile.*` records; `tiers` includes split capture paths; `keys` includes the key-rotation completeness warning. The v1 `run tail witnessed` gap includes an unwitnessed tail. The `fail-open classes`, `log tail`, and `break-glass approvals` warnings are also omitted.

The Go verifier rejects some inputs accepted by Python: a run with a findings companion, an open-only runset, empty monitors/issuers/analyzers lists, two log keys or extra algorithms, duplicate witness pins, v2 numeric spellings `v: 2.0`, `run_seq: -0`, or `tree_size: 18.0`, noncanonical base64 signatures or inclusion nodes, checkpoint filenames outside its constraints, v1 ZIP archives with more than 10,000 entries, and v1 ZIP members whose name or extra field contains a crafted ambiguous local-header signature. An open run whose run-set range contains a second `run.registered` leaf gets `FAILED` from Go and `VERIFIED TO HEAD (open)` from Python. These are false rejections and remain verdict differences if present in the golden corpus.

## Run

```sh
cd contrib/independent-go-verifier
go run ./cmd/tkverify -bundle ../../tests/golden/v2/closed.tkb -trust ../../tests/golden/v2/trust.json -json
go run ./cmd/tkverify -bundle ../../tests/golden/v1/demo-run.tkb -key ../../tests/golden/v1/signer.pub -json
```

Signed capture gaps, tampering, binding mismatches and policy violations are exposed as structured warning checks and as `[WARN]` lines in text output. They describe the recorded run while the integrity verdict describes whether its evidence is intact.

V1 key pins may be a raw/base64 public-key file or an `ed25519:` key ID. Use `-witness file:/path/to/checkpoints.jsonl` for an independently selected v1 witness copy. A v1 bundle without an independent key or a valid witness checkpoint agreeing with its ledger is explicitly reported as unanchored. An empty witness file never establishes trust, intentionally tightening the reference verifier’s behavior outside the golden corpus.

## Tests

```sh
cd contrib/independent-go-verifier
go test ./... -count=1
go vet ./...
go build ./cmd/tkverify
```

The suite includes directly embedded published checkpoint, record and eight small-order Ed25519 key vectors, deterministic ZIP fixtures, mutation tests, synthetic signed registry and multipart bundles, consistency proofs across all sizes up to 16 leaves, strict JSON tests and RFC 6962 tree sizes 1 through 5. In a full Tracekit checkout, `TestRepositoryJCSVectors` and `TestRepositorySignatureVectors` additionally execute **all** the published JSONL vectors. They skip explicitly when the upstream files are absent; check the test log for `SKIP` before treating them as covered.

Security regressions additionally exercise authenticated schema-invalid events, unsupported semantic features, malformed trust/DER, invalid live constraints, modified TSA/Rekor signatures and proofs, unpinned TSAs, wrong publishing keys, expired shards, and v1 key/signature/checkpoint/policy mutations. Run the differential gate below separately: standalone Go unit tests do not substitute for corpus parity. The main repository’s full pytest and TypeScript suites are not covered by this module’s test result.

## Maintainer-required golden differential gate

With a complete upstream checkout and the Python verifier's dependencies installed:

```sh
python contrib/independent-go-verifier/scripts/differential_golden.py --report golden-parity.json
```

The gate enumerates the repository's v1, v2, negative and multipart `.tkb`
fixtures, including the trust variants listed in the published case manifests.
It fails if a bundle is not covered by a case. **Verdict parity is the exact
three-field tuple `(exit_code, integrity, assurance)`** from the machine-readable
reports of the two processes. The gate compares warning and failed check names separately. Differences outside the version-scoped known gaps listed above fail; known differences are recorded separately in the report. For v2, the Python verifier runs in a separate
subprocess via `tracekit.verify.v2.verify` (matching `tests/test_golden.py`),
not the auto-detecting CLI: deliberately malformed v2 bundles can otherwise
be misrouted to v1 and produce a non-JSON argument error. V1 cases use the
Python CLI. Every verdict mismatch and every unexpected check-name difference fails the gate and is captured in the optional JSON report.

The gate compares exit code, integrity, assurance, and the names of warning and failed checks. It is an executable acceptance test, not a substitute for reviewing unsupported features. Rerun it against the checkout being reviewed; report files are generated on demand and are not committed.
