# Tracekit issue #260: independent Go verifier

This dependency-free Go implementation reads evidence offline without invoking either existing verifier. Its development consulted the Python verifier and golden corpus, so it does not establish whether the specification alone is sufficient to write a verifier. The embedded event schemas are public format data copied from the repository schemas.

## Current coverage

- Strict JSON parser: UTF-8, duplicate keys, lone surrogates, nesting limit, unsafe integer tokens, nonfinite numbers and trailing data.
- RFC 8785 JCS: UTF-16 key ordering, ECMAScript binary64 formatting, minimal string escapes.
- Record envelopes and SHA-256 event hashes; SHA-256 SPKI key IDs; domain-separated Ed25519 messages; cofactorless Ed25519 verification and rejection of noncanonical/small-order keys.
- RFC 6962 / RFC 9162 record Merkle leaf, node and inclusion proof verification.
- C2SP signed checkpoint notes, log vkeys, witness cosignatures, duplicate signature-key rejection and witness quorum.
- Rigid ZIP layout and limits, manifest file hashes, record-key epochs and retirement positions, per-run hash chains, multi-part run concatenation and first/last/key-record inclusion proofs.
- Cryptographic registry run-set checks: derived-origin signed checkpoints, RFC 9162 consistency proofs, per-leaf inclusion proofs, fixed-width leaf contents, record signatures, run-final uniqueness and selected-run limits. These are *necessary* checks, not sufficient to establish the complete run-set semantics.

- Event schema validation for both generations: embedded public schemas, conditional payload checks, local references, required and additional properties, enums, constants, patterns and size/numeric bounds.
- V1 chain and elided-record signatures, checkpoints, file witnesses, independent key pins, policy snapshots/rule citations, completeness warnings and signer-isolation assurance.
- V2 policy snapshot digests and live constraints; unsupported security-sensitive semantics fail closed.
- Offline Rekor v2 anchors: RFC 3161 CMS signed attributes and data imprint, pinned TSA certificate validity, P-256 publishing signatures, hashedrekord binding, shard validity, inclusion proofs and signed Rekor checkpoints. TSA trust is the leaf certificate in the auditor-pinned trusted root; certificates carried by the token do not establish trust.
- Integrity/exit/assurance reporting, including witness classes/timestamps, self-approval, open runs, registry assurance caps and key-retirement completeness.

The CLI can report `VERIFIED` for supported evidence after all applicable implemented checks pass. **Golden parity is not complete format coverage or a production security audit.** Unsupported features fail closed: hybrid SLH-DSA log pins, record-key issuer certificates/revocations, monitor/analyzer trust, v1-to-v2 bridges, signed reviews/findings/replays, agent approvals, containment incidents and extensions. V1 supports file witnesses only; its stricter JSON/schema handling may reject historical inputs the original verifier accepts. The CLI does not implement strict-warning mode or the reference verifier's full per-check report.

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
reports of the two processes. For v2, the Python verifier runs in a separate
subprocess via `tracekit.verify.v2.verify` (matching `tests/test_golden.py`),
not the auto-detecting CLI: deliberately malformed v2 bundles can otherwise
be misrouted to v1 and produce a non-JSON argument error. V1 cases use the
Python CLI. Every mismatch fails the gate and is captured in the optional
JSON report; no mismatches are suppressed or reclassified as skips.

The gate is an executable acceptance test, not a substitute for reviewing unsupported features. The recorded result in `scripts/golden-parity.json` covers every current case; rerun it against the checkout being reviewed. Intermediate `parity-phase*.json` reports preserve the progression from the partial implementation.
