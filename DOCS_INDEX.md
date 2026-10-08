# Docs Index

Last full scan: 2026-10-08 · 22 docs · 9 stale (41%)

## Active

| Doc | Path | Status | Updated |
|---|---|---|---|
| Readme | `README.md` | active (overclaims to fix — see Stale) | 2026-10-08 |
| Changelog | `CHANGELOG.md` | active | 2026-10-08 |
| Contributing | `CONTRIBUTING.md` | active | 2026-10-02 |
| Security policy | `SECURITY.md` | active | 2026-10-02 |
| Coding agents (Codex, Cursor, Gemini) | `docs/coding-agents.md` | active | 2026-10-07 |
| Privacy | `docs/privacy.md` | active | 2026-10-07 |
| Proof pack | `docs/proofpack.md` | active | 2026-10-07 |
| Findings detectors | `docs/findings.md` | active | 2026-10-07 |
| SQL index | `docs/sql.md` | active | 2026-10-07 |
| OpenTelemetry | `docs/otel.md` | active | 2026-10-07 |
| Signing | `docs/signing.md` | active | 2026-10-07 |
| Witnesses | `docs/witnesses.md` | active | 2026-10-07 |
| Sample bundles | `docs/sample/README.md` | active | 2026-10-07 |

## Stale

| Doc | Path | Since | Reason |
|---|---|---|---|
| Readme | `README.md` | 2026-10-08 | Overclaims (separate-user signing, off-machine witness, "reported as a coverage gap"); E8 missing from eval table; approvals args-binding gap undisclosed |
| Threat model | `docs/threat-model.md` | 2026-10-07 | Attacker levels named L1–L4 (clash with capture layers); scope omits Codex/Cursor/Gemini/OTel/TS; table formatting breaks the L4 row |
| Evaluation | `docs/evaluation.md` | 2026-10-07 | "Seven experiments" — E8 missing |
| Portability | `docs/portability.md` | 2026-10-02 | Says CI never ran and quotes old test counts |
| Remote ingest | `docs/remote-ingest.md` | 2026-10-07 | Accepted event types incomplete; tokens never expire |
| Adapters | `docs/adapters.md` | 2026-10-07 | Missing browser adapter and TS SDK |
| Integrations | `docs/integrations.md` | 2026-10-07 | MCP section duplicates adapters.md; Vercel section telemetry-only |
| Review packet | `docs/review-packet.md` | 2026-10-02 | Predates harness binding, 0.2.1 fixes and E8 |
| Releasing | `docs/RELEASING.md` | 2026-10-02 | No signing, SBOM or npm steps |

Fix with `/repair-docs`: it re-verifies the prose against the code, then refreshes the manifest.

## Missing

Code with no design doc:

- `tracekit/daemon.py`: signer internals (run state, approvals, checkpoints) — only partly covered by `docs/signing.md`
- `tracekit/policy.py`: policy rule format and matching semantics have no reference doc

## Archived

Superseded docs: marked here, not deleted.

- `docs/design-partner-kit.md` — contradicts the self-serve direction; scheduled for removal
- `paper/main.tex` — describes v0.1; frozen artifact
