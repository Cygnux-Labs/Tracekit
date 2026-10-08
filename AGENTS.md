# Tracekit

<!--
  Root context for coding agents. Loaded automatically by Pi, Codex, Cursor, Copilot
  and others; Claude Code loads it via `@AGENTS.md` in CLAUDE.md.
  Keep it under ~150 lines. Every `backticked/path` is checked by `agent-flow doctor`.
  Markers: [HIGH CONFIDENCE] read in code · [INFERRED] from names/patterns · [NEEDS VERIFICATION] unknown
  Machine-readable references: CONTEXT_MANIFEST.json
-->

## What this is

Tamper-evident tracing for AI agents: every tool call is recorded as an Ed25519-signed, hash-chained event by a signer
the agent can't control, checkpointed to witnesses, gated by a policy engine, and exported as offline-verifiable `.tkb`
bundles. Today's code (v0.3) targets laptop coding agents (Claude Code, Codex, Cursor, Gemini hooks) plus Python/TS SDKs;
it is being rebuilt for server-hosted agents (signer service, evidence format v2, signer-side policy). [HIGH CONFIDENCE —
read `tracekit/daemon.py`, `tracekit/ledger.py`, `tracekit/hook.py`, `tracekit/bundle.py`]

## Where things live

| Path | Purpose | Confidence |
|---|---|---|
| `tracekit/daemon.py` | Signer daemon (tracekitd): socket, peer identity, run state, approvals, checkpoints | [HIGH CONFIDENCE] |
| `tracekit/ledger.py` | Append-only JSONL ledger, file key, v1 record envelope | [HIGH CONFIDENCE] |
| `tracekit/core.py` | Canonical JSON, hashing, v1 signature message, scrub | [HIGH CONFIDENCE] |
| `tracekit/schema/tracekit.event.v1.json` | Frozen v1 event schema (validated by `tracekit/schema.py`) | [HIGH CONFIDENCE] |
| `tracekit/hook.py`, `tracekit/agent_hooks.py` | Claude Code / Codex / Cursor / Gemini hook capture | [HIGH CONFIDENCE] |
| `tracekit/agent_sdk.py`, `tracekit/autotrace.py`, `tracekit/adapters/` | Python SDK, model-SDK autotrace, framework adapters | [HIGH CONFIDENCE] |
| `tracekit/policy.py`, `tracekit/policy/` | Regex policy engine and its YAML rule packs | [HIGH CONFIDENCE] |
| `tracekit/bundle.py` | Bundle export and the offline verifier | [HIGH CONFIDENCE] |
| `tracekit/install.py`, `tracekit/cli.py` | `tracekit init` (dev/system mode), CLI | [HIGH CONFIDENCE] |
| `tracekit/witness.py`, `tracekit/witness_server.py`, `tracekit/rekor.py` | Checkpoint witnesses | [HIGH CONFIDENCE] |
| `tracekit/otlp.py`, `tracekit/ingest.py`, `tracekit/proxy.py` | OTLP receiver, remote ingest, Anthropic proxy | [HIGH CONFIDENCE] |
| `sdk/typescript/` | TS SDK (currently spawns `tracekit/bridge.py`) | [HIGH CONFIDENCE] |
| `plugin/` | Claude Code plugin (laptop on-ramp) | [HIGH CONFIDENCE] |
| `tests/` | pytest suite (real daemons, no `conftest.py` yet) | [HIGH CONFIDENCE] |
| `eval/` | Experiments E1–E8; E8 (insider attacks) gates CI on Linux | [HIGH CONFIDENCE] |
| `docs/` | User docs; `docs/sample/` holds the shipped sample bundles | [HIGH CONFIDENCE] |
| `paper/` | v0.1 paper — frozen artifact, don't update | [HIGH CONFIDENCE] |

## Commands

| Task | Command | Source |
|---|---|---|
| Install (dev) | `make install` | Makefile |
| Test | `make test` | Makefile |
| Lint | `make lint` | Makefile |
| Build | `make build` | Makefile |
| All checks | `make check` | Makefile |
| TS SDK tests | `make test-ts` | Makefile |
| Offline evals | `make eval` | Makefile |

There is no typecheck step.

## Paved paths

- New tests: `tests/test_<area>.py`, `unittest` classes run by pytest; build events with the helpers in
  `tests/test_hotfix_021.py` until shared factories exist. [HIGH CONFIDENCE]
- Every change that touches the signer, ledger, verifier or policy gets a regression test that fails without it.
- CHANGELOG entry under "Unreleased" for user-visible changes (`CHANGELOG.md`). [HIGH CONFIDENCE]

## Local traps

- The v1 evidence format is evidence: never change `core.sig_message`, `ledger.make_record`, the v1 schema, or how the
  v1 verifier treats existing bundles without an explicit task saying so — old bundles must keep verifying.
- Secret-looking strings in `tests/` and `tracekit/demo.py` are deliberate redaction fixtures. Don't "clean" them.
- `tracekit/policy.py` (module) and `tracekit/policy/` (data dir) share a name; importing works only because the module wins.
- Tests marked root-only and the harness-binding tests (Linux `/proc`) skip on a normal laptop; CI runs Linux as the
  merge gate, macOS/Windows are advisory. A green local run isn't proof for those paths.
- `make test` takes ~2 minutes: many tests start a real signer daemon and spawn hook processes.
- Rules in `tracekit/policy/default.yaml` match raw strings: quoted text that mentions a risky command can trip them.
- `planning/` is local and gitignored — task specs must be copied into the issue, not referenced by path. <!-- agent-flow:ignore-refs -->

## Rules

- Never modify protected paths (`agent-flow brief` lists them; don't read the manifest). Escalate instead.
- All changes land via PR from `agent/issue-N`; never push to `main`.
- New dependencies need risk review (`agent-flow audit-risk`).
- If code contradicts this file, trust the code and flag `[CONTEXT_STALE]`.
- Fix root causes; no comments that justify workarounds.
- Security invariants (the product's promise): the agent never holds a signing key or assigns sequence numbers; nothing
  an agent-controlled process supplies (isolation level, fail mode, gap/tamper records, approval identity) is trusted by
  the signer or verifier; gaps are signed, never silent; never ship verification code inside a bundle.

## Personal preferences

Not here — this file is shared. Put personal notes in `AGENTS.local.md` / `CLAUDE.local.md` and add them to `.gitignore`.
