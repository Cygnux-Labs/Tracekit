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
bundles. Today's code (1.5) has two generations: the v1 laptop path (tracekitd, the
JSONL ledger, Claude Code / Codex / Cursor / Gemini / OpenCode / goose / Qwen Code / Factory Droid / Antigravity hooks) and the v2 signer service for server-hosted agents (evidence
format v2 at 1.4, signer-side policy, detection and containment, custody through the executor and MCP gateway, egress
observation), with Python and TypeScript SDKs and framework integrations. [HIGH CONFIDENCE — read
`tracekit/signer/service.py`, `tracekit/signer/pipeline.py`, `tracekit/verify/v2.py`, `tracekit/daemon.py`,
`tracekit/ledger.py`]

## Where things live

| Path | Purpose | Confidence |
|---|---|---|
| `tracekit/signer/` | v2 signer service: `service.py` (RPCs, approvals, containment, CLI `tracekit signer`), `pipeline.py` (single writer, run state), `reconcile.py`, `detect.py`, `rpc_schema.py` (frozen RPC contract) | [HIGH CONFIDENCE] |
| `tracekit/schema/tracekit.event.v2.json`, `tracekit/bundle_v2.py` | v2 event schema (a copy in `sdk/typescript/src/verify/`), v2 bundle export and the VERSIONS gate | [HIGH CONFIDENCE] |
| `tracekit/verify/` | Offline verifiers: `v2.py`, and `v1.py` re-exporting the v1 one (an independent TS verifier is in `sdk/typescript/src/verify/`) | [HIGH CONFIDENCE] |
| `tracekit/policy2/` | v2 policy engine, compiler/lint and packs (`packs/*.yaml`) | [HIGH CONFIDENCE] |
| `tracekit/sdk/`, `tracekit/autowire.py` | Python v2 client (`RunHandle`), dev-signer autospawn, `tracekit.instrument()` | [HIGH CONFIDENCE] |
| `tracekit/integrations/` | v2 framework integrations (OpenAI Agents, LangChain/LangGraph, Claude Agent SDK, MCP, Browser Use, CrewAI, Pydantic AI, Google ADK, Haystack, LlamaIndex, Microsoft Agent Framework, Strands Agents, Hermes Agent, Claude Code and harness hooks) | [HIGH CONFIDENCE] |
| `tracekit/gateway.py`, `tracekit/executor.py`, `tracekit/mcp_gateway.py`, `tracekit/a2a_gateway.py`, `tracekit/egress.py` | LLM gateway, T2 tool executor, MCP gateway, A2A gateway (experimental), egress observer | [HIGH CONFIDENCE] |
| `tracekit/graph.py` | `tracekit graph`: a graded graph of what agents did across verified bundles (experimental) | [HIGH CONFIDENCE] |
| `tracekit/why/` | `tracekit why`: causal investigation and replay | [HIGH CONFIDENCE] |
| `tracekit/pcm/` | PCM 0.1, proof-carrying messages (experimental): `__init__.py` (message, schema and grant checks, replay, `verify`), `claims.py` (claim evidence), `cli.py` (`tracekit pcm verify`, `tracekit pcm demo`), `tools.json` (the frozen tool placement table, part of the protocol); its signer RPCs (`pcm_*`, contract version 20) are in `tracekit/signer/` | [HIGH CONFIDENCE] |
| `tracekit/findings_v2.py`, `tracekit/findings_text.py`, `tracekit/findings_effects.py`, `tracekit/parsers.py`, `tracekit/review_model.py` | `tracekit analyze --v2`: intent, reasoning and action checks (TK-X200..X204, X208) over a v2 run and its content vault, the text checks (TK-X205 and v1's say-vs-do checks) and the effect checks (TK-X206, TK-X207: kernel sensor effects joined to calls); `parsers.said()` reads what a model said before each tool use; `--review`: the reviewer model (TK-X210, warn only) | [HIGH CONFIDENCE] |
| `tracekit/storage/`, `tracekit/identity/`, `tracekit/transport/` | v2 storage (file, Postgres), caller identities (uid, token, mTLS, k8s service account, OIDC, WebAuthn), RPC transports | [HIGH CONFIDENCE] |
| `tracekit/daemon.py` | v1 signer daemon (tracekitd): socket, peer identity, run state, approvals, checkpoints | [HIGH CONFIDENCE] |
| `tracekit/ledger.py` | v1 append-only JSONL ledger, file key, v1 record envelope | [HIGH CONFIDENCE] |
| `tracekit/core.py` | Canonical JSON, hashing, v1 signature message, scrub | [HIGH CONFIDENCE] |
| `tracekit/schema/tracekit.event.v1.json` | Frozen v1 event schema (validated by `tracekit/schema.py`) | [HIGH CONFIDENCE] |
| `tracekit/hook.py`, `tracekit/agent_hooks.py` | Claude Code / Codex / Cursor / Gemini / OpenCode / goose / Qwen Code / Factory Droid / Antigravity hook capture | [HIGH CONFIDENCE] |
| `tracekit/agent_sdk.py`, `tracekit/autotrace.py`, `tracekit/adapters/` | Python SDK, model-SDK autotrace, framework adapters | [HIGH CONFIDENCE] |
| `tracekit/policy.py`, `tracekit/policy/` | v1 regex policy engine and its YAML rule packs | [HIGH CONFIDENCE] |
| `tracekit/bundle.py` | v1 bundle export and the frozen v1 verifier (`tracekit/verify/v1.py` re-exports it; its `Report` is shared with v2) | [HIGH CONFIDENCE] |
| `tracekit/install.py`, `tracekit/cli.py` | `tracekit init` (dev/system mode), CLI | [HIGH CONFIDENCE] |
| `tracekit/witness.py`, `tracekit/witness_server.py`, `tracekit/rekor.py` | Checkpoint witnesses | [HIGH CONFIDENCE] |
| `tracekit/otlp.py`, `tracekit/ingest.py`, `tracekit/proxy.py` | OTLP receiver, remote ingest, Anthropic proxy | [HIGH CONFIDENCE] |
| `sdk/typescript/` | TS SDK: the v2 client speaks the signer RPC itself (`sdk/typescript/src/v2/`); only the legacy v1 API (`sdk/typescript/src/v1.ts`) spawns `tracekit.bridge`; the independent verifier is in `sdk/typescript/src/verify/` | [HIGH CONFIDENCE] |
| `plugin/` | Claude Code plugin (laptop on-ramp) | [HIGH CONFIDENCE] |
| `tests/` | pytest suite (real daemons); `tests/conftest.py` (markers, env isolation), `tests/factories.py` (shared builders), `tests/golden/` (frozen verifier corpus) | [HIGH CONFIDENCE] |
| `eval/` | Experiments E1–E22 (`eval/e*.py`; E7 is `contrib/query/e7_sql_scale.py`; no E13 script); E8 (insider attacks, v1 and v2) gates CI on Linux; CI also runs E9, E15 and an offline `evals` job (most of `make eval`, results compared with `eval/results/`); `.github/workflows/nightly-evals.yml` runs E2, E7, E9/E16 on Postgres, full E14 and E22 | [HIGH CONFIDENCE] |
| `docs/` | User docs; `docs/sample/` holds the shipped sample bundles | [HIGH CONFIDENCE] |
| `paper/` | the v2 paper (`Tracekit-v2-paper.pdf`, Tracekit 1.4.1); the owner's, don't edit | [HIGH CONFIDENCE] |

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

- New tests: `tests/test_<area>.py`, `unittest` classes run by pytest; build events, signers and bundles with the shared
  builders in `tests/factories.py`. [HIGH CONFIDENCE]
- Every change that touches the signer, ledger, verifier or policy gets a regression test that fails without it.
- Every v2 bundle a test exports in the test process must verify (`tests/conftest.py`); a test that builds a bad
  bundle on purpose carries `@pytest.mark.unverified_bundles`. Bundles exported by a child process aren't checked.

## Local traps

- The v1 evidence format is evidence: never change `core.sig_message`, `ledger.make_record`, the v1 schema, or how the
  v1 verifier treats existing bundles without an explicit task saying so — old bundles must keep verifying.
- Secret-looking strings in `tests/` and `tracekit/demo.py` are deliberate redaction fixtures. Don't "clean" them.
- `tracekit/policy.py` (module) and `tracekit/policy/` (data dir) share a name; importing works only because the module wins.
- Tests marked root-only and the harness-binding tests (Linux `/proc`) skip on a normal laptop; CI runs Linux as the
  merge gate, macOS/Windows are advisory. A green local run isn't proof for those paths.
- `make test` takes ~10–11 minutes (about 3,750 tests): many start a real signer daemon and spawn hook processes. Run
  single files while iterating.
- `agent-flow gates run` runs in the main checkout, not the worktree you call it from. In a worktree run the gates
  there: `PYTHONPATH=$PWD make test-ts lint build test PY=<repo>/.venv/bin/python` (the venv's editable install points
  at the main checkout, so without PYTHONPATH test subprocesses import its code).
- Rules in `tracekit/policy/default.yaml` match raw strings: quoted text that mentions a risky command can trip them.
- `planning/` is local and gitignored — task specs must be copied into the issue, not referenced by path. <!-- agent-flow:ignore-refs -->

## Rules

- Never modify protected paths (`agent-flow brief` lists them; don't read the manifest). Escalate instead.
- All changes land via PR from `agent/issue-N`; never push to `main`.
- New dependencies need risk review (`agent-flow audit-risk`).
- If code contradicts this file, trust the code and flag `[CONTEXT_STALE]`.
- Fix root causes; no comments that justify workarounds.
- Apply the `ponytail` skill (full intensity) to every coding task: the smallest correct change, stdlib and existing
  code before new code, no speculative abstraction, no dead code or unused fixtures. Mark deliberate shortcuts `lean:`.
- Don't edit `CHANGELOG.md` in feature PRs; release notes are written once per release.
- Security invariants (the product's promise): the agent never holds a signing key or assigns sequence numbers; nothing
  an agent-controlled process supplies (isolation level, fail mode, gap/tamper records, approval identity) is trusted by
  the signer or verifier; gaps are signed, never silent; never ship verification code inside a bundle.

## Personal preferences

Not here — this file is shared. Put personal notes in `AGENTS.local.md` / `CLAUDE.local.md` and add them to `.gitignore`.
