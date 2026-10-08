# Changelog

All notable changes to Tracekit. Versions follow [PEP 440](https://peps.python.org/pep-0440/).

## Unreleased

### Security (0.2.1 hotfix: insider attacks on the capture path)
Four attacks on a Linux system-mode install made hidden or fabricated activity verify as a clean `VERIFIED`. None
broke the signature, chain or witness; they all went around what feeds the ledger. Found by a black-box audit with
real separate OS users; reproduced as eval E8 (`eval/e8_insider.py`, now a required CI job).
- **Signer redirect (E8.1, E8.2).** The hooks took the signer address from the agent-writable
  `~/.tracekit-client/config.json` or `TRACEKIT_SOCKET`, so an agent could send tool calls to a decoy signer and
  switch back; restoring its counter files hid the gap. System mode now reads a root-owned
  `/etc/tracekit/client.json` (trusted only if root-owned and not group/world-writable) and ignores both.
- **Cross-user injection (E8.3).** Appends after `run.start` were not checked against the run's owner, and the
  socket is world-writable, so any local user could write events into another user's run, recorded as
  `source: hook`. The signer now refuses events from a uid other than the run owner's (the signer's own uid, used by
  the proxy, still passes) and records each refusal against the targeted run; ownership survives a restart.
- **Fail-open by default (E8.4).** A tool call ran unrecorded while the signer was down. System mode now fails
  closed unless the root-owned config sets `fail_mode: open`.
- **Policy swap (E8.5).** `TRACEKIT_POLICY` is ignored in system mode. `tracekit init` also pins the effective
  policy hash in the signer config; a run or decision under any other policy is a `policy_mismatch` capture gap.
- **Verdict.** `verify` and proof packs say `VERIFIED WITH GAPS (...)` instead of `VERIFIED` when capture gaps or
  refused writes exist. Single-run exports now keep refused-write `error` events, which were elided before.
- **Label.** The `hook` capture source now reads "reported by a hook process (any process running as the agent's
  user can send these)" instead of "observed at the harness hook".
- **Upgrading:** `sudo tracekit migrate --system [--fail-mode open|closed]`, then restart `tracekitd`. Dev mode is
  unchanged.
- **Still open:** an agent can send a fully fabricated, well-formed run through the real hook path (E8.6). It needs
  harness binding (planned for 0.3); with the proxy on it surfaces as `proxy_missing`.

### Added
- **LangGraph node tracing, Browser Use and Stagehand hooks** (#6): `TracekitCallbackHandler(tracer, nodes=True)` records
  each graph node as a policy-checked `node:<name>` step; `tracekit.adapters.browser` gates and records Browser Use
  actions and Stagehand `act`/`extract`/`observe`/`goto` (Python), `instrumentStagehand` in the TypeScript SDK. Runnable
  examples for every adapter in `examples/` (and `sdk/typescript/examples/`), run in CI.
- **`tracekit demo --agent codex|cursor|gemini`** (#7): the scripted demo sent as that agent's own hook payloads; a
  guarantee matrix per capture path in the README.
- **Observer over bundles, with cost** (#9): `tracekit observe --bundle run.tkb` (verified first; live view or
  `--export`), `--prices prices.json` adds cost per model call, agent and session.
- **`tracekit.init()`** (#5) as the one-line entry point (same as `tracekit_sdk.init()`), with an offline example for
  OpenAI, Anthropic and Gemini (`examples/model_calls.py`).
- **PGS end to end on a local chain** (#15): `examples/pgs_onchain_demo.py` drives Proof-Gated Signing's guard and
  wallet on a Hardhat chain; blocked transactions are checked on-chain to be unsigned (nonce unchanged), a drift attack
  reverts on its post-conditions. Fixed: transaction summaries now keep the target of PGS-style call dicts.
- **Jaeger example** (#13): `examples/otel_jaeger_check.py` matches every span Jaeger holds to a signed record of a
  verified bundle (run against Jaeger 2.22).
- **Key attestation in bundles** (#16): `--key-attestation FILE` with an external signer; the document's hash is signed
  into checkpoints, exports carry the document, `verify` reports it (Tracekit checks identity, not vendor contents).
- **Auditor walkthrough** (#12) in docs/proofpack.md; `verify.pyz` checked on a machine without Tracekit.
- **E7: SQL at a million events** (#8): every typical query under 1 s on 2 vCPUs; rollup columns are copied out of the
  JSON at index time (index format 4, rebuilt automatically) and inserts are batched.
- **TypeScript SDK** (`sdk/typescript`, `@cygnux/tracekit`): policy-gated `tool()`, OpenAI and Anthropic instrumentation
  (streaming included), Vercel AI SDK middleware; runs on Tracekit's Python engine through `python -m tracekit.bridge`.
- **OTLP/gRPC ingest**: `tracekit otel serve --grpc-port 4317` (optional `grpcio`), same receiver and guarantees as HTTP.
- **The signer refuses findings whose evidence does not match the ledger** (missing record, wrong hash, none cited), in
  addition to the check `tracekit verify` makes offline.
- **Token usage and cost** (#9). Optional `usage` on `model.exchange` responses (input, output, cache read, cache write,
  reasoning tokens), normalised from the Anthropic proxy, the OpenAI / Anthropic / Gemini SDKs and OpenTelemetry
  (GenAI semconv, OpenLLMetry, OpenInference, Vercel AI SDK). Exported as `gen_ai.usage.*`, queryable in SQL, shown in
  the observer. `tracekit cost` totals per run or model; cost only with a user-supplied price table (none built in).
  The schema change is additive (optional field); bundles that use it need this verifier.
- **Coding-agent hooks** (#7): `tracekit init --dev --agent codex|cursor|gemini` on the Claude Code hook pipeline (policy
  gate, approvals, signing, transcript hashing), with tool names mapped onto the policy vocabulary.
- **Adapters** (#6): MCP client sessions (`tracekit.adapters.mcp`) and Vercel AI SDK telemetry spans.
- **Proof packs** (#12): `tracekit proofpack` / `tracekit report`: bundle, readable report with every check, findings,
  coverage and an evidence-to-control map (EU AI Act Art. 12, SOC 2 CC7.2, ISO/IEC 42001 A.6.2.8), and `verify.pyz`, a
  verifier that needs only Python.
- **Witness service** (#17): `tracekit witness init|token|serve`, an append-only RFC 6962 Merkle log of checkpoints with
  signed tree heads, per-signer tokens, fork refusal and conflict log; `https://` witness specs check inclusion and
  consistency proofs against a pinned witness key.
- **External signers** (#16): keep the signing key in a TPM, HSM, enclave or KMS through a long-lived helper process;
  signatures verified before use; key assurance signed into checkpoints and reported by `verify` ("signing key").
- **Causeway integration** (#14): `tracekit causeway anchor|verify|import-tests|export`.
- **Guarded onchain transactions** (#15): `tracekit.adapters.onchain.guarded_tx` records a transaction guard's verdict
  (Proof-Gated Signing's `Guard.check` interface) before signing and never signs a blocked transaction; detectors
  TK-X006 to TK-X008.
- **Signed findings** (#10) and **say-vs-do detectors** (#11). `tracekit analyze` runs deterministic detectors (claims vs
  executed commands, requests vs executions, risky actions left out of the agent's account, secrets in output,
  retrospective policy violations) and signs each finding as a `review` event in `findings:<run>`, citing records by seq
  and hash. Bundles carry findings with their run; `tracekit verify` adds "findings cite intact evidence" and fails on
  missing or altered evidence. Findings appear in the live observer. E6 (`eval/e6_findings.py`) measures the detectors
  on 2,000 synthetic sessions, including held-out paraphrases they miss.
- **SQL over the ledger** (#8). `tracekit sql` with views `runs`, `tool_calls`, `model_exchanges`, `findings`, `gaps`,
  backed by a stdlib SQLite index that reads only the ledger's new tail, checks hash links, and rebuilds itself if the
  ledger was rewritten. Read-only connection, time budget, table/JSON/CSV output, and `--mcp` for coding agents.
- **OTLP push with auth** (#13). `tracekit otel push --endpoint URL --header K=V [--all|--run R|--follow]` sends signed
  runs to Jaeger, Tempo or any OTLP/HTTP backend, once per run; `export --otel-header` and
  `OTEL_EXPORTER_OTLP_HEADERS` are honoured. An explicit endpoint path is used as given.
- **One-line SDK auto-instrumentation** (#5). `tracekit_sdk.init()` patches the installed OpenAI (chat completions,
  Responses), Anthropic (messages.create, messages.stream) and Google Gen AI (generate_content, generate_content_stream)
  SDKs, sync and async, streaming included. Each call is a signed request event written before the call is sent and a
  response event with model, finish reason, requested tool calls, error, status, latency and time to first chunk.
  Streams are recorded when exhausted, closed or garbage collected (abandoned streams are marked). Recording failures
  never affect the call; `fail_mode: closed` refuses a call that cannot be recorded before it reaches the provider.
  `Tracer.tool(..., tool_use_id=...)` links an execution to the model request that asked for it. The remote gateway
  accepts `model.exchange` as SDK evidence.
- **OpenTelemetry ingest** (#4). `tracekit otel serve` receives OTLP/HTTP traces (protobuf or JSON, gzip or deflate)
  on loopback, and the ingest gateway serves the same endpoint at `/v1/traces` with TLS and per-client tokens.
  GenAI semantic-convention spans, OpenLLMetry and OpenInference spans become signed `model.exchange`, `tool.call`,
  `policy.decision` and `tool.result` events, one run per trace. Policy is evaluated retrospectively: a call a deny or
  ask rule would have stopped is recorded as `flag` with the would-be decision. Exporter retries never duplicate
  evidence, a signer outage returns 503 so the exporter keeps the batch, and a rejected event is reported as an
  OTLP partial success. The protobuf decoder is built in, so the receiver adds no dependencies. See `docs/otel.md`.
- **OTLP export carries evidence links.** Every exported span has `tracekit.entry_hash`, the hash of the signed
  ledger entry it came from. Runs ingested from OpenTelemetry export with their original trace and span ids, and
  model spans report their real provider instead of always `anthropic`.

### Changed
- SDK tool calls made without a model id now get `tk_` ids (were `call_`, which collides with OpenAI call ids).
- `tracekit analyze`, `otel` and `sql` parse their own options (a leading `--option` used to be rejected).

### Fixed
- **TK-D010** denied `cp .env /tmp/x` as "writing to a credentials file"; it now matches credentials files only as the
  destination of `cp`/`mv`/`install`. Default policy version `2026.10-1`.
- The coverage report called every model exchange "at the proxy, cross-checked against hooks"; application-reported
  exchanges are now listed separately, and only proxy exchanges are cross-checked against hooks by the signer.
- `test_rate_limit` was timing-dependent and failed on slow machines; the bucket no longer refills during the test.

## 0.2.0rc1

First release candidate of v0.2: the signed evidence-bundle core, live observer and custom-agent SDK.
This entry lists the fixes from the production-hardening review on top of the v0.2 development branch.

### Added
- Evaluations E2 (overhead), E4 (seeded faults against a real bundle) and E5 (opt-in real Claude Code runs) ported to
  v0.2, with `make eval-agents`; results in `docs/evaluation.md`. `eval/_stack.py` is the shared throwaway-signer helper.

### Fixed
- **The browser verifier could show a valid run as TAMPERED.** Python and JavaScript write some numbers differently
  (`1e-05` against `0.00001`, `1.5e+20` against `150000000000000000000`) and JavaScript cannot hold integers above
  2**53, so any run containing such a value hashed differently in `replay.html` and the observer than in Python.
  Canonical JSON now writes numbers the way JavaScript does, and integers beyond 2**53 are recorded as strings.
  `tests/test_parity.py` runs the real JavaScript from both pages under Node against Python (skipped without Node).
- **Windows: stopping the signer.** `os.kill(pid, 0)` was used as a liveness probe, but on Windows signal 0 is a Ctrl+C
  event sent to the console process group, which can interrupt the caller. Liveness is now asked of the kernel, and
  the signer is asked for a final checkpoint before it is terminated (Windows has no catchable SIGTERM).
- **CI could hang for hours.** Jobs now have a 25 minute timeout, tests run verbosely, and a test stuck for 4 minutes
  dumps every thread's stack, so a hang fails with a diagnosis.
- **Bursts of concurrent writers lost events.** The signer's accept queue was Python's default of 5, so eight or more
  writers connecting at once got `EAGAIN` and, being fail-open, dropped events. The queue is 256 and the client retries
  a full-queue connect. Found by the new E2 evaluation; covered by `BurstOfWriters`.
- **A write to a path containing a NUL byte was not flagged on some Python and OS combinations.** The
  out-of-scope check relied on `realpath` raising; it now treats an embedded NUL as out of scope explicitly.
- **Tests assumed Linux.** Approvals used GNU `script -c` and `SO_PEERCRED`; they now use a stdlib `pty` helper
  and `peercred.has_peer_credentials()`. The full suite passes natively on macOS 26 (arm64, Python 3.9.6).
- **A retrying client could flood the ledger with `error` events** (47,947 records from one invalid event).
  Rejections are now recorded for the first 10 repeats per run and message, then once per power of ten.
- **Trusted-key files whose raw 32-byte key began or ended with a whitespace byte were mis-stripped**
  and rejected (a roughly 5% flaky failure). Raw keys are no longer stripped.
- **TK-D004 (`rm -rf /`) had super-linear regex behaviour** on adversarial input; it is rewritten linearly.
- **`tracekit init` crashed on a normal install.** `_hook_command()` built its command inside the
  `except` branch, so `tracekit init --dev` raised `UnboundLocalError` and wrote no hooks.
- **The observer replay showed `CHAIN ✗ TAMPERED` for every v0.2 run.** The browser re-hashed the
  translated display records instead of the raw ledger records. Replays now embed the raw records and
  verify the real hash chain; a one-byte edit still turns the badge red.
- **Canonical JSON could differ between Python and the browser** (`2.0` vs `2`, key order for
  characters outside the BMP), which could make a valid bundle look broken in `replay.html`.
- **The verifier could crash on a malformed bundle.** It now reports a failed check instead, rejects
  duplicate zip members and zip bombs, flags files the manifest does not list, cross-checks the
  manifest range, and no longer lets the (unsigned) manifest narrow which runs get checked.
- **Git witness retries failed** with "nothing to commit" after a partial publish, and `git init -b`
  needs git 2.28+. Publishing is idempotent and works with older git.
- **A lone UTF-16 surrogate, `NaN` or deeply nested JSON in an agent's output** could make the signer
  drop the event or a redaction recurse without bound. Events are sanitised before signing.
- **The SDK could raise inside the agent** on sets, bytes, datetimes or `NaN` in tool arguments or
  results. Values are coerced; `Tracer` is now a context manager that always records `run.end`.
- **Hook** no longer crashes on a non-object `tool_input` or malformed transcript lines, creates its
  state directory if missing, and hashes the transcript in a stream instead of reading it twice into memory.
- **Policy** validation rejects non-numeric `checkpoint_every` / `approval_timeout_s` and non-boolean
  flags; evaluation no longer fails on odd inputs or a path containing a NUL byte.
- **Settings files**: Tracekit refuses to touch a Claude Code settings file it cannot parse, writes
  atomically, and makes no new backup when nothing changes.
- **Dev setup** is idempotent (re-running `init --dev` no longer kills a healthy signer), and a stale
  pidfile can no longer cause an unrelated process to be signalled.
- **`tracekit uninstall --project`** no longer stops the shared dev signer.
- **Observer server**: Host-header allow-list against DNS rebinding, constant-time token check,
  Content-Security-Policy and other security headers, cached verification, resilient ledger tail,
  friendly errors for a busy port or a missing ledger.
- **Observer UI**: no third-party font request (the replay is now fully offline), real error states and
  automatic retry in live mode, phone layout, `<noscript>` note.
- **CLI**: `--version`, clear one-line errors instead of tracebacks (`TRACEKIT_DEBUG=1` restores them),
  approval ids may be abbreviated to a unique prefix, bad numeric options are rejected, `export --run`
  and `--since` are honoured.
- **Signer** takes a final checkpoint on Ctrl-C as well as SIGTERM, and tightens a group- or
  world-readable key file.

### Added
- Claude Code plugin and marketplace manifest (`plugin/`, `.claude-plugin/`), with `/tracekit-status`, `/tracekit-verify`, `/tracekit-pending`.
- Adapters: `tracekit.adapters.traced` (any function) and `tracekit.adapters.langchain` (LangChain / LangGraph), `tracekit[langchain]` extra.
- Remote ingestion: `tracekit ingest token|serve`, `tracekit init --remote`; token-authenticated, TLS, rate-limited, events recorded as namespaced `sdk` runs.
- Rekor witness (experimental): RFC 6962 inclusion proofs, signed-entry-timestamp check against a pinned key, `rekord` entries.
- macOS: `LOCAL_PEERCRED` caller attestation, `ps`-based process checks, and an experimental launchd system mode (`--experimental-macos`). `docs/portability.md`.
- `docs/sample/` (a real bundle, a tampered copy, the key), `docs/evaluation.md`, design-partner kit, review packet, `paper/v0.2-update-draft.md`.
- Default policy: TK-D010 (shell writes to credential files) and TK-D011 (sending key and cloud-credential files), and wider TK-D002 (pipes to python/perl/ruby/node, download-then-run) and TK-D004 (quoted `$HOME`, split flags).
- `tracekit init --no-hooks` now also applies to system mode.
- `action.yml`: a composite GitHub Action that runs `tracekit verify` on a bundle.
- `Makefile` (`make check`, `make eval`, `make demo`), `CONTRIBUTING.md`, issue and PR templates,
  a tag-driven release workflow with PyPI trusted publishing (`docs/RELEASING.md`).

### Changed
- The v0.1 prototype was removed (root scripts, `legacy/`, its tests, demo script and sample output, and the
  v0.1 experiment code). `tracekit migrate` still converts v0.1 ledgers. `tracekit_sdk.Tracer` is now the
  v0.2 signed SDK only; the unauthenticated `endpoint=` ingest mode is gone. The duplicate root `schema/` was removed.
- E1 (integrity) and E3 (policy gate) evaluations were rewritten for v0.2; E2/E4/E5 and the paper figure
  generators were v0.1-only and were removed (the paper in `paper/` describes v0.1).
- Observer: the live feed is bounded (`TRACEKIT_OBSERVE_MAX_RECORDS`, default 50000); `/api/snapshot` now returns
  `{next, dropped, records}`.
- Policy: regexes with a repeat of a repeat are rejected at load; each match has a 0.5 s budget (a timeout counts as
  a match); subjects are matched in overlapping 16 KiB windows so padding cannot push a command out of view, and a subject over 256 KiB is treated as matching (fail safe). Default rules no longer deny `.env.example`-style files or the word
  `sudo` inside `grep`/`echo` arguments (E3 benign false positives 3/40 to 0/40).
- An unreachable OTLP collector no longer aborts `tracekit export --otel-endpoint`; the bundle is still written.
- Exports (`tracekit export`, `tracekit observe --export`) are written atomically.
- Version is single-sourced from `tracekit/__init__.py`; packaging metadata, classifiers and sdist
  manifest added; CI workflow added.
