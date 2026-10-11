# Changelog

All notable changes to Tracekit. Versions follow [PEP 440](https://peps.python.org/pep-0440/).

## 1.0.0 (2026-10-11) — first stable release

1.0.0 is 1.0.0rc2 made stable: the v2 signer, evidence format v2 and its verifier, witnesses, the monitor, team approvals,
server deployments (container, Kubernetes sidecar, central signer on Postgres) and the run viewer. The v2 format is now
stable: 1.x verifiers verify every 1.0 bundle, and a bundle that needs a newer verifier says so (`UNVERIFIABLE`), never
`FAILED`. The v1 laptop setup and v1 bundles keep working unchanged. Upgrade notes from 0.4.0: see 1.0.0rc1 below.

### Fixed
- A network service that refused a request before reading its body (wrong Host, missing session or CSRF token) could
  reset the connection before the client read the answer, on Windows always and elsewhere while a large body was
  still arriving. Each service now reads what the client sent, up to 1 MiB, before closing.
- A config file written as JSON (`signer.yaml`, the viewer's and the gateway's) failed to load where PyYAML isn't
  installed, which `tracekit-ai[signer]` doesn't install. JSON documents now load either way.

### Release
- npm: no `@cygnux/tracekit-signer-darwin-x64` package (google-re2 and cryptography publish no Intel-Mac wheels it can
  use). On an Intel Mac, `pip install 'tracekit-ai[signer]'`; `@cygnux/tracekit` uses that `tracekit` from PATH.
- Releases are built and published by the attested release workflow: PyPI files, npm packages and the signer image
  carry SLSA build provenance and SBOMs, the image is cosign-signed, and `SHA256SUMS` is attached to the GitHub release
  ([docs/RELEASING.md](docs/RELEASING.md#verifying-a-release)).
- SECURITY.md: 1.x is the supported line.

## 1.0.0rc2 (2026-10-11) — the run viewer

The second 1.0 release candidate. Nothing changes in the signer, the evidence formats, the verifier or the policy
packs: rc1's bundles, configs and clients work unchanged (signer RPC version 12).

### Viewer (`tracekit view`)
- **Runs panel**: each v2 run with its agent's registered name, its verifier verdict (`VERIFIED`, `FAILED`, `PENDING`),
  start, duration, and its calls, blocked, held and gaps. Selecting a run scopes the tape, timeline, tool mix and header
  to it; the header shows the selected run's own verdict, or how many runs failed.
- **Run review**: integrity and assurance, what the policy allowed, flagged, denied and held, who approved (attested or
  bridged, and whether it was self-approved), gaps by kind and coverage; each line opens its first record.
- **Replay**: step through a run, or jump to the next deny, hold or gap, with the header and tape as of that moment.
- **In words**: blocked calls show their rules' reasons; holds and approvals are their own `HOLD`, `APPROVE` and
  `REJECT` rows; the signer's own records no longer count as an agent; tape filters for decisions, approvals, and gaps
  and alerts; the timeline is scaled to the calls shown.

### Docs
- [docs/viewer.md](docs/viewer.md): a screenshot of a run under review; the README quickstart ends with `tracekit view --dev`.

## 1.0.0rc1 (2026-10-10) — server deployments and teams

The first 1.0 release candidate: the v2 signer becomes the way to run Tracekit, on a laptop, in a container, as a
Kubernetes sidecar or as a central service on Postgres, with witnesses, a monitor and team approvals. The v1 laptop
setup and v1 bundles keep working unchanged. [docs/launch-checklist.md](docs/launch-checklist.md) lists what the 1.0
release still waits on; 1.0 itself is the owner's call after real use.

### Upgrade notes
- **Signer RPC version 12** (0.4.0 spoke 7). Clients and signers of different versions refuse each other; upgrade the
  signer and its clients together. A dev signer of the old version is reported, never restarted behind your back.
- **v2 bundles now need tracekit >= 1.0.0 to verify** (`verifier_min_version`): they can carry anchors, hybrid
  checkpoint signatures, certified record keys and other records 0.4.0's verifier doesn't know. An older verifier
  reports them `UNVERIFIABLE`, never as failed. 0.4.0 bundles still verify. v1 bundles and the v1 verifier are unchanged.
- **TypeScript**: `@cygnux/tracekit`'s default import is now the native v2 client; the v1 API is at
  `@cygnux/tracekit/v1`, and the Python bridge it used is deprecated.
- **Server deployments run the server policy pack.** The image, the compose stack and both Helm charts now set
  `policy:` (before, they fell back to the laptop pack). Replace `/etc/tracekit/policy.yaml` to run your own.
- **Run-sets need their registry notes cosigned**: with `witnesses_required` set, a run-set exported before the
  witnesses cosigned its registry note verifies `INCOMPLETE`; the run-set line now names its tenant.
- **Policy packs**: rules now match what a call acts on (`target`) rather than everything it carries, so writing a file
  that merely mentions a credentials path is no longer denied; `TK-S005` is folded into `TK-S004`; new rules
  `TK-N003`, `TK-B003` and `TK-SQL-PARSE`. Policy files are always read by the built-in YAML subset (duplicate keys and
  anchors are errors even where PyYAML is installed). A command or SQL statement the parser can't read is held (ask).
- **Clients**: one run's events are sent one at a time (other runs still in parallel); a v2 hook that can't start now
  blocks the call in dev mode too.

### Fixes from the pre-1.0 review
A five-part review of the signer, storage and verifier, network services, clients and policy before this release; each
fix has a regression test.
- **Approvals**: self-approval is detected across every identity mapped to the same person, including OIDC person ids;
  a consumed approval covers only the arguments it approved; a passkey-required approval is refused without a verified
  assertion on every path; a blank break-glass reason is refused; a bridge acts for people of its own tenant only
  (unless it is a multi-tenant app); passkeys are registered only soon after a sign-in.
- **Signer**: nothing is signed with a record key whose certificate has expired; runs are refused in tenants the key
  isn't certified for; closing a log ends its open runs first; finished runs leave the writer's working set; retry
  caches are bounded per identity and keep no executor arguments; OTLP import adds spans only to the importer's own runs.
- **Verifier and storage**: run-set completeness requires the registry notes' witness quorum and that every bundled run
  is of the run-set's tenant; a power loss can no longer leave the file store unable to start; Postgres calls time out
  instead of hanging; registry notes are read on demand; fsck checks the trees against the logs; exporting an active
  run works; the monitor and export write durably.
- **Network services**: the signer's HTTPS listener, the viewer, metrics and the Slack bridge bound their connections
  and enforce request deadlines; a pending viewer login can't be evicted; valid credentials work behind an address
  that others failed from; loopback receivers answer only loopback host names; witness proofs no longer rehash the log.
- **Clients**: an answer can't reach the wrong caller; a stalled signer fails every waiting call within its timeout;
  installers refuse agent settings of an unexpected shape rather than rewriting them; hook approval waits fit the
  harness's hook timeout.
- **Policy**: SQL rules match outside comments and every literal form; hosts are normalised (numeric, mapped and
  encoded forms) before matching; command names built from expansions, more wrappers, interpreter programs in every
  form, option-borne commands and bundled force-push flags are covered; paths match whatever the separator or case.
- **Deploy**: the agent's mount of the signer socket is read-only; every chart container has resource requests and
  limits; image and npm bundle dependencies are pinned, and the npm bundles are built from the release's checked wheel.

### Deploy anywhere
- **Container image** of the signer (non-root uid 10001, digest-pinned base) and a **Docker Compose stack**: signer,
  Postgres, a shipped witness and the viewer.
- **Postgres storage** (one writer per log, advisory lock, a SELECT-only reader role for export, view and reveal) next
  to the file store, whose snapshots are now HMAC-authenticated.
- **Helm charts**: `tracekit-signer` (a sidecar the agent's container can't read) and `tracekit-central` (one writer
  per log, run ids routed by prefix, a viewer of every log).
- **Keys**: the log key can live in AWS KMS (Ed25519) or GCP; an issuer service certifies short-lived record keys,
  witnessed before it returns them; checkpoints can carry a second, post-quantum signature (SLH-DSA, FIPS 205).
- **Anchoring and monitoring**: checkpoints anchored in Rekor v2 with RFC 3161 timestamps; `tracekit monitor` follows a
  log, checks its rules and publishes signed reports, so bundles can verify at `witnessed+monitored`.
- **`tracekit doctor`** checks v2 deployments, including Kubernetes; laptop **system mode** runs the v2 signer as its
  own user, with harness binding through a root-owned helper.
- **Remote clients** reach the signer over HTTPS with Kubernetes service-account, mTLS, bearer-token or OIDC
  identities; v1 remote ingest is replaced.
- **LLM gateway** (OpenAI-compatible) that records model calls through the signer, optionally mandatory.

### Capture and evidence
- **Reconciliation** of three capture layers (transcripts, hooks, SDK) in the signer, with signed coverage gaps; a
  hardened Claude Code transcript tailer; v2 hooks for Codex, Cursor and Gemini CLI.
- **Verifier**: the complete v2 report, a golden corpus and a negative corpus, run-set completeness, retired-key use
  failing, revocations reported as unverifiable.
- **OpenTelemetry** in (OTLP into the signer) and out (spans from v2 records).

### Policy and approvals
- **Server policy packs**: SQL, HTTP egress, cloud CLIs and MCP tools, payments, email and chat, plus cloud metadata,
  secrets and credential files on every tool. On the shipped corpora they catch every deny case and hold 0.16% of
  benign calls. `extends` takes a list of packs.
- **Team approvals**: OIDC sign-in for approvers and the viewer; a run's end-user principal can be attested from their
  token and never approves its own run; web approval pages, with passkeys (WebAuthn) required for high-risk rules;
  Slack approvals; break-glass answers need a reason and are recorded.
- **External decisions** from AWS AgentCore Policy, Amazon Verified Permissions, VS Code agent hooks and GitHub Copilot
  hooks are imported as signed inputs, and a disagreement with the signer becomes a signed gap.
- **OCSF webhook**: decisions, denies, approvals, gaps and tamper records sent HMAC-signed to a SIEM, without agent
  content.

### Viewer
- **Multi-tenant viewer** over every log of a central deployment: auditor (one tenant), approver and operator-admin
  roles, search and pagination, each run checked by the verifier (labelled as the operator's view) and downloadable as a
  bundle to re-verify.

### SDKs and integrations
- **Native TypeScript client** of the signer RPC, with adapters for the OpenAI Agents SDK, the Vercel AI SDK and the
  Claude Agent SDK, and `npx @cygnux/tracekit up` for Node-only users.
- Runnable v2 examples and quickstarts per framework; `tracekit demo --server`; a Browser Use adapter.

### Release and docs
- Release engineering for signed artifacts with provenance, SBOMs and multi-arch images (the target workflow is in
  [docs/RELEASING.md](docs/RELEASING.md)).
- Deployment, migration, architecture, security-checklist, FAQ and limits docs; a rewritten README; the technical
  report ([report/tracekit-v2.md](report/tracekit-v2.md)) with the E-series results.

## 0.4.0 (2026-10-10) — v2 signer preview

A **preview of the v2 architecture** for server-hosted agents, shipped alongside the unchanged v1 laptop setup.
Everything v1 (`tracekit init`, the v1 hooks, `tracekitd`, `.tkb` v1 bundles and their verifier) works as in 0.3.0;
the v2 pieces are opt-in (`pip install 'tracekit-ai[signer]'` for the signer). Formats and the signer RPC may still
change before 1.0. Quickstart: [docs/quickstart-v2.md](docs/quickstart-v2.md).

### The v2 signer (preview)
- **`tracekit signer serve`**: a signer service that holds the keys and assigns sequence numbers; agents talk to it over
  a versioned RPC (Unix socket with peer-uid identity, loopback TCP with a token for dev, HTTPS with Kubernetes
  service-account tokens, mTLS/SPIFFE or a bearer token). Per-method authorization and tenant mapping from config.
- **Same-user dev signer, started on first use** by the Python client (`tracekit up | down | status`); a signer of an
  incompatible version is refused, never restarted behind your back.
- **Evidence format v2**: JCS canonical JSON, domain-separated Ed25519 record signatures, an RFC 6962 Merkle tree over
  all records, C2SP checkpoint notes signed by a separate log key, per-tenant registry logs, and per-run bundles.
- **`tracekit verify`** reads v2 bundles against a pinned trust config (`tracekit signer trust` writes one for a dev
  signer) and reports `Integrity` and `Assurance` separately; a dev signer's runs verify at `Assurance: dev`.
  Assurance levels describe how far the checkpoint is anchored (`dev`, `local`, `witnessed`), not where the signer
  runs: a signer running as the agent's own user can still reach `witnessed`.
- **Run lifecycle** in the signer: registration, idle timeout, closing window for late results, `run.final`; gap and
  tamper records are written by the signer only.
- **Policy v2 inside the signer**: an RE2-subset engine (google-re2 or `regex`, same results), a structural shell
  parser, tool classes, the coding packs, `unless` exemptions; decisions are bound to the exact arguments that later run.
- **Approvals**: one per tool call attempt, bound to its arguments, consumed once; edited arguments, swapped ids and
  expired approvals are refused and recorded; pending approvals survive a signer restart (arguments kept encrypted);
  `tracekit approvals list | show | approve | reject`. Self-approval is allowed in dev mode, labelled, and caps
  assurance at `dev`. A signer started from a config refuses self-approval and accepts only configured approvers of
  the run's tenant (`approvals: {approvers, self_approval, break_glass}`); break-glass answers need a reason and are
  recorded; an ask rule may name a T2 executor, which gets back exactly the approved arguments.
- **Checkpoints, export and viewing**: signed notes after each run ends and on a cadence; `tracekit export --v2`;
  `tracekit view`, a read-only laptop viewer where every run is checked by the verifier.
- **Witness publishing**: checkpoint notes go to configured C2SP tlog-witnesses in the background; cosignatures are
  merged into the stored notes; a persisted retry queue survives restarts; a witness that stays unreachable gets a
  signed gap. A run cosigned by a pinned non-operator witness verifies `Assurance: witnessed`.
- **Privacy**: tool results and the approver's copy of arguments are redacted inside the signer before anything is
  committed, with a manifest of the rules that fired; every published digest of agent content is a salted
  commitment, and `tracekit signer reveal --record N` gives an auditor the salt of that one record
  ([docs/privacy.md](docs/privacy.md)).
- **Metrics**: Prometheus `/metrics` on its own port ([docs/observability.md](docs/observability.md)).
- **Run-set completeness**: per-tenant registry logs are checkpointed; `tracekit export --v2 --run-set` bundles every
  run a tenant registered in a window, so a deleted run or a withheld key retirement fails verification; a
  single-run bundle reports key retirements as not proven complete (a warning; `--strict` exits 3).
- **Format bridge**: `tracekit signer bridge` continues a v1 ledger in a v2 log and retires the v1 key.

### Integrations on v2 (preview)
- **Claude Code**: `tracekit init --dev --v2` wires a thin v2 hook (no local policy, no keys; ~55 ms per tool call).
- **OpenAI Agents SDK** (`tracekit.integrations.openai_agents`): signer-side approvals through the tool input
  guardrail, `apply_decisions(state)` for paused runs; hosted tools are recorded and listed as uncovered.
- **LangChain v1** middleware (`tracekit.integrations.langchain`): deny-and-continue, approvals through LangGraph
  `interrupt()` that survive a process restart; `tracekit_tool_node` for graphs built on `ToolNode`; and
  `TracekitCheckpointer`, which commits every saved checkpoint (pending tool calls included) so an edited
  checkpoint is recorded as `state_tamper`.
- **Claude Agent SDK** (`tracekit.integrations.claude_agent_sdk`): hooks for `ClaudeAgentOptions` and a session
  store wrapper that commits saved transcripts.
- **MCP client** (`tracekit.integrations.mcp`): every `call_tool` on a wrapped `ClientSession` is decided by the
  signer and recorded as `mcp:<server>/<tool>`.
- Every adapter: when the signer can't be reached, the run's fail mode for the tool class applies (default: closed);
  a signer refusal, or a failure once a call waits for approval, never lets the call run; a failure to record an
  outcome warns and leaves the tool's result as it was.
- **Autotrace on v2** with shared parsers for OpenAI (Chat Completions, Responses), Anthropic and Google Gen AI: the
  tool calls a model asked for are recorded (as salted commitments) for later reconciliation.
- An adapter contract suite that every integration runs against both a test signer and the real one.

### Hardening from the release review
A review of everything above before release found and fixed, among others: the Claude Code v2 hook letting calls
through unrecorded after ~32 calls in a session (one event stream per session now); shell-parser inputs that could
stall the signer, and policy bypasses (argv-list commands, `bash -c --`, globs and braces in the command name,
scripts piped into a shell, quote splicing, `..` paths, missing wrappers and tool names); a result recorded after a
deny now leaves a signed gap; key files written atomically and checked at start; a log rolled back below its own
checkpoint is detected; memory of finished runs released; restarts keep idle and grace clocks; background loops no
longer die silently; `verify --trust` refuses bundles that are not v2; run-set and key-retirement soundness; the
viewer always requires its token; `tcp://` signers are loopback-only; mTLS identities are tied to their trust
domain's CA; Kubernetes JWKS keys expire and errors are no longer echoed to unauthenticated callers.

### Changes v1 users can notice
- **New required dependency `rfc8785`** (canonical JSON for format v2). Verifying a v1 bundle still needs only the
  standard library: the v2 verifier loads only for v2 bundles.
- **`tracekit verify`** refuses flags that don't apply to the bundle's format (`--trust`, `--v1-ledger`, `--v1-key`
  with a v1 bundle; `--key`, `--witness` with a v2 bundle) instead of ignoring them.
- **`tracekit status`** gains a `signer_v2` section (it starts and creates nothing).
- **Hooks:** `tracekit init` says when it replaces a v1 hook with a v2 one or the other way round.
- **Autotrace (v1):** also records `.parse()` calls of OpenAI Chat Completions, Responses and Anthropic Messages;
  usage for new captures counts OpenAI cache-write tokens separately and includes Gemini thinking tokens in output
  tokens, so `tracekit cost` totals for new runs can differ from 0.3.0 for the same traffic.
- **Windows:** non-blocking file-lock contention raises `BlockingIOError`, as on POSIX.

### Fixes
- A second v1 signer started on the same home no longer cuts off the running one (#73).
- Windows: the test suite runs again (it stopped at collection), file-lock contention is reported the same way as on
  POSIX, and the v2 client reaches a Windows dev signer over loopback TCP.

## 0.3.0 (2026-10-09)

First release published on PyPI, as **`tracekit-ai`** (`pip install tracekit-ai`; the import and the command stay
`tracekit`). The name `tracekit` on PyPI belongs to an unrelated project: do not install it.

### Breaking changes
- **Niche modules moved to `contrib/`** as separate packages: proof packs (`tracekit-proofpack`, also `tracekit-report`),
  SQL over the ledger (`tracekit-sql`), Causeway, on-chain guards and Stagehand. The old `tracekit proofpack`, `report`,
  `sql` and `causeway` subcommands print where they went. Entries below that mention them describe the contrib
  packages.
- **Proof packs no longer contain a verifier** (`verify.pyz` and `SHA256SUMS` are gone): auditors verify with a
  Tracekit release they install themselves. A bundled `replay.html` never affects a verdict.
- **The ingest gateway, the Anthropic model proxy and the OTLP receiver need `--experimental`**; they are being rebuilt
  for server-hosted agents.
- **GitHub Action:** `require-anchor` defaults to `true`, so an unanchored bundle fails the step.
- **System mode** runs only from a root-owned virtualenv at `/opt/tracekit`, installed from PyPI (`tracekit-ai`, the
  same version) or from a root-owned clone, with a root-owned Python. `tracekit migrate --system` refuses installs that
  predate it: re-run `sudo /usr/bin/python3 -m tracekit init --user <agent-user>`.
- **`tracekit cost`** reads the ledger directly; `--index` was removed.
- **`tracekit verify` output:** besides `Integrity:` and `Assurance:`, `--json` now carries `integrity`, `assurance`
  and `notes`. Assurance is `separate-user` only where the signer itself attested it.

### Security and correctness
- **Signer:** stamps `signer_isolation` on `run.start` itself; records an approval before it takes effect; validates
  approval requests (types, sizes, caller owns a started run, bounded `wait_s`, per-user cap); decides approvals only
  from facts it observes (peer uid, the approving process's terminal); runs first seen without `run.start` get an owner.
- **Hooks and client:** an untrusted or unreadable `/etc/tracekit/client.json` fails closed instead of falling back;
  subagent transcript paths are confined to the session; payloads without ids are not merged and leave a signed gap;
  a signer-rejected tool call blocks under `fail_mode: closed`, also when an approval was given; client state files use
  collision-free names (existing state carries over); Codex, Cursor and Gemini sessions keep their `run.start` when
  `reasoning_capture` is on.
- **Redaction:** linear time on adversarial input; long connection-string passwords are redacted; a `.env` mention no
  longer hides the command being run; lone surrogates are recorded instead of breaking capture.
- **Verifier:** honest exports are no longer failed by a single missed witness publish (a warning instead); a malformed
  or deeply nested bundle is a FAIL, never a crash; the witness-coverage detail names only checkpoints the witness holds.
- **Installer:** every file write is safe against symlinks and races; reinstalling never leaves an empty runtime (the new
  virtualenv is swapped in only once it imports); the system-mode hook blocks if it cannot run; re-running init keeps
  the policy pin and registered harnesses and restarts the signer; `tracekit doctor` checks the whole runtime without
  following symlinks; the GitHub Action passes inputs to the shell only through the environment.
- **Network servers** (witness, ingest): TLS handshakes per connection with timeouts, an overall per-connection
  deadline, bounded threads and a per-client cap; the witness log is locked against a second server and rolls back a
  failed write; witness and Rekor URLs are validated and redirects refused; Rekor read-back includes the signature.
- **Observer and replay:** all event-derived content is escaped; nonce-based CSP; the observer's token becomes an
  HttpOnly cookie; static exports carry a CSP.
- **SDKs:** a crashing or slow TypeScript bridge never crashes or hangs the host process, and fail-open lets model calls
  through; bridge requests that time out leave no unfinished signed records; abandoned Python streams are recorded
  before `run.end`.
- **Packaging:** contrib packages depend on `tracekit-ai`; the sdist ships what its tests need.

### Added
- **`tracekit observe` polish** and a reproducible interface video (`docs/demo/observer_scene.py`,
  `record_observer.mjs`).
- **Golden verifier corpus** (`tests/golden/`): frozen v0.1 and v1 evidence with the verifier's recorded verdicts.
- **Known-gap tests** (`tests/test_known_gaps.py`): strict expected failures for gaps the next evidence format closes.
- **`eval/e8_insider.py --require-harness`**, SECURITY.md, CONTRIBUTING (sign-off for contributions from forks).

### Earlier in this cycle

### Installer file writes
- `tracekit init` writes every config, settings file and backup through a directory fd: temp files get an
  unpredictable name, are created exclusively with their final mode (0600 for configs), and nothing follows a symlink.
  A symlinked `~/.claude/settings.json`, `~/.tracekit-client/` entry or signer `config.json` is refused with an error.
- As root, writes into the agent user's home run as that user; signer files are `fchown`ed on the open file.
- Backups are named `<file>.bak-<time>-<random>`.
- Dev mode over TCP: tracekitd binds a free port itself and records it in its config; init reads it back instead of
  probing for a free port.

### Project
- `SECURITY.md` states supported versions, a disclosure timeline, safe harbour and the operator caveat.
- Contributions need a DCO sign-off (`git commit -s`); a CI check enforces it on pull requests.
- Issue templates for policy false positives/negatives and integration requests; blank issues are off and
  security reports go to private advisories. The PR template checks security invariants and evidence-format changes.

### Hook invocation
- Generated hook commands (Claude Code, Codex, Cursor, Gemini) and the plugin's `tracekit-hook` run Python in
  isolated mode (`-I`): the project directory and `PYTHON*` variables no longer affect which `tracekit` is imported.
  Re-run `tracekit init` to rewrite existing hook commands.
- Cursor's `failClosed` and wiring errors in the Codex/Cursor/Gemini hook entry now follow the configured fail mode.
- The plugin's `tracekit-hook` blocks instead of allowing when the package is missing and
  `/etc/tracekit/client.json` is fail-closed.

### Validate remote endpoint URLs
- `tracekit init --remote` and `tracekit otel push` parse the URL: `https://` to any host, plain `http://` only when the
  host is exactly `localhost`, `127.0.0.1` or `::1`; URLs with `user@` are refused.
- The remote signer client and `otel push` no longer follow HTTP redirects, so credentials never reach a redirect target.
- An empty or non-JSON-object reply from the signer is treated as "signer unavailable", like a refused connection.
- `init --remote` refuses to write its config through a symlink.

### Verifier: v1 run completeness (interim, until evidence format v2)
v1 signatures cover `(hash, prev_hash, seq)` only, so an elided stub does not say which run it belonged to.
- **Elided records.** A bundle with any elided stub reports every selected run as "run completeness unproven (v1
  bundle with elided records)" and ends `VERIFIED WITH GAPS (run completeness)`, never plain `VERIFIED`. Export
  already includes every record of the selected runs; selecting fewer runs than the ledger holds now shows this gap.
- **Run boundaries.** Each selected run must have a non-elided `run.start` and a signed `run.end`; otherwise
  "run boundaries unproven" / "tail unproven" (a gap, not a failure). Findings and anchor runs are exempt.
- **Witnessed tail.** With `--witness`, the bundle must reach the first witnessed checkpoint at or after each run's
  `run.end`; a bundle that stops before that checkpoint fails with "tail not covered by a witnessed checkpoint".
- **Output.** The verdict is now two lines, `Integrity: …` and `Assurance: …`; assurance is `dev` when a run.start
  says the signer ran as the agent's own user (`signer_isolation: same-user`), so dev bundles never print a bare
  `VERIFIED.`.

### Fixed
- Redaction stays fast on large tool arguments: the private-key, JWT, connection-string, dotenv and secret-assignment
  rules no longer take quadratic time on repeated prefixes. Connection-string user and password parts are capped at
  256 characters, and URLs with an empty user (`redis://:p@h:6379`) are now redacted.
- When a tool call mentions a `.env` file, every `KEY=value` line in its inputs, including the fields always recorded
  in clear (such as `command`), is redacted.

### Security (observer and replay rendering)
- `tracekit observe` and `replay.html` escape every record-derived value they put into HTML, and fill their data
  slots in one pass, so bundle content cannot inject markup or script.
- The observer's CSP allows only its own script, by a per-response nonce (no `'unsafe-inline'` scripts).
- `observe --bundle` refuses a bundle that fails verification (non-zero exit) instead of showing it.
- With `TRACEKIT_OBSERVE_TOKEN`, open `/?token=…` once: the token is exchanged for an HttpOnly, SameSite=Strict
  cookie and the browser is redirected to a URL without it. API calls take the cookie or `Authorization: Bearer`,
  no longer `?token=`. A `--host 0.0.0.0` observer now answers on its LAN address for authorized requests.

### Security (0.3: harness binding, closing fabricated runs)
After 0.2.1, any process running as the agent's user could still drive the real hook with a complete, well-formed
run that never happened, and it verified as `VERIFIED` (E8.6). The signer now checks *which program* sent each event,
from the kernel's view of the sender's process tree, not from anything the agent can write.
- **Registered harnesses.** `sudo tracekit init --harness [NAME=]PATH` (repeatable; default: the agent's CLI on
  root's PATH) registers the agent program. It must be root-owned with no group/world-writable file or directory
  above it, so the agent cannot replace it. An npm-installed CLI registers as its interpreter plus its script.
- **Binding.** A hook `run.start` is accepted only from a process descending from a registered harness binary,
  matched by executable (`/proc/<pid>/exe`), not by name. The signer records the harness instance (pid + kernel start
  time) in the signed `run.start` (`data.harness`, never accepted from the client), and every later hook or
  transcript event of that run must come from the same instance. Anything else is refused and recorded against the
  targeted run, so a fabricated run, or a detached helper writing into a live run, ends `VERIFIED WITH GAPS`.
- **Fabricated runs from inside the session** are still possible (the agent's own tool call can run the hook with a
  new session id). A second open run in the same harness instance is recorded as a `concurrent_run` capture gap.
- **Verifier.** A new `harness attribution` check names the attested harness, or warns that a system-mode run has no
  binding and its hook events could have come from any process running as the agent's user.
- **Signer privilege.** Reading another user's `/proc/<pid>/exe` needs `CAP_SYS_PTRACE`; the systemd unit grants it
  only when a harness is registered (`AmbientCapabilities`, `CapabilityBoundingSet`).
- **Modes.** `harness_binding: enforce` (default with a registered harness in system mode), `record` (gaps instead
  of refusals), or `off` (default with no harness, and in dev mode). The proxy and SDK sources are not bound.
- **Upgrading:** `sudo tracekit migrate --system --harness /usr/local/bin/claude`, then restart `tracekitd`.
- **Eval.** E8 gains E8.6 (fabricated run outside the harness), E8.7 (fabricated run inside a live session) and E8.8
  (a detached helper writing into a live run). Upstream 0.2.1 verifies all three as clean `VERIFIED`; with binding,
  all eight E8 cases are caught. CI runs E8 with a registered harness and gates on all eight.
- **Still open:** fabricated *events inside the real run*, sent by the agent's own tool calls through the same
  harness instance, are only caught by the proxy cross-check (`proxy_missing`). Closing that needs OS-level capture
  (planned for 0.4).

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
- **PGS end to end on a local chain** (#15): `contrib/onchain/pgs_onchain_demo.py` drives Proof-Gated Signing's guard and
  wallet on a Hardhat chain; blocked transactions are checked on-chain to be unsigned (nonce unchanged), a drift attack
  reverts on its post-conditions. Fixed: transaction summaries now keep the target of PGS-style call dicts.
- **Jaeger example** (#13): `examples/otel_jaeger_check.py` matches every span Jaeger holds to a signed record of a
  verified bundle (run against Jaeger 2.22).
- **Key attestation in bundles** (#16): `--key-attestation FILE` with an external signer; the document's hash is signed
  into checkpoints, exports carry the document, `verify` reports it (Tracekit checks identity, not vendor contents).
- **Auditor walkthrough** (#12), now in contrib/proofpack/README.md.
- **E7: SQL at a million events** (#8, now `contrib/query/e7_sql_scale.py`): every typical query under 1 s on 2 vCPUs; rollup columns are copied out of the
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
- **Proof packs** (#12, now `contrib/proofpack`: `tracekit-proofpack` / `tracekit-report`): bundle, readable report with every check, findings,
  coverage and an evidence-to-control map (EU AI Act Art. 12, SOC 2 CC7.2, ISO/IEC 42001 A.6.2.8). (It also shipped `verify.pyz`, a
  bundled verifier; removed in 0.3.0.)
- **Witness service** (#17): `tracekit witness init|token|serve`, an append-only RFC 6962 Merkle log of checkpoints with
  signed tree heads, per-signer tokens, fork refusal and conflict log; `https://` witness specs check inclusion and
  consistency proofs against a pinned witness key.
- **External signers** (#16): keep the signing key in a TPM, HSM, enclave or KMS through a long-lived helper process;
  signatures verified before use; key assurance signed into checkpoints and reported by `verify` ("signing key").
- **Causeway integration** (#14, now `contrib/causeway`): `tracekit causeway anchor|verify|import-tests|export`.
- **Guarded onchain transactions** (#15, now `contrib/onchain`): `guarded_tx` records a transaction guard's verdict
  (Proof-Gated Signing's `Guard.check` interface) before signing and never signs a blocked transaction; detectors
  TK-X006 to TK-X008.
- **Signed findings** (#10) and **say-vs-do detectors** (#11). `tracekit analyze` runs deterministic detectors (claims vs
  executed commands, requests vs executions, risky actions left out of the agent's account, secrets in output,
  retrospective policy violations) and signs each finding as a `review` event in `findings:<run>`, citing records by seq
  and hash. Bundles carry findings with their run; `tracekit verify` adds "findings cite intact evidence" and fails on
  missing or altered evidence. Findings appear in the live observer. E6 (`eval/e6_findings.py`) measures the detectors
  on 2,000 synthetic sessions, including held-out paraphrases they miss.
- **SQL over the ledger** (#8, now `contrib/query`: `tracekit-sql`). `tracekit sql` with views `runs`, `tool_calls`, `model_exchanges`, `findings`, `gaps`,
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
