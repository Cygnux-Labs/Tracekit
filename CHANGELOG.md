# Changelog

All notable changes to Tracekit. Versions follow [PEP 440](https://peps.python.org/pep-0440/).

## 1.2.1 (2026-10-16) — on npm

A patch for 1.2: the TypeScript SDK goes on npm, and the fixes a first-time user hits in their first ten minutes.
Bundles are unchanged: 1.2.1 writes and verifies the same evidence format as 1.2.0.

### Changed
- **npm: `@cygnuxlabs/tracekit`.** The TypeScript SDK installs with `npm install @cygnuxlabs/tracekit` (the
  `@cygnux` scope belongs to someone else, so the packages moved). On Apple Silicon macOS, Linux (x64 and arm64,
  glibc) and Windows x64, npm also installs a `@cygnuxlabs/tracekit-signer-<platform>` package that bundles a Python,
  so `npx @cygnuxlabs/tracekit up` starts a dev signer without one. On an Intel Mac or Alpine,
  `pip install 'tracekit-ai[signer]'` ([limits](docs/limits.md#install)).
- **A refusal says why.** `decide` answers a deny or an ask with its rules' reasons in `reason`, an optional field
  RPC 16 already had, so older clients are unaffected. The Claude Code hook prints
  `Blocked by tracekit policy: TK-D007: touching Tracekit's own files or signer`, and the framework integrations pass
  the reason to the model.

### Fixed
- `tracekit doctor` on a fresh dev home says to start the dev signer (`tracekit up`) for the missing keys, not to run
  doctor as root, and that a dev signer's assurance stays `dev` (it takes no witnesses).
- The manifest check's failure names the files that differ from the manifest and how (changed, missing, not listed),
  the same in the Python and TypeScript verifiers; it repeated the pass text.
- `tracekit down` right after `tracekit up` stops the starting signer; it exited 1 (`Hung`) or missed it.
- `tracekit uninstall` says what it removed once.

## 1.2.0 (2026-10-13) — control

1.1 records why an agent acted. 1.2 lets the signer act on what it sees, for agents running on servers:
- tool calls run with credentials the agent never holds ([executor](docs/executor.md),
  [MCP gateway](docs/mcp-gateway.md));
- the signer detects risky sequences across calls and contains the runs that trip them
  ([incidents](docs/incidents.md));
- reviewer agents may answer routine approvals inside bounds the policy sets
  ([agent approvers](docs/approvals.md#agent-approvers));
- a call that was allowed but never reported back becomes a signed gap, and an
  [egress observer](docs/egress.md) records network effects from outside the agent.

It also has fixes from running Tracekit inside eight real agent projects: OpenAI's customer-service demo, LangGraph,
Browser Use, mcp-agent, OpenAI Agents JS, the Vercel AI SDK, PydanticAI and CrewAI. v1 bundles and 1.0/1.1 bundles
keep verifying. Every limit of the new features is in [docs/limits.md](docs/limits.md).

1.1.0rc1 was never published, and neither was 1.0.1 on PyPI; this release includes everything listed under
both below.

### Upgrade notes
- **Signer RPC version 16.** A 1.2 signer serves RPC 15 and 16. Coming from 1.0 (RPC 12), upgrade the signer and its
  clients together.
- **Bundles a 1.2 signer writes need a 1.2 verifier** (`verifier_min_version: 1.2.0`): every finished run's `run.final`
  carries the coverage matrix, and 1.2 adds completeness gaps, `run.child`, incidents and containment records, agent
  approvals, `effect.observed`, `run.registered`'s `posture`, `parent_run` and `session`, `provider_executed` and
  `paired_by_args`. Older verifiers report such a bundle `UNVERIFIABLE (needs tracekit >= 1.2.0)`, never `FAILED`.
  Bundles from 1.0 signers keep verifying as before.
- **`verify` warns on more**: every signed gap that isn't informational, fail-open tool classes, unexplained network
  effects, lost observers, held calls left unresolved, unchecked agent approvals, missing incident policies, and
  calls whose records name different tiers (this one can fire on older bundles too). `verify --strict` exits 3 on
  them, so a CI gate that passed on 1.0 may now stop. Each warning names what it found.
- **Policies**: map your application's own tools to the new class `app` (mapping a tool to `unknown` is now a policy
  warning; a 1.1 policy still loads). Name handoff tools in `handoffs:` and structured-output tools in
  `structured_output:`. No shipped pack names any handoff, so `transfer_to_*` calls reconcile as `hook_missing` until
  you name them.
- **Python custom loops** (#218): `RunHandle.decide` no longer raises `SignerUnavailable`; see Behaviour
  changes. A loop that caught that exception to block now blocks by `d["decision"]`.
- **Containment operators** (#213): the signer refuses to start when one `authorize` entry grants both
  `register_run` and an operator call. Give operators an identity of their own.
- **Long-running servers**: open a run per conversation and make it current per request (`with conversation.current():`
  in Python, `withRun()` in TypeScript), as [the quickstart](docs/quickstart-v2.md#a-server-a-run-per-conversation)
  shows.

### Behaviour changes
- **One viewer** (#224): `tracekit view` opens the v2 signer's runs (default), why logs (`--why DIR`), the v1 ledger
  (`--ledger`) or a v1 bundle (`--bundle`, refused when it fails verification). `tracekit observe` and `tracekit why
  serve` keep working and say they are now part of `tracekit view`. `tracekit view --why DIR` with no store shows the
  why logs alone; `--dev --why DIR` combines them with the dev signer's runs.
- **Experimental surfaces say so** (#226): each experimental command or server prints one line when it starts, and
  the signer names the experimental settings it was given. [docs/support.md](docs/support.md) lists the stable core.
- **npm is paused** (#225): the TypeScript SDK installs from the `.tgz` attached to the GitHub release.
- **Python `RunHandle.decide` no longer raises `SignerUnavailable`** (#218). While the signer can't be
  reached, it returns the run's fail-mode decision with `unavailable: True` and a warning, as the TypeScript client
  does. A refusal still raises `RPCError`.
- **Python `RunHandle.complete` never raises** (#218). The call already ran, so a result the signer can't
  take is a warning (it returns None), and the signer records the call as decided and not completed.
- Tracekit's model-call refusals raise `tracekit.Refused`, a `PermissionError` (#218).
- Mapping a tool to `unknown` in a policy is a warning (#212).
- `verify` (Python and TypeScript) warns on non-informational gap kinds and fail-open classes; `--strict` exits 3
  (#212).
- LangGraph: a Tracekit `ask` pauses the graph whatever the ToolNode's `handle_tool_errors` is, and through
  `.with_fallbacks()` (#212).
- `instrument()` (Python) renews its process run after the signer closes it for idleness, and sends work to the current
  run while one is set (#206). It no longer patches OpenAI Agents' `Runner` (#206). TypeScript does the same, at most
  once per call (#214).
- TypeScript: a run with pending or approved-but-unconsumed approvals stays open at exit, so another process can
  approve and resume it. SIGINT/SIGTERM close the run only when nothing else handles the signal (#214).
- Browser pack: `browser_use:evaluate` asks; a navigation with a query string counts as sending data to its host;
  `send_keys` and `select_dropdown` count as typing (#212).
- `tool_results_sent` counts only results since the model's last turn (#206).
- Refusal texts the model sees leave out `TK-UNKNOWN-TOOL`; the signed `rule_ids` are unchanged (#218).
- `tracekit init`, `uninstall` and `doctor` use `$CLAUDE_CONFIG_DIR/settings.json` when it is set (#218).
- Containment (#213): no trigger suspends an identity. Suspension is an operator's call: a policy with
  `suspend:` in `respond` fails to compile, so the signer won't load it.

### Added
- **The viewer works like the why app it came from** (#224, #228): RUNS, OVERVIEW, TIMELINE, WHY DID IT HAPPEN?,
  GRAPH, AGENTS and INFLUENCE views; the graph is a flowchart with arrows and confirmed causes drawn to their target
  with their effect; clicking a node shows what it saw, produced, came from and led to. A store opened without why logs
  gets a graph of each signed run's calls with their decisions. A screenshot tour is in [docs/viewer.md](docs/viewer.md#tour).
- **`tracekit why report`** (#228): one offline HTML file with every run; `tracekit why demo` writes one.
- **`tracekit view --webhook URL`**: POSTs each new high why alert as JSON (Slack-compatible), as `tracekit why serve` did.
- **Faster signer** (#223): about 12% more events per second in E9's quick run and 15% less CPU per event at
  ack-on-write; no record, hash or
  signature changes.
- **Signer settings** (signer.yaml): `posture`, `observe_grace_s`, `gateway_wait_s`, `suspensions`,
  `approvals.agents`, a configurable `approvals.ttl_s`, `agent_consume_s` and `agent_timeout_s`; the signer refuses to
  start when an agent approver's `veto_s` isn't shorter than `approvals.ttl_s`. `tracekit init --v2 --egress` routes
  an agent user's traffic through the egress observer (Linux system mode).
- **Custody, tier T2** (#209): `tracekit executor` runs registered actions with credentials the agent never holds;
  `tracekit mcp-gateway` proxies MCP servers whose credentials stay in it. Adapters honour an ask rule's `approval: {executor: t2}`. Calls a
  gateway holds are bound to it and its caller, recorded with `via`, and resolved or signed `held_call_unresolved` when
  the run closes. Helm and compose services and an opt-in egress NetworkPolicy ship too.
- **Completeness** (#210): signed gaps for calls allowed or approved that never completed (`decided_not_completed`),
  for writes after `run.final` (`late_activity`), for a second run in one bound harness process (`concurrent_run`) and
  for a killed tailer (heartbeats). There is also a live `reconcile.hook_missing` when the gateway sees a result go
  back with no decide. Inputs of provider-executed tools are committed, and the gateway gets a `provider_tools`
  allow/deny.
- **Detection** (#207): `sequences:` and `limits:` in the policy, over rule ids and labels, scoped to a run, session,
  owner or attested principal. They are recorded as `incident.opened` / `incident.updated` (shadow unless a
  `respond:` rule enforces), with `tracekit policy backtest` and shadow-mode rules in the shipped packs.
- **Containment** (#213): enforced `hold` (each call asks a person, never an agent or self-approval) and
  `quarantine` (deny, then refuse; the gateway stops the model loop). New runs of the same owner and principal
  inherit them for a cooldown. Operator calls (`tracekit signer incidents list|show|resolve|hold|quarantine|resume|
  pause|unpause|suspend|unsuspend`), a shared suspension list, a durable incident outbox (OCSF 2005, Slack), and
  verifier checks that each response was honoured.
- **Agent approvers** (#208): a reviewer agent may answer approvals inside typed bounds the policy sets
  (`approval.agent`), with budgets and a veto delay; people answer everything else. The reference reviewer
  (`tracekit reviewer`), bridges, viewer desk and verifier checks (#211).
- **Run sessions** (#203): `register_run`'s `parent` links a child run to its parent (`parent_run`, `session`), and
  detection scopes by session.
- **Format 1.2 gate** (#203): one version table sets each bundle's `verifier_min_version`; shipped rows are frozen by a
  test (#214).
- **CrewAI** (#218): `tracekit.instrument()` wires CrewAI's tool hooks, which block by return value, never
  by raising ([CrewAI](docs/integrations/crewai.md)).
- **Pairing without call ids** (#218): a call decided under an adapter's own id is reconciled with the
  model's tool use of the same turn by its arguments, when unambiguous (`run.final.paired_by_args`).
- **Policy**: class `app` for an application's own tools; `handoffs:`; `structured_output:` (#206, #212).
- **MCP**: mcp 1.x sessions are named from `initialize()` (or `TracekitSession(..., server=)`) (#212). TypeScript
  gates local MCP servers (agents-js) and `@ai-sdk/mcp` tools as `mcp:<server>/<tool>` (#214).
- `instrument()` wires Browser Use (#212).
- **Egress observation and the coverage matrix** (#215): `tracekit egress`, a forward/CONNECT proxy outside the
  agent (no TLS interception) that checks each run's token, records `effect.observed` and flags
  `reconcile.unexplained_effect`; `run.final` and both verifiers report per action class whether it was enforced,
  observed, reported or not covered.
- **Recorded demos** of the main use cases in [docs/demos](docs/demos/README.md) (`make demos` regenerates and
  checks them), and a case study of Tracekit on real open-source agents
  ([docs/case-study-oss-agents.md](docs/case-study-oss-agents.md)).

### Fixed
- The v1 client: a reply lost after the request went out no longer resends and records a false "counter went
  backwards" gap and a `signer_down` gap (#218).
- Python `RunHandle.approval_consume` never raises (it returns `{"ok": False, "reason": ...}`), and result fields never
  raise on values that aren't plain JSON (#218).
- Claude Code's SessionEnd names the session's last `client_seq`, and a run the signer already closed still takes a
  client's trailing gap (pre-release review).
- **A denied tool ran in CrewAI while the signer was down.** CrewAI runs a tool when a hook raises, and Python's
  `decide` raised. Fixed by the fail-mode `decide` and the CrewAI integration (#218).
- **An event lost in an outage at the very end of a run left no signed gap.** `close_run` now names each stream's last
  `client_seq` (#214).
- Python `complete` raised after the tool ran when the signer was down, and crashed the agent (#218).
- Streamed OpenAI responses (`with_streaming_response` + `parse()`) were recorded empty, so every tool call
  reconciled as `fabricated` (#206).
- OpenAI Agents: `ask` raised TypeError with an app's own run context (#206).
- Long-running servers were refused every call after the process run's idle close: Python (#206), TypeScript (#214).
- mcp 1.x: `instrument()` broke every MCP call, and MCP error results were signed `ok` (#212).
- Reconciliation: an MCP call matches the names frameworks show the model (bare tool, `mcp__<server>__<tool>`,
  `mcp_<server>__<tool>`) and is compared by signer-computed digests (#214). No `class_mismatch` gap when the policy's
  own mapping is at least as strict as an adapter's generic hint (#218).
- A model response missed in an outage is sent at the next call after a signed gap. Leaving a `with client.run()`
  block never hides the block's own exception (#212).
- The policy YAML subset reads flow lists split over lines (#218).
- A tool result with a lone surrogate no longer crashes the adapter after the action ran (#218).
- Python `run.call("approval_list")` works, and every Python client `call` takes keywords (#218).
- The TypeScript gate follows `currentRun()` / `withRun()`, and a call an app's own guardrail refuses is completed as
  an error (#214).
- CI: three intermittent test failures (#205).

### Security
- A client's tool class hint can never exempt a call through a rule's `unless` (pre-release review).
- Agent approvers: a person's reject now sticks: an agent can't approve the same call by asking again (pre-release review).
- Bundles with a passkey-approved call verify: the schema now admits `approval.request`'s `passkey` (gated as 1.2;
  this also affected the unpublished 1.1.0rc1 commit) (pre-release review).
- Browser Use: secrets from `sensitive_data` are masked in every encoded form (percent-encoding at any depth, HTML
  references, JSON and `\u` escapes) before anything reaches the signer (#212).
- Browser Use: every page the agent reads is observed as untrusted before its next action, and an unobservable page
  refuses the action unless `browser` fails open. A `client_counter_gap` makes the run's provenance index partial
  (#212).
- An MCP tool is also checked under its bare name, the stricter verdict applying, so relabelling a tool as MCP gains
  nothing (#214).
- Calls a gateway or executor holds can't be completed, consumed or abandoned by the agent (#209).
- The LangChain adapter uses plain `http://` only to an IP-literal loopback signer (#212).
- Containment hardening from an independent review (#213): several holds per run, cooldowns for operator holds,
  suspension checked on every call, and verifiers that check an enforced response was recorded.

### Not in this release
- Linking an OpenTelemetry-imported run to the run that gated the same calls (docs say how to read them apart).
- A server-name map for MCP under mcp-agent: its calls stay unpaired (`reconcile.hook_missing` + `fabricated`), as
  [limits](docs/limits.md) says.
- A policy key marking MCP servers trusted, a delegation class for CrewAI coworker tools, a Python approval-states
  helper.

## 1.1.0rc1 (2026-10-11) — the why

The first 1.1 release candidate. 1.0 records what an agent did, provably; 1.1 adds why it did it, also provably:
the signer tracks where each argument came from and can hold a call whose value came only from untrusted content,
and `tracekit why` finds which input caused an action by replaying the run without it. Everything 1.0 promises is
unchanged; v1 bundles and 1.0 bundles keep verifying. Every limit of the new features: [docs/limits.md](docs/limits.md).

### Upgrade notes
- **Signer RPC version 15** (1.0 spoke 12): upgrade the signer and its clients together, as before.
- **Bundles with 1.1 records need a 1.1 verifier** (`verifier_min_version: 1.1.0`): `input.observed` records,
  decisions with `provenance`, content-vault and why-finding records. A 1.0 verifier reports them `UNVERIFIABLE`,
  never `FAILED`. Runs with none of them stay readable by 1.0. Export bundles from a 1.1 signer with tracekit >= 1.1.
- **Provenance fails closed.** After a signer restart, or when a run's index is truncated, partial or out of time,
  `from: untrusted` rules hold the calls whose pattern matches (emails, payments, data sent to a host) until the run
  ends; the decision records why. Values your app supplies: observe them as trusted.
- **Postgres**: existing stores keep working; turning the content vault on needs `tracekit signer migrate` (schema 2).

### Added
- **Signed provenance** ([policy](docs/policy-v2.md#provenance-untrusted-and-from-untrusted)): per run, the signer
  indexes (as keyed hashes, in memory) the values that untrusted tools' results and observed inputs carried; every
  decision records which arguments carry untrusted-only values and from which record. New policy keys `untrusted:`
  and `from: untrusted`; rules TK-P001 (an email recipient), TK-P002 (a payee or account) and TK-P003 (data sent to a
  host) hold such calls for a person. Every shipped integration sends untrusted tools' results to the signer
  (`send_result`), so this works with OpenAI Agents, LangGraph, the Claude Agent SDK, MCP, Browser Use, Claude Code and
  the TypeScript adapters. `run.observe(value, source=, trust=)` (Python and TypeScript) records other content.
- **`tracekit why`** (formerly Causeway, now part of Tracekit): a causal log of multi-agent runs, lineage and argument
  provenance, candidate causes, counterfactual replay with paired seeds and confidence intervals, sequential tests,
  and Find the cause (`tracekit why attribute`). Replays serve tool results from the recording and never run tools.
  Runs recorded with a signer cite the signed records behind every event; `tracekit why import --store/--bundle`
  turns signed runs into why runs; `tracekit why verify --salts` checks quoted content against the signed
  commitments.
- **Attribution on signed runs**: decision replay and agentless loop replay of OpenAI- and Anthropic-style agents,
  through the gateway, from the content vault, without the agent's code; a ranking that picks what to test first;
  results written as signed `why.finding` records whose replay runs are signed too, and which the verifier
  recomputes (interval, verdict, and each hit against the recorded model responses).
- **LangGraph fork replay** (`tracekit why attribute --langgraph module:factory`): replays a LangGraph thread from the
  checkpoint before the suspect input, in scratch branches that never touch the app's thread, store, cache or tools.
- **Content vault** (opt-in, [privacy](docs/privacy.md)): the signer keeps each record's redacted content encrypted
  (per-run keys, bound to the record); reading it takes a `content_read` grant and writes a signed `content.accessed`
  record; erasure and retention delete the run's key (and its replay runs') and write `content.erased`.
- **The viewer is the why UI**: where each argument came from (signed), the WHY panel (lineage, candidate causes,
  tests), graph, agents and influence views, why alerts, for runs with why logs (`tracekit view --why DIR`).
- **Independent TypeScript verifier** (`@cygnux/tracekit/verify`, `npx @cygnux/tracekit verify`): written from
  docs/format-v2.md, zero dependencies, Node and browsers; CI checks it agrees with the Python verifier on every case.
- **Public witness** ([witnesses](docs/witnesses.md#the-public-witness)): a free C2SP witness server with open
  registration (`tracekit public-witness serve`), the signer's one-line opt-in `witnesses: [public]`, and a deployment
  kit (deploy/public-witness). Its URL and key ship once it is deployed.
- `demo --why`: the support desk end to end — a held exfiltration email, the cause found by replay, the citation
  checked in the verified bundle.
- docs/quickstart-v2.md: how each integration waits for a person on a held call.

### Fixed (from the pre-1.1 review)
- The v2 verifier reads bundles strictly (one canonical zip layout, integer run-set bounds, JSON depth 128); also in
  1.0.1.
- Provenance: linear-time value extraction (an adversarial page no longer costs seconds per call), redaction no longer
  hides an injected value, list fields and hosts are matched as written, normalisation of Unicode tricks, the index
  survives a storage outage.
- `tracekit why`: replays through the Anthropic adapter never run real tools; ingest is answered before analysis and
  stays fast on long runs; ingest tokens are separate from the viewer's and bound to their runs; malformed or
  duplicated events are refused; test results are hash-chained; p-values are corrected for every input tested.
- The public witness: per-client limits, buffered request bodies behind Caddy, expiring unused origins, a total
  deadline on witness requests, and start-up that no hostile witness can stall.
- Claude Code: the transcript tailer follows the session's subagent transcripts too, so a subagent's tool calls no
  longer reconcile as `fabricated` (and `verify --strict` no longer exits 3 on them).
- Windows: `tracekit doctor` reports that it doesn't read ACLs instead of failing the key and content-vault checks on
  POSIX file modes; the dev signer's start tolerates its config being rewritten.
- Docs say what ships: no T2 executor yet (run held calls in a worker of your own), a v2 hook payload that can't be
  parsed passes unrecorded, and the Claude Agent SDK adapter honours `fail_modes`.

### Not in this release
- The viewer's FIND THE CAUSE and RUN TEST buttons for signed runs: use `tracekit why attribute --run ...`.
- The public witness's URL and key (the shortcut says so until it is deployed).
- npm packages are not published yet.

### Corrections
- The 1.0.0 entry says npm packages are signed release artifacts; no npm packages were published for 1.0.0.

## 1.0.1 (2026-10-11) — stricter bundle reading

A patch for 1.0: the v2 verifier reads bundles more strictly. Bundles written by Tracekit are unaffected; every
existing bundle verifies as before.

### Fixed
- A v2 bundle must have one zip layout ([format v2 §9](docs/format-v2.md#9-bundle-layout)): no zip64 records, no
  archive or entry comments, no extra fields, entries contiguous from offset 0, the central directory and its end
  record exactly where they belong, stored or deflate only, flags 0. Anything else is `UNUSABLE BUNDLE`, so every zip
  reader sees the same entries the verifier checked.
- `registry/run-set.json` bounds must be JSON integers.
- JSON nested deeper than 128 levels is refused everywhere: by both verifiers' strict parser and by the signer, which
  denies such tool-call arguments (`TK-ARGS-INVALID`).

## 1.0.0 (2026-10-11) — first stable release

1.0.0 is 1.0.0rc2 made stable: the v2 signer, evidence format v2 and its verifier, witnesses, the monitor, team approvals,
server deployments (container, Kubernetes sidecar, central signer on Postgres) and the run viewer. The v2 format is now
stable: 1.x verifiers verify every 1.0 bundle, and a bundle that needs a newer verifier says so (`UNVERIFIABLE`), never
`FAILED`. The v1 laptop setup and v1 bundles keep working unchanged. Upgrade notes from 0.4.0: see 1.0.0rc1 below.

### Added
- **One install, one line, a verified run.** `pip install tracekit-ai` now installs everything the dev signer needs
  (`tracekit-ai[signer]` still works); `pip install --no-deps tracekit-ai` is the verifier alone, on the standard
  library. `import tracekit; tracekit.instrument()` wires the frameworks it finds (OpenAI Agents SDK, LangGraph /
  LangChain, Claude Agent SDK, MCP, and the OpenAI, Anthropic and Google Gen AI SDKs), starting a dev signer if none
  is running. `tracekit last` exports the newest finished run, pins the dev signer's key and verifies it. The README
  and each framework quickstart are those three steps. What this path doesn't cover:
  [docs/limits.md](docs/limits.md).
- [docs/limits.md](docs/limits.md): every known limit and trade-off on one page.

### Changed
- `tracekit.instrument(tracer)` (v1 model-call tracing) is now `tracekit.autotrace.instrument(tracer)`;
  `tracekit.instrument()` raises a `TypeError` naming it when given a tracer.

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
