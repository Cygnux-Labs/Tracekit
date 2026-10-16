<div align="center">

# Tracekit

**The tamper-evident flight recorder for AI agents.**

What your AI agents did, and why.

[![CI](https://img.shields.io/github/actions/workflow/status/Cygnux-Labs/Tracekit/ci.yml?branch=main&label=CI)](https://github.com/Cygnux-Labs/Tracekit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tracekit-ai)](https://pypi.org/project/tracekit-ai/)
[![Python](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue)](https://github.com/Cygnux-Labs/Tracekit/blob/main/pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE)

</div>

An agent's log is written by the agent. When a prompt injection or a bug makes it delete something, it can rewrite
that log too, and `grep` finds nothing. Tracekit checks each tool call before it runs, records every call and decision
as a signed, hash-chained record, and exports each run as one file that anyone can verify offline. Change one record
and verification fails at that record.

<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4"><img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/demo/cover-up.gif" alt="Tracekit demo: a ticket with a hidden instruction makes a support agent delete 43 orders, then edit its own log and Tracekit's record of the delete. grep finds no delete; Tracekit marks the run FAILED because record 7 no longer matches its hash." width="100%"></a>

<p align="center"><sub>A support ticket hides an instruction. The agent deletes 43 orders, then edits its own log and
Tracekit's record of the delete. <code>grep</code> finds nothing; Tracekit marks the run FAILED. The database, signer,
viewer and both edits are real; the model is scripted.
<a href="https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4">Watch it with sound (1 min 47 s)</a></sub></p>

## Try it in one command

No API key, and with [uv](https://docs.astral.sh/uv/) nothing to install. It takes a few seconds:

```sh
uvx --from tracekit-ai tracekit demo --server
```

A scripted agent runs three shell commands. Tracekit allows the first, denies the second before it runs, and holds
the third for approval. Then the demo rewrites the denied call as allowed in a copy of the run, and verifies both:

```text
== agent run (SCRIPTED: fixed tool calls, not a model)
  Bash 'ls': allow
  Bash 'sudo rm -rf /': deny TK-D001 TK-D004 TK-F003
  Bash 'echo "unterminated': ask TK-SHELL-PARSE
...
Integrity: VERIFIED.

== tamper test: rewrite the denied call as allowed in a copy, then verify again
[FAIL] signatures — 11 record(s), keys valid at their position
        seq 4: hash does not match the event
...
Integrity: FAILED.
```

Without uv: `pip install tracekit-ai`, then `tracekit demo --server`.

## The agent's log vs Tracekit

| | The agent's own log | Tracekit |
|---|---|---|
| A risky call | written down after it ran | checked before it runs: allowed, denied, or held for a person |
| The agent edits a line | nothing shows | verification fails at that record |
| The agent deletes a line | nothing shows | the chain has a hole, and the run won't export |
| An event never arrives | silence | a signed gap record |
| Someone else has to check it | they trust you | they verify one `.tkb` file offline, with keys they pinned |
| The operator rewrites history | nothing shows | an independent witness and a monitor make it visible |

**Read this before you rely on it:** in dev mode, the signer runs as your own user, so an agent that runs commands as
you can read its key and re-sign the log. The table holds when the signer runs where the agent can't reach it: as a
separate OS user, in a container sidecar, or on a central host, with a witness the operator doesn't control
([deployment](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md),
[every limit](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md)).

## Add it to your agent

Three steps, with the agent you already have (OpenAI Agents SDK, LangGraph / LangChain, Claude Agent SDK, an MCP
client, or plain OpenAI / Anthropic / Google Gen AI calls):

```sh
pip install tracekit-ai
```

```python
import tracekit; tracekit.instrument()     # the first line of your agent; then run it as usual
```

```sh
tracekit last                               # Integrity: VERIFIED. / Assurance: dev; ...
```

`tracekit.instrument()` starts a dev signer in the background (or reuses the running one) and gates and records every
tool and model call of the frameworks it finds. `tracekit last` exports the most recent finished run, pins the dev
signer's key, verifies the bundle and says where it is. `Assurance: dev` means the signer ran as you; see above. Then
`tracekit view --dev` browses every run: verdicts, denials, approvals, replay. A call the policy holds for a person
(`ask`) pauses the run or waits, depending on the framework:
[how each integration waits](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstart-v2.md#when-a-call-needs-a-person-ask).

Per framework, with a 10-line example each:
[OpenAI Agents SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/openai-agents.md),
[LangChain / LangGraph](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/langchain.md),
[Claude Agent SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/claude-agent-sdk.md),
[MCP client](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/mcp.md),
[a custom agent](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/custom.md). The
[v2 quickstart](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstart-v2.md) explains each step.

**Coding agents.** `tracekit init --dev --v2` wires Claude Code's hooks to a dev signer; add `--agent codex`,
`cursor` or `gemini` for Codex CLI, Cursor or Gemini CLI
([coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md)).

**Works with** the OpenAI Agents SDK, LangChain and LangGraph, the Claude Agent SDK, MCP clients, Browser Use and
CrewAI in Python; the Vercel AI SDK in TypeScript; OpenTelemetry traces, imported as evidence
([OpenTelemetry](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/otel.md)); and any OpenAI-compatible API
through an LLM gateway that records model calls outside the agent's process
([gateway](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/gateway.md)).

### See it

`tracekit view --dev` opens the one viewer on your runs: each run verified, every call with its decision, and (with
why logs) why a call happened, down to clicking any node of the run's graph. A store opened without why logs gets a
graph of each signed run's calls and their decisions.

![tracekit view: the planner's model call clicked in the run graph, with what it saw, produced and led to](https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/viewer/graph-node.png)

A screenshot tour of every panel: [viewer tour](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md#tour).
Every step end to end, recorded on a clean install with its real output and screenshots:
[walkthrough](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/walkthrough.md).

### More demos

Each runs in a temp dir and needs no API key. `--server` is the demo above. `--why` shows a held email whose cause is
found by replay and cited by its signed record:

```sh
tracekit demo --server                # exit 0
tracekit demo --why                   # exit 0
tracekit init --dev --v2
```

From a checkout, `python examples/v2/langchain/agent.py --scripted` runs a LangGraph agent with a mock model. Or check
the shipped sample bundles (v1) with the verifier alone (`pip install --no-deps tracekit-ai` is enough):

```sh
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # exit 1
```

## What it does

| | |
|---|---|
| **Record** | Every tool call, its decision and its result, plus model calls and approvals, as signed records in one chain per run. A missed or lost event becomes a signed gap record. Gaps are never silent. |
| **Decide** | Each call is allowed, denied, or held until a person answers (`ask`). Policy packs cover coding agents, server agents, browser agents, SQL, HTTP, cloud CLIs, and payments and messaging ([policy reference](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md)). |
| **Approve** | A held call runs only after an approver says yes, from the command line, a web page with OIDC sign-in and passkeys, or Slack. The approval is bound to the exact arguments and used once ([approvals](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md)). A reviewer agent may answer routine approvals inside bounds the policy sets, with budgets and a veto delay; people answer everything else ([agent approvers](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md#agent-approvers)). |
| **Contain** (experimental) | The policy names risky sequences of calls and limits on them. When one trips, the signer opens a signed incident and can hold or quarantine the run; new runs of the same owner and principal inherit that for a cooldown ([incidents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/incidents.md)). Tool calls can run with credentials the agent never holds, through the [tool executor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/executor.md) or [MCP gateway](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/mcp-gateway.md). An [egress observer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/egress.md) outside the agent flags network effects no recorded call explains, and each finished run reports, per action class, whether it was enforced, observed, only reported, or not covered. |
| **Prove** | `tracekit verify` checks a bundle offline against keys you pinned. Witnesses cosign checkpoints of the log, and a monitor watches it from outside ([witnesses](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/witnesses.md), [monitor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/monitor.md)). Each report states an assurance level: `dev`, `local`, `witnessed` or `witnessed+monitored` ([reading a verify report](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md)). |
| **Watch** | `tracekit view` shows runs with their verdicts, blocked and held calls, approvals, gaps, a replay of each run, and a run review ([viewer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md)). |
| **Explain** (experimental) | Where each argument came from: the signer tracks values that entered a run through untrusted content (a fetched page, an email, a ticket) and can hold a call whose recipient, payee or host came only from there ([provenance](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md#provenance-untrusted-and-from-untrusted)). Which input caused an action: `tracekit why` replays a run with each suspect input removed, tools served from the recording, and reports the cause with a confidence interval; results on signed runs are signed findings the verifier rechecks ([tracekit why](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why.md)). |

## How it works

```text
  agent ──► client or hook ──────► signer ─────────────► witnesses
            (SDK, adapter,         - policy: allow,       cosign each
             coding-agent hook)      deny or ask          checkpoint
            holds a run token,     - keys: signs every
            never a key              record
                                   - log: hash chain,
                                     Merkle checkpoints
                                          │
                                          ▼
                                    run.tkb bundle ──► tracekit verify
                                                       (offline, with the keys
                                                        and witnesses you pinned)
```

1. The agent's client asks the signer to decide each tool call before it runs.
2. The signer decides with its own policy, signs the decision, and adds it to the log.
3. After the call, the client reports the result, and the signer records that too.
4. The signer signs checkpoints of the log. Witnesses cosign them.
5. A run is exported as a bundle. Anyone can verify it offline.

Each record is signed and carries the hash of the one before it, so changing any byte of a record makes
verification fail at that record.

The trust model:

- The agent never holds a signing key and never assigns sequence numbers.
- Nothing the agent reports about itself is trusted: not its isolation, its fail mode, gaps, or who approved a call.
  The signer measures or configures these itself.
- Who can rewrite the log decides what a bundle is worth. A dev signer runs as your own user, so an agent that runs
  commands as you can rewrite it. A signer under a separate OS user, in a container sidecar, or on a central host is
  out of the agent's reach.
- The operator who runs the signer could still rewrite its log with its own key. An independent witness and a monitor
  make that visible.

The full model: [architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/architecture.md),
[laptop](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/threat-model-laptop.md) and
[server](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/threat-model-server.md) threat models.

## Run it where the agent can't reach it

The agent's code is the same in every mode; `TRACEKIT_SIGNER` points it at the signer.

| Mode | Who can reach the keys and log | Recorded isolation |
|---|---|---|
| Laptop dev | the agent's own user | `same-user` |
| Laptop system mode (Linux; macOS experimental) | root and the signer's OS user | `separate-user` |
| Container or Kubernetes sidecar | the signer's uid and the node's administrator | `separate-user` |
| Central signer over HTTPS (or Docker Compose) | the signer host's administrators | `remote` |

Each mode end to end, with its commands, its `tracekit doctor` check and the assurance its bundles reach:
[deployment guide](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md). Moving from the v1 signer or from
a laptop to a server: [migration](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/migration.md).

What you need:

- **Python 3.9 to 3.13**, and `pip install tracekit-ai`. The framework integrations need Python 3.10 or
  newer. For the TypeScript SDK, Node 18 or newer and the package file from the GitHub release:
  `npm install https://github.com/Cygnux-Labs/Tracekit/releases/download/v1.2.0/cygnux-tracekit-1.2.0.tgz`. It isn't on npm yet
  ([TypeScript SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/sdk/typescript/README.md#install)).
- **An OS.** Dev mode runs on macOS, Linux and Windows. A signer under its own OS user runs on Linux (macOS is
  experimental). Containers and Kubernetes run on Linux
  ([platforms](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/portability.md)).
- **To try it:** nothing more. Dev mode starts a signer as your own user.
- **For protection against the agent:** a signer the agent can't reach. That is a separate OS user, a container
  sidecar, or a central signer ([deployment guide](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md)).
- **For protection against the operator:** a witness the operator doesn't control, and a monitor.
- **For approvals by people:** approvers listed in the signer's config. They answer from the command line, or through
  an OIDC identity provider (web page, passkeys) or Slack
  ([identity](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/identity.md)).

## Be careful with

- **Dev mode protects nothing against an agent that runs as you.** It can read the key, stop the signer and re-sign
  the log; dev bundles say `isolation: same-user`
  ([FAQ](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md#what-does-same-user-dev-mode-protect)).
- **A verified bundle proves the record is intact.** It does not prove intent, that a reported tool result is true,
  or that every action was captured
  ([FAQ](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md#what-cant-tracekit-prove)).
- **Actions outside the capture path leave no record**, such as a subprocess a hook never sees or code that skips the
  adapter ([adapters](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/adapters.md)).
- **Policy rules match text.** A determined agent can reword a command so no rule matches. Rules are tripwires; the
  protection is the signer's isolation
  ([policy reference](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md#packs-shipped)).
- **Rules match tool names.** A shell tool named `run_command` is not covered by the shell rules until you map it
  ([adapters](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/adapters.md#any-function)).
- **Fail-open tool classes run while the signer is down**, unrecorded; the signer then writes a signed gap for them.
  Every class fails closed by default
  ([FAQ](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md#what-happens-when-the-signer-is-down)).
- **The agent's own claims are never trusted.** Isolation, fail modes and approvers come from the signer's config, so
  set them there ([approvals](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md#who-may-answer)).
- **Without an independent witness, the operator can rewrite the log unseen.** A system-mode signer with no witness
  still verifies as `Assurance: dev` ([deployment](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md#what-decides-a-bundles-assurance)).
- **Commitments hide content, not metadata.** Timing, sizes and counts still show, and witnesses learn when
  checkpoints happen ([privacy](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/privacy.md#what-hashes-and-metadata-still-leak)).
- **The viewer's verdicts are operator-side.** For evidence, verify the bundle yourself with keys you pinned
  ([viewer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md#central-viewer)).

Every limit: [docs/limits.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md)

## The evidence format

For anyone evaluating the format itself, or writing another verifier:

- **Specified.** [Evidence format v2](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/format-v2.md) aims to be
  precise enough to write an independent verifier. Normative
  [test vectors](https://github.com/Cygnux-Labs/Tracekit/tree/main/tests/vectors) pin canonical JSON, record
  signatures and checkpoints.
- **Built on standards.** Canonical JSON is JCS (RFC 8785). Records are signed with Ed25519. Each log is an RFC 6962
  Merkle tree. Checkpoints are C2SP signed notes, and witnesses cosign them per C2SP tlog-cosignature.
- **Self-contained.** A bundle is a zip of records, inclusion proofs, checkpoints and the policy snapshots that
  decided the calls. It holds no verification code. The verifier checks it offline against a trust file you pinned:
  log keys, witnesses and quorum, and optionally a monitor.
- **Old bundles keep verifying.** Formats only grow, and each format's verifier is frozen. v1 bundles go to the v1
  verifier, which needs only the Python standard library.
- **Forward-safe.** A bundle names the minimum verifier version it needs. An older verifier reports it
  `UNVERIFIABLE (needs tracekit >= x)`, never `FAILED`.

## Use in CI

Verify a v1 bundle in a GitHub Actions workflow:

```yaml
- uses: Cygnux-Labs/Tracekit@main
  with:
    bundle: run.tkb
    key: keys/signer.pub        # pin the signer; or witness: git:/path/to/clone
```

`require-anchor` defaults to `true`, so an unanchored bundle fails the step; set `require-anchor: "false"` to only
report it.

## Docs

- Seeing it work: a [walkthrough](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/walkthrough.md) of every step,
  recorded on a clean install with screenshots; [recorded demos](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demos/README.md)
  of each main use case, offline, with their bundles and verify reports
- The videos: [the cover-up](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demo/cover-up.mp4) (1 min 47 s),
  and a [terminal tour](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/demos/tracekit-tour.mp4) of every demo
  running (3 min 44 s)
- What's stable and what's experimental: [support](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/support.md)
- How it fits together: [architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/architecture.md),
  [evidence format v2](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/format-v2.md)
- Running it: [deployment](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md),
  [compose](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy-compose.md),
  [container](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy-container.md),
  [Kubernetes](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy-kubernetes.md),
  [doctor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/doctor.md),
  [witnesses](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/witnesses.md),
  [monitor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/monitor.md),
  [viewer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md),
  [observability](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/observability.md),
  [privacy](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/privacy.md),
  [remote ingest](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/remote-ingest.md),
  [record-key issuer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/issuer.md)
- Deciding calls: [policy reference](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md),
  [approvals](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md),
  [LLM gateway](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/gateway.md),
  [tool executor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/executor.md),
  [MCP gateway](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/mcp-gateway.md),
  [egress observer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/egress.md),
  [incidents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/incidents.md),
  [webhooks](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/webhooks.md),
  [OpenTelemetry](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/otel.md)
- Checking evidence: [reading a verify report](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md),
  [auditor guide](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/auditor-guide.md),
  [evaluation](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/evaluation.md),
  [technical report](https://github.com/Cygnux-Labs/Tracekit/blob/main/report/tracekit-v2.md),
  [FAQ and limits](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md),
  [known limits and trade-offs](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md),
  [security checklist](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/security-checklist.md),
  [case study: two open-source agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/case-study-oss-agents.md)
- Asking why an action happened: [tracekit why](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why.md), [its architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why-architecture.md)
- Releasing: [the procedure](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/RELEASING.md),
  [launch checklist](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/launch-checklist.md)
- The v1 laptop signer (`tracekitd`, `tracekit init --dev`, `tracekit demo`, `tracekit view --ledger`) and its bundles keep
  working: [coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md),
  [signing](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/signing.md),
  [findings](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/findings.md),
  [v1 adapters and integrations](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/integrations.md),
  [platforms](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/portability.md)

## Status

This is 1.2.0. 1.0 was the first stable release, and 1.x is the supported line
([SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md)). What changed in each release:
[CHANGELOG.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/CHANGELOG.md).

- **Stable:** evidence format v2 and its verifier. 1.x verifiers verify every 1.0 bundle. v1 bundles and the v1
  verifier are unchanged.
- **Versioned:** the signer RPC (version 16; a 1.2 signer also serves version 15 clients). A client newer than its
  signer is refused, so upgrade the signer first ([changelog](https://github.com/Cygnux-Labs/Tracekit/blob/main/CHANGELOG.md)).
- **Stable core:** the v2 signer (dev mode and Linux system mode, file storage), the Python SDK with
  `tracekit.instrument()` and its OpenAI Agents, LangChain / LangGraph, Claude Agent SDK and MCP integrations, the
  Claude Code hooks (v2), policy v2 with its packs, bundle export, the Python and TypeScript verifiers, `tracekit view`
  and `tracekit doctor`.
- **Experimental:** everything else. It works and is tested, but may change and gets less hardening; experimental
  commands and servers say so when they start
  ([what's stable](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/support.md)). The v1 OTLP receiver, ingest
  gateway and model proxy also need `--experimental`.
- **Not yet done:** an external review of the threat models, and some release checks that wait on the owner
  ([launch checklist](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/launch-checklist.md)).

## Contributing and security

[CONTRIBUTING.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md): `make install`, then `make check`.
Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md).
Questions and ideas are welcome in [issues](https://github.com/Cygnux-Labs/Tracekit/issues). If Tracekit is useful to
you, a star helps other teams find it.

## Licence

MIT, Copyright Cygnux Labs. See [LICENSE](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE).
