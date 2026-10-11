<div align="center">

# Tracekit

**Tamper-evident records of what your AI agents did.**

[![CI](https://img.shields.io/github/actions/workflow/status/Cygnux-Labs/Tracekit/ci.yml?branch=main&label=CI)](https://github.com/Cygnux-Labs/Tracekit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tracekit-ai)](https://pypi.org/project/tracekit-ai/)
[![Python](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue)](https://github.com/Cygnux-Labs/Tracekit/blob/main/pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE)

</div>

Tracekit is a signer that sits between an AI agent and its tools. Before each tool call runs, the signer checks it
against your policy and allows it, denies it, or holds it for a person to approve. Every call and decision is written
as a signed, hash-chained record that the agent can't edit. A run exports as one `.tkb` file that anyone can verify
offline.

<img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/demo/observer.gif" alt="tracekit observe: four coding agents traced live; each dangerous action is blocked by policy and recorded" width="100%">

## Why it exists

Agents now run shell commands, edit code, query databases and send messages on real systems. Most agent logs are
written by the agent's own process, so whatever controls the agent can also edit them or skip them. When something
goes wrong, you need a record you can trust. You also need to show it to someone else: a security team, an auditor, a
customer. Tracekit keeps that record outside the agent's control, and lets anyone check it without trusting you.

## What it does

**Record**
- Every tool call, its decision and its result, plus model calls and approvals, as signed records in one chain per run.
- A missed or lost event becomes a signed gap record. Gaps are never silent.

**Decide**
- Policy packs for coding agents, server agents, browser agents, SQL, HTTP, cloud CLIs, and payments and messaging
  ([policy reference](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md)).
- Each call is allowed, denied, or held until a person answers (`ask`).

**Approve**
- A held call runs only after an approver says yes. The approval is bound to the exact arguments and used once.
- Approvers answer from the command line, from a web page with OIDC sign-in and passkeys, or from Slack
  ([approvals](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md)).

**Prove**
- `tracekit verify` checks a bundle offline against keys you pinned.
- Witnesses cosign checkpoints of the log, and a monitor watches it from outside
  ([witnesses](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/witnesses.md),
  [monitor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/monitor.md)).
- Each report states an assurance level: `dev`, `local`, `witnessed` or `witnessed+monitored`
  ([reading a verify report](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md)).

**Watch**
- `tracekit view` shows runs with their verdicts, blocked and held calls, approvals, gaps, a replay of each run, and a
  run review ([viewer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md)).

**Integrate**
- Coding agents through their hooks: Claude Code, Codex CLI, Cursor, Gemini CLI
  ([coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md)).
- Python and TypeScript SDKs, with integrations for LangChain and LangGraph, the OpenAI Agents SDK, the Claude Agent
  SDK, MCP clients, Browser Use (Python) and the Vercel AI SDK (TypeScript)
  ([quickstarts](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstart-v2.md)).
- OpenTelemetry traces imported as evidence ([OpenTelemetry](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/otel.md)).
- An LLM gateway for OpenAI-compatible APIs that records model calls outside the agent's process
  ([gateway](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/gateway.md)).

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

## Quickstart (under two minutes)

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
signer's key, verifies the bundle and says where it is. Then `tracekit view --dev` browses every run: verdicts,
denials, approvals, replay.

Per framework, with a 10-line example each:
[OpenAI Agents SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/openai-agents.md),
[LangChain / LangGraph](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/langchain.md),
[Claude Agent SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/claude-agent-sdk.md),
[MCP client](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/mcp.md),
[a custom agent](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/custom.md). The
[v2 quickstart](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstart-v2.md) explains each step and what
`dev` assurance means; [limits](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md) lists what this path
doesn't cover.

No agent at hand? From a checkout, `python examples/v2/langchain/agent.py --scripted` runs a LangGraph agent with a
mock model whose calls are allowed, denied and held for an approval. Without one, the same loop in a temp dir (with a
witness cosignature and a tampered copy that fails), and Claude Code's hooks wired to a dev signer:

```sh
tracekit demo --server                # exit 0
tracekit init --dev --v2
```

Or check the shipped sample bundles (v1) with the verifier alone (`pip install --no-deps tracekit-ai` is enough):

```sh
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # exit 1
```

## What you need

- **Python 3.9 to 3.13**, and `pip install tracekit-ai`. The framework integrations need Python 3.10 or
  newer. For the TypeScript SDK, Node 18 or newer and `@cygnux/tracekit`.
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

## Deployment modes

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

- How it fits together: [architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/architecture.md),
  [evidence format v2](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/format-v2.md)
- Running it: [deployment](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/deploy.md),
  [doctor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/doctor.md),
  [witnesses](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/witnesses.md),
  [monitor](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/monitor.md),
  [viewer](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/viewer.md),
  [observability](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/observability.md),
  [privacy](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/privacy.md)
- Deciding calls: [policy reference](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/policy-v2.md),
  [approvals](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/approvals.md),
  [LLM gateway](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/gateway.md),
  [OpenTelemetry](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/otel.md)
- Checking evidence: [reading a verify report](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md),
  [auditor guide](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/auditor-guide.md),
  [evaluation](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/evaluation.md),
  [technical report](https://github.com/Cygnux-Labs/Tracekit/blob/main/report/tracekit-v2.md),
  [FAQ and limits](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md),
  [known limits and trade-offs](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/limits.md)
- Asking why an action happened: [tracekit why](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why.md), [its architecture](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/why-architecture.md)
- Releasing: [launch checklist for 1.0](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/launch-checklist.md)
- The v1 laptop signer (`tracekitd`, `tracekit init --dev`, `tracekit demo`, `tracekit observe`) and its bundles keep
  working: [coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md),
  [signing](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/signing.md),
  [platforms](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/portability.md)

## Status

1.0 is the first stable release, and 1.x is the supported line
([SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md)).

- **Stable:** evidence format v2 and its verifier. 1.x verifiers verify every 1.0 bundle. v1 bundles and the v1
  verifier are unchanged.
- **Versioned:** the signer RPC (version 12). Clients and signers of different RPC versions refuse each other, so
  upgrade them together ([changelog](https://github.com/Cygnux-Labs/Tracekit/blob/main/CHANGELOG.md)).
- **Experimental:** laptop system mode on macOS, the Rekor witness of the v1 signer, and the v1 OTLP receiver, ingest
  gateway and model proxy (each needs `--experimental`).
- **Not yet done:** an external review of the threat models, and some release checks that wait on the owner
  ([launch checklist](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/launch-checklist.md)).

## Contributing and security

[CONTRIBUTING.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md): `make install`, then `make check`.
Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md).

## Licence

MIT, Copyright Cygnux Labs. See [LICENSE](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE).
