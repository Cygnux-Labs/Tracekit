<div align="center">

# Tracekit

**Tamper-evident records of what your AI agents did.**

[![CI](https://img.shields.io/github/actions/workflow/status/Cygnux-Labs/Tracekit/ci.yml?branch=main&label=CI)](https://github.com/Cygnux-Labs/Tracekit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tracekit-ai)](https://pypi.org/project/tracekit-ai/)
[![Python](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue)](https://github.com/Cygnux-Labs/Tracekit/blob/main/pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE)

</div>

Tracekit puts a signer between your agent and its tools: before each tool call runs, the signer decides it against
your policy, and it records every call as a signed, hash-chained event the agent can't edit. Checkpoints of that log go
to witnesses you choose, so even the signer's operator can't quietly rewrite it. A run exports as a `.tkb` bundle that
anyone can verify offline, with a report that says what it proves and what it can't.

<img src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/demo/observer.gif" alt="tracekit observe: four coding agents traced live; each dangerous action is blocked by policy and recorded" width="100%">

## The promise, and its limits

- The agent never holds a signing key or assigns a sequence number; nothing it reports about itself (isolation, fail
  mode, gaps, who approved) is trusted.
- A missed or lost event becomes a signed gap, never silence. An edited, dropped, reordered or added record fails
  verification.
- Who can rewrite the log decides what a bundle is worth. A dev signer runs as your own user, so an agent that runs
  commands as you can rewrite it: dev bundles say `isolation: same-user` and `Assurance: dev`. Protection against the
  agent needs a signer it can't reach ([deployment modes](#deployment-modes)); protection against the operator needs an
  independent witness and a monitor.
- A verified bundle doesn't prove intent, that every action was captured, or that a tool result the agent reported is
  true. [FAQ and limits](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/faq.md) lists them all;
  [laptop](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/threat-model-laptop.md) and
  [server](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/threat-model-server.md) threat models map each to
  its attacker.

## Quickstart (60 seconds)

A dev signer, a LangGraph agent with a mock model (no API key), and a verified bundle:

```sh
git clone https://github.com/Cygnux-Labs/Tracekit && cd Tracekit
python3 -m venv .venv && . .venv/bin/activate
pip install '.[signer]' 'langchain>=1.4,<1.5' 'langgraph>=1.2,<1.3'
python examples/v2/langchain/agent.py --scripted
```

The first call starts a dev signer in the background. One call is allowed, one denied, one held until a second process
approves it; then the example pins the signer's key, exports the run and verifies it:

```sh
tracekit signer trust -o trust.json
tracekit export --v2 --run <run id> -o run.tkb
tracekit verify run.tkb --trust trust.json          # Integrity: VERIFIED. / Assurance: dev; ...
tracekit view --dev                                 # browse the runs: verdicts, denials, approvals, replay
```

Other frameworks: [OpenAI Agents SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/openai-agents.md),
[Claude Agent SDK](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/claude-agent-sdk.md),
[MCP client](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/mcp.md),
[a custom agent](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstarts/custom.md). The
[v2 quickstart](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/quickstart-v2.md) explains each step.

Without a checkout, the same loop in a temp dir (with a witness cosignature and a tampered copy that fails), and
Claude Code's hooks wired to a dev signer:

```sh
pip install 'tracekit-ai[signer]'
tracekit demo --server                # exit 0
tracekit init --dev --v2
```

Or check the shipped sample bundles (v1) with the verifier alone:

```sh
tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub            # exit 0
tracekit verify docs/sample/demo-run-tampered.tkb --key docs/sample/signer.pub   # exit 1
```

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
- Releasing: [launch checklist for 1.0](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/launch-checklist.md)
- The v1 laptop signer (`tracekitd`, `tracekit init --dev`, `tracekit demo`, `tracekit observe`) and its bundles keep
  working: [coding agents](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/coding-agents.md),
  [signing](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/signing.md),
  [platforms](https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/portability.md)

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

## Contributing and security

[CONTRIBUTING.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/CONTRIBUTING.md): `make install`, then `make check`.
Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Cygnux-Labs/Tracekit/blob/main/SECURITY.md).

## Licence

MIT, Copyright Cygnux Labs. See [LICENSE](https://github.com/Cygnux-Labs/Tracekit/blob/main/LICENSE).
