# What's stable

Tracekit has a small stable core and a larger set of experimental surfaces. Both ship in the same package.

**Stable** means it is tested end to end on every push to main and every pull request, and hardened first.

**Experimental** means it works and is tested, but it may change between releases and gets less hardening. Each
experimental command or server prints one line to stderr when it starts. Anything not listed as stable is
experimental.

## Stable core

| Surface | What it covers |
|---|---|
| v2 signer, dev mode | `tracekit.instrument()`, `tracekit up/down/last`, `tracekit signer serve --dev`, file storage |
| v2 signer, system mode on Linux | `sudo tracekit init --v2 --user AGENT`: the signer as its own OS user, file storage, uid and token callers |
| Python SDK | `tracekit.sdk` (`RunHandle`) and `tracekit.instrument()` |
| Framework integrations | OpenAI Agents SDK, LangChain / LangGraph, Claude Agent SDK, MCP client wrapping: each runs the adapter contract against the pinned real library on every push to main and every pull request |
| Claude Code hooks (v2) | `tracekit init --dev --v2` and system mode's hooks |
| Policy v2 | the engine, `tracekit policy compile/lint`, the shipped packs (`tracekit/policy2/packs/`), `ask` approvals from the command line (`tracekit approvals`) |
| Bundles | `tracekit export --v2`, evidence format v2 |
| Verifiers | `tracekit verify` (v2, and v1 bundles with the frozen v1 verifier) and the TypeScript verifier (`sdk/typescript/src/verify/`) |
| `tracekit view` | the laptop viewer |
| `tracekit doctor` | setup checks |

## Experimental

| Surface | Docs |
|---|---|
| `tracekit why`: investigation, replay, signed findings | [why](why.md) |
| Detection and containment: sequences and limits, holds, quarantine, suspensions, incidents, the webhook outbox | [incidents](incidents.md), [webhooks](webhooks.md) |
| Argument provenance (`untrusted`, `from_untrusted`) | [policy](policy-v2.md#provenance-untrusted-and-from-untrusted) |
| Agent approvers, the reference reviewer (`tracekit reviewer`), Slack approvals, passkey (WebAuthn) approvals | [approvals](approvals.md) |
| The signer's HTTPS transport and its OIDC, Kubernetes service-account and mTLS identities | [identity](identity.md), [remote clients](remote-ingest.md) |
| Postgres storage and multi-tenant signers | [deployment](deploy.md) |
| LLM gateway, tool executor, MCP gateway, egress observer | [gateway](gateway.md), [executor](executor.md), [MCP gateway](mcp-gateway.md), [egress](egress.md) |
| Verified tool results (signer.yaml `verify_tool_results`) | [gateway](gateway.md#verified-tool-results) |
| OTLP import and export, the v1 OTLP receiver, ingest gateway and model proxy (these three need `--experimental`) | [OpenTelemetry](otel.md) |
| Witnesses, the public witness, Rekor and RFC 3161 anchors, `tracekit monitor`, the record-key issuer, external and KMS log keys, SLH-DSA hybrid checkpoints | [witnesses](witnesses.md), [monitor](monitor.md), [issuer](issuer.md) |
| Cost, usage, coverage and findings (`tracekit cost`, `tracekit analyze`) | [findings](findings.md) |
| Container image, Helm chart, compose stack (`tracekit deploy compose`) | [compose](deploy-compose.md), [Kubernetes](deploy-kubernetes.md), [container](deploy-container.md) |
| System mode on macOS (`--experimental-macos`) | [platforms](portability.md) |
| Harness binding and the transcript tailer | [quickstart](quickstart-v2.md#system-mode-linux-macos-experimental) |
| The Claude Code plugin (`plugin/`): the v2 Claude Code hooks through Claude Code's plugin system (its hook script is tested against the dev signer; loading inside a live Claude Code isn't) | [plugin](../plugin/README.md) |
| Codex CLI, Cursor and Gemini CLI hooks (checked against recorded hook payloads, not the live tools) | [coding agents](coding-agents.md) |
| CrewAI (tested against a stand-in, not the real library) and Browser Use (its real-library contract runs nightly only) | [CrewAI](integrations/crewai.md), [Browser Use](integrations/browser-use.md) |
| Pydantic AI (tested against the real library; not yet run through `tests/adapter_contract.py`) | [Pydantic AI](integrations/pydantic-ai.md) |
| Google ADK (tested against the real library; not yet run through `tests/adapter_contract.py`) | [Google ADK](integrations/google-adk.md) |
| Haystack (tested against the real library; not yet run through `tests/adapter_contract.py`) | [Haystack](integrations/haystack.md) |
| LlamaIndex agents: `FunctionAgent`, `ReActAgent`, `CodeActAgent`, `AgentWorkflow` (tested against the real library; not yet run through `tests/adapter_contract.py`) | [LlamaIndex](integrations/llamaindex.md) |
| Microsoft Agent Framework (tested against the real library with a scripted chat client; not yet run through `tests/adapter_contract.py`; its MCP tools need `mcp` 1.x) | [Microsoft Agent Framework](integrations/microsoft-agent-framework.md) |
| Strands Agents (tested against the real library in a CI job of its own, as strands-agents needs `mcp` below 2.2; not yet run through `tests/adapter_contract.py`) | [Strands Agents](integrations/strands.md) |
| Docker's MCP Gateway as an upstream of the MCP gateway (tested against a stand-in for `docker mcp gateway run`, not Docker's gateway itself) | [Docker MCP Gateway](integrations/docker-mcp-gateway.md) |
| The TypeScript SDK client and its Vercel AI SDK integration (`@cygnuxlabs/tracekit` on npm) | [TypeScript SDK](../sdk/typescript/README.md), [Vercel AI SDK](integrations/vercel-ai.md) |
| `contrib/` packages | [contrib](../contrib) |
| The v1 signer path: `tracekitd`, `tracekit init` without `--v2`, `tracekit observe`, v1 adapters. Verifying v1 bundles stays stable. | [coding agents](coding-agents.md), [signing](signing.md) |
