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
| `tracekit graph`: graph and report built from v2 bundles | [graph](graph.md) |
| Detection and containment: sequences and limits, holds, quarantine, suspensions, incidents, the webhook outbox | [incidents](incidents.md), [webhooks](webhooks.md) |
| Argument provenance (`untrusted`, `from_untrusted`) | [policy](policy-v2.md#provenance-untrusted-and-from-untrusted) |
| Readable reasoning: what the model said, recorded by the transcript tailer, the coding-agent hooks, the framework integrations and the LLM gateway | [reasoning](reasoning.md) |
| Live constraints: a limit the person's prompt states ("don't touch billing.py") held by the signer for the rest of the run (its grammar is tested against E20's phrase sets) | [policy](policy-v2.md#live-constraints) |
| Agent approvers, the reference reviewer (`tracekit reviewer`), Slack approvals, passkey (WebAuthn) approvals | [approvals](approvals.md) |
| PCM 0.1, proof-carrying messages between agents: the four `pcm_*` RPCs, the Python verifier and SDK methods, `tracekit pcm verify` and `tracekit pcm demo` (no TypeScript verifier; the A2A gateway doesn't enforce them yet, a follow-up) | [PCM](pcm.md) |
| The signer's HTTPS transport and its OIDC, Kubernetes service-account and mTLS identities | [identity](identity.md), [remote clients](remote-ingest.md) |
| Postgres storage and multi-tenant signers | [deployment](deploy.md) |
| LLM gateway, tool executor, MCP gateway, egress observer | [gateway](gateway.md), [executor](executor.md), [MCP gateway](mcp-gateway.md), [egress](egress.md) |
| The A2A gateway (`tracekit a2a-gateway`: `message/send`, `message/stream` and `tasks/get`, tested against an in-process A2A server, not a third-party one) and latent transfers (`run.transfer`, the C2C integration and `tracekit why transfer`, tested against a stand-in for C2C's `RosettaModel`, not C2C itself) | [A2A gateway](a2a.md), [latent transfers](c2c.md) |
| The egress observer's SOCKS5 listener for E2B's and microsandbox's outbound proxies (tested against E2B's API description and microsandbox's source, not either running) | [E2B](integrations/e2b.md), [microsandbox](integrations/microsandbox.md) |
| agentgateway: the `ext_mcp` processor (`tracekit ext-mcp`) and the import of its MCP spans (tested against the protocol and span attributes in agentgateway's source, not a running agentgateway) | [agentgateway](integrations/agentgateway.md) |
| Wassette behind the MCP gateway (its policy rule is tested against a stand-in with Wassette's tool names, not against Wassette in CI) | [Wassette](integrations/wassette.md) |
| `tracekit follow` (agentsh's audit log) and the signer's `importers` | [agentsh](integrations/agentsh.md) |
| Verified tool results (signer.yaml `verify_tool_results`) | [gateway](gateway.md#verified-tool-results) |
| The kernel sensor import (`tracekit sensor import`), Linux: checked against event lines shaped as Tetragon's and Falco's source writes them, not a live sensor | [Tetragon](integrations/tetragon.md), [Falco](integrations/falco.md) |
| OTLP import and export, the v1 OTLP receiver, ingest gateway and model proxy (these three need `--experimental`) | [OpenTelemetry](otel.md) |
| Witnesses, the public witness, Rekor and RFC 3161 anchors, `tracekit monitor`, the record-key issuer, external and KMS log keys, SLH-DSA hybrid checkpoints | [witnesses](witnesses.md), [monitor](monitor.md), [issuer](issuer.md) |
| Cost, usage, coverage and findings (`tracekit cost`, `tracekit analyze`), and the intent, reasoning and action checks of v2 runs (`tracekit analyze --v2`, signed into a findings run with `review_finding`; `--review`, a reviewer model) | [findings](findings.md) |
| Container image, Helm chart, compose stack (`tracekit deploy compose`) | [compose](deploy-compose.md), [Kubernetes](deploy-kubernetes.md), [container](deploy-container.md) |
| The signer outside a Kubernetes agent-sandbox `Sandbox` (tested end to end on a kind cluster with agent-sandbox v1.0.7; not with a gVisor or Kata RuntimeClass) | [agent-sandbox](integrations/agent-sandbox.md) |
| System mode on macOS (`--experimental-macos`) | [platforms](portability.md) |
| Harness binding and the transcript tailer | [quickstart](quickstart-v2.md#system-mode-linux-macos-experimental) |
| The Claude Code plugin (`plugin/`): the v2 Claude Code hooks through Claude Code's plugin system (its hook script is tested against the dev signer; loading inside a live Claude Code isn't) | [plugin](../plugin/README.md) |
| The sandbox-runtime decider (`tracekit srt-decider`; tested against a stand-in that speaks srt-proxy's decider protocol, not a released srt-proxy) | [sandbox-runtime](integrations/sandbox-runtime.md) |
| Codex CLI, Cursor, Gemini CLI and OpenCode 1.x hooks (checked against recorded hook payloads, OpenCode's written in its documented shape, not the live tools) | [coding agents](coding-agents.md) |
| The Hermes Agent plugin (`integrations/hermes/`; tested against a stand-in for the sequential path of Hermes's agent loop and its plugin hook dispatch as v0.22.5's source defines them, not a running Hermes) | [Hermes Agent](integrations/hermes.md) |
| CrewAI (tested against a stand-in, not the real library) and Browser Use (its real-library contract runs nightly only) | [CrewAI](integrations/crewai.md), [Browser Use](integrations/browser-use.md) |
| Pydantic AI (tested against the real library; not yet run through `tests/adapter_contract.py`) | [Pydantic AI](integrations/pydantic-ai.md) |
| Google ADK (tested against the real library; not yet run through `tests/adapter_contract.py`) | [Google ADK](integrations/google-adk.md) |
| Haystack (tested against the real library; not yet run through `tests/adapter_contract.py`) | [Haystack](integrations/haystack.md) |
| LlamaIndex agents: `FunctionAgent`, `ReActAgent`, `CodeActAgent`, `AgentWorkflow` (tested against the real library; not yet run through `tests/adapter_contract.py`) | [LlamaIndex](integrations/llamaindex.md) |
| Microsoft Agent Framework (tested against the real library with a scripted chat client; not yet run through `tests/adapter_contract.py`; its MCP tools need `mcp` 1.x) | [Microsoft Agent Framework](integrations/microsoft-agent-framework.md) |
| Strands Agents (tested against the real library in a CI job of its own, as strands-agents needs `mcp` below 2.2; not yet run through `tests/adapter_contract.py`) | [Strands Agents](integrations/strands.md) |
| The NVIDIA OpenShell supervisor middleware, `tracekit openshell-middleware` (tested with a gRPC client playing OpenShell's supervisor, not a live OpenShell) | [OpenShell](integrations/openshell.md) |
| The import of OpenShell's OCSF events into each sandbox's run (tested with log batches built as OpenShell's exporter writes them, not a live OpenShell) | [OpenShell](integrations/openshell.md#openshells-ocsf-events) |
| The LiteLLM guardrail for LiteLLM's MCP gateway (tested against LiteLLM's guardrail interface as its source defines it, not a running proxy) | [LiteLLM](integrations/litellm.md) |
| Docker's MCP Gateway as an upstream of the MCP gateway (tested against a stand-in for `docker mcp gateway run`, not Docker's gateway itself) | [Docker MCP Gateway](integrations/docker-mcp-gateway.md) |
| The TypeScript SDK client and its Vercel AI SDK integration (`@cygnuxlabs/tracekit` on npm) | [TypeScript SDK](../sdk/typescript/README.md), [Vercel AI SDK](integrations/vercel-ai.md) |
| `contrib/` packages | [contrib](../contrib) |
| The v1 signer path: `tracekitd`, `tracekit init` without `--v2`, `tracekit observe`, v1 adapters. Verifying v1 bundles stays stable. | [coding agents](coding-agents.md), [signing](signing.md) |
