# Integrations

Every place Tracekit plugs into an agent, with its status: **stable** and **experimental** mean what they mean in
[what's stable](support.md). Every integration keeps the same contract with the signer:
[how integrations work](concepts/integrations.md).

## Frameworks

Start with [`tracekit.instrument()`](concepts/integrations.md#tracekitinstrument), which wires every framework it finds
installed, or a [quickstart](quickstarts/README.md). Stable integrations run the adapter contract against the pinned
real library on every push to main and every pull request; each experimental page says what it was tested against.

| Framework | Status | Guide |
|---|---|---|
| OpenAI Agents SDK | Stable | [OpenAI Agents](integrations/openai-agents.md) |
| LangChain / LangGraph | Stable | [LangChain](integrations/langchain.md) |
| Claude Agent SDK | Stable | [Claude Agent SDK](integrations/claude-agent-sdk.md) |
| MCP client sessions | Stable | [MCP](integrations/mcp.md) |
| Browser Use | Experimental | [Browser Use](integrations/browser-use.md) |
| CrewAI | Experimental | [CrewAI](integrations/crewai.md) |
| Pydantic AI | Experimental | [Pydantic AI](integrations/pydantic-ai.md) |
| Google ADK | Experimental | [Google ADK](integrations/google-adk.md) |
| Strands Agents | Experimental | [Strands Agents](integrations/strands.md) |
| LlamaIndex | Experimental | [LlamaIndex](integrations/llamaindex.md) |
| Haystack | Experimental | [Haystack](integrations/haystack.md) |
| Microsoft Agent Framework | Experimental | [Microsoft Agent Framework](integrations/microsoft-agent-framework.md) |
| Vercel AI SDK (TypeScript) | Experimental | [Vercel AI SDK](integrations/vercel-ai.md), [TypeScript SDK](../sdk/typescript/README.md) |

Another agent: record its calls with the SDK's run handle ([custom agent](quickstarts/custom.md)).

## Coding agents

| Agent | Status | Guide |
|---|---|---|
| Claude Code hooks (`tracekit init --dev --v2`) | Stable | [quickstart](quickstart-v2.md) |
| The Claude Code plugin | Experimental | [plugin](../plugin/README.md) |
| Codex CLI, Cursor, Gemini CLI, OpenCode | Experimental | [coding agents](coding-agents.md) |
| goose (`tracekit init --dev --v2 --agent goose`) | Experimental | [coding agents](coding-agents.md#on-the-v2-signer) |
| Qwen Code (`tracekit init --dev --v2 --agent qwen`) | Experimental | [coding agents](coding-agents.md) |
| Factory Droid (`tracekit init --dev --v2 --agent droid`) | Experimental | [coding agents](coding-agents.md) |
| Antigravity CLI (`tracekit init --dev --v2 --agent antigravity`) | Experimental | [Antigravity CLI](coding-agents.md#antigravity-cli) |
| Hermes Agent plugin | Experimental | [Hermes Agent](integrations/hermes.md) |

The goose, Qwen Code, Factory Droid and Antigravity CLI hooks are written to each harness's published hook
documentation and tested against payloads in that shape, not yet in a live session of the tool.

## Sandboxes, gateways and sensors

Tracekit doesn't sandbox anything. It records and gates what goes through a sandbox or gateway you already run, from a
signer outside it. All of these are experimental, except Claude Code's sandbox rules, which are in the stable coding
pack. What each one records: [sandboxes, gateways and sensors](concepts/integrations.md#sandboxes-gateways-and-sensors).

- Sandboxes: [NVIDIA OpenShell](integrations/openshell.md), [agentsh](integrations/agentsh.md),
  [sandbox-runtime](integrations/sandbox-runtime.md), [Claude Code's sandbox](integrations/claude-code-sandbox.md),
  [Codex's sandbox](integrations/codex-sandbox.md), [Gemini CLI's sandbox](integrations/gemini-sandbox.md),
  [E2B](integrations/e2b.md), [microsandbox](integrations/microsandbox.md),
  [Kubernetes agent-sandbox](integrations/agent-sandbox.md).
- Agent and MCP gateways: [A2A gateway](a2a.md), [agentgateway](integrations/agentgateway.md), [LiteLLM](integrations/litellm.md),
  [Docker MCP Gateway](integrations/docker-mcp-gateway.md), [Wassette](integrations/wassette.md).
- Kernel sensors: [Tetragon](integrations/tetragon.md), [Falco](integrations/falco.md).

Tracekit's own [A2A gateway](a2a.md), [MCP gateway](mcp-gateway.md), [LLM gateway](gateway.md), [tool executor](executor.md) and
[egress observer](egress.md) (experimental) record calls out of the agent's process.

## OpenTelemetry and remote agents

- [OpenTelemetry](otel.md) (experimental): spans imported as tier T3 evidence, and runs exported as spans.
- [Remote clients](remote-ingest.md) (experimental): agents on other machines reach the signer over HTTPS with named
  tokens.

## The v1 path

The v1 laptop signer (`tracekitd`) has its own adapters for any function, LangChain callbacks and MCP client sessions:
[adapters](adapters.md) (experimental; new agents use the frameworks above). The `contrib/` packages build on the v1
path and are experimental too: [Causeway](../contrib/causeway/README.md), [onchain transaction guards](../contrib/onchain/README.md),
[Stagehand](../contrib/stagehand/README.md), [proof packs](../contrib/proofpack/README.md) and
[SQL over the ledger](../contrib/query/README.md).
