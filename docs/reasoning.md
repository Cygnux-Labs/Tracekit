# Reading the model's reasoning

**In one line:** Tracekit records what the model said before each tool call (its reasoning, its text, the call it
asked for) wherever the agent, framework or provider hands it over, and this page says, for each one, how much of that
reasoning you will be able to read and the one setting that makes it readable.

Tracekit always signs a commitment to what the model said. The text itself is kept only when the signer's
[content vault](privacy.md#the-content-vault) is on (the dev signer keeps it for 7 days), so `tracekit analyze --v2`
([findings](findings.md#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2)) and `tracekit view` can read it,
and erase it when retention ends.

What the columns mean:

- **Recorded**: `full` is the model's own reasoning text (open models return it); `summary` is the provider's summary
  of it (Claude, OpenAI's reasoning models and Gemini return summaries); `encrypted only` means the provider returned
  the reasoning sealed (a signature, `redacted_thinking`, `encrypted_content`, a `thought_signature`), which Tracekit
  keeps byte for byte but nobody can read today; `none` means no reasoning reaches anything Tracekit sees.
- **Linked** means the record carries the id the call was decided under, so each action is checked against what was
  said right before it. An unlinked record is still signed and readable; the checks report its calls as `unlinked`.
- Reasoning is the model's account of itself: self-reported, not proof. Text from a coding agent's transcript or hook
  is written by the agent's own process, and the findings label it so (trust tier `transcript`).

`tracekit doctor` says, for each agent whose hooks are installed, whether its reasoning will be readable, and prints
the fix (`D-THINKING-SUMMARIES`, `D-CODEX-REASONING`, `D-GEMINI-THOUGHTS`; [doctor](doctor.md)).

## Coding agents

| Agent | Recorded | How to turn it on | Where it comes from | Linked |
|---|---|---|---|---|
| Claude Code | summary; encrypted only while summaries are off | `"showThinkingSummaries": true` in its settings (`tracekit init --v2` sets it); headless: `claude -p --thinking-display summarized` | its transcript, read by the transcript tailer | yes, by `tool_use_id` |
| Codex CLI | summary, and the `encrypted_content`; encrypted only while summaries are off | `model_reasoning_summary = "auto"` in `~/.codex/config.toml` (`tracekit init --v2 --agent codex` sets it; Codex's current models default to `none`) | its rollout file, read at each hook | yes, by `call_id` |
| Gemini CLI | summary (its thought summaries) | on by default; don't set `includeThoughts: false` in `modelConfigs` | its chat recording, read at each hook | no: Gemini CLI gives a call no id, and writes the thoughts after the calls run |
| Cursor | the thinking text Cursor reports (recorded as a summary) | nothing: `tracekit init --v2 --agent cursor` installs its `afterAgentThought` and `afterAgentResponse` hooks | those hooks | no: they carry no call id |

Gemini CLI's and Cursor's messages are recorded `said_only`: what the model said, without the calls it asked for, which
their hooks can't name. The signer reconciles no call against them, so an honest session never reads as one whose calls
no model asked for (`reconcile.fabricated`); it also gets no such cross-check.

## Frameworks

| Framework | Recorded | How to turn it on | Where it comes from | Linked |
|---|---|---|---|---|
| OpenAI Agents SDK | summary, and `encrypted_content`, as the Responses API returns them | ask the model for summaries: `ModelSettings(reasoning=Reasoning(summary="auto"))` | the integration (`hooks=tk`, each model response) | yes, by `call_id` |
| Claude Agent SDK | summary, and the thinking's signature | `thinking={"type": "adaptive", "display": "summarized"}` (Opus 4.7 and later omit the text by default) | the integration: hand each message to `tracekit_said` | yes, by `tool_use_id` |
| LangChain / LangGraph `create_agent` | summary (reasoning blocks, with their signature or encrypted content); full for an open model's `reasoning_content` or inline `<think>` | the model's own reasoning settings | the middleware (each model call) | yes, by tool call id |
| LangGraph with `tracekit_tool_node` | none from the integration | use `tracekit.instrument()` or the LLM gateway | - | - |
| Pydantic AI | summary (`ThinkingPart`), and its signature | the model's own thinking settings | the capability (each model response; an output function's call or an approved tool's is added to its response when it is decided) | yes, by `tool_call_id` |
| Google ADK | summary (thought parts), and each `thought_signature` | `include_thoughts=True` in the agent's thinking config | the plugin (each model response event) | yes, by ADK's call ids |
| Strands Agents | summary (`reasoningContent`), and its signature or redacted content | the model provider's reasoning settings | the hook provider (each model message) | yes, by `toolUseId` |
| Haystack | summary (the message's reasoning), and OpenAI's `encrypted_content` | the chat generator's reasoning settings | the `before_tool` hook | yes, by the call id (one Tracekit gives a call that has none) |
| LlamaIndex | summary (`ThinkingBlock`) | the LLM's thinking settings | the gate (each agent output) | yes where the model names the call; otherwise paired by arguments only |
| Microsoft Agent Framework | summary (`text_reasoning`), and its `protected_data` | add `tk.chat` to `middleware=` beside `tk` | the chat middleware (each model response) | yes, by `call_id` |
| CrewAI | none from the integration | use `tracekit.instrument()` or the LLM gateway | - | no: CrewAI's tool hooks carry no call id |
| Browser Use | none from the integration | use `tracekit.instrument()` or the LLM gateway | - | no: an action has no model call id |
| Vercel AI SDK (TypeScript) | a commitment to the response, reasoning parts included; not readable | use the LLM gateway for readable reasoning | the middleware | yes, by `toolCallId` |

## Providers

Through the [LLM gateway](gateway.md), which records the provider's response before the agent gets it, or
`tracekit.instrument()` in the agent's process. The gateway can also [ask the provider for readable
reasoning](gateway.md#readable-reasoning).

| Provider | Recorded | How to turn it on |
|---|---|---|
| Anthropic (Claude) | summary, and each thinking block's signature; encrypted only with display `omitted` | thinking `display: "summarized"` (Opus 4.7 and later default to `omitted`) |
| OpenAI Responses (o-series, GPT-5) | summary; encrypted only with `encrypted_content` alone | `reasoning.summary: "auto"`; for the sealed form too, `include: ["reasoning.encrypted_content"]` |
| OpenAI Chat Completions (reasoning models) | none: the API returns no reasoning, only its token count | use the Responses API |
| OpenAI-compatible open models (vLLM, Ollama, OpenRouter) | full: `reasoning_content`, `reasoning`, or inline `<think>` | the server's reasoning parser, or nothing (inline) |
| Google Gemini | summary (thought parts); encrypted only (`thought_signature`) without them | `thinking_config: {include_thoughts: true}` |
| DeepSeek, Qwen, gpt-oss | full | nothing: they return their reasoning |

## Where to go next

- What stays unreadable, and why: [limits](limits.md#intent-reasoning-and-action-checks).
- How the text is kept, encrypted, read and erased: [privacy](privacy.md#the-content-vault).
- Each integration's page says what it records: [integrations](integrations.md).
