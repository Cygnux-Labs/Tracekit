# Integrations

Tracekit plugs into an agent where its tool calls happen: a framework's tool-calling hook, an MCP client session, a
coding agent's hook configuration. Every integration follows the same contract with the signer, so the guarantees are
the same whichever framework you use. This page explains the contract, `tracekit.instrument()`, and how each
framework and coding agent is wired.

## The adapter contract

For every tool call, an integration:

1. asks the signer to **decide**;
2. for `ask`, requests an approval and **waits** (or pauses the run, where the framework supports it);
3. **consumes** the approval just before running the call, and runs the arguments the consume returns;
4. reports the result with **complete**, against its decision;
5. sends the full result of tools the policy marks untrusted, for [provenance](provenance-and-why.md).

A shared test suite runs every stable integration against a fake signer and the real one. Besides the normal cases
(an allowed call runs once, a denied call returns an error and the run continues, a retry is a new decision), it tries
to trick the integration, and each attempt must be refused:

- resuming from a replayed snapshot;
- resuming from saved state whose arguments were edited;
- using another run's approval;
- resuming without a person's approval;
- rewriting a call id;
- running arguments other than the approved ones on a T2 path.

## `tracekit.instrument()`

One line at the top of an agent wires up every framework it finds installed:

```python
import tracekit; tracekit.instrument()
```

It finds a signer (the one `TRACEKIT_SIGNER` names, the system signer, or else a dev signer it starts for you), opens a
run for the process, and patches the OpenAI Agents SDK, LangChain / LangGraph, the Claude Agent SDK, MCP client sessions,
Browser Use and CrewAI, plus OpenAI, Anthropic and Google Gen AI model calls. Don't also wire an adapter by hand: the
same call would be decided twice. For one run per request in a server, see the [quickstarts](../quickstart-v2.md).

## Frameworks

| Framework | How it's wired | Status |
|---|---|---|
| OpenAI Agents SDK | Run hooks and a tool wrapper; a held call interrupts the run | Stable |
| LangChain / LangGraph | Agent middleware (or a `ToolNode` wrapper) with `interrupt()`; a checkpointer wrapper records state digests | Stable |
| Claude Agent SDK | PreToolUse and PostToolUse hooks (not `can_use_tool`, which bypass-permission modes skip); a session-store wrapper | Stable |
| MCP client | Wraps `call_tool` as `mcp:<server>/<tool>` | Stable |
| Browser Use | Wraps action execution, and observes each page as untrusted content | Experimental |
| CrewAI | Global before and after hooks. CrewAI has no call ids, so calls are paired by arguments | Experimental |
| Vercel AI SDK (TypeScript) | Model middleware and the SDK's tool-approval flow | Experimental |
| OpenTelemetry | Spans imported as tier T3 evidence (receipt only); runs exported as spans carrying record hashes | Experimental |

Per-framework guides: [quickstarts](../quickstart-v2.md). Other agents: the SDK's run handle
([custom agent](../quickstarts/custom.md)).

## Coding agents

`tracekit init --dev --v2` wires Claude Code's hooks to a dev signer; add `--agent codex`, `--agent cursor` or
`--agent gemini` for the others (experimental). In system mode, `sudo tracekit init --v2 --user AGENT` does the same
against the system signer.

For Claude Code, each tool call runs the hook before and after:

- **Before (`PreToolUse`):** the hook asks the signer to decide. A deny exits with code 2, which makes Claude Code block
  the call. An ask waits up to 9 minutes for a person. An allow consumes and lets the call run.
- **After (`PostToolUse`):** the hook reports the result. `SessionEnd` closes the run.
- **Any error** in the hook (a missing id, an unreadable payload, a failed call) also exits 2: the hook fails closed.
- A **transcript tailer** reads the session transcript as capture layer L3, so a tool use the hook never reported shows
  as a gap.

Details: [coding agents](../coding-agents.md).

## What real agents taught

Running two open-source agents through Tracekit ([case study](../case-study-oss-agents.md)) found real bugs:

- **CrewAI swallowed the hook's exception** and ran the tool anyway: a denied `close_account` ran while the signer was
  down. Hooks now refuse by returning a refusal, never by raising, and the rule since is that a gate must block on any
  error.
- **Streamed model responses** weren't captured, which produced false `fabricated` findings until it was fixed.

## Reference

[Quickstarts](../quickstart-v2.md) · [coding agents](../coding-agents.md) · [OpenTelemetry](../otel.md) ·
[TypeScript SDK](../../sdk/typescript/README.md) · integrations: [`tracekit/integrations/`](../../tracekit/integrations) ·
autowiring: [`tracekit/autowire.py`](../../tracekit/autowire.py)

---

Previous: [Storage, durability and performance](storage-and-performance.md) · [All concepts](README.md) · Next:
[Security model](security-model.md)
