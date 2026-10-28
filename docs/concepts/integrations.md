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

Most integrations also record what the model said before each call (its reasoning, its text, the calls it asked for)
wherever the framework hands it over, linked to the decision by the call id where there is one, so
`tracekit analyze --v2` can compare what was said with what was done. How much of the reasoning is readable depends on the framework and the provider:
[reading the model's reasoning](../reasoning.md).

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
Browser Use, CrewAI and Pydantic AI, plus OpenAI, Anthropic and Google Gen AI model calls. A framework it can't wire is
skipped with a warning, and one outside the versions Tracekit is tested with is wired with a warning. Google ADK,
Strands Agents, LlamaIndex, Haystack and Microsoft Agent Framework are wired by hand, one line each. Don't also wire an
adapter by hand for a framework `instrument()` patches: the same call would be decided twice. For one run per request
in a server, see the [quickstarts](../quickstart-v2.md).

## Frameworks

| Framework | How it's wired | Status |
|---|---|---|
| OpenAI Agents SDK | Run hooks and a tool wrapper; a held call interrupts the run | Stable |
| LangChain / LangGraph | Agent middleware (or a `ToolNode` wrapper) with `interrupt()`; a checkpointer wrapper records state digests | Stable |
| Claude Agent SDK | PreToolUse and PostToolUse hooks (not `can_use_tool`, which bypass-permission modes skip); a session-store wrapper | Stable |
| MCP client | Wraps `call_tool` as `mcp:<server>/<tool>` | Stable |
| Browser Use | Wraps action execution, and observes each page as untrusted content | Experimental |
| CrewAI | Global before and after hooks. CrewAI has no call ids, so calls are paired by arguments | Experimental |
| Pydantic AI | A capability: its `wrap_tool_execute` and `wrap_output_process` hooks, so output functions are gated too | Experimental |
| Google ADK | A Runner plugin's before, after and error tool callbacks, for every agent the Runner runs, sub-agents included | Experimental |
| Strands Agents | A hook provider on `BeforeToolCallEvent` and `AfterToolCallEvent` | Experimental |
| LlamaIndex | Overrides the agent workflow's `call_tool` step, which every tool call goes through | Experimental |
| Haystack | The `Agent`'s `before_tool` and `after_tool` hooks | Experimental |
| Microsoft Agent Framework | Function middleware around each function call | Experimental |
| Vercel AI SDK (TypeScript) | Model middleware and the SDK's tool-approval flow | Experimental |
| OpenTelemetry | Spans imported as tier T3 evidence (receipt only); runs exported as spans carrying record hashes | Experimental |

Pydantic AI, Google ADK, Strands Agents, LlamaIndex, Haystack and Microsoft Agent Framework share one gate,
[`tracekit/integrations/gate.py`](../../tracekit/integrations/gate.py): decide, wait for a person on `ask` (up to 5
minutes), consume, record the outcome, and refuse the call when Tracekit itself fails. A fix to how calls are decided
lands in all six. Each is tested against the real library but not yet run through the shared contract suite.

Per-framework guides: [quickstarts](../quickstart-v2.md) and the [integration pages](../integrations/pydantic-ai.md).
Other agents: the SDK's run handle ([custom agent](../quickstarts/custom.md)).

## Coding agents

`tracekit init --dev --v2` wires Claude Code's hooks to a dev signer; add `--agent codex`, `--agent cursor` or
`--agent gemini` for the others (experimental). In system mode, `tracekit init --v2 --user AGENT` run as root
([laptop system mode](../deploy.md#laptop-system-mode)) does the same
against the system signer. The Claude Code plugin (experimental) runs the same v2 hook; use it or `init`'s hooks, not
both, or each call is decided twice.

For Claude Code, each tool call runs the hook before and after:

- **Before (`PreToolUse`):** the hook asks the signer to decide. A deny exits with code 2, which makes Claude Code block
  the call. An ask waits up to 9 minutes for a person. An allow consumes and lets the call run.
- **After (`PostToolUse`):** the hook reports the result. `SessionEnd` closes the run.
- **Any error** in a `PreToolUse` hook (a missing id, an unreadable payload, a failed call) also exits 2: a tool call
  fails closed. A hook for any other event (a prompt, `Stop`) that fails exits 1, an error Claude Code shows without
  blocking, so a broken hook never erases a prompt.
- **At each prompt** (`UserPromptSubmit`), the hook records the prompt as submitted, and sends each constraint it
  states ("don't touch X", "read-only") as a [live constraint](../policy-v2.md#live-constraints), which holds a later
  call that breaks it for a person.
- A **transcript tailer** reads the session transcript as capture layer L3 (the model's tool uses, its thinking and
  text, and the prompts), so a tool use the hook never reported shows as a gap.

Codex's hooks read the model's reasoning and calls from its rollout file, linked by call id; Gemini CLI's and Cursor's
record what the model said without the calls, since their hooks name none.

Details: [coding agents](../coding-agents.md).

## Sandboxes, gateways and sensors

Tracekit doesn't sandbox anything. It records and gates what goes through a sandbox or gateway you already run, from a
signer outside it. All of these are experimental, except Claude Code's sandbox rules, which are in the stable coding
pack.

| Where the agent runs | What Tracekit does | Evidence |
|---|---|---|
| Claude Code's, Codex's or Gemini CLI's sandbox | The hooks gate every call, sandboxed or not. `TK-A003` and `TK-A014` hold for a person a Claude Code command run outside its sandbox or with extra hosts opened, `TK-A004` a Gemini CLI sandbox expansion; `tracekit doctor` checks the sandbox settings | T1 hook records |
| sandbox-runtime's proxy on its own | `tracekit srt-decider` decides each request `srt-proxy` forwards, as the tool `srt:request` | Signed decisions and approvals |
| NVIDIA OpenShell | Middleware decides each HTTP request OpenShell lets out; its OCSF events go into the same run | T2, and imported effects |
| agentsh | `tracekit follow agentsh` signs each decision agentsh logs, as agentsh's word | T3 |
| E2B, microsandbox | Their outbound SOCKS5 proxy points at the [egress observer](custody.md#the-egress-observer) | Network effects |
| Kubernetes agent-sandbox | The signer runs outside the `Sandbox`, in its own namespace | The agent's integration's records, kept out of the pod |
| agentgateway, LiteLLM, Docker's MCP Gateway, Wassette | Each MCP tool call is decided before it runs: agentgateway's `ext_mcp` processor, a LiteLLM guardrail, or Tracekit's MCP gateway in front of Docker's or Wassette | T2; agentgateway's spans can also be imported (T3) |
| Tetragon, Falco | `tracekit sensor import` signs the processes, connections and file writes they saw into each agent's run | Imported effects ([capture](capture-and-completeness.md#kernel-sensors-and-sandboxes)) |

Each page says what it was tested against; most have not yet run against a live release of the other project. Pages:
[OpenShell](../integrations/openshell.md), [agentsh](../integrations/agentsh.md),
[sandbox-runtime](../integrations/sandbox-runtime.md), [Claude Code's sandbox](../integrations/claude-code-sandbox.md),
[Codex's sandbox](../integrations/codex-sandbox.md), [Gemini CLI's sandbox](../integrations/gemini-sandbox.md),
[E2B](../integrations/e2b.md), [microsandbox](../integrations/microsandbox.md),
[agent-sandbox](../integrations/agent-sandbox.md), [agentgateway](../integrations/agentgateway.md),
[LiteLLM](../integrations/litellm.md), [Docker MCP Gateway](../integrations/docker-mcp-gateway.md),
[Wassette](../integrations/wassette.md), [Tetragon](../integrations/tetragon.md), [Falco](../integrations/falco.md).

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
