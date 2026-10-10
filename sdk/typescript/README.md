# @cygnux/tracekit

Tracekit for TypeScript and JavaScript agents: every tool call is decided by the Tracekit signer before it runs and
recorded after, and model responses become signed evidence. The client talks to the signer directly; it needs no Python
at runtime (the same-user dev signer is started with Python when none is running).

## Signer client (`@cygnux/tracekit`)

A native client of the v2 signer RPC with no runtime dependencies (Node ≥ 18 built-ins only, no Python bridge); also
exported as `@cygnux/tracekit/v2`.

```ts
import { Client, withRun, currentRun } from "@cygnux/tracekit";

const client = new Client();                              // or new Client({ signer: "https://signer:8443" })
const run = await client.registerRun("research-bot");
const d = await run.decide(call.id, "Bash", call.function.arguments);   // the raw model string, or a parsed value
if (d.decision === "allow") {
  const out = await runShell(call);
  await run.complete(call.id, "ok", { result: out });      // never throws: a recording failure is a warning
} else if (d.decision === "ask") {
  const { approval_id } = await run.approvalRequest(call.id);
  const { state } = await run.approvalWait(approval_id, 300_000);   // on a connection of its own
}
await run.close();
await client.close();                                     // waits for what is in flight
```

- **Signer:** `$TRACEKIT_SIGNER` names a Unix socket, `tcp://127.0.0.1:port` (with `$TRACEKIT_SIGNER_TOKEN`; both sides
  prove they hold it, it never goes on the wire) or `https://host:port` (`$TRACEKIT_SIGNER_TOKEN_FILE`: a bearer token
  re-read per call; `$TRACEKIT_SIGNER_CERT`/`_KEY`: mTLS; `$TRACEKIT_SIGNER_CA`: the signer's CA). In system mode the
  signer named by the root-owned `/etc/tracekit/client.json` is used and a different `$TRACEKIT_SIGNER` is refused.
  Otherwise the same-user dev signer is found, or started with `tracekit up --json`: `$TRACEKIT_PYTHON -m tracekit` if
  set, else a pip-installed `tracekit` on PATH, else the Python bundled in the `@cygnux/tracekit-signer-<platform>`
  package npm installs with this one. `npx @cygnux/tracekit up|down|status|view|verify|signer` runs the same command.
- **Protocol:** `hello` first; a signer that does not speak this client's RPC version is refused with `Incompatible`.
  Requests are validated against the RPC schemas before they are sent, pipelined on one connection and answered in
  order; a call whose connection drops is resent with the same `request_id`. Each handle's events carry the client's
  `stream` and a `client_seq` per run.
- **Fail modes:** only when the signer cannot be reached does `decide` return the run's fail mode for the tool class
  (`fields.tool_class_hint`, from `register_run`'s `fail_modes`, default closed) with `unavailable: true`. A refusal
  from the signer rejects with `RPCError`, never an allow.
- **Serverless:** `client.waitUntil(promise)` and `await client.flush()` before the host freezes the process.
- `withRun(run, fn)` makes `run` the `currentRun()` of everything `fn` awaits (AsyncLocalStorage).
- `argsDigest(tool, args)`, `canonicalize`, `strictParse`: JCS (RFC 8785) and the strict parser, byte-identical to
  the Python client on the shared vectors in `tests/vectors/jcs.jsonl`.

## v2 framework adapters

Each adapter gates every tool call through the signer: it passes the call id, its attempt and the model's raw
arguments, the signer decides, an `ask` waits for a person (held in the hook where the framework allows, else paused
and resumed), and every call, allowed or approved, runs only after the signer's `approval_consume` agrees. A `deny`
reaches the model as the tool's error result and the run goes on. The run's fail mode (`register_run`'s `fail_modes`)
applies only when the signer cannot be reached at the decision; a refusal, or a failure while waiting for an approval,
never lets the call run. Recording a finished call never throws and never changes its result (a failure is a
`TracekitWarning`). The frameworks are optional peer dependencies: the adapters import none of them, and the client
keeps no runtime dependencies. No adapter wraps a provider client, so the SDKs' own `APIPromise` (`.withResponse()`)
and streams (`messages.stream()`, `streamText`) work as without Tracekit. Offline examples: `examples/v2_*.mjs`.

**OpenAI Agents SDK** (`@cygnux/tracekit/v2/openai-agents`)

```ts
import { Agent, Runner, tool } from "@openai/agents";
import { TracekitAgents } from "@cygnux/tracekit/v2/openai-agents";
const tk = new TracekitAgents(await new Client().registerRun("payer"));
const agent = new Agent({ name: "payer", tools: [tk.tool(tool, { name: "pay", description, parameters, execute })] });
let result = await runner.run(agent, "pay acct-42 $15", { context: {} });   // the context must be an object
if (result.interruptions.length) {                                         // an `ask`: once decided in the signer
  await tk.applyDecisions(result.state);
  result = await runner.run(agent, result.state);
}
await tk.recordResponses(result.rawResponses, "gpt-5");
```

`tk.tool(tool, options)` builds the tool with the SDK's `tool()`: the signer's policy replaces `needsApproval`, and a
tool input guardrail (after your own) gates the call on its raw arguments. The approval id travels in the RunState only
as a hint (`context.tracekit.approvals`); the signer checks it. Leave `toolExecution.preApprovalInputGuardrails` off.
Not gated, listed as uncovered: hosted tools (web and file search, code interpreter, hosted MCP, hosted shell), shell,
apply_patch and computer tools, and handoffs. `recordResponses` records them (T3) in a signed model event per response.

**Vercel AI SDK v7** (`@cygnux/tracekit/v2/vercel-ai`)

```ts
import { generateText, wrapLanguageModel } from "ai";
import { tracekitAI } from "@cygnux/tracekit/v2/vercel-ai";
const tk = tracekitAI(await new Client().registerRun("assistant"));
const model = wrapLanguageModel({ model: openai("gpt-5"), middleware: tk.middleware });
const r = await generateText({ model, tools: tk.tools({ pay }), toolApproval: tk.toolApproval, messages });
// asks end the step with tool-approval-request parts; once decided in the signer:
messages.push(...r.response.messages, { role: "tool", content: await tk.approvalResponses(r.content) });
```

The same options work for `streamText` and `ToolLoopAgent`. `tk.middleware` records each model response (V3 usage,
the tool calls asked for) and keeps each call's raw arguments by `toolCallId` for the decision. `tk.toolApproval` maps
`deny` to `denied` and `ask` to `user-approval`; without it an `ask` is refused. `tk.tools()` wraps each `execute`, so a
forged or replayed `tool-approval-response` runs nothing. `experimental_toolApprovalSecret` (the SDK's HMAC over its own
approval requests) may be set too; it does not replace the signer's check. Spans from `@ai-sdk/otel` are telemetry, not
evidence: the signed records are the middleware's and the adapter's. Tools without `execute` and provider-executed tools
are not gated; they appear in the recorded model responses.

**Claude Agent SDK** (`@cygnux/tracekit/v2/claude-agent-sdk`)

```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
import { tracekitHooks, tracekitSessionStore } from "@cygnux/tracekit/v2/claude-agent-sdk";
const run = await new Client().registerRun("my-agent");
query({ prompt, options: { hooks: tracekitHooks(run), sessionStore: tracekitSessionStore(myStore, run) } });
```

The gate is the `PreToolUse` hook (it runs for every call; `canUseTool` is skipped for calls the CLI's permission mode
allows). An `ask` is held in the hook for up to 540 s, below the hook timeout it sets (600 s); a call not approved by
then is blocked. `PostToolUse`/`PostToolUseFailure` complete the call, `SessionEnd` closes the run. The session store
wrapper commits each saved transcript as a `state_write` chained from the last one, so a transcript edited in the store
between two writes shows up as a signed `state_tamper` gap.

## Migrating from v1

The v1 SDK (`Tracekit`, driving `python -m tracekit.bridge`) is deprecated and removed in 0.5.0. Until then it stays at
`@cygnux/tracekit/v1`; `Tracekit.start` warns once per process (`DeprecationWarning`, code `TRACEKIT_V1`) and the bridge
prints a matching notice on stderr; `TRACEKIT_NO_DEPRECATION=1` silences both. The import becomes
`import { Tracekit } from "@cygnux/tracekit/v1"`.

| v1 (`@cygnux/tracekit/v1`) | v2 (`@cygnux/tracekit`) |
|---|---|
| `await Tracekit.start({ agent })` | `const client = new Client(); const run = await client.registerRun(agent)` |
| `await tk.tool(name, args, fn, { toolUseId })` | `await run.decide(toolUseId, name, args)`, run `fn` on `allow`, then `await run.complete(toolUseId, "ok", { result })` |
| `TracekitDenied` | `d.decision === "deny"` (`d.rule_ids`); a refusal by the signer rejects with `RPCError` |
| held for approval inside `tk.tool` | `d.decision === "ask"`: `run.approvalRequest(id)`, then `run.approvalWait(approval_id)` |
| `instrumentOpenAI` / `instrumentAnthropic`, `tk.modelBegin` / `tk.modelEnd` | `run.modelEvent(provider, model, "response", { stop_reason, usage, tool_uses })`, or a framework adapter below |
| `tracekitMiddleware(tk)` | `tracekitAI(run).middleware` from `@cygnux/tracekit/v2/vercel-ai`, with `tools` and `toolApproval` |
| `tk.prompt` / `tk.say` / `tk.think` | not recorded by the v2 signer |
| `tk.end(reason)` | `await run.close(reason); await client.close()` |

```ts
// v1
import { Tracekit, TracekitDenied } from "@cygnux/tracekit/v1";
const tk = await Tracekit.start({ agent: "research-bot" });
try {
  out = await tk.tool("Bash", args, () => runShell(args), { toolUseId: call.id });
} catch (e) {
  if (!(e instanceof TracekitDenied)) throw e;
}
await tk.end();

// v2
import { Client } from "@cygnux/tracekit";
const client = new Client();
const run = await client.registerRun("research-bot");
const d = await run.decide(call.id, "Bash", call.function.arguments);
if (d.decision === "allow") {
  out = await runShell(args);
  await run.complete(call.id, "ok", { result: out });
}
await run.close();
await client.close();
```

## v1 SDK (deprecated, `@cygnux/tracekit/v1`)

Removed in 0.5.0; see the migration above. Tool calls pass Tracekit's policy gate before they run, and model calls
become signed evidence, in the same ledger and format as the Python SDK.

```ts
import OpenAI from "openai";
import { Tracekit, TracekitDenied, instrumentOpenAI } from "@cygnux/tracekit/v1";

const tk = await Tracekit.start({ agent: "research-bot" });
const openai = instrumentOpenAI(new OpenAI(), tk);        // also: instrumentAnthropic(client, tk), tracekitMiddleware(tk) for the Vercel AI SDK

const r = await openai.chat.completions.create({ model: "gpt-4o", messages, tools });
for (const call of r.choices[0].message.tool_calls ?? []) {
  await tk.tool("Bash", JSON.parse(call.function.arguments), () => runShell(call), { toolUseId: call.id });  // TracekitDenied if blocked
}
await tk.end();
```

- `tk.tool(name, args, fn)`: the policy decision is made and signed before `fn` runs; a denied (or held, not approved)
  call throws `TracekitDenied` and `fn` never runs. Pass the model's call id as `toolUseId` to link request and execution.
- `instrumentOpenAI` (chat completions, Responses), `instrumentAnthropic` (messages): a signed request event before the
  call is sent, and a response event with model, finish reason, requested tool calls, token usage, error, status and
  time to first chunk. Streams are recorded when they end, fail or are abandoned: the SDK replaces the stream's async
  iterator in place with a recording one; non-streamed responses come back as the provider SDK returned them. The
  wrapped `create` is an async function, so it returns a plain Promise: helpers on the SDK's own promise object (such
  as `.withResponse()`) are not available through it. A provider error is recorded and rethrown. The request event is
  written before the call is sent: if the bridge reports an error or times out, that error is thrown and the call is not sent; if the
  bridge has exited, `fail_mode: closed` throws `TracekitDenied` and `fail_mode: open` sends the call unrecorded with a
  warning on stderr. A failure to record a call that already completed is written to stderr and counted in
  `tk.recordFailures`; it never replaces the call's result.
- `tracekitMiddleware(tk)`: `wrapLanguageModel({ model, middleware: tracekitMiddleware(tk) })` in the Vercel AI SDK
  (v4 and v5 result shapes).

**How it works.** The SDK starts `python -m tracekit.bridge` and talks to it over stdio, so policy evaluation, secret
redaction, the signer client and the event format are Tracekit's own Python code, not a second implementation. It needs
the `tracekit` Python package and a signer (`tracekit init --dev`); set `TRACEKIT_PYTHON` to pick the interpreter.

Tests (`npm test`): `test/sdk.test.mjs` runs the v1 SDK with the real OpenAI and Anthropic SDKs against a mocked fetch and a real signer, then verify the
bundle; `test/adapters.test.mjs` runs the adapter contract for each adapter, through small stand-ins for the
frameworks' hook and middleware interfaces, against an in-test fake signer and (with Python and the signer extra) the
real one.
