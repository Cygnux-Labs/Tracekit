# Vercel AI SDK

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

`tracekitAI` (`@cygnuxlabs/tracekit/v2/vercel-ai`, in the [TypeScript SDK](../../sdk/typescript/README.md)) gates the
tool calls of a Vercel AI SDK v7 app: before each tool runs, the Tracekit signer decides it (an `ask` waits for a
person), and the call is recorded after it runs. Its middleware records each model response. It works with
`generateText`, `streamText` and `ToolLoopAgent`.

## Install

Node 18 or newer:

```sh
npm install @cygnuxlabs/tracekit ai@7
```

npm also installs the signer package for your platform (`@cygnuxlabs/tracekit-signer-<platform>`: Apple Silicon
macOS, Linux x64 and arm64 with glibc, Windows x64), which bundles a Python, so a dev signer starts without one. On an
Intel Mac or Alpine there is none: `pip install 'tracekit-ai[signer]'`.

Tested by the TypeScript adapter contract against the real signer, and in CI by
[`examples/v2_vercel_ai.mjs`](../../sdk/typescript/examples/v2_vercel_ai.mjs) against `ai` 7 with a mock model (no API
key).

## Setup

```ts
import { openai } from "@ai-sdk/openai";           // any provider
import { generateText, wrapLanguageModel } from "ai";
import { Client } from "@cygnuxlabs/tracekit";
import { tracekitAI } from "@cygnuxlabs/tracekit/v2/vercel-ai";

const client = new Client();                       // the local signer; a dev signer is started if none answers
const run = await client.registerRun("assistant");
const tk = tracekitAI(run);
const model = wrapLanguageModel({ model: openai("gpt-5"), middleware: tk.middleware });
const r = await generateText({ model, tools: tk.tools({ pay }), toolApproval: tk.toolApproval, messages });
// asks end the step with tool-approval-request parts; once decided in the signer:
messages.push(...r.response.messages, { role: "tool", content: await tk.approvalResponses(r.content) });
await run.close();
await client.close();
```

Or let `instrument()` register the run and close it when the process is about to exit: `const tk = await
instrument()` (from `@cygnuxlabs/tracekit`), then `tk.ai.middleware`, `tk.ai.tools(...)` and `tk.ai.toolApproval`.
ES modules can't be patched from outside, so you pass the adapters to the SDK yourself. Then `tracekit last` exports
the run, pins the dev signer's key and verifies it.

A server registers a run per conversation and makes it current around each request with
`withRun(run, () => generateText(...))`; exit handling and the LLM gateway are in the
[TypeScript SDK](../../sdk/typescript/README.md#v2-framework-adapters).

## What it does

- **Decides the model's raw arguments.** `tk.middleware` records each model response (V3 usage, the tool calls asked
  for) and keeps each call's raw arguments by `toolCallId` for the decision.
- **Maps the signer's decision onto the SDK's approvals.** `tk.toolApproval` maps `deny` to `denied` and `ask` to
  `user-approval`; without it an `ask` is refused. A `deny` reaches the model as the tool's error result and the run
  goes on.
- **Runs only what the signer approved.** `tk.tools()` wraps each `execute`: every call, allowed or approved, runs only
  after the signer's `approval_consume` agrees, so a forged or replayed `tool-approval-response` runs nothing.
  `experimental_toolApprovalSecret` (the SDK's HMAC over its own approval requests) may be set too; it does not replace
  the signer's check.
- **Fails closed on a refusal.** The run's fail mode applies only when the signer can't be reached at the decision; a
  refusal, or a failure while waiting for an approval, never lets the call run. Recording a finished call never throws
  and never changes its result (a failure is a `TracekitWarning`).

MCP tools (`@ai-sdk/mcp`): `tk.tools(await client.tools(), { mcp: "filesystem" })` decides each as
`mcp:filesystem/<tool>`. Your own `toolApproval` (a function, or one per tool name) composes with the signer's:
`toolApproval: tk.toolApprovalWith(mine)` asks the policy first, and your answer applies only to a call the policy
allows (a call you deny is recorded as refused; one you answer `user-approval` and then deny in your own UI stays
decided and not completed); `tk.toolApproval` alone replaces yours.

## What the model said

`tk.middleware` commits to each response's content, its reasoning parts included, but doesn't send the content: the
reasoning isn't readable from this record. Use the [LLM gateway](../gateway.md) for readable reasoning. Which frameworks and providers return readable reasoning, and how to turn it on: [reasoning](../reasoning.md).

## Not covered

- Tools without `execute` and provider-executed tools are not gated; they appear in the recorded model responses.
  Without `toolApproval`, the adapter keeps the arguments of up to 4,096 such calls
  ([limits](../limits.md#one-line-setup-tracekitinstrument)).
- Spans from `@ai-sdk/otel` are telemetry, not evidence: the signed records are the middleware's and the adapter's.
- An MCP tool's server isn't tied to the model's call by a bare tool name, so rules keyed on the server don't apply
  ([limits](../limits.md#signer-and-capture)).
- With a remote signer, the agent's identity needs grants for the RPCs the adapter calls, `approval_list` included
  ([limits](../limits.md#deployment)).
