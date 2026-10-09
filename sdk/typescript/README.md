# @cygnux/tracekit

Tracekit for TypeScript and JavaScript agents: tool calls pass Tracekit's policy gate before they run, and model calls
become signed evidence, in the same ledger and format as the Python SDK.

```ts
import OpenAI from "openai";
import { Tracekit, TracekitDenied, instrumentOpenAI } from "@cygnux/tracekit";

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

Tests (`npm test`) run the real OpenAI and Anthropic SDKs against a mocked fetch and a real signer, then verify the bundle.
