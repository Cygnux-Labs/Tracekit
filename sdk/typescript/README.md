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

## v2 signer client (`@cygnux/tracekit/v2`)

A native client of the v2 signer RPC with no runtime dependencies (Node ≥ 18 built-ins only, no Python bridge).

```ts
import { Client, withRun, currentRun } from "@cygnux/tracekit/v2";

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
  Otherwise the same-user dev signer is found, or started with `python -m tracekit up --json` (`$TRACEKIT_PYTHON`).
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

Tests (`npm test`) run the real OpenAI and Anthropic SDKs against a mocked fetch and a real signer, then verify the bundle.
