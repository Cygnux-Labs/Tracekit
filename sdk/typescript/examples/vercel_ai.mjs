// Vercel AI SDK middleware, offline: a stub language model wrapped with tracekitMiddleware, plus a policy-checked tool.
// With the real SDK: wrapLanguageModel({ model: openai("gpt-4o"), middleware: tracekitMiddleware(tk) }).
// The deprecated v1 API (`@cygnux/tracekit/v1`); the v2 client: examples/v2_vercel_ai.mjs.
// Needs a running signer (tracekit init) and `npm run build` first.   node examples/vercel_ai.mjs
import { Tracekit, TracekitDenied, tracekitMiddleware } from "../dist/v1.js";

const tk = await Tracekit.start({ agent: "vercel-example" });
const mw = tracekitMiddleware(tk);
const model = { provider: "openai.chat", modelId: "gpt-4o-mini" };
const r = await mw.wrapGenerate({ model, params: { prompt: [] }, doGenerate: async () => ({
  content: [{ type: "tool-call", toolCallId: "t1", toolName: "Bash", input: "{\"command\":\"ls\"}" }],
  finishReason: "tool-calls", usage: { inputTokens: 42, outputTokens: 9 } }) });
const call = r.content[0];
console.log(await tk.tool("Bash", JSON.parse(call.input), () => "README.md", { toolUseId: call.toolCallId }));
try {
  await tk.tool("Bash", { command: "sudo rm -rf /" }, () => { throw new Error("must not run"); });
} catch (e) {
  if (!(e instanceof TracekitDenied)) throw e;
  console.log("denied:", e.message);
}
await tk.end();
console.log("vercel example finished");
