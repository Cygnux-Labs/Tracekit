// Vercel AI SDK adapter on the v2 signer, offline and without `ai` installed: a stub model call goes through
// tk.middleware, then each tool call it asks for through tk.toolApproval and the gated execute, as generateText does.
// With the real SDK see examples/v2_vercel_ai.mjs. Needs `npm run build` and Python with tracekit (a dev signer is
// started on demand).   node examples/vercel_ai.mjs
import { Client } from "../dist/v2/client.js";
import { tracekitAI } from "../dist/v2/adapters/vercel-ai.js";

const client = new Client(), run = await client.registerRun("vercel-example");
const tk = tracekitAI(run);
const call = (id, command) => ({ type: "tool-call", toolCallId: id, toolName: "Bash", input: JSON.stringify({ command }) });
const r = await tk.middleware.wrapGenerate({ model: { provider: "openai.chat", modelId: "gpt-4o-mini" }, doGenerate: async () => ({
  content: [call("t1", "ls"), call("t2", "sudo rm -rf /")], finishReason: "tool-calls", usage: { inputTokens: { total: 42 }, outputTokens: { total: 9 } } }) });
const { Bash } = tk.tools({ Bash: { execute: async ({ command }) => `(pretend) ran ${command}` } });
for (const toolCall of r.content) {
  const a = await tk.toolApproval({ toolCall });
  console.log(a === "not-applicable" ? await Bash.execute(JSON.parse(toolCall.input), { toolCallId: toolCall.toolCallId }) : `${a.type}: ${a.reason}`);
}
await run.close();
await client.close();
console.log("vercel example finished");
