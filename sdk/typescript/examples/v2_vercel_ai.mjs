// Vercel AI SDK v7 on the v2 signer, offline: a mock model asks for two shell commands; the signer's default policy
// allows `ls` and denies `sudo rm -rf /`, whose refusal the model gets as the tool result.
// Needs `npm i ai`, `npm run build` and Python with tracekit (a dev signer is started on demand).
//   node examples/v2_vercel_ai.mjs
import { generateText, jsonSchema, stepCountIs, tool, wrapLanguageModel } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { Client } from "../dist/v2/client.js";
import { tracekitAI } from "../dist/v2/adapters/vercel-ai.js";

const client = new Client(), run = await client.registerRun("vercel-example");
const tk = tracekitAI(run);
const usage = { inputTokens: { total: 12, noCache: 12, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 5, text: 5, reasoning: 0 } };
const call = (id, command) => ({ type: "tool-call", toolCallId: id, toolName: "Bash", input: JSON.stringify({ command }) });
const model = wrapLanguageModel({
  model: new MockLanguageModelV4({ doGenerate: [
    { content: [call("call_1", "ls"), call("call_2", "sudo rm -rf /")], finishReason: { unified: "tool-calls", raw: "tool_use" }, usage, warnings: [] },
    { content: [{ type: "text", text: "Listed the files; the other command was refused." }], finishReason: { unified: "stop", raw: "end_turn" }, usage, warnings: [] },
  ] }),
  middleware: tk.middleware,
});
const Bash = tool({
  description: "Run a shell command",
  inputSchema: jsonSchema({ type: "object", properties: { command: { type: "string" } }, required: ["command"] }),
  execute: async ({ command }) => `(pretend) ran ${command}`,
});

// an `ask` would end the step with a tool-approval-request; after a person decides in the signer, resume with
// messages.push(...r.response.messages, { role: "tool", content: await tk.approvalResponses(r.content) })
const r = await generateText({ model, tools: tk.tools({ Bash }), toolApproval: tk.toolApproval, stopWhen: stepCountIs(3), prompt: "tidy up" });
for (const p of r.steps[0].content) if (p.type !== "tool-call") console.log(p.type, JSON.stringify(p.output ?? p));
console.log(r.text);
await run.close();
await client.close();
