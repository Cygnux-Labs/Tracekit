// OpenAI Agents SDK (JS) on the v2 signer, offline: a mock model asks for two shell commands; the signer's default
// policy allows `ls` and denies `sudo rm -rf /`, whose refusal the model gets as the tool output.
// Needs `npm i @openai/agents`, `npm run build` and Python with tracekit (a dev signer is started on demand).
//   node examples/v2_openai_agents.mjs
import { Agent, Runner, Usage, tool } from "@openai/agents";
import { Client } from "../dist/v2/client.js";
import { TracekitAgents } from "../dist/v2/adapters/openai-agents.js";

const call = (callId, command) => ({ type: "function_call", callId, name: "Bash", arguments: JSON.stringify({ command }), status: "completed" });
const replies = [
  [call("call_1", "ls"), call("call_2", "sudo rm -rf /")],
  [{ type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: "Listed the files; the other command was refused." }] }],
];
const model = {   // a Model that answers from `replies`, in order
  async getResponse() {
    return { usage: new Usage({ requests: 1, inputTokens: 12, outputTokens: 5, totalTokens: 17 }), output: replies.shift(), responseId: `resp_${replies.length}` };
  },
  async *getStreamedResponse() {},
};

const client = new Client(), tk = new TracekitAgents(await client.registerRun("agents-example"));
const Bash = tk.tool(tool, {
  name: "Bash",
  description: "Run a shell command",
  parameters: { type: "object", properties: { command: { type: "string" } }, required: ["command"], additionalProperties: false },
  strict: true,
  execute: async ({ command }) => `(pretend) ran ${command}`,
});
const agent = new Agent({ name: "shell", instructions: "Tidy up.", model, tools: [Bash] });
// an `ask` interrupts the run (result.interruptions); after a person decides in the signer:
// await tk.applyDecisions(result.state); result = await runner.run(agent, result.state)
const result = await new Runner({ tracingDisabled: true }).run(agent, "tidy up", { context: {} });
for (const item of result.newItems) if (item.type === "tool_call_output_item") console.log(item.rawItem.callId, JSON.stringify(item.output));
console.log(result.finalOutput);
await tk.recordResponses(result.rawResponses, "mock");
await tk.run.close();
await client.close();
