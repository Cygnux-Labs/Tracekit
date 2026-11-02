// Offline Vercel AI SDK v7: pause for approval, then resume the same run in a second process.
// Needs `npm i -D ai@7`, `npm run build` and Python with tracekit (a dev signer is started on demand).
//   node examples/v2_vercel_ai_resume.mjs /tmp/vercel-resume.json
//   tracekit approvals approve <the printed id>                 # another terminal, same signer
//   node examples/v2_vercel_ai_resume.mjs /tmp/vercel-resume.json
//   tracekit last
// The state file contains the run token: keep it private, out of git, and delete it when finished.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { generateText, jsonSchema, stepCountIs, tool, wrapLanguageModel } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { Client, RunHandle } from "../dist/v2/client.js";
import { tracekitAI } from "../dist/v2/adapters/vercel-ai.js";

const file = process.argv[2];
if (!file) throw new Error("Usage: node examples/v2_vercel_ai_resume.mjs /path/to/private-state.json");
let saved;
try {
  saved = JSON.parse(await readFile(file, "utf8"));
} catch (e) {
  if (e.code !== "ENOENT") throw e;
}
const run = saved
  ? new RunHandle(new Client(), { run_id: saved.runId, run_token: saved.runToken })
  : await new Client().registerRun("vercel-resume-example");
const tk = tracekitAI(run);
const usage = { inputTokens: { total: 12, noCache: 12, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 5, text: 5, reasoning: 0 } };
const model = wrapLanguageModel({
  model: new MockLanguageModelV4({ doGenerate: {
    content: saved ? [{ type: "text", text: "Approval handled." }] : [{
      type: "tool-call", toolCallId: "held-call", toolName: "Bash", input: JSON.stringify({ command: 'echo "unterminated' }),
    }],
    finishReason: { unified: saved ? "stop" : "tool-calls", raw: saved ? "end_turn" : "tool_use" }, usage, warnings: [],
  } }),
  middleware: tk.middleware,
});
let executions = 0;
const Bash = tool({
  description: "Pretend to run a shell command",
  inputSchema: jsonSchema({ type: "object", properties: { command: { type: "string" } }, required: ["command"] }),
  execute: async ({ command }) => {
    executions++;
    const output = `(pretend) ran ${command}`;
    console.log(output);
    return output;
  },
});

try {
  if (!saved) {
    const messages = [{ role: "user", content: "Run the demonstration command." }];
    const r = await generateText({ model, tools: tk.tools({ Bash }), toolApproval: tk.toolApproval, messages });
    assert.equal(executions, 0);
    const { approvals } = await run.client.call("approval_list", { run_id: run.runId });
    const approval = approvals.find((a) => a.tool_call_id === "held-call");
    assert.equal(approval?.state, "requested");
    assert.ok(approval.rule_ids.includes("TK-SHELL-PARSE"));
    await writeFile(file, JSON.stringify({ runId: run.runId, runToken: run.runToken,
      messages: [...messages, ...r.response.messages], content: r.content }, null, 2), { flag: "wx", mode: 0o600 });
    console.log(`Held: TK-SHELL-PARSE; executed ${executions} times; run ${run.runId}`);
    console.log(`Saved private state to ${file}. Run left open.`);
    console.log(`Approve in another terminal: tracekit approvals approve ${approval.approval_id}`);
    console.log("Then run this example again with the same state file and signer.");
  } else {
    const responses = await tk.approvalResponses(saved.content);
    if (!responses.length) {
      console.log("No approval response available; executed 0 times.");
      assert.equal(executions, 0);
    } else {
      const messages = [...saved.messages, { role: "tool", content: responses }];
      const r = await generateText({ model, tools: tk.tools({ Bash }), toolApproval: tk.toolApproval,
        messages, stopWhen: stepCountIs(3) });
      assert.equal(executions, responses.some((p) => p.approved) ? 1 : 0);
      console.log(r.text);
      await run.close();
      console.log(`Executed ${executions} time(s); closed run ${run.runId}.`);
    }
  }
} finally {
  await run.client.close();
}
