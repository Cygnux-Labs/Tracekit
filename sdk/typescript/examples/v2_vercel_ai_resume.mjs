// Offline Vercel AI SDK v7: pause for approval, then resume the same run in a second process.
// Needs `npm i -D ai@7`, `npm run build` and Python with tracekit (a dev signer is started on demand).
//   STATE="$(mktemp -d)/state.json"
//   node examples/v2_vercel_ai_resume.mjs "$STATE"
//   tracekit approvals approve <the printed id>                 # another terminal, same signer
//   node examples/v2_vercel_ai_resume.mjs "$STATE"
//   tracekit last
// The state file contains the run token: keep it private and out of git; it is deleted after the run closes. It is
// read only when it is a regular file you own that no one else can read or write (not a symlink).
import assert from "node:assert/strict";
import { constants } from "node:fs";
import { open, unlink, writeFile } from "node:fs/promises";
import { generateText, jsonSchema, stepCountIs, tool, wrapLanguageModel } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { Client, RunHandle } from "../dist/v2/client.js";
import { tracekitAI } from "../dist/v2/adapters/vercel-ai.js";

const file = process.argv[2];
if (!file) {
  console.error('Usage: STATE="$(mktemp -d)/state.json"; node examples/v2_vercel_ai_resume.mjs "$STATE"');
  process.exit(2);
}
let saved;   // none (ENOENT): a fresh start
try {
  const fh = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = await fh.stat();
    if (!st.isFile() || st.uid !== process.getuid() || st.mode & 0o077)
      throw new Error(`${file} must be a regular file owned by you with mode 0600; refused`);
    saved = JSON.parse(await fh.readFile("utf8"));
  } finally {
    await fh.close();
  }
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
      type: "tool-call", toolCallId: "held-call", toolName: "Bash", input: JSON.stringify({ command: "terraform destroy" }),
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
    assert.ok(approval.rule_ids.includes("TK-A001"));
    await writeFile(file, JSON.stringify({ runId: run.runId, runToken: run.runToken,
      messages: [...messages, ...r.response.messages], content: r.content }, null, 2), { flag: "wx", mode: 0o600 });
    console.log(`Held: TK-A001; executed ${executions} times; run ${run.runId}`);
    console.log(`Saved private state to ${file}. Run left open.`);
    console.log(`Approve in another terminal: tracekit approvals approve ${approval.approval_id}`);
    console.log("Then run this example again with the same state file and signer.");
  } else {
    const { approvals } = await run.client.call("approval_list", { run_id: run.runId });
    const approval = approvals.find((a) => a.tool_call_id === "held-call");
    if (approval?.state === "requested" && !approval.run_closing) {
      console.log(`Not answered yet; executed 0 times. Approve in another terminal: tracekit approvals approve ${approval.approval_id}`);
      console.log(`Kept the private state file ${file}; run this example again after the approval.`);
    } else if (approval?.state !== "approved" && approval?.state !== "rejected") {
      // expired, already used, its run ended, or a signer that never held it: nothing to resume
      const why = !approval ? "the signer has no approval for the held call"
        : approval.run_closing ? "the run ended" : `the approval is ${approval.state}`;
      await run.close().catch((e) => console.log(`Closing run ${run.runId}: ${e.message}`));
      await unlink(file);
      console.log(`Nothing to resume: ${why}. Executed 0 times; deleted the private state file.`);
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
        await unlink(file);
        console.log(`Executed ${executions} time(s); closed run ${run.runId} and deleted the private state file.`);
      }
    }
  }
} finally {
  await run.client.close();
}
