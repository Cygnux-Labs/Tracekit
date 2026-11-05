// A Mastra workflow whose tool calls go through Tracekit: each call is decided by the signer first, a held call
// suspends its step until a person answers, and resuming passes the approval id to approval_consume. Offline: the
// model is a script of the calls it asks for, and the tool only pretends to run them. Steps in README.md.
import { Mastra } from "@mastra/core";
import { InMemoryStore } from "@mastra/core/storage";
import { createStep, createWorkflow } from "@mastra/core/workflows";
import { z } from "zod";
import { Client, digest } from "../../dist/v2/client.js";

process.env.MASTRA_TELEMETRY_DISABLED = "1";   // offline: Mastra reads it at each event, so nothing is sent to Mastra

const MODEL = [   // what a model would ask for, one tool call at a time
  { id: "call-1", tool: "Bash", args: { command: "ls infra" } },             // allowed
  { id: "call-2", tool: "Bash", args: { command: "rm -rf ~" } },             // denied
  { id: "call-3", tool: "Bash", args: { command: "terraform destroy" } },    // held for a person (TK-A001)
];

const call = z.object({ id: z.string(), tool: z.string(), args: z.object({ command: z.string() }) });
const outcome = z.object({ id: z.string(), outcome: z.string() });

const model = createStep({
  id: "model", inputSchema: z.object({ task: z.string() }), outputSchema: z.array(call),
  execute: async () => MODEL,
});

const tool = createStep({
  id: "tool", inputSchema: call, outputSchema: outcome,
  suspendSchema: z.object({ approvalId: z.string() }), resumeSchema: z.object({ approvalId: z.string() }),
  execute: async ({ inputData: c, resumeData, suspend }) => {
    const done = (outcome) => (console.log(`${c.args.command}: ${outcome}`), { id: c.id, outcome });
    if (!resumeData) {   // 1. the signer decides before anything runs
      const d = await run.decide(c.id, c.tool, c.args);
      if (d.decision === "deny") return done(`denied (${d.rule_ids.join(", ")})`);
      if (d.decision === "ask") {   // 2. held: the step suspends with the approval id
        const { approval_id } = await run.approvalRequest(c.id);
        console.log(`${c.args.command}: held (${d.rule_ids.join(", ")}); the workflow is suspended. In another terminal:`);
        console.log(`  tracekit approvals approve ${approval_id}     (or: tracekit approvals reject ${approval_id})`);
        return suspend({ approvalId: approval_id });
      }
    }
    // 3. allowed, or resumed with the approval id: the call runs only if the signer's approval_consume agrees
    const consumed = await run.call("approval_consume", { tool_call_id: c.id, tool: c.tool, args: c.args,
      args_source: "parsed", ...(resumeData ? { approval_id_hint: resumeData.approvalId } : {}) });
    if (!consumed.ok) return done(`not run (${consumed.reason ?? consumed.rule_ids.join(", ")})`);
    const out = "(pretend) ran it";
    await run.complete(c.id, "ok", { result: digest(out) });
    return done(out);
  },
});

const workflow = createWorkflow({
  id: "tidy-infra", inputSchema: z.object({ task: z.string() }), outputSchema: z.array(outcome),
}).then(model).foreach(tool).commit();
// resume() reads the suspended run's snapshot from storage: Mastra's in-memory store keeps it for this process
const mastra = new Mastra({ workflows: { workflow }, storage: new InMemoryStore() });

const run = await new Client().registerRun("mastra-example");
try {
  const wrun = await mastra.getWorkflow("workflow").createRun();
  let result = await wrun.start({ inputData: { task: "Tidy up the staging stack." } });
  while (result.status === "suspended") {
    const { approvalId } = result.steps.tool.suspendPayload;
    let state = "requested";
    while (state === "requested") state = (await run.approvalWait(approvalId, 300_000)).state;
    console.log(`Approval ${state}; resuming the workflow.`);
    result = await wrun.resume({ step: "tool", resumeData: { approvalId } });
  }
  if (result.status !== "success") throw new Error(`workflow ${result.status}: ${result.error?.message ?? ""}`);
} finally {
  await run.close();
  await run.client.close();
}
console.log(`Closed run ${run.runId}. Export and verify it: tracekit last -o mastra.tkb`);
