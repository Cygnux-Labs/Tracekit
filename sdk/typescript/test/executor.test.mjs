// The executor client helpers (src/v2/executor.ts) against a stand-in executor: the listing, a call with the run and
// the model's call id, a refusal as ExecutorRefused, and the framework tools built from them.   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { EXECUTOR, ExecutorRefused, executorActions, openaiAgentsTool, vercelTool } from "../dist/v2/executor.js";
import { tracekitAI } from "../dist/v2/adapters/vercel-ai.js";
import { tracekitHooks } from "../dist/v2/adapters/claude-agent-sdk.js";

const ARGS = { type: "object", required: ["to"], properties: { to: { type: "string" } } };

test("executor actions: listed, called for the run, refusals thrown, as OpenAI Agents and Vercel AI tools", async (t) => {
  const seen = [];
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, run: req.headers["x-tracekit-run"], body: body && JSON.parse(body) });
      const [status, out] = req.url === "/v1/actions" ? [200, { actions: [{ name: "pay", description: "Pay", args: ARGS }, { name: "wipe", description: "", args: ARGS }] }]
        : req.url === "/v1/actions/wipe" ? [403, { error: { message: "tracekit executor: denied by policy: R-WIPE" } }]
        : [200, { status: 201, result: { ok: true } }];
      res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(out));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  const run = { runId: "run-1", runToken: "p.mac" };
  const [pay, wipe] = await executorActions(`http://127.0.0.1:${srv.address().port}/`, run, { headers: { authorization: "Bearer agent" } });
  assert.deepEqual([pay.name, pay.description, pay.args], ["pay", "Pay", ARGS]);
  assert.deepEqual(await pay.call({ to: "a" }, "call-1"), { status: 201, result: { ok: true } });
  assert.deepEqual(seen.at(-1), { method: "POST", url: "/v1/actions/pay", auth: "Bearer agent", run: "run-1.p.mac", body: { args: { to: "a" }, tool_call_id: "call-1" } });
  await assert.rejects(wipe.call({ to: "a" }), (e) => e instanceof ExecutorRefused && /R-WIPE/.test(e.message));
  for (const url of ["http://executor.internal:8090", "https://user:pw@executor.internal", "executor.internal"]) {
    const before = seen.length;   // refused before anything is sent: the run token never goes in clear
    await assert.rejects(executorActions(url, run, { headers: { authorization: "Bearer agent" } }), /must use https|must not contain|invalid URL/);
    assert.equal(seen.length, before);
  }

  const oa = openaiAgentsTool((o) => o, pay);
  assert.deepEqual([oa.name, oa.parameters, oa.strict], ["pay", ARGS, false]);
  assert.equal(await oa.execute({ to: "b" }, {}, { toolCall: { callId: "call-2" } }), JSON.stringify({ status: 201, result: { ok: true } }));
  assert.equal(seen.at(-1).body.tool_call_id, "call-2");
  const ai = vercelTool(pay, (s) => ({ wrapped: s }));
  assert.deepEqual(ai.inputSchema, { wrapped: ARGS });
  await ai.execute({ to: "c" }, { toolCallId: "call-3" });
  assert.equal(seen.at(-1).body.tool_call_id, "call-3");
});

test("the Vercel AI adapter leaves executor tools to the executor: no decide on the call id the executor gets", async () => {
  const run = { decide: async () => { throw new Error("decided by the adapter"); } };
  const a = { name: "pay", description: "", args: ARGS, call: async (input, id) => ({ status: 201, id }) };
  const pay = vercelTool(a, (s) => s), call = { toolCallId: "call-1", toolName: "pay", input: { to: "a" } };
  const tk = tracekitAI(run), tools = tk.tools({ pay });
  assert.equal(tools.pay, pay);
  assert.equal(await tk.toolApproval({ toolCall: call, tools: {} }), "not-applicable");   // known from tk.tools
  assert.equal(await tracekitAI(run).toolApproval({ toolCall: call, tools: { pay } }), "not-applicable");
  assert.deepEqual(await tools.pay.execute(call.input, { toolCallId: "call-1" }), { status: 201, id: "call-1" });
  assert.equal(openaiAgentsTool((o) => ({ ...o }), a)[EXECUTOR], true);
  const [pre] = tracekitHooks(run).PreToolUse[0].hooks;   // the Claude Agent SDK hooks: by the server's name
  assert.deepEqual(await pre({ tool_name: "mcp__tracekit-executor__pay", tool_use_id: "tu-1", tool_input: {} }), {});
});
