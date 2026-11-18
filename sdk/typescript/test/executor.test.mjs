// The executor client helpers (src/v2/executor.ts) against a stand-in executor: the listing, a call with the run and
// the model's call id, a refusal as ExecutorRefused, and the framework tools built from them.   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { EXECUTOR, ExecutorRefused, SERVER, claudeAgentSdkTool, executorActions, openaiAgentsTool, vercelTool } from "../dist/v2/executor.js";
import { tracekitAI } from "../dist/v2/adapters/vercel-ai.js";
import { tracekitHooks } from "../dist/v2/adapters/claude-agent-sdk.js";

const ARGS = { type: "object", required: ["to"], properties: { to: { type: "string" } } };
// a minimal zod and the Claude Agent SDK's tool(), standing in for the app's
const zt = (t) => ({ t, int: () => zt(`${t}.int`), optional() { return { ...this, opt: true }; }, describe(d) { return { ...this, d }; } });
const z = { string: () => zt("string"), number: () => zt("number"), boolean: () => zt("boolean"), enum: (v) => zt(`enum:${v}`), array: (i) => zt(`array:${i.t}`) };
const sdkTool = (name, description, shape, handler) => ({ name, description, shape, handler });
const plain = (shape) => Object.fromEntries(Object.entries(shape).map(([k, { t, opt, d }]) => [k, [t, !!opt, d]]));

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

  const flat = { ...pay, args: { type: "object", required: ["to", "amount"], properties: { to: { type: "string", description: "payee" },
    amount: { type: "integer" }, rate: { type: "number" }, urgent: { type: "boolean" }, tags: { type: "array", items: { type: "string" } },
    kind: { enum: ["card", "wire"] } } } };
  const ca = claudeAgentSdkTool(sdkTool, z, flat);
  assert.deepEqual([ca.name, ca.description], ["pay", "Pay"]);
  assert.deepEqual(plain(ca.shape), { to: ["string", false, "payee"], amount: ["number.int", false, undefined], rate: ["number", true, undefined],
    urgent: ["boolean", true, undefined], tags: ["array:string", true, undefined], kind: ["enum:card,wire", true, undefined] });
  assert.deepEqual(await ca.handler({ to: "d", amount: 5 }), { content: [{ type: "text", text: JSON.stringify({ status: 201, result: { ok: true } }) }] });
  assert.deepEqual(seen.at(-1).body, { args: { to: "d", amount: 5 } });
  const refused = await claudeAgentSdkTool(sdkTool, z, wipe).handler({ to: "e" });
  assert.equal(refused.isError, true);
  assert.match(refused.content[0].text, /R-WIPE/);
});

test("a Claude Agent SDK tool isn't built from a schema it can't express as a zod shape: the error names the property", () => {
  const a = (properties) => ({ name: "pay", description: "", args: { type: "object", properties }, call: async () => ({}) });
  for (const [k, s] of [["to", { type: "object", properties: { iban: { type: "string" } } }], ["to", { type: ["string", "null"] }],
    ["ids", { type: "array", items: { type: "object" } }], ["ids", { type: "array" }], ["n", { enum: [1, 2] }], ["n", { type: "constructor" }]]) {
    assert.throws(() => claudeAgentSdkTool(sdkTool, z, a({ ok: { type: "string" }, [k]: s })), new RegExp(`^Error: pay: argument "${k}": unsupported`));
  }
  assert.throws(() => claudeAgentSdkTool(sdkTool, z, { ...a({}), args: { type: "array" } }), /pay: the arguments' schema must be an object/);
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
  // the Claude Agent SDK hooks: the app's own in-process server under the name, as `query()` gets it
  const mcpServers = { "tracekit-executor": { type: "sdk", name: "tracekit-executor", instance: {} } };
  const [pre] = tracekitHooks(run, { mcpServers, executorActions: [a] }).PreToolUse[0].hooks;
  assert.deepEqual(await pre({ tool_name: "mcp__tracekit-executor__pay", tool_use_id: "tu-1", tool_input: {} }), {});
  // and the tool claudeAgentSdkTool builds, in the server the app makes of it
  const built = claudeAgentSdkTool(sdkTool, z, a);
  const servers = { [SERVER]: { type: "sdk", name: SERVER, instance: { tools: [built] } } };
  const [pre2] = tracekitHooks(run, { mcpServers: servers, executorActions: [a] }).PreToolUse[0].hooks;
  assert.deepEqual(await pre2({ tool_name: `mcp__${SERVER}__${built.name}`, tool_use_id: "tu-2", tool_input: { to: "a" } }), {});
});

test("the Claude Agent SDK hooks gate every tool but the app's executor actions, by exact name (#588)", async () => {
  const decided = [];
  const run = { decide: async (id, tool) => { decided.push([id, tool]); throw new Error("refused"); } };
  const project = { "tracekit-executor": { type: "stdio", command: "/tmp/not-the-executor" } };   // as .mcp.json adds it
  const app = { "tracekit-executor": { type: "sdk", name: "tracekit-executor", instance: {} } };
  const pay = "mcp__tracekit-executor__pay", actions = [{ name: "pay" }];
  const cases = [[undefined, pay], [{}, pay], [{ mcpServers: {} }, pay], [{ mcpServers: project, executorActions: actions }, pay],
    [{ mcpServers: app }, pay],   // no actions named
    // a project server keyed `tracekit-executor__pay` or `tracekit-executor_` next to the app's executor
    ...["mcp__tracekit-executor__pay__shell", "mcp__tracekit-executor___x", "mcp__tracekit-executor__payx"].map(
      (t) => [{ mcpServers: app, executorActions: actions }, t])];
  for (const [i, [opts, tool]] of cases.entries()) {
    const [pre] = tracekitHooks(run, opts).PreToolUse[0].hooks;
    const out = await pre({ tool_name: tool, tool_use_id: `tu-${i}`, tool_input: {} });
    assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  }
  assert.deepEqual(decided, cases.map(([, tool], i) => [`tu-${i}`, tool]));
});
