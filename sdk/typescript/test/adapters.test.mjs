// The adapter contract (04-design §7.3, tests/adapter_contract.py in TypeScript) for the v2 adapters, each driven
// through a small stand-in for its framework's hook or middleware interface, against an in-test fake signer and, when
// Python with the signer extra is there, the real signer.   npm test
// The policy: "pay" asks (R-PAY, with a T2 executor), "wipe" is denied (R-WIPE), everything else is allowed; "echo"'s results are untrusted.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import { Client, RPC_VERSION, argsDigest, digest, instrument, withRun } from "../dist/v2/client.js";
import { TracekitAgents } from "../dist/v2/adapters/openai-agents.js";
import { tracekitAI } from "../dist/v2/adapters/vercel-ai.js";
import { tracekitHooks, tracekitSessionStore } from "../dist/v2/adapters/claude-agent-sdk.js";

const ROOT = resolve(import.meta.dirname, "../../..");
const PY = process.env.TRACEKIT_PYTHON ?? "python3";
const PY_ENV = { ...process.env, PYTHONPATH: ROOT };
const NO_SIGNER = spawnSync(PY, ["-c", "from tracekit.policy2 import engine; engine._backend(None)"], { env: PY_ENV }).status === 0
  ? false : `needs ${PY} with the tracekit [signer] extra (set TRACEKIT_PYTHON)`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PAY = { to: "acct-42", cents: 1500 };

// ------------------------------------------------------------------ signers

/** An in-test signer on a Unix socket. `override(frame)` may answer first. */
async function fakeSigner({ failModes = { default: "closed" }, override = () => null } = {}) {
  const dir = mkdtempSync("/tmp/tkad-"), path = join(dir, "s.sock"), socks = new Set();   // short: macOS socket paths
  const events = [], decisions = new Map(), approvals = new Map();
  let n = 0;
  const id = (p) => `${p}-${++n}`;
  const emit = (run_id, type, data) => (events.push({ run_id, type, data }), { run_seq: events.length });
  const mine = (f) => (x) => x.run_id === f.run_id && x.tool_call_id === f.tool_call_id && x.attempt === (f.attempt ?? 0);
  const no = (rule) => ({ ok: false, rule_ids: [rule] });
  const answer = async (f) => {
    switch (f.method) {
      case "hello": return { proto: [RPC_VERSION, RPC_VERSION], version: "test", pid: 1 };
      case "register_run": return { run_id: id("run"), run_token: "tok", tenant: "default", fail_modes: failModes };
      case "decide": {
        const tool = f.tool.split("/").pop();
        const [decision, rule_ids] = tool === "pay" ? ["ask", ["R-PAY"]] : tool === "wipe" ? ["deny", ["R-WIPE"]] : ["allow", []];
        const d = { run_id: f.run_id, decision_id: id("dec"), tool_call_id: f.tool_call_id, attempt: f.attempt ?? 0, decision, rule_ids, digest: argsDigest(f.tool, f.args), args: f.args };
        decisions.set(d.decision_id, d);
        return { ...emit(f.run_id, "policy.decision", d), decision, rule_ids, decision_id: d.decision_id,
          ...(tool.endsWith("echo") ? { send_result: true } : {}) };   // echo's results are untrusted
      }
      case "approval_request": {   // one approval per call attempt: asking again returns it
        const d = [...decisions.values()].findLast(mine(f));
        if (d?.decision !== "ask") return { error: { code: "unknown_tool_call", message: "no ask to approve" } };
        const a = [...approvals.values()].find(mine(f)) ?? { ...d, approval_id: id("apr"), state: "requested" };
        approvals.set(a.approval_id, a);
        return { approval_id: a.approval_id, state: a.state };
      }
      case "approval_wait": {
        const a = approvals.get(f.approval_id);
        for (const end = Date.now() + f.timeout_ms; a.state === "requested" && Date.now() < end;) await sleep(10);
        return { approval_id: a.approval_id, state: a.state };
      }
      case "approval_decide": {
        const a = approvals.get(f.approval_id);
        a.state = f.decision === "approve" ? "approved" : "rejected";
        return { approval_id: a.approval_id, state: a.state };
      }
      case "approval_list": return { approvals: [...approvals.values()].filter((a) => a.run_id === f.run_id).reverse() };
      case "approval_consume": {
        const d = [...decisions.values()].findLast(mine(f)), digest = argsDigest(f.tool, f.args);
        if (!d || d.decision === "deny") return no("TK-NOT-ALLOWED");
        if (d.decision === "allow") return d.digest === digest ? { ok: true } : no("TK-APPROVAL-MISMATCH");
        const a = [...approvals.values()].find(mine(f));
        if (!a || a.state === "requested") return no("TK-APPROVAL-REQUESTED");
        if (a.state !== "approved") return no(a.state === "consumed" ? "TK-APPROVAL-CONSUMED" : "TK-APPROVAL-REJECTED");
        if (a.digest !== digest) return no("TK-APPROVAL-MISMATCH");
        a.state = "consumed";
        emit(f.run_id, "approval.consumed", { tool_call_id: f.tool_call_id, attempt: a.attempt });
        return { ok: true, args: typeof a.args === "string" ? JSON.parse(a.args) : a.args };   // T2: the signer's copy
      }
      case "complete": {
        const d = decisions.get(f.decision_id);
        if (!d || d.tool_call_id !== f.tool_call_id || d.attempt !== (f.attempt ?? 0) || d.digest !== f.args_digest)
          return { error: { code: "invalid_request", message: "not bound to its decision" } };
        return emit(f.run_id, "tool.result", { decision_id: d.decision_id, tool_call_id: d.tool_call_id, attempt: d.attempt, ok: f.status === "ok", result: f.result });
      }
      case "read": return { events: events.filter((e) => e.run_id === f.run_id) };
      case "model_event": return emit(f.run_id, "model.exchange", f);
      case "state_write": return emit(f.run_id, "state.write", f);
      case "close_run": return { ...emit(f.run_id, "run.closed", {}), run_id: f.run_id, state: "closing" };
      default: return { error: { code: "invalid_request", message: f.method } };
    }
  };
  const server = createServer((sock) => {
    let buf = "", queue = Promise.resolve();
    socks.add(sock);
    sock.on("close", () => socks.delete(sock));
    sock.on("error", () => {});
    sock.on("data", (d) => {
      buf += d;
      for (let i; (i = buf.indexOf("\n")) >= 0;) {
        const f = JSON.parse(buf.slice(0, i));
        buf = buf.slice(i + 1);
        queue = queue.then(async () => sock.write(JSON.stringify((await override(f)) || (await answer(f))) + "\n"));
      }
    });
  });
  await new Promise((r) => server.listen(path, r));
  const stop = () => new Promise((r) => {
    server.close(() => r(rmSync(dir, { recursive: true, force: true })));
    socks.forEach((s) => s.destroy());
  });
  return { path, stop };
}

/** The real signer (SignerService) with the same policy, served by Python; `read` answers with the signed records,
 * which keep `attempt` (the RPC's `read` leaves the top-level fields out). */
async function realSigner() {
  const p = spawn(PY, ["-c", `
import json, os, sys, tempfile, threading
from tracekit.policy2.engine import Engine
from tracekit.signer.service import SignerService
from tracekit.transport import answering_hello, hello
from tracekit.transport.unix import UnixServer
d = tempfile.mkdtemp(dir="/tmp")
s = SignerService(d, policy=Engine({"ask": [{"id": "R-PAY", "tool": "^(.*/)?pay$", "pattern": "^", "approval": {"executor": "t2"}}],
                                    "deny": [{"id": "R-WIPE", "tool": "^(.*/)?wipe$", "pattern": "^"}], "untrusted": ["*echo"]}))
def handle(identity, frame):
    if frame.get("method") == "read":
        return {"events": [r["event"] for r in s.log.storage.iter_run("default", frame["run_id"])]}
    return s.handle_frame(identity, frame)
srv = UnixServer(os.path.join(d, "s.sock"), answering_hello(handle, hello()))
threading.Thread(target=srv.serve_forever, args=(0.2,), daemon=True).start()
print(json.dumps(os.path.join(d, "s.sock")), flush=True)
sys.stdin.read()
s.close()`], { env: PY_ENV, stdio: ["pipe", "pipe", "inherit"] });
  let out = "";
  for await (const d of p.stdout) if ((out += d).includes("\n")) break;
  return { path: JSON.parse(out), stop: async () => p.kill() };
}

// ------------------------------------------------------------------ framework stand-ins

const RAN = [];
const TOOLS = {
  echo: ({ text }) => (RAN.push("echo"), text),
  pay: ({ cents }) => (RAN.push("pay"), `paid ${cents}`),
  wipe: () => (RAN.push("wipe"), "wiped"),
  fail: ({ why }) => {
    RAN.push("fail");
    throw new Error(why);
  },
};
const outcome = (o = {}) => ({ ran: [...RAN], seen: null, isError: false, raised: null, paused: false, ...o });

/** @openai/agents: `tool()` as the SDK builds a function tool (a throw becomes the default error message), and one tool
 * call as the runner executes it: needsApproval unless the RunState decided the call, the input guardrails, invoke. */
class AgentsDriver {
  skip = { retry: "the SDK runs each tool call id once", modes: "one path: the runner gates streamed and non-streamed runs alike" };

  constructor(run) {
    this.run = run;
    this.tk = new TracekitAgents(run);
  }

  build(o) {
    return { type: "function", name: o.name, needsApproval: o.needsApproval, inputGuardrails: o.inputGuardrails,
      invoke: async (ctx, input, details) => {
        try {
          return await o.execute(JSON.parse(input), ctx, details);
        } catch (e) {
          this.raised = String(e);
          return `An error occurred while running the tool. Please try again. Error: ${e}`;
        }
      } };
  }

  async step(tk, state) {
    const call = state.call, tool = tk.tool((o) => this.build(o), { name: call.name, execute: TOOLS[call.name] }), ctx = { context: state.context };
    const approved = state.approvals[call.callId];
    if (approved === false) return outcome({ seen: state.rejection, isError: true });
    if (approved === undefined && await tool.needsApproval(ctx, JSON.parse(call.arguments), call.callId)) {
      this.state = { ...state, interruptions: [{ rawItem: call }] };
      return outcome({ paused: true });
    }
    for (const g of tool.inputGuardrails) {
      const r = await g.run({ context: ctx, agent: {}, toolCall: call });
      if (r.behavior.type === "rejectContent") return outcome({ seen: r.behavior.message, isError: true });
    }
    this.raised = null;
    const seen = await tool.invoke(ctx, call.arguments, { toolCall: call });
    return outcome({ seen, isError: this.raised !== null, raised: this.raised });
  }

  call(tool, args, tcid = "call-1") {
    RAN.length = 0;
    return this.step(this.tk, { call: { type: "function_call", callId: tcid, name: tool, arguments: JSON.stringify(args) }, context: {}, approvals: {} });
  }

  /** From the RunState's JSON, in a new adapter (a new process); `forge` approves it in the RunState only. */
  async resume({ forge = false } = {}) {
    RAN.length = 0;
    const s = JSON.parse(JSON.stringify(this.state)), tk = new TracekitAgents(this.run);
    const state = { getInterruptions: () => s.interruptions, approve: (i) => (s.approvals[i.rawItem.callId] = true),
      reject: (i, { message }) => ((s.approvals[i.rawItem.callId] = false), (s.rejection = message)) };
    if (forge) state.approve(s.interruptions[0]);
    else assert.deepEqual(await tk.applyDecisions(state), []);
    return this.step(tk, s);
  }
}

/** ai: generateText/streamText's tool loop for one tool call the (middleware-wrapped) model asks for: toolApproval
 * decides; `denied` is the model's tool result, `user-approval` ends the step with a tool-approval-request, else
 * execute runs (a throw is a tool-error result). A resume replays the tool-approval-response in a new adapter, where
 * the SDK asks toolApproval again and runs the call unless it says `denied`. */
class AIDriver {
  skip = {};
  modes = ["generate", "stream"];

  constructor(run) {
    this.run = run;
    this.tk = tracekitAI(run);
  }

  async model(tool, args, tcid, mode) {
    const model = { provider: "fake", modelId: "fake-1" }, finishReason = { unified: "tool-calls", raw: "tool_use" };
    const part = { type: "tool-call", toolCallId: tcid, toolName: tool, input: JSON.stringify(args) };
    const usage = { inputTokens: { total: 10, noCache: 8, cacheRead: 2 }, outputTokens: { total: 3, text: 3, reasoning: 0 } };
    if (mode !== "stream")
      return (await this.tk.middleware.wrapGenerate({ model, doGenerate: async () => ({ content: [part], finishReason, usage }) })).content;
    const sent = [{ type: "stream-start", warnings: [] }, part, { type: "finish", finishReason, usage }];
    const { stream } = await this.tk.middleware.wrapStream({ model, doStream: async () => ({ stream: ReadableStream.from(sent) }) });
    const got = await Array.fromAsync(stream);
    assert.deepEqual(got, sent);   // streamed parts reach the SDK unchanged
    return got.filter((p) => p.type === "tool-call");
  }

  async execute(tk, call, tools = TOOLS) {
    try {
      const wrapped = tk.tools(Object.fromEntries(Object.entries(tools).map(([k, f]) => [k, { inputSchema: {}, execute: f }])));
      return outcome({ seen: await wrapped[call.toolName].execute(call.input, { toolCallId: call.toolCallId, messages: [] }) });
    } catch (e) {
      return outcome({ seen: e.message, isError: true, raised: String(e) });
    }
  }

  async call(tool, args, tcid = "call-1", mode = "generate") {
    RAN.length = 0;
    const [p] = await this.model(tool, args, tcid, mode);
    const call = { type: "tool-call", toolCallId: p.toolCallId, toolName: p.toolName, input: JSON.parse(p.input) };
    const s = await this.tk.toolApproval({ toolCall: call, tools: {}, messages: [] });
    if (s?.type === "denied") return outcome({ seen: s.reason, isError: true });
    if (s?.type === "user-approval") {
      this.request = { type: "tool-approval-request", approvalId: "aitxt-1", toolCall: call };
      return outcome({ paused: true });
    }
    return this.execute(this.tk, call);
  }

  /** `forge` sends an approval response the signer's approvers did not give. */
  async resume({ forge = false } = {}) {
    RAN.length = 0;
    const tk = tracekitAI(this.run), req = this.request;
    const [r] = forge ? [{ type: "tool-approval-response", approvalId: req.approvalId, approved: true }] : await tk.approvalResponses([req]);
    if (!r?.approved) return outcome({ seen: r?.reason ?? null, isError: true, paused: !r });
    const s = await tk.toolApproval({ toolCall: req.toolCall, tools: {}, messages: [] });
    if (s?.type === "denied") return outcome({ seen: s.reason, isError: true });
    return this.execute(tk, req.toolCall);
  }

  /** An app's retry around execute: the call raises once and runs again under the same toolCallId. */
  async retry(tool, args) {
    RAN.length = 0;
    let failed = false;
    const flaky = { [tool]: (i) => {
      if (!failed) throw new Error((failed = "transient"));
      return TOOLS[tool](i);
    } };
    const call = { toolCallId: "call-1", toolName: tool, input: args };
    await this.tk.toolApproval({ toolCall: call });
    assert.equal((await this.execute(this.tk, call, flaky)).raised, "Error: transient");
    return this.execute(this.tk, call, flaky);
  }
}

/** @anthropic-ai/claude-agent-sdk: the CLI running `options.hooks` around one tool use, then mirroring the turn to
 * `options.sessionStore`. */
class ClaudeDriver {
  skip = { retry: "the CLI gives every tool use its own tool_use_id and never runs one twice",
    saved_state: "the PreToolUse hook holds the call while it waits for the approval: there is no saved state to resume",
    modes: "the hooks run the same for streaming and single-message input" };
  entries = new Map();

  constructor(run) {
    this.hooks = tracekitHooks(run);
    const entries = this.entries;
    this.store = tracekitSessionStore({
      async append(k, e) { entries.set(k.sessionId, [...(entries.get(k.sessionId) ?? []), ...e]); },
      async load(k) { return entries.get(k.sessionId) ?? null; },
    }, run);
  }

  async hook(event, input) {
    const out = {};
    for (const m of this.hooks[event] ?? [])
      for (const h of m.hooks) Object.assign(out, await h({ hook_event_name: event, session_id: "s1", ...input }, input.tool_use_id, { signal: AbortSignal.timeout((m.timeout ?? 60) * 1000) }));
    return out;
  }

  call(tool, args, tcid = "call-1") {
    RAN.length = 0;
    return (this.pending = this.turn({ tool_name: tool, tool_input: args, tool_use_id: tcid }));
  }

  async turn(call) {
    const pre = (await this.hook("PreToolUse", call)).hookSpecificOutput;
    let o;
    if (pre?.permissionDecision === "deny") {
      o = outcome({ seen: pre.permissionDecisionReason, isError: true });
    } else {
      call = { ...call, tool_input: pre?.updatedInput ?? call.tool_input };   // the CLI runs the hook's updatedInput
      try {
        o = outcome({ seen: TOOLS[call.tool_name](call.tool_input) });
      } catch (e) {
        o = outcome({ seen: e.message, isError: true, raised: String(e) });
      }
      await (o.raised ? this.hook("PostToolUseFailure", { ...call, error: o.seen }) : this.hook("PostToolUse", { ...call, tool_response: { stdout: o.seen } }));
    }
    await this.store.append({ projectKey: "p", sessionId: "s1" }, [{ type: "user", uuid: randomUUID(), message: call }]);
    return o;
  }

  resume() {
    return this.pending;
  }
}

// ------------------------------------------------------------------ the contract

const norm = (e) => {
  const d = e.data;
  return { type: e.type, decision: d.decision, decision_id: d.decision_id, tcid: d.tool_call_id ?? d.tool_use_id,
    attempt: d.attempt ?? e.attempt ?? 0, ok: d.ok ?? d.status === "ok" };
};

function contract(name, Driver, serve, skip) {
  describe(name, { skip }, () => {
    let signer, client, run, d;
    before(async () => (signer = await serve()));
    after(() => signer?.stop());

    const setup = async (t) => {
      client = new Client({ signer: signer.path });
      run = await client.registerRun("contract");
      d = new Driver(run);
      t.after(() => client.close());
    };
    const recorded = async (type) => (await run.call("read", { limit: 1000 })).events.filter((e) => e.type === type).map(norm);
    const decideApproval = (approval_id, decision = "approve") => client.call("approval_decide", { approval_id, decision });
    const paused = async (tcid = "call-1") => {
      const out = d.call("pay", PAY, tcid);
      for (let i = 0; i < 500; i++) {
        const a = (await client.call("approval_list", { run_id: run.runId })).approvals.find((x) => x.tool_call_id === tcid && x.state === "requested");
        if (a) {
          if (!d.skip.saved_state) assert.deepEqual(await out, outcome({ paused: true }));
          return a.approval_id;
        }
        await sleep(10);
      }
      assert.fail(`no approval requested: ${JSON.stringify(await out)}`);
    };
    /** Each executed call completed once, against its own decision. */
    const bound = async (n = 1) => {
      const decisions = new Map((await recorded("policy.decision")).map((x) => [x.decision_id, x])), results = await recorded("tool.result");
      assert.equal(results.length, n, JSON.stringify(results));
      for (const r of results) assert.deepEqual([r.tcid, r.attempt], [decisions.get(r.decision_id).tcid, decisions.get(r.decision_id).attempt]);
      return results;
    };

    it("allow: runs once and completes bound to its decision", async (t) => {
      await setup(t);
      assert.deepEqual(await d.call("echo", { text: "hi" }), outcome({ ran: ["echo"], seen: "hi" }));
      const [x] = await recorded("policy.decision");
      assert.equal(x.decision, "allow");
      const [r] = await bound();
      assert.deepEqual([r.decision_id, r.ok], [x.decision_id, true]);
    });

    it("an untrusted tool's result goes to the signer itself (send_result), for its provenance index", async (t) => {
      await setup(t);
      assert.deepEqual((await d.call("echo", { text: "mail audit@vendor.example" })).ran, ["echo"]);
      const events = async () => (await run.call("read", { limit: 1000 })).events;
      const result = (await events()).find((e) => e.type === "tool.result").data;
      if ("result" in result) return assert.match(JSON.stringify(result.result), /audit@vendor\.example/);   // the fake
      await run.decide("send-1", "send", { to: "audit@vendor.example" });   // the real signer: a digest is `partial`
      const x = (await events()).find((e) => e.type === "policy.decision" && e.data.tool_use_id === "send-1").data;
      assert.deepEqual([x.provenance_state, x.provenance?.[0]?.kind], ["complete", "email"]);
    });

    it("deny: the model gets the refusal and the run goes on", async (t) => {
      await setup(t);
      refused(await d.call("wipe", { path: "/" }), "R-WIPE");
      assert.deepEqual(await recorded("tool.result"), []);
      assert.deepEqual((await d.call("echo", { text: "next" }, "call-2")).ran, ["echo"]);
    });

    it("a tool's exception reaches the framework and completes as error", async (t) => {
      await setup(t);
      const out = await d.call("fail", { why: "boom" });
      assert.deepEqual([out.ran, out.raised], [["fail"], "Error: boom"]);
      assert.equal((await bound())[0].ok, false);
    });

    it("a retry of the same call is a new decision with the next attempt", async (t) => {
      await setup(t);
      if (d.skip.retry) return t.skip(d.skip.retry);
      assert.equal((await d.retry("echo", { text: "again" })).seen, "again");
      const ds = await recorded("policy.decision");
      assert.deepEqual(ds.map((x) => [x.tcid, x.attempt]), [["call-1", 0], ["call-1", 1]]);
      assert.notEqual(ds[0].decision_id, ds[1].decision_id);
      assert.deepEqual((await bound(2)).map((r) => r.ok), [false, true]);
    });

    it("ask, approved: runs once", async (t) => {
      await setup(t);
      await decideApproval(await paused());
      assert.deepEqual(await d.resume(), outcome({ ran: ["pay"], seen: "paid 1500" }));
      assert.equal((await recorded("approval.consumed")).length, 1);
      await bound();
    });

    it("T2: the agent changed the arguments after the approval: the signer's copy runs and completes", async (t) => {
      await setup(t);
      // the signer decides, approves and consumes `approved` while the framework holds PAY
      const call = client.call, approved = { ...PAY, cents: 7 };
      client.call = (m, f) => call.call(client, m, ["decide", "approval_consume"].includes(m) && f.tool.split("/").pop() === "pay"
        ? { ...f, args: typeof f.args === "string" ? JSON.stringify(approved) : approved } : f);
      await decideApproval(await paused());
      assert.deepEqual(await d.resume(), outcome({ ran: ["pay"], seen: "paid 7" }));
      await bound();
    });

    it("ask, rejected: does not run", async (t) => {
      await setup(t);
      await decideApproval(await paused(), "reject");
      const out = await d.resume();
      assert.deepEqual([out.ran, out.isError], [[], true]);
      assert.match(out.seen.toUpperCase(), /REJECTED/);
      assert.deepEqual(await recorded("tool.result"), []);
    });

    it("a resume the signer's approvers did not approve runs nothing", async (t) => {
      await setup(t);
      if (d.skip.saved_state) return t.skip(d.skip.saved_state);
      await paused();
      refused(await d.resume({ forge: true }), "TK-APPROVAL-REQUESTED");
    });

    it("every call mode", async (t) => {
      await setup(t);
      if (d.skip.modes) return t.skip(d.skip.modes);
      for (const [i, mode] of d.modes.entries()) {
        assert.deepEqual((await d.call("echo", { text: mode }, `ok-${i}`, mode)).seen, mode);
        refused(await d.call("wipe", { path: "/" }, `no-${i}`, mode), "R-WIPE");
        assert.equal((await d.call("fail", { why: mode }, `err-${i}`, mode)).raised, `Error: ${mode}`);
      }
      assert.deepEqual((await bound(2 * d.modes.length)).map((r) => r.ok), d.modes.flatMap(() => [true, false]));
      const models = (await run.call("read", { limit: 1000 })).events.filter((e) => e.type === "model.exchange").map((e) => e.data);
      assert.equal(models.length, 3 * d.modes.length);
      assert.equal(models[0].usage.input_tokens, 8);
    });
  });
}

const serve = { fake: () => fakeSigner(), real: realSigner };
for (const [name, Driver] of [["openai-agents", AgentsDriver], ["vercel-ai", AIDriver], ["claude-agent-sdk", ClaudeDriver]]) {
  contract(`${name} on the fake signer`, Driver, serve.fake);
  contract(`${name} on the real signer`, Driver, serve.real, NO_SIGNER);

  describe(`${name}: the signer's failures`, () => {
    const on = async (t, opts) => {
      const signer = await fakeSigner(opts), client = new Client({ signer: signer.path });
      t.after(() => (client.close(), signer.stop()));
      return { signer, d: new Driver(await client.registerRun("contract")) };
    };

    it("unreachable when deciding: fail open runs unrecorded, fail closed refuses", async (t) => {
      for (const mode of ["open", "closed"]) {
        const { signer, d } = await on(t, { failModes: { default: mode } });
        await signer.stop();
        const out = await d.call("echo", { text: "hi" });
        if (mode === "open") assert.deepEqual(out, outcome({ ran: ["echo"], seen: "hi" }));
        else refused(out, "signer unavailable");
      }
    });

    it("a refusal from the signer blocks the call, failing open or not", async (t) => {
      const { d } = await on(t, { failModes: { default: "open" }, override: (f) => f.method === "decide" && { error: { code: "forbidden", message: "no" } } });
      refused(await d.call("echo", { text: "hi" }), "forbidden");
    });

    it("a failure to complete warns and keeps the result", async (t) => {
      const { d } = await on(t, { override: (f) => f.method === "complete" && { error: { code: "internal", message: "disk full" } } });
      const warnings = [], seen = (w) => warnings.push(w.message);
      process.on("warning", seen);
      t.after(() => process.off("warning", seen));
      assert.deepEqual(await d.call("echo", { text: "hi" }), outcome({ ran: ["echo"], seen: "hi" }));
      await sleep(10);   // warnings are emitted on the next tick
      assert.ok(warnings.some((m) => m.includes("disk full")), warnings);
    });
  });
}

function refused(out, code) {
  assert.deepEqual(out.ran, []);
  assert.ok(out.isError, JSON.stringify(out));
  assert.match(out.seen, new RegExp(code));
}

describe("claude-agent-sdk session store", () => {
  it("commits each transcript append, chained from what the store held", async (t) => {
    const signer = await fakeSigner(), client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    const run = await client.registerRun("store"), d = new ClaudeDriver(run);
    await d.call("echo", { text: "a" });
    await d.call("echo", { text: "b" }, "call-2");
    const writes = (await run.call("read", { limit: 1000 })).events.filter((e) => e.type === "state.write").map((e) => e.data);
    assert.deepEqual(writes.map((w) => w.key), ["claude-agent-sdk:s1", "claude-agent-sdk:s1"]);
    assert.equal(writes[0].prev_digest, digest([]));   // an empty transcript: the store had none
    assert.equal(writes[1].prev_digest, writes[0].value_digest);
    assert.equal(new Set(writes.map((w) => w.stream)).size, 1);
    assert.deepEqual(writes.map((w) => w.client_seq), [0, 1]);
  });
});

describe("the app's own input guardrails (OpenAI Agents)", () => {
  it("a call they refuse after the signer decided it is completed as refused, not left open", async (t) => {
    const frames = [], signer = await fakeSigner({ override: (f) => (frames.push(f), null) });
    const client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    const tk = new TracekitAgents(await client.registerRun("a"));
    const only = (city) => ({ name: "japan-only", run: async ({ toolCall }) =>
      ({ behavior: JSON.parse(toolCall.arguments).city === city ? { type: "allow" } : { type: "rejectContent", message: "Japan only" } }) });
    const tool = tk.tool((o) => o, { name: "echo", execute: async () => "ok", inputGuardrails: [only("Tokyo")] });
    for (const [id, city] of [["g1", "Tokyo"], ["g2", "Paris"]]) {
      const toolCall = { callId: id, name: "echo", arguments: JSON.stringify({ city }) };
      assert.equal(await tool.needsApproval({ context: {} }, { city }, id), false);   // decided: allowed
      await tool.inputGuardrails[0].run({ context: { context: {} }, toolCall });
    }
    const completes = frames.filter((f) => f.method === "complete").map((f) => [f.tool_call_id, f.status]);
    assert.deepEqual(completes, [["g2", "error"]]);   // g1 goes on to Tracekit's guardrail and runs; g2 is closed
  });
});

describe("local MCP servers (OpenAI Agents)", () => {
  it("each call is decided as mcp:<server>/<tool> in the input guardrail and completed in the output guardrail", async (t) => {
    const frames = [], signer = await fakeSigner({ override: (f) => (frames.push(f), null) });
    const client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    const tk = new TracekitAgents(await client.registerRun("a")), g = tk.mcp("file system");
    const call = (callId, name) => ({ toolCall: { callId, name, arguments: '{"path": "a"}' } });
    assert.deepEqual((await g.toolInputGuardrails[0].run(call("m1", "read_text_file"))).behavior, { type: "allow" });
    await g.toolOutputGuardrails[0].run({ ...call("m1", "read_text_file"), output: "text" });
    const denied = (await g.toolInputGuardrails[0].run(call("m2", "wipe"))).behavior;
    assert.deepEqual([denied.type, denied.message], ["rejectContent", "Tool call blocked by policy: R-WIPE"]);
    const sent = (m) => frames.filter((f) => f.method === m).map((f) => [f.tool_call_id, f.tool]);
    await g.toolInputGuardrails[0].run(call("m3", "mcp_file_system__read_text_file"));   // includeServerInToolNames
    assert.deepEqual(sent("decide"), [["m1", "mcp:file_system/read_text_file"], ["m2", "mcp:file_system/wipe"],
      ["m3", "mcp:file_system/read_text_file"]]);
    assert.deepEqual(sent("complete").map(([id]) => id), ["m1"]);
  });

  it("a server name is made safe in time linear in its length", async (t) => {
    // a run of _ or - inside the name made trimming its ends quadratic (CodeQL js/polynomial-redos)
    const signer = await fakeSigner(), client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    const tk = new TracekitAgents(await client.registerRun("a")), start = Date.now();
    tk.mcp(`a${"_".repeat(150_000)}a`);
    assert.ok(Date.now() - start < 500, `${Date.now() - start} ms`);
  });
});

describe("Vercel AI: MCP tools and the app's own toolApproval", () => {
  async function setup(t) {
    const frames = [], signer = await fakeSigner({ override: (f) => (frames.push(f), null) });
    const client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    return [tracekitAI(await client.registerRun("a")), frames];
  }
  const call = (id, name) => ({ toolCall: { toolCallId: id, toolName: name, input: {} } });

  it("tools(…, { mcp }) decides each as mcp:<server>/<tool>", async (t) => {
    const [tk, frames] = await setup(t);
    const tools = tk.tools({ read_text_file: { execute: async () => "text" } }, { mcp: "filesystem" });
    assert.equal(await tk.toolApproval(call("m1", "read_text_file")), "not-applicable");
    assert.equal(await tools.read_text_file.execute({}, { toolCallId: "m1" }), "text");
    assert.deepEqual(frames.filter((f) => ["decide", "approval_consume"].includes(f.method)).map((f) => f.tool),
      ["mcp:filesystem/read_text_file", "mcp:filesystem/read_text_file"]);
  });

  it("toolApprovalWith(app): the policy first; the app's answer only for a call the policy allows", async (t) => {
    const [tk, frames] = await setup(t);
    const approval = tk.toolApprovalWith({ echo: () => "denied", wipe: () => "approved", pay: () => "approved" });
    assert.equal(await approval(call("c1", "echo")), "denied");   // allowed by the policy, denied by the app
    assert.equal((await approval(call("c2", "wipe"))).type, "denied");   // the policy's deny stands
    assert.equal((await approval(call("c3", "pay"))).type, "user-approval");   // the policy's ask stands
    const completes = frames.filter((f) => f.method === "complete").map((f) => [f.tool_call_id, f.status]);
    assert.deepEqual(completes, [["c1", "error"]]);   // recorded as refused: no decided-but-never-completed gap
  });
});

describe("a run per conversation (withRun)", () => {
  it("each call is decided, consumed and completed in the run current when it was decided", async (t) => {
    const frames = [], signer = await fakeSigner({ override: (f) => (frames.push(f), null) });
    const client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    const [base, a, b] = [await client.registerRun("srv"), await client.registerRun("alice"), await client.registerRun("bob")];
    const tk = tracekitAI(base), echo = tk.tools({ echo: { execute: async (input) => input.text } }).echo;
    const call = async (id) => {
      const toolCall = { toolCallId: id, toolName: "echo", input: { text: id } };
      await tk.toolApproval({ toolCall });
      return () => echo.execute(toolCall.input, { toolCallId: id });
    };
    const runA = await withRun(a, () => call("ca")), runB = await withRun(b, () => call("cb")), runBase = await call("cx");
    await Promise.all([runA(), runB(), runBase()]);   // executed outside any withRun: still their own runs
    const where = (m) => Object.fromEntries(frames.filter((f) => f.method === m).map((f) => [f.tool_call_id, f.run_id]));
    const want = { ca: a.runId, cb: b.runId, cx: base.runId };
    assert.deepEqual([where("decide"), where("approval_consume"), where("complete")], [want, want, want]);
  });
});

describe("instrument", () => {
  it("one call: one run, the adapters bound to it, the same on a second call", async (t) => {
    const signer = await fakeSigner();
    const first = instrument("quickstart", { signer: signer.path }), tk = await first;
    t.after(() => (tk.run.client.close(), signer.stop()));
    assert.equal(instrument(), first);
    assert.equal(tk.agents.run, tk.run);
    const echo = tk.ai.tools({ echo: { execute: async (input) => input.text } }).echo;
    const call = { toolCallId: "call-1", toolName: "echo", input: { text: "hi" } };
    assert.equal(await tk.ai.toolApproval({ toolCall: call }), "not-applicable");   // allowed: execute consumes
    assert.equal(await echo.execute(call.input, { toolCallId: "call-1" }), "hi");
    const types = (await tk.run.call("read", { limit: 100 })).events.map((e) => e.type);
    assert.deepEqual(types.filter((x) => x !== "run.registered"), ["policy.decision", "tool.result"]);
    assert.equal(tk.run.renewAs, "quickstart");
  });

  it("its run is renewed once the signer closed it idle; a call completes in the run it was decided in", async (t) => {
    const closed = new Set(), frames = [];
    const signer = await fakeSigner({ override: (f) => {
      frames.push(f);
      return closed.has(f.run_id) && f.method === "decide" ? { error: { code: "run_closed", message: f.run_id } } : null;
    } });
    const client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    const run = await client.registerRun("srv");
    run.renewAs = "srv";   // what instrument() sets
    const first = run.runId;
    await run.decide("c1", "echo", {});
    closed.add(first);   // the signer closes it after it was idle
    await run.decide("c2", "echo", {});
    assert.notEqual(run.runId, first);
    assert.deepEqual(frames.findLast((f) => f.method === "register_run").parent, { run_id: first, run_token: "tok" });
    await run.complete("c1");
    await run.complete("c2");
    const results = (id) => frames.filter((f) => f.method === "complete" && f.run_id === id).map((f) => f.tool_call_id);
    assert.deepEqual([results(first), results(run.runId)], [["c1"], ["c2"]]);


    const app = await client.registerRun("srv");
    app.renewAs = "srv";
    await app.close();   // closed by the app: never renewed
    closed.add(app.runId);
    await assert.rejects(app.decide("c3", "echo", {}), (e) => e.code === "run_closed");
  });

  it("renews at most once per call: a signer that refuses the new run too gets its refusal back", async (t) => {
    let registered = 0;
    const signer = await fakeSigner({ override: (f) => f.method === "register_run" ? (registered++, null)
      : f.method === "decide" && { error: { code: "unknown_run", message: f.run_id } } });
    const client = new Client({ signer: signer.path });
    t.after(() => (client.close(), signer.stop()));
    const run = await client.registerRun("srv");
    run.renewAs = "srv";
    await assert.rejects(run.decide("c1", "echo", {}), (e) => e.code === "unknown_run");
    assert.equal(registered, 2);   // the run, and one renewal
  });

  // A process that instrument()s, does `body`, then ends as `body` leaves it. -> [its frames' methods, exit signal].
  async function child(body, refuse = () => null) {
    const frames = [], signer = await fakeSigner({ override: (f) => (frames.push(f.method), refuse(f)) });
    const code = `import { instrument } from ${JSON.stringify(resolve(import.meta.dirname, "../dist/v2/client.js"))};
      const tk = await instrument("child", { signer: ${JSON.stringify(signer.path)} }); ${body}`;
    let out = "";
    const p = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "pipe", "ignore"] });
    p.stdout.on("data", (d) => (out += d));
    const [code_, signal] = await new Promise((r) => p.on("exit", (c, sig) => r([c, sig])));
    await signer.stop();
    return [frames.filter((m) => m !== "hello"), signal, code_, out.trim()];
  }

  it("closes its run as the process ends, or on SIGTERM (then the signal's default action still happens)", async () => {
    assert.deepEqual((await child(`await tk.run.decide("c1", "echo", {});`)).slice(0, 2), [["register_run", "decide", "approval_list", "approval_list", "close_run"], null]);
    const [frames, signal] = await child(`setTimeout(() => {}, 10000); process.kill(process.pid, "SIGTERM");`);
    assert.deepEqual([frames.at(-1), signal], ["close_run", "SIGTERM"]);
  });

  it("leaves a signal the app handles to the app: its graceful shutdown runs, a REPL keeps its run", async () => {
    const [, signal, code, out] = await child(`process.once("SIGTERM", () => setTimeout(() => (console.log("graceful done"), process.exit(0)), 100));
      await tk.run.decide("c1", "echo", {}); setTimeout(() => {}, 10000); process.kill(process.pid, "SIGTERM");`);
    assert.deepEqual([signal, code, out], [null, 0, "graceful done"]);
    const [frames, , , repl] = await child(`process.on("SIGINT", () => {});   // Ctrl-C cancels a step, the app goes on
      process.kill(process.pid, "SIGINT"); await new Promise((r) => setTimeout(r, 100));
      console.log((await tk.run.decide("c2", "echo", {})).decision); process.removeAllListeners("SIGINT");`);
    assert.equal(repl, "allow");
    assert.equal(frames.filter((m) => m === "close_run").length, 1);   // at beforeExit only
  });

  it("closes its run at exit even when it may not list approvals", async () => {
    const [frames] = await child(`await tk.run.decide("c1", "echo", {});`,
      (f) => f.method === "approval_list" && { error: { code: "forbidden", message: "not granted" } });
    assert.equal(frames.at(-1), "close_run");
  });

  it("leaves its run open while an approved call waits to be resumed", async () => {
    const [frames] = await child(`await tk.run.decide("c1", "echo", {});`,
      (f) => f.method === "approval_list" && { approvals: f.state === "approved" ? [{ approval_id: "apr-1", state: "approved" }] : [] });
    assert.ok(!frames.includes("close_run"));
  });

  it("leaves its run open when approvals of it wait for a person, for another process to resume", async () => {
    const [frames] = await child(`await tk.run.decide("p1", "pay", {}); await tk.run.approvalRequest("p1");`);
    assert.deepEqual(frames.slice(0, 3), ["register_run", "decide", "approval_request"]);
    assert.ok(!frames.includes("close_run"));
  });
});
