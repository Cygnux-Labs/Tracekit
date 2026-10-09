// End to end against a real dev signer: the TS SDK -> python bridge -> signer -> ledger, then `tracekit verify`.
// Model SDKs talk to a mocked fetch: no network, no keys.   npm test
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { Tracekit, TracekitDenied, instrumentOpenAI, instrumentAnthropic, tracekitMiddleware, instrumentStagehand } from "../dist/index.js";

const ROOT = resolve(import.meta.dirname, "../../..");
const PY = process.env.TRACEKIT_PYTHON ?? "python3";
const dir = mkdtempSync(join(tmpdir(), "tk-ts-"));
const home = join(dir, "signer");
const env = { TRACEKIT_CLIENT_HOME: join(dir, "client"), PYTHONPATH: ROOT };
const py = (code) => execFileSync(PY, ["-c", code], { env: { ...process.env, ...env }, encoding: "utf8" });

before(() => { py(`from tracekit import install; install.init_dev(${JSON.stringify(home)}, [], start=True)`); });
after(() => { py(`from tracekit import install; install.stop_dev_daemon(${JSON.stringify(home)})`); rmSync(dir, { recursive: true, force: true }); });

const events = (run) => JSON.parse(py(`
import json; from tracekit.ledger import read_records
print(json.dumps([r["event"] for _, r, _ in read_records(${JSON.stringify(join(home, "ledger", "ledger.jsonl"))}) if r and r["event"]["run_id"] == ${JSON.stringify(run)}]))`));

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const sse = (items) => new Response(items.map((x) => (x.type && !x.object ? `event: ${x.type}\n` : "") + `data: ${JSON.stringify(x)}\n\n`).join("") + "data: [DONE]\n\n",
  { status: 200, headers: { "content-type": "text/event-stream" } });

test("tools: allowed runs, denied never runs, errors are recorded", async () => {
  const tk = await Tracekit.start({ agent: "ts-bot", sessionId: "ts-tools", cwd: dir, env });
  const ran = [];
  assert.equal(await tk.tool("Bash", { command: "ls" }, () => { ran.push("ls"); return "a.txt"; }), "a.txt");
  await assert.rejects(tk.tool("Bash", { command: "sudo rm -rf /" }, () => { ran.push("sudo"); }), TracekitDenied);
  await assert.rejects(tk.tool("Read", { file_path: "/nope" }, () => { throw new Error("ENOENT"); }), /ENOENT/);
  await tk.end();
  assert.deepEqual(ran, ["ls"]);
  const evs = events("ts-tools");
  assert.deepEqual(evs.filter((e) => e.type === "policy.decision").map((e) => e.data.decision), ["allow", "deny", "allow"]);
  assert.deepEqual(evs.filter((e) => e.type === "tool.result").map((e) => e.data.ok), [true, false]);
  assert.equal(evs.at(-1).type, "run.end");
  assert.equal(evs[0].data.agent.name, "ts-bot");
});

test("OpenAI: create, streaming, tool-call ids link to executions, usage recorded", async () => {
  const tk = await Tracekit.start({ agent: "oa", sessionId: "ts-openai", cwd: dir, env });
  let n = 0;
  const fetch = async () => (n++ === 0
    ? json({ id: "c1", object: "chat.completion", created: 1, model: "gpt-4o-2026", usage: { prompt_tokens: 100, completion_tokens: 7, prompt_tokens_details: { cached_tokens: 60 } },
             choices: [{ index: 0, finish_reason: "tool_calls", message: { role: "assistant", content: null, tool_calls: [{ id: "call_x", type: "function", function: { name: "Bash", arguments: "{\"command\":\"pwd\"}" } }] } }] })
    : sse([{ id: "c2", object: "chat.completion.chunk", created: 1, model: "gpt-4o-2026", choices: [{ index: 0, delta: { content: "Hel" } }] },
           { id: "c2", object: "chat.completion.chunk", created: 1, model: "gpt-4o-2026", choices: [{ index: 0, delta: { content: "lo" }, finish_reason: "stop" }] },
           { id: "c2", object: "chat.completion.chunk", created: 1, model: "gpt-4o-2026", choices: [], usage: { prompt_tokens: 5, completion_tokens: 2 } }]));
  const client = instrumentOpenAI(new OpenAI({ apiKey: "sk-test-not-real", baseURL: "http://mock/v1", fetch, maxRetries: 0 }), tk);
  const r = await client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: "where am I" }] });
  const tc = r.choices[0].message.tool_calls[0];
  await tk.tool("Bash", JSON.parse(tc.function.arguments), () => "/home", { toolUseId: tc.id });
  let text = "";
  for await (const ch of await client.chat.completions.create({ model: "gpt-4o", messages: [], stream: true, stream_options: { include_usage: true } }))
    text += ch.choices[0]?.delta?.content ?? "";
  assert.equal(text, "Hello");
  await tk.end();
  const evs = events("ts-openai");
  const resp = evs.filter((e) => e.type === "model.exchange" && e.data.phase === "response").map((e) => e.data);
  assert.deepEqual(resp[0].tool_uses, [{ id: "call_x", name: "Bash" }]);
  assert.deepEqual([resp[0].usage.input_tokens, resp[0].usage.cache_read_tokens, resp[0].usage.output_tokens], [40, 60, 7]);
  assert.equal(evs.find((e) => e.type === "tool.call").data.tool_use_id, "call_x");
  assert.equal(resp[1].streamed, true);
  assert.equal(resp[1].stop_reason, "stop");
  assert.equal(resp[1].usage.output_tokens, 2);
  assert.ok(!JSON.stringify(evs).includes("sk-test-not-real"), "API key never recorded");
});

test("Anthropic: create and stream", async () => {
  const tk = await Tracekit.start({ agent: "an", sessionId: "ts-anthropic", cwd: dir, env });
  let n = 0;
  const fetch = async () => (n++ === 0
    ? json({ id: "m1", type: "message", role: "assistant", model: "claude-x-1", stop_reason: "tool_use", stop_sequence: null,
             content: [{ type: "tool_use", id: "toolu_1", name: "Read", input: {} }], usage: { input_tokens: 9, output_tokens: 3, cache_read_input_tokens: 100 } })
    : sse([{ type: "message_start", message: { id: "m2", type: "message", role: "assistant", model: "claude-x-1", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 4, output_tokens: 1 } } },
           { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
           { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "hi" } },
           { type: "content_block_stop", index: 0 },
           { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 6 } },
           { type: "message_stop" }]));
  const client = instrumentAnthropic(new Anthropic({ apiKey: "k", baseURL: "http://mock", fetch, maxRetries: 0 }), tk);
  await client.messages.create({ model: "claude-x", max_tokens: 10, messages: [{ role: "user", content: "hi" }] });
  for await (const _ of await client.messages.create({ model: "claude-x", max_tokens: 10, messages: [], stream: true })) { /* drain */ }
  await tk.end();
  const resp = events("ts-anthropic").filter((e) => e.type === "model.exchange" && e.data.phase === "response").map((e) => e.data);
  assert.deepEqual(resp[0].tool_uses, [{ id: "toolu_1", name: "Read" }]);
  assert.equal(resp[0].usage.cache_read_tokens, 100);
  assert.deepEqual([resp[1].stop_reason, resp[1].usage.input_tokens, resp[1].usage.output_tokens], ["end_turn", 4, 6]);
});

test("Vercel AI SDK middleware (v5 shapes) and a verifiable bundle", async () => {
  const tk = await Tracekit.start({ agent: "vercel", sessionId: "ts-vercel", cwd: dir, env });
  const mw = tracekitMiddleware(tk);
  const model = { provider: "openai.chat", modelId: "gpt-4o-mini" };
  await mw.wrapGenerate({ model, params: { prompt: [] }, doGenerate: async () => ({
    content: [{ type: "tool-call", toolCallId: "v1", toolName: "weather", input: "{}" }], finishReason: "tool-calls",
    usage: { inputTokens: 30, outputTokens: 5 } }) });
  const parts = [{ type: "text-delta", delta: "ok" }, { type: "finish", finishReason: "stop", usage: { inputTokens: 3, outputTokens: 1 } }];
  const { stream } = await mw.wrapStream({ model, params: {}, doStream: async () => ({ stream: new ReadableStream({ start(c) { parts.forEach((p) => c.enqueue(p)); c.close(); } }) }) });
  for await (const _ of stream) { /* drain */ }
  await tk.end();
  const resp = events("ts-vercel").filter((e) => e.type === "model.exchange" && e.data.phase === "response").map((e) => e.data);
  assert.deepEqual(resp[0].tool_uses, [{ id: "v1", name: "weather" }]);
  assert.equal(resp[0].upstream, "sdk:openai.chat:generate");
  assert.deepEqual([resp[1].stop_reason, resp[1].usage.output_tokens], ["stop", 1]);
  const out = join(dir, "v.tkb");
  py(`from tracekit import bundle; bundle.export(${JSON.stringify(home)}, ${JSON.stringify(out)}, run="ts-vercel")`);
  const code = py(`from tracekit import bundle; print(bundle.verify(${JSON.stringify(out)})[1])`).trim();
  assert.equal(code, "0");
  assert.ok(readFileSync(out).length > 0);
});

test("Stagehand: page actions are policy-checked steps", async () => {
  const tk = await Tracekit.start({ agent: "sh", sessionId: "ts-stagehand", cwd: dir, env });
  const ran = [];
  const page = instrumentStagehand({
    async act(i) { ran.push(i); return { success: true }; },
    async extract(i, o) { ran.push(i); return { title: "Docs" }; },
    async goto(u) { ran.push(u); },
  }, tk);
  assert.deepEqual(await page.act("click sign in"), { success: true });
  assert.deepEqual(await page.extract({ instruction: "get the title" }), { title: "Docs" });
  await page.goto("https://docs.example");
  await tk.end();
  assert.equal(ran.length, 3);
  const evs = events("ts-stagehand");
  assert.deepEqual(evs.filter((e) => e.type === "tool.call").map((e) => e.data.name), ["browser:act", "browser:extract", "browser:goto"]);
  assert.deepEqual(evs.filter((e) => e.type === "tool.result").map((e) => e.data.ok), [true, true, true]);
});

test("a recording failure after the wrapped call succeeded never throws over its result", async () => {
  const tk = await Tracekit.start({ agent: "nt", sessionId: "ts-no-throw", cwd: dir, env });
  const bridge = tk.bridge, call = bridge.call.bind(bridge);
  bridge.call = (op, args, t) => (op === "tool_end" || op === "model_end" ? Promise.reject(new Error("bridge hiccup")) : call(op, args, t));
  assert.equal(await tk.tool("Bash", { command: "ls" }, () => "a.txt"), "a.txt");
  const client = instrumentOpenAI(new OpenAI({ apiKey: "k", baseURL: "http://mock/v1", maxRetries: 0,
    fetch: async () => json({ id: "c1", object: "chat.completion", created: 1, model: "m", choices: [] }) }), tk);
  assert.equal((await client.chat.completions.create({ model: "m", messages: [] })).id, "c1");
  assert.equal(tk.recordFailures, 2);
  bridge.call = call;
  await tk.end();
});

test("bridge requests time out, and a bridge exit follows the fail mode (open: run unrecorded)", async () => {
  const tk = await Tracekit.start({ agent: "bx", sessionId: "ts-bridge-exit", cwd: dir, env });
  const bridge = tk.bridge;
  bridge.proc.kill("SIGSTOP");  // a bridge that stops answering
  await assert.rejects(bridge.call("ping", {}, 50), /timed out/);
  bridge.proc.kill("SIGCONT");
  bridge.proc.kill();
  await new Promise((res) => bridge.proc.once("exit", res));
  assert.equal(await tk.tool("Bash", { command: "ls" }, () => "ran"), "ran");
  await tk.end();
});

// Fake bridges: a `tracekit.bridge` module earlier on PYTHONPATH that answers start, then misbehaves per FAKE_MODE.
const fake = join(dir, "fake");
mkdirSync(join(fake, "tracekit"), { recursive: true });
writeFileSync(join(fake, "tracekit", "__init__.py"), "");
writeFileSync(join(fake, "tracekit", "bridge.py"), `
import json, os, sys, time
mode = os.environ["FAKE_MODE"]
def reply(o):
    sys.stdout.write(json.dumps(o) + "\\n"); sys.stdout.flush()
reply({"id": 0, "ok": True, "ready": True})
while True:
    line = sys.stdin.readline()
    if not line:
        break
    req = json.loads(line)
    if req["op"] == "start":
        reply({"id": req["id"], "ok": True, "run": "r1", "session_id": "s", "fail_mode": os.environ["FAKE_FAIL_MODE"]})
        if mode == "exit":
            os.read(0, 1)
            os._exit(0)
        if mode == "close":
            os.close(0)
            time.sleep(30)
    elif not (mode == "silent" and req["op"] in ("model_begin", "tool_begin")):
        reply({"id": req["id"], "ok": True})
`);
const fakeStart = (mode, failMode, timeoutMs) =>
  Tracekit.start({ timeoutMs, approvalTimeoutMs: timeoutMs, env: { PYTHONPATH: fake, FAKE_MODE: mode, FAKE_FAIL_MODE: failMode } });

for (const mode of ["exit", "close"]) {
  test(`a bridge that ${mode === "exit" ? "exits mid-write" : "closes its stdin"} never crashes the host; the call follows the fail mode`, async () => {
    const big = { data: "x".repeat(8_000_000) };
    const open = await fakeStart(mode, "open");
    assert.equal(await open.tool("Bash", big, () => "ran"), "ran");
    await open.end();
    const closed = await fakeStart(mode, "closed");
    const ran = [];
    await assert.rejects(closed.tool("Bash", big, () => ran.push(1)), TracekitDenied);
    assert.deepEqual(ran, []);
    await assert.rejects(closed.end(), TracekitDenied);
  });
}

test("a failed start does not leave the bridge running", () => {
  const code = `import { Tracekit } from ${JSON.stringify(resolve(import.meta.dirname, "../dist/index.js"))};
    await Tracekit.start({ sessionId: "x".repeat(300), env: ${JSON.stringify(env)} }).then(() => process.exit(3), () => console.log("rejected"));`;
  const out = execFileSync(process.execPath, ["--input-type=module", "-e", code], { encoding: "utf8", timeout: 20_000 });
  assert.equal(out.trim(), "rejected");  // and the process exited on its own (no timeout)
});

test("fail_mode=open: an unanswered model_begin lets the model call proceed unrecorded", async () => {
  const tk = await fakeStart("silent", "open", 200);
  const client = instrumentAnthropic({ messages: { create: async () => ({ content: [], stop_reason: "end_turn" }) } }, tk);
  assert.equal((await client.messages.create({ model: "m", messages: [] })).stop_reason, "end_turn");
  await assert.rejects(tk.tool("Bash", { command: "ls" }, () => "ran"), /timed out/);  // tool_begin still refuses
  await tk.end();
});
