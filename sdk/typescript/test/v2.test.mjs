// The native v2 client (src/v2): JCS against the shared vectors and Python, the RPC schemas against rpc_schema.py, a
// real dev signer started on demand, Python's TCP dev and HTTPS transports, and an in-test fake signer.   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import {
  Client, Incompatible, RPCError, RPC_VERSION, RunHandle, SignerUnavailable, StrictJSONError, argsDigest, canonicalize,
  currentRun, defaultSigner, devRuntimeDir, instrument, strictParse, systemConfig, withRun,
} from "../dist/v2/client.js";
import { REQUESTS } from "../dist/v2/rpc_schema.js";
import { validate } from "../dist/v2/validate.js";

const ROOT = resolve(import.meta.dirname, "../../..");
const PY = process.env.TRACEKIT_PYTHON ?? "python3";
const PY_ENV = { ...process.env, PYTHONPATH: ROOT };
const pyCan = (imports) => spawnSync(PY, ["-c", imports], { env: PY_ENV }).status === 0
  ? false : `needs ${PY} with ${imports.replace("import ", "")} (set TRACEKIT_PYTHON)`;
const NO_PY = pyCan("import tracekit.sdk.client");
const NO_PKI = NO_PY || pyCan("import cryptography");
const NO_SIGNER = NO_PKI || pyCan("from tracekit.policy2 import engine; engine._backend(None)");   // the [signer] extra
const py = (code, input) => spawnSync(PY, ["-c", code], { env: PY_ENV, input, encoding: "utf8" }).stdout;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = (t) => {
  const d = mkdtempSync("/tmp/tkv2-");   // short: macOS caps socket paths at 104 bytes
  t.after(() => rmSync(d, { recursive: true, force: true }));
  return d;
};

/** A Python server that prints one JSON line once it listens; stopped with the test. */
async function pyServer(t, code) {
  const p = spawn(PY, ["-c", code], { env: PY_ENV, stdio: ["pipe", "pipe", "inherit"] });
  t.after(() => p.kill());
  let out = "";
  for await (const d of p.stdout) if ((out += d).includes("\n")) break;
  return JSON.parse(out);
}

const PY_FAKE = `
import json, sys, threading
from tracekit.testing import FakeSigner
from tracekit.transport import answering_hello, hello
signer = FakeSigner()
def handle(identity, frame):
    return getattr(signer, frame.pop("method"))(frame)
handle = answering_hello(handle, hello())
def run(srv, info):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(json.dumps(info), flush=True)
    sys.stdin.read()
`;

test("JCS: every shared vector, byte for byte (tests/vectors/jcs.jsonl, the S4 vectors)", () => {
  const lines = readFileSync(join(ROOT, "tests/vectors/jcs.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(lines.length, 250);
  for (const v of lines) {
    if (v.error) {
      assert.throws(() => strictParse(v.input), (e) => e instanceof StrictJSONError && e.code === v.error, v.id);
    } else {
      const text = canonicalize(strictParse(v.input));
      assert.equal(text, v.canonical, v.id);
      assert.equal(createHash("sha256").update(text, "utf8").digest("hex"), v.sha256, v.id);
    }
  }
});

test("args digests equal Python's for the same inputs", { skip: NO_PY }, () => {
  const cases = [
    ["Bash", '{"command": "ls"}'],
    ["w", '{"b":1,"a":[1.0,2e3,"\\u00e9",{"\\ud83d\\ude00":null,"\\ue000":0}],"n":1e21,"m":-0.0,"s":"\\u2028/"}'],
    ["w", { x: [1, 2.5, { y: "z" }], "é": 1, "\uE000": 2, "😀": 3, f: 1e-7, big: 9007199254740991 }],
  ];
  const theirs = JSON.parse(py(`
import json, sys
from tracekit.format.canon import event_hash, loads_strict
print(json.dumps([event_hash({"tool": t, "args": loads_strict(a) if isinstance(a, str) else a}) for t, a in json.load(sys.stdin)]))`,
  JSON.stringify(cases)));
  assert.deepEqual(cases.map(([t, a]) => argsDigest(t, a)), theirs);
});

test("the request schemas are rpc_schema.py's", { skip: NO_PY }, () => {
  const theirs = JSON.parse(py("import json; from tracekit.signer import rpc_schema as s; print(json.dumps([s.RPC_VERSION, s.REQUESTS]))"));
  assert.deepEqual([RPC_VERSION, REQUESTS], theirs);
});

test("a real dev signer, started on demand: decide/complete, deny and continue, pipelined calls", { skip: NO_SIGNER }, async (t) => {
  const d = mkdtempSync("/tmp/tkv2-"), saved = { ...process.env };
  Object.assign(process.env, { TRACEKIT_RUNTIME_DIR: join(d, "run"), HOME: join(d, "home"), XDG_DATA_HOME: join(d, "data"), PYTHONPATH: ROOT, TRACEKIT_PYTHON: PY });
  delete process.env.TRACEKIT_SIGNER;
  t.after(() => {
    spawnSync(PY, ["-m", "tracekit", "down"], { env: process.env });
    process.env = saved;
    rmSync(d, { recursive: true, force: true });
  });
  const c = new Client();
  const run = await c.registerRun({ name: "ts-v2", version: "1" });
  assert.equal(c.hello.proto[1], RPC_VERSION);
  assert.equal((await run.decide("c1", "Bash", '{"command": "ls"}')).decision, "allow");
  assert.ok(await run.complete("c1", "ok", { result: "a.txt" }), "the signer accepted our args digest");
  const denied = await run.decide("c2", "Bash", { command: "sudo rm -rf /" });
  assert.equal(denied.decision, "deny");
  assert.ok(denied.rule_ids.length);
  const many = await Promise.all(Array.from({ length: 20 }, (_, i) => run.decide(`p${i}`, "Bash", { command: `echo ${i}` })));
  assert.deepEqual(many.map((x) => x.decision), Array(20).fill("allow"));
  assert.deepEqual(many.map((x) => x.run_seq), [...many.map((x) => x.run_seq)].sort((a, b) => a - b));
  await run.close();
  const { events } = await run.call("read", { limit: 1000 });
  assert.equal(events.filter((e) => e.type.includes("gap")).length, 0, JSON.stringify(events.map((e) => e.type)));
  await c.close();
});

test("a dev signer from before an upgrade is replaced, not a reason to fail every call", { skip: NO_SIGNER }, async (t) => {
  const d = mkdtempSync("/tmp/tkv2-"), saved = { ...process.env };
  Object.assign(process.env, { TRACEKIT_RUNTIME_DIR: join(d, "run"), HOME: join(d, "home"), XDG_DATA_HOME: join(d, "data"), PYTHONPATH: ROOT, TRACEKIT_PYTHON: PY });
  delete process.env.TRACEKIT_SIGNER;
  const old = spawn(PY, ["-m", "tracekit.testing", "--proto", `${RPC_VERSION - 2}-${RPC_VERSION - 1}`], { env: process.env, stdio: "ignore" });
  const exited = new Promise((r) => old.once("exit", r));
  t.after(() => {
    old.kill();
    spawnSync(PY, ["-m", "tracekit", "down"], { env: process.env });
    process.env = saved;
    rmSync(d, { recursive: true, force: true });
  });
  while (pyCan(`import json; assert json.load(open(${JSON.stringify(join(d, "run", "endpoint.json"))}))["pid"]`)) await sleep(50);   // a reason until it has a pid
  const c = new Client();
  await c.registerRun({ name: "ts-upgrade", version: "1" });
  assert.equal(c.hello.proto[1], RPC_VERSION);
  assert.notEqual(c.hello.pid, old.pid);
  await exited;
  await c.close();
});

test("TCP dev transport: mutual HMAC proof of the token (Python's server)", { skip: NO_PY }, async (t) => {
  const info = await pyServer(t, PY_FAKE + `
import os, tempfile
from tracekit.identity.token import DevToken
from tracekit.signer.rpc_schema import REQUESTS
from tracekit.transport.tcp_dev import TcpDevServer
ep = os.path.join(tempfile.mkdtemp(), "endpoint.json")
srv = TcpDevServer(ep, DevToken("dev", [*REQUESTS, "hello"], ttl_s=600), handle)
run(srv, json.load(open(ep)))`);
  const signer = `tcp://127.0.0.1:${info.port}`;
  process.env.TRACEKIT_SIGNER_TOKEN = info.token;
  t.after(() => delete process.env.TRACEKIT_SIGNER_TOKEN);
  const c = new Client({ signer });
  assert.equal((await c.call("status")).rpc_version, RPC_VERSION);
  const run = await c.registerRun("tcp");
  assert.equal((await run.decide("t1", "Bash", {})).decision, "allow");
  await c.close();
  process.env.TRACEKIT_SIGNER_TOKEN = "x".repeat(64);
  await assert.rejects(new Client({ signer }).call("status"), SignerUnavailable);
  await assert.rejects(new Client({ signer: "tcp://10.0.0.1:9" }).call("status"), /loopback/);
});

test("HTTPS: the bearer token file is re-read per call (Python's server)", { skip: NO_PKI }, async (t) => {
  const info = await pyServer(t, PY_FAKE + `
import os, tempfile
sys.path.insert(0, ${JSON.stringify(join(ROOT, "tests"))})
from test_identity_mtls import Pki
from tracekit.transport import http as tk_http
d = tempfile.mkdtemp()
pki, token = Pki(d), os.path.join(d, "bearer")
cert, key = pki.issue("server")
with open(token, "w") as f:
    f.write("t" * 40)
_, auths, tls = tk_http.configure({"listen": "127.0.0.1:0", "cert": cert, "key": key, "authenticators": ["token"], "token_file": token})
srv = tk_http.HttpServer(("127.0.0.1", 0), auths, tls, handle)
run(srv, {"port": srv.server_address[1], "ca": pki.path, "token": "t" * 40})`);
  const tokenFile = join(tmp(t), "token");
  writeFileSync(tokenFile, "wrong-token\n");
  Object.assign(process.env, { TRACEKIT_SIGNER_CA: info.ca, TRACEKIT_SIGNER_TOKEN_FILE: tokenFile });
  t.after(() => { delete process.env.TRACEKIT_SIGNER_CA; delete process.env.TRACEKIT_SIGNER_TOKEN_FILE; });
  const c = new Client({ signer: `https://127.0.0.1:${info.port}` });
  await assert.rejects(c.call("status"), (e) => e instanceof RPCError && e.code === "unauthenticated");
  writeFileSync(tokenFile, info.token + "\n");   // rotated
  assert.equal((await c.call("status")).rpc_version, RPC_VERSION);
  const run = await c.registerRun("https");
  assert.equal((await run.decide("h1", "Bash", '{"command": "ls"}')).decision, "allow");
  assert.ok(await run.complete("h1"));
});

test("HTTPS: TRACEKIT_API_KEY is the token, a token file wins over it, and no error status is asked for (Python's server)", { skip: NO_PKI }, async (t) => {
  const info = await pyServer(t, PY_FAKE + `
import os, tempfile
sys.path.insert(0, ${JSON.stringify(join(ROOT, "tests"))})
from test_identity_mtls import Pki
from tracekit.transport import http as tk_http
d = tempfile.mkdtemp()
pki, token = Pki(d), os.path.join(d, "bearer")
cert, key = pki.issue("server")
with open(token, "w") as f:
    f.write("t" * 40)
asked = []
class Handler(tk_http._Handler):
    def do_POST(self):
        asked.append(self.headers.get("Tracekit-Errors"))
        super().do_POST()
_, auths, tls = tk_http.configure({"listen": "127.0.0.1:0", "cert": cert, "key": key, "authenticators": ["token"], "token_file": token})
srv = tk_http.HttpServer(("127.0.0.1", 0), auths, tls, lambda i, f: {**handle(i, f), "asked": asked[-1]}, handler=Handler)
run(srv, {"port": srv.server_address[1], "ca": pki.path, "token": "t" * 40})`);
  const wrong = join(tmp(t), "wrong");
  writeFileSync(wrong, "wrong-token\n");
  Object.assign(process.env, { TRACEKIT_SIGNER_CA: info.ca, TRACEKIT_API_KEY: ` ${info.token}\n` });
  t.after(() => ["TRACEKIT_SIGNER_CA", "TRACEKIT_API_KEY", "TRACEKIT_SIGNER_TOKEN_FILE"].forEach((k) => delete process.env[k]));
  const c = new Client({ signer: `https://127.0.0.1:${info.port}` });
  const status = await c.call("status");
  assert.equal(status.rpc_version, RPC_VERSION);
  assert.equal(status.asked, null);   // the body says it all: a proxy in front sees 200 for a refusal and acts on none
  process.env.TRACEKIT_SIGNER_TOKEN_FILE = wrong;
  await assert.rejects(c.call("status"), (e) => e instanceof RPCError && e.code === "unauthenticated");
});

// An in-test signer on a Unix socket: "pay" asks, "rm" is denied, everything else allowed; approvals are granted after
// 300 ms. `handle(frame)` may answer first. `frames` records each request with the number of its connection.
async function fake(t, { hello = { proto: [RPC_VERSION, RPC_VERSION], version: "test", pid: 1 }, failModes = { default: "closed" }, handle = () => null, path = join(tmp(t), "s.sock"), timeoutMs } = {}) {
  const frames = [], socks = new Set();
  let seq = 0, conns = 0;
  const answer = async (f) => {
    switch (f.method) {
      case "register_run": return { run_id: "run-1", run_token: "tok-1", tenant: "default", tenant_attested: true, principal_attested: false, fail_modes: failModes };
      case "decide": return { decision: f.tool === "pay" ? "ask" : f.tool === "rm" ? "deny" : "allow", decision_id: `dec-${f.tool_call_id}`, rule_ids: f.tool === "rm" ? ["R1"] : [], run_seq: ++seq };
      case "approval_request": return { approval_id: "apr-1", state: "requested" };
      case "approval_wait": return sleep(300).then(() => ({ approval_id: f.approval_id, state: "approved" }));
      case "close_run": return { run_id: f.run_id, state: "closing", run_seq: ++seq };
      default: return { run_seq: ++seq };
    }
  };
  const server = createServer((sock) => {
    const conn = ++conns;
    let buf = "", queue = Promise.resolve();
    socks.add(sock);
    sock.on("close", () => socks.delete(sock));
    sock.on("error", () => {});
    sock.on("data", (d) => {
      buf += d;
      for (let n; (n = buf.indexOf("\n")) >= 0;) {
        const f = JSON.parse(buf.slice(0, n));
        buf = buf.slice(n + 1);
        if (f.method !== "hello") frames.push({ ...f, conn });
        queue = queue.then(async () => {
          const out = f.method === "hello" ? (typeof hello === "function" ? await hello(conn) : hello)
            : (await handle(f, sock)) || (await answer(f));
          if (!sock.destroyed) sock.write(JSON.stringify(out) + "\n");
        });
      }
    });
  });
  await new Promise((r) => server.listen(path, r));
  const stop = () => new Promise((r) => { server.close(r); socks.forEach((s) => s.destroy()); });
  t.after(stop);
  return { client: new Client({ signer: path, timeoutMs }), frames, stop, path };
}

test("fake: decide, complete, deny and continue; requests are validated before they are sent", async (t) => {
  const { client, frames } = await fake(t);
  const run = await client.registerRun("a");
  assert.equal((await run.decide("t1", "Bash", '{"command": "ls"}')).decision, "allow");
  await run.complete("t1", "ok");
  const complete = frames.find((f) => f.method === "complete");
  assert.equal(complete.decision_id, "dec-t1");
  assert.equal(complete.args_digest, argsDigest("Bash", { command: "ls" }));
  assert.deepEqual(await run.decide("t2", "rm", {}).then((d) => d.rule_ids), ["R1"]);
  assert.equal((await run.decide("t3", "Bash", {})).decision, "allow");
  await assert.rejects(run.decide("not an id", "Bash", {}), (e) => e instanceof RPCError && e.code === "invalid_request");
  assert.equal(frames.filter((f) => f.method === "decide").length, 3);
});

test("fake: a complete's result goes as the tool returned it, a model_receipts key and a URL included", async (t) => {
  const { client, frames } = await fake(t);
  const run = await client.registerRun("a");
  const planted = [{ path: "/w/model.safetensors", sha256: `sha256:${"0".repeat(64)}`, reported_by: "hook" }];
  for (const [id, result] of [["t1", { content: "x", model_receipts: planted }], ["t2", new URL("https://example.com/a")]]) {
    await run.decide(id, "mcp__fs__write", { path: "model.safetensors" });
    await run.complete(id, "ok", { result });
  }
  assert.deepEqual(frames.filter((f) => f.method === "complete").map((f) => f.result),
    [{ content: "x", model_receipts: planted }, "https://example.com/a"]);
});

test("fake: with TRACEKIT_EGRESS_PROXY, a run's id and token become its commands' proxy credentials, not the process's", async (t) => {
  const { client } = await fake(t);
  const saved = Object.fromEntries(["TRACEKIT_EGRESS_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
    .map((k) => [k, process.env[k]]));
  t.after(() => { for (const [k, v] of Object.entries(saved)) v === undefined ? delete process.env[k] : (process.env[k] = v); });
  delete process.env.TRACEKIT_EGRESS_PROXY;
  assert.deepEqual((await client.registerRun("a")).proxyEnv, {});
  process.env.TRACEKIT_EGRESS_PROXY = "https://egress:3128";
  const before = { ...process.env };
  const run = await client.registerRun("a");
  assert.deepEqual(process.env, before);
  const u = new URL(run.proxyEnv.HTTPS_PROXY);
  assert.deepEqual([u.host, decodeURIComponent(u.username), decodeURIComponent(u.password), run.proxyEnv.http_proxy],
    ["egress:3128", run.runId, run.runToken, u.href]);
});

test("fake: ask, then the approval wait holds up no other call", async (t) => {
  const { client, frames } = await fake(t);
  const run = await client.registerRun("a");
  assert.equal((await run.decide("t1", "pay", { amount: 1 })).decision, "ask");
  const { approval_id } = await run.approvalRequest("t1", { reason: "pay the invoice" });
  let waited = false;
  const wait = run.approvalWait(approval_id, 5000).then((r) => ((waited = true), r));
  assert.equal((await run.decide("t2", "Bash", {})).decision, "allow");
  assert.equal(waited, false);
  assert.equal((await wait).state, "approved");
  const conn = (m) => frames.find((f) => f.method === m).conn;
  assert.notEqual(conn("approval_wait"), conn("decide"));
});

test("fake: approvalConsume sends the hint only when given, args_source by the args' type, and never rejects", async (t) => {
  const refused = { error: { code: "forbidden", message: "r".repeat(1100) } };
  const replies = { t1: { ok: true, rule_ids: [], args: { amount: 1, currency: "USD" } }, t2: { ok: true, rule_ids: [] },
    t3: refused, t4: { ok: false, rule_ids: ["R1"], reason: "x" } };
  const { client, frames, stop } = await fake(t, { handle: (f) => f.method === "approval_consume" && replies[f.tool_call_id] });
  const run = await client.registerRun("a");
  const warnings = [], seen = (w) => warnings.push(w.message);
  process.on("warning", seen);
  t.after(() => process.off("warning", seen));
  assert.equal((await run.decide("t1", "pay", { amount: 1 })).decision, "ask");
  const { approval_id } = await run.approvalRequest("t1");
  assert.equal((await run.approvalWait(approval_id, 5000)).state, "approved");
  assert.deepEqual(await run.approvalConsume("t1", "pay", { amount: 1 }, approval_id, { attempt: 1 }), replies.t1);   // T2: the args to run
  assert.equal((await run.decide("t2", "Bash", '{"command": "ls"}')).decision, "allow");
  assert.deepEqual(await run.approvalConsume("t2", "Bash", '{"command": "ls"}'), replies.t2);
  assert.deepEqual(await run.approvalConsume("t2", "Bash", '{"command": "ls"}', ""), replies.t2);   // an empty hint is none
  const sent = frames.filter((f) => f.method === "approval_consume");
  assert.deepEqual(sent.map((f) => [f.tool_call_id, f.tool, f.args, f.args_source, f.approval_id_hint, f.attempt, f.run_id]),
    [["t1", "pay", { amount: 1 }, "parsed", "apr-1", 1, "run-1"], ["t2", "Bash", '{"command": "ls"}', "raw", undefined, undefined, "run-1"],
      ["t2", "Bash", '{"command": "ls"}', "raw", undefined, undefined, "run-1"]]);
  assert.deepEqual(await run.approvalConsume("t4", "Bash", {}), replies.t4);   // the signer's own refusal, as sent
  const c = await run.approvalConsume("t3", "Bash", {});   // refused: ok false, the reason cut to the contract's 1024
  assert.deepEqual([c.ok, c.rule_ids, c.reason.length, c.reason.startsWith("approval_consume failed: forbidden: rrr")], [false, [], 1024, true]);
  await stop();
  const down = await run.approvalConsume("t2", "Bash", {});
  assert.deepEqual([down.ok, down.rule_ids], [false, []]);
  assert.match(down.reason, /^approval_consume failed: /);
  await sleep(10);   // warnings are emitted on the next tick
  assert.equal(warnings.filter((m) => m.includes("Bash is blocked: approval_consume failed")).length, 2, warnings);
});

test("fake: approvalConsume refuses, never rejects, when the signer is incompatible", async (t) => {
  const { client } = await fake(t, { hello: { proto: [RPC_VERSION + 1, RPC_VERSION + 1], version: "test", pid: 1 } });
  const run = new RunHandle(client, { run_id: "run-1", run_token: "tok-1" });
  const warnings = [], seen = (w) => warnings.push(w.message);
  process.on("warning", seen);
  t.after(() => process.off("warning", seen));
  const c = await run.approvalConsume("t1", "Bash", {});
  assert.deepEqual([c.ok, c.rule_ids], [false, []]);
  assert.match(c.reason, /^approval_consume failed: the Tracekit signer test \(pid 1, protocol \[\d+,\d+\]\) at .* cannot serve this client/);
  await sleep(10);
  assert.equal(warnings.filter((m) => m.startsWith("tracekit: Bash is blocked: approval_consume failed: the Tracekit signer test")).length, 1, warnings);
});

test("fake: the fail mode of the tool class applies only while the signer is unreachable", async (t) => {
  const { client, stop, path } = await fake(t, { failModes: { default: "closed", net: "open" } });
  const run = await client.registerRun("a");
  await stop();
  const open = await run.decide("t1", "fetch", {}, { tool_class_hint: "net" });
  assert.deepEqual([open.decision, open.unavailable], ["allow", true]);
  const closed = await run.decide("t2", "Bash", {});
  assert.deepEqual([closed.decision, closed.unavailable], ["deny", true]);
  assert.equal(await run.complete("t1"), null);   // never throws
  await assert.rejects(client.registerRun("b"), SignerUnavailable);
  const back = await fake(t, { path });   // the decides the signer never saw used up client_seq 0-1: its gap covers them
  await run.decide("t3", "Bash", {});
  assert.deepEqual(back.frames.filter((f) => f.method === "decide").map((f) => f.client_seq), [2]);
});

test("fake: close_run names the last client_seq used, even one lost while the signer was down", async (t) => {
  const { client, stop, path } = await fake(t);
  const run = await client.registerRun("a");
  await run.decide("t1", "Bash", {});
  await stop();
  assert.equal(await run.complete("t1"), null);   // client_seq 1, never received
  const back = await fake(t, { path });
  await run.close();
  const close = back.frames.find((f) => f.method === "close_run");
  assert.deepEqual(close.last_client_seq, [{ stream: client.stream, client_seq: 1 }]);
});

test("fake: a refusal is never fail-open", async (t) => {
  const { client } = await fake(t, { failModes: { default: "open" }, handle: (f) => f.method === "decide" && { error: { code: "forbidden", message: "no" } } });
  const run = await client.registerRun("a");
  await assert.rejects(run.decide("t1", "Bash", {}), (e) => e instanceof RPCError && e.code === "forbidden");
});

test("fake: pipelined calls share one connection and are answered in order", async (t) => {
  const { client, frames } = await fake(t, { handle: (f) => f.method === "decide" && sleep(Math.random() * 5).then(() => null) });
  const run = await client.registerRun("a");
  const ds = await Promise.all(Array.from({ length: 50 }, (_, i) => run.decide(`p${i}`, "Bash", {})));
  assert.deepEqual(ds.map((d) => d.decision_id), ds.map((_, i) => `dec-p${i}`));
  const decides = frames.filter((f) => f.method === "decide");
  assert.equal(new Set(frames.map((f) => f.conn)).size, 1);
  assert.deepEqual(decides.map((f) => f.client_seq), decides.map((_, i) => i));
  assert.equal(new Set(decides.map((f) => f.stream)).size, 1);
});

test("fake: a request that is not JSON takes no answer and no client_seq", async (t) => {
  const { client, frames } = await fake(t);
  const run = await client.registerRun("a");
  await assert.rejects(run.decide("t1", "Bash", { n: 10n }), (e) => e instanceof RPCError && e.code === "invalid_request");
  const [other, mine] = await Promise.all([run.decide("t2", "Bash", {}), run.decide("t3", "rm", {})]);
  assert.deepEqual([other.decision_id, mine.decision_id, mine.decision], ["dec-t2", "dec-t3", "deny"]);
  assert.deepEqual(frames.filter((f) => f.method === "decide").map((f) => f.client_seq), [0, 1]);
});

/** A Client of an HTTPS signer whose requests `answer(frame)` answers, in place of the network. */
function https(answer, timeoutMs) {
  const c = new Client({ signer: "https://signer.test:8443", timeoutMs });
  c.https.post = async (f, ms, reportedMs) =>
    (f.method === "hello" ? { proto: [RPC_VERSION, RPC_VERSION], version: "test", pid: 1 } : answer(f, ms, reportedMs));
  return c;
}
const event = (run_id, tool_call_id) => ({ run_id, run_token: "t", tool_call_id, tool: "Bash", args: {}, args_source: "parsed" });

test("HTTPS: a run's events reach the signer in client_seq order", async () => {
  const arrived = { r0: [], r1: [] };
  const c = https(async (f) => {
    await sleep(Math.random() * 5);   // the network: requests sent in order may arrive out of it
    arrived[f.run_id].push(f.client_seq);
    return { ok: true };
  });
  await Promise.all(Array.from({ length: 40 }, (_, i) => c.call("decide", event(`r${i % 2}`, `c${i}`))));
  assert.deepEqual(arrived, { r0: [...Array(20).keys()], r1: [...Array(20).keys()] });
});

test("HTTPS: an event call refused by a rate limit or an outage is sent again as it was, and no other call is", async () => {
  const base = { run_id: "r1", run_token: "t" }, digest = "sha256:" + "0".repeat(64);
  const events = {
    decide: { tool_call_id: "c1", tool: "Bash", args_source: "parsed", args: {} },
    complete: { tool_call_id: "c1", decision_id: "dec-1", args_digest: digest, status: "ok" },
    observe: { source: "mail", trust: "untrusted", value: "a mail" },
    state_write: { key: "k", value_digest: digest },
    model_event: { provider: "openai", model: "m", phase: "request" },
  };
  const limit = { code: "quota_exceeded", message: "event rate limit", retry_after_ms: 5 };
  for (const [method, fields] of Object.entries(events)) {
    for (const refusal of [limit, { code: "unavailable", message: "storage refused writes", retry_after_ms: 10 }]) {
      const sent = [];
      const c = https(async (f) => (sent.push(f), sent.length === 1 ? { error: refusal } : { run_seq: 1 }));
      assert.deepEqual(await c.call(method, { ...base, ...fields }), { run_seq: 1 }, method);
      assert.equal(sent.length, 2, method);
      assert.deepEqual(sent[1], sent[0], method);   // its request_id, stream and client_seq
    }
  }
  const size = { code: "quota_exceeded", message: "string longer than 1048576 characters" };   // never fits
  for (const [method, fields, refusal] of [["register_run", { agent: { name: "a" } }, limit], ["close_run", base, limit],
    ["approval_request", { ...base, tool_call_id: "c1" }, limit], ["decide", { ...base, ...events.decide }, size]]) {
    const sent = [];
    const c = https(async (f) => (sent.push(f), { error: refusal }));
    await assert.rejects(c.call(method, fields), (e) => e instanceof RPCError && e.code === refusal.code);
    assert.equal(sent.length, 1, method);
  }
});

test("HTTPS: refusals and lost connections are counted apart; a retry refused as recorded is the first try's outage", async () => {
  const limit = { error: { code: "quota_exceeded", message: "event rate limit", retry_after_ms: 5 } };
  const outage = { error: { code: "unavailable", message: "storage refused writes" } };
  const reused = { error: { code: "client_seq_reused", message: "s/0" } };
  const decide = (answers) => {
    const sent = [];
    const c = https(async (f) => {
      sent.push(f);
      const a = answers.shift();   // "lost": the client's own post to a port nothing listens on
      return a !== "lost" ? a : Object.getPrototypeOf(c.https).post.call(
        { url: new URL("https://127.0.0.1:1/v2/rpc"), agent: c.https.agent }, f, 1000);
    });
    return { sent, call: c.call("decide", event("r1", "c1")) };
  };
  // two rate limits and a lost connection are not three lost connections: the refusals that run out are the signer's
  const mixed = decide([limit, limit, "lost", limit]);
  await assert.rejects(mixed.call, (e) => e instanceof RPCError && e.code === "quota_exceeded");
  assert.equal(mixed.sent.length, 4);
  assert.equal(new Set(mixed.sent.map((f) => `${f.request_id}/${f.stream}/${f.client_seq}`)).size, 1);
  await assert.rejects(decide([outage, reused]).call,
    (e) => e instanceof RPCError && e.code === "unavailable" && e.message === "unavailable: storage refused writes");
  await assert.rejects(decide([reused]).call, (e) => e instanceof RPCError && e.code === "client_seq_reused");
});

test("HTTPS: an event waiting behind an unanswered one gives up in time and uses its client_seq", async () => {
  const arrived = [];
  const c = https(async (f) => {
    arrived.push(f.client_seq);
    if (f.tool_call_id === "slow") await sleep(600);
    return { ok: true };
  }, 200);
  const slow = c.call("decide", event("r1", "slow"));
  const t = Date.now();
  await assert.rejects(c.call("decide", event("r1", "waits")), SignerUnavailable);
  assert.ok(Date.now() - t < 500);
  await slow;
  await c.call("decide", event("r1", "next"));
  assert.deepEqual(arrived, [0, 2]);   // 1, the call that gave up, is the signer's client_counter_gap
});

test("HTTPS: a lost connection past the call's timeout is not retried and names the call's timeout", async (t) => {
  const postTo = (c, port, f, ms, reportedMs) => Object.getPrototypeOf(c.https).post.call(
    { url: new URL(`https://127.0.0.1:${port}/v2/rpc`), agent: c.https.agent }, f, ms, reportedMs);
  const socks = new Set(), drop = createServer((s) => s.destroy()), hung = createServer((s) => { socks.add(s); });
  await Promise.all([new Promise((r) => drop.listen(0, "127.0.0.1", r)), new Promise((r) => hung.listen(0, "127.0.0.1", r))]);
  t.after(() => { drop.close(); hung.close(); socks.forEach((s) => s.destroy()); });
  const sent = [];
  const c = https(async (f) => {
    sent.push(f);
    await sleep(600);
    return postTo(c, drop.address().port, f, 1000);
  }, 500);
  let start = Date.now();
  await assert.rejects(c.call("status"),
    (e) => e instanceof SignerUnavailable && e.message === "no answer from the signer within 0.5s");
  assert.ok(Date.now() - start < 1000);
  assert.deepEqual(sent.map((f) => f.method), ["status"]);

  let tries = 0;
  const c2 = https(async (f, ms, reportedMs) => {
    if (++tries === 1) {
      await sleep(200);
      return postTo(c2, drop.address().port, f, 1000);
    }
    return postTo(c2, hung.address().port, f, ms, reportedMs);
  }, 500);
  start = Date.now();
  await assert.rejects(c2.call("status"),
    (e) => e instanceof SignerUnavailable && e.message === "no answer from the signer within 0.5s");
  assert.ok(Date.now() - start < 1000);
  assert.equal(tries, 2);
});

test("fake: a retry after a lost connection stays within the call's timeout", async (t) => {
  const { client, frames } = await fake(t, {
    timeoutMs: 500,
    hello: async (conn) => {
      if (conn > 1) await sleep(1500);
      return { proto: [RPC_VERSION, RPC_VERSION], version: "test", pid: 1 };
    },
    handle: (_f, sock) => { sock.destroy(); },
  });
  const start = Date.now();
  await assert.rejects(client.call("status"), SignerUnavailable);
  assert.ok(Date.now() - start < 1000);
  assert.deepEqual(frames.map((f) => f.method), ["status"]);
});

test("TCP dev transport: a retry after a lost connection stays within the call's timeout", { skip: NO_PY }, async (t) => {
  const info = await pyServer(t, `
import contextlib, json, os, socket, sys, tempfile, threading, time
from tracekit.identity.token import DevToken
from tracekit.signer.rpc_schema import REQUESTS
from tracekit.transport import hello
from tracekit.transport.tcp_dev import TcpDevServer
d = tempfile.mkdtemp()
ep, frames = os.path.join(d, "endpoint.json"), os.path.join(d, "frames.jsonl")
tok = DevToken("dev", [*REQUESTS, "hello"], ttl_s=600)
local, hellos = threading.local(), 0
class Tok:
    secret = tok.secret
    @staticmethod
    def authenticate(conn, frame):
        local.conn = conn
        return tok.authenticate(conn, frame)
def handle(_, frame):
    global hellos
    if frame["method"] == "hello":
        hellos += 1
        if hellos > 1:
            time.sleep(1.5)
        return hello()
    with open(frames, "a") as f:
        f.write(json.dumps(frame) + "\\n")
    with contextlib.suppress(OSError):
        local.conn.shutdown(socket.SHUT_RDWR)
    local.conn.close()
    return {}
srv = TcpDevServer(ep, Tok, handle)
threading.Thread(target=srv.serve_forever, daemon=True).start()
print(json.dumps({**json.load(open(ep)), "frames": frames}), flush=True)
sys.stdin.read()`);
  process.env.TRACEKIT_SIGNER_TOKEN = info.token;
  t.after(() => delete process.env.TRACEKIT_SIGNER_TOKEN);
  const c = new Client({ signer: `tcp://127.0.0.1:${info.port}`, timeoutMs: 500 });
  const start = Date.now();
  await assert.rejects(c.call("status"), SignerUnavailable);
  assert.ok(Date.now() - start < 1000);
  const seen = readFileSync(info.frames, "utf8").trim().split("\n").map((l) => JSON.parse(l).method);
  assert.deepEqual(seen, ["status"]);
});

test("fake: a signer of another protocol version is refused", async (t) => {
  const { client } = await fake(t, { hello: { proto: [RPC_VERSION + 1, RPC_VERSION + 2], version: "9.9.9", pid: 7 } });
  await assert.rejects(client.registerRun("a"), (e) => e instanceof Incompatible && /9\.9\.9/.test(e.message));
});

test("fake: flush() waits for calls and waitUntil promises; close() drains", async (t) => {
  const { client } = await fake(t, { handle: (f) => f.method === "decide" && sleep(50).then(() => null) });
  const run = await client.registerRun("a");
  let done = 0;
  for (let i = 0; i < 3; i++) run.decide(`f${i}`, "Bash", {}).then(() => done++);
  client.waitUntil(sleep(120).then(() => done++));
  await client.flush();
  assert.equal(done, 4);
  run.complete("f0").then(() => done++);
  await client.close();
  assert.equal(done, 5);
});

test("withRun / currentRun", async (t) => {
  const { client } = await fake(t);
  const run = await client.registerRun("a");
  await withRun(run, async () => {
    await sleep(1);
    assert.equal(currentRun(), run);
  });
  assert.equal(currentRun(), undefined);
});

test("system mode: its signer wins and another TRACEKIT_SIGNER is refused", (t) => {
  const system = { signer: "/run/tracekit/signer.sock" };
  assert.throws(() => defaultSigner({ TRACEKIT_SIGNER: "/tmp/mine.sock" }, system), /refused/);
  assert.equal(defaultSigner({ TRACEKIT_SIGNER: system.signer }, system), system.signer);
  assert.equal(defaultSigner({}, system), system.signer);
  assert.equal(defaultSigner({ TRACEKIT_SIGNER: "/tmp/mine.sock" }, null), "/tmp/mine.sock");
  const cfg = join(tmp(t), "client.json");
  assert.equal(systemConfig(cfg), null);
  writeFileSync(cfg, JSON.stringify(system));
  if (process.getuid?.() !== 0) assert.throws(() => systemConfig(cfg), /owned by root/);   // the agent's own file is not trusted
  assert.throws(() => devRuntimeDir(cfg), /system mode/);   // a config without `signer` still rules out a same-user dev signer
  assert.equal(typeof devRuntimeDir(join(tmp(t), "absent.json")), "string");
});

test("the validator refuses schema keywords it does not implement", () => {
  assert.deepEqual(validate({ type: "string" }, "x"), []);
  assert.throws(() => validate({ allOf: [] }, "x"), /unsupported schema keywords at \$: allOf/);
});

test("an identity takes every character the signer's Python takes: a line feed is the only one refused", () => {
  const caller = REQUESTS.decide.properties.caller;
  for (const id of ["uid:990102\r x", "uid:a b", "uid:a b"]) assert.deepEqual(validate(caller, id), [], id);
  assert.notDeepEqual(validate(caller, "uid:a\nb"), []);
});

test("HTTPS: an id with a central replica's route goes to that replica, others to the signer", async () => {
  const { routeUrl } = await import("../dist/v2/client.js");
  const base = new URL("https://tracekit-signer.tk.svc:8443/v2/rpc");
  assert.equal(routeUrl(base, { run_id: "tracekit-signer-2.abc" }).href, "https://tracekit-signer-2.tk.svc:8443/v2/rpc");
  assert.equal(routeUrl(base, { approval_id: "tracekit-signer-0.x" }).hostname, "tracekit-signer-0.tk.svc");
  assert.equal(routeUrl(base, { parent: { run_id: "tracekit-signer-3.y", run_token: "t" } }).hostname, "tracekit-signer-3.tk.svc");
  for (const id of ["abc", "other-2.abc", "tracekit-signer-x.abc", "tracekit-signer-2"])
    assert.equal(routeUrl(base, { run_id: id }), base, id);
});

test("fake: a long-lived run remembers no denied call, and at most 4096 others", async (t) => {
  const { client } = await fake(t);
  const run = await client.registerRun("a");
  for (let i = 0; i < 20; i++) await run.decide(`d${i}`, "rm", {});   // denied: never completed
  assert.equal(run.decided.size, 0);
  for (let i = 0; i < 4100; i++) await run.decide(`a${i}`, "pay", {});   // asked, never approved
  assert.equal(run.decided.size, 4096);
});

test("fake: a call refused as closed while its run closes registers no new run", async (t) => {
  const { client, frames } = await fake(t, {
    handle: (f) => f.method === "decide" ? sleep(100).then(() => ({ error: { code: "run_closed", message: "run-1" } })) : null,
  });
  const run = await client.registerRun("a");
  run.renewAs = "a";   // as instrument()'s process run
  const late = run.decide("t1", "Bash", {});
  await run.close();
  await assert.rejects(late, (e) => e instanceof RPCError && e.code === "run_closed");
  assert.equal(frames.filter((f) => f.method === "register_run").length, 1);
});

test("instrument() rejects, never throws, when its client can't be built", async () => {
  const before = process.env.TRACEKIT_SIGNER_CA;
  process.env.TRACEKIT_SIGNER_CA = "/nonexistent/ca.pem";
  try {
    let threw = false, p;
    try { p = instrument("a", { signer: "https://127.0.0.1:9" }); } catch { threw = true; }
    assert.equal(threw, false);
    await assert.rejects(p);
  } finally {
    if (before === undefined) delete process.env.TRACEKIT_SIGNER_CA; else process.env.TRACEKIT_SIGNER_CA = before;
  }
});
