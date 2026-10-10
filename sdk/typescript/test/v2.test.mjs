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
  Client, Incompatible, RPCError, RPC_VERSION, SignerUnavailable, StrictJSONError, argsDigest, canonicalize, currentRun,
  defaultSigner, devRuntimeDir, strictParse, systemConfig, withRun,
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
  assert.equal(lines.length, 248);
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

// An in-test signer on a Unix socket: "pay" asks, "rm" is denied, everything else allowed; approvals are granted after
// 300 ms. `handle(frame)` may answer first. `frames` records each request with the number of its connection.
async function fake(t, { hello = { proto: [RPC_VERSION, RPC_VERSION], version: "test", pid: 1 }, failModes = { default: "closed" }, handle = () => null } = {}) {
  const path = join(tmp(t), "s.sock"), frames = [], socks = new Set();
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
        queue = queue.then(async () => sock.write(JSON.stringify(f.method === "hello" ? hello : (await handle(f)) || (await answer(f))) + "\n"));
      }
    });
  });
  await new Promise((r) => server.listen(path, r));
  const stop = () => new Promise((r) => { server.close(r); socks.forEach((s) => s.destroy()); });
  t.after(stop);
  return { client: new Client({ signer: path }), frames, stop };
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

test("fake: the fail mode of the tool class applies only while the signer is unreachable", async (t) => {
  const { client, stop } = await fake(t, { failModes: { default: "closed", net: "open" } });
  const run = await client.registerRun("a");
  await stop();
  const open = await run.decide("t1", "fetch", {}, { tool_class_hint: "net" });
  assert.deepEqual([open.decision, open.unavailable], ["allow", true]);
  const closed = await run.decide("t2", "Bash", {});
  assert.deepEqual([closed.decision, closed.unavailable], ["deny", true]);
  assert.equal(await run.complete("t1"), null);   // never throws
  await assert.rejects(client.registerRun("b"), SignerUnavailable);
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
