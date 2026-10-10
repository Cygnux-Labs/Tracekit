// bin/tracekit.mjs and src/v2/launcher.ts: PATH first, then the platform signer package, else an install hint and exit 1;
// the v2 client's dev auto-spawn runs the same command. Fake `tracekit`s are shell scripts.   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Client, SignerUnavailable } from "../dist/v2/client.js";
import { platformKey } from "../dist/v2/launcher.js";

const BIN = resolve(import.meta.dirname, "../bin/tracekit.mjs");
const POSIX = process.platform === "win32" ? "fake commands are shell scripts" : false;

function fixture(t) {
  const d = mkdtempSync("/tmp/tkl-");
  t.after(() => rmSync(d, { recursive: true, force: true }));
  const script = (path, body) => {
    mkdirSync(resolve(path, ".."), { recursive: true });
    writeFileSync(path, `#!/bin/sh\n${body}\n`);
    chmodSync(path, 0o755);
  };
  script(join(d, "path/tracekit"), 'echo "path $*"; exit 3');
  const pkg = join(d, `node_modules/@cygnux/tracekit-signer-${platformKey()}`);
  script(join(pkg, "python/bin/python3"), 'echo "pkg $*"');
  writeFileSync(join(pkg, "package.json"), "{}");
  mkdirSync(join(d, "self"));
  symlinkSync(BIN, join(d, "self/tracekit"));   // npm's .bin link to the launcher itself
  return d;
}

const launch = (env) => {
  const { TRACEKIT_PYTHON, NODE_PATH, ...rest } = process.env;
  return spawnSync(process.execPath, [BIN, "up", "--json"], { env: { ...rest, ...env }, encoding: "utf8" });
};

test("launcher: a tracekit on PATH wins, argv and exit code forwarded", { skip: POSIX || !platformKey() }, (t) => {
  const d = fixture(t);
  const r = launch({ PATH: join(d, "path"), NODE_PATH: join(d, "node_modules") });
  assert.equal(r.stdout, "path up --json\n");
  assert.equal(r.status, 3);
});

test("launcher: else the platform package's bundled Python, skipping npm's link to itself", { skip: POSIX || !platformKey() }, (t) => {
  const d = fixture(t);
  const r = launch({ PATH: join(d, "self"), NODE_PATH: join(d, "node_modules") });
  assert.equal(r.stdout, "pkg -m tracekit up --json\n");
  assert.equal(r.status, 0);
});

test("launcher: neither -> both install routes and exit 1", { skip: POSIX }, (t) => {
  const d = fixture(t);
  const r = launch({ PATH: join(d, "self") });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /pip install 'tracekit-ai\[signer\]'.*--omit=optional/s);
});

test("the v2 client's dev auto-spawn runs `tracekit up --json` from the launcher", { skip: POSIX }, async (t) => {
  const d = mkdtempSync("/tmp/tkl-"), saved = { ...process.env };
  t.after(() => {
    process.env = saved;
    rmSync(d, { recursive: true, force: true });
  });
  mkdirSync(join(d, "path"));
  writeFileSync(join(d, "path/tracekit"), `#!/bin/sh\necho "$*" >> ${d}/argv; exit 1\n`);
  chmodSync(join(d, "path/tracekit"), 0o755);
  process.env.PATH = join(d, "path");
  process.env.TRACEKIT_RUNTIME_DIR = join(d, "run");
  delete process.env.TRACEKIT_PYTHON;
  delete process.env.TRACEKIT_SIGNER;
  await assert.rejects(new Client().registerRun("a"), (e) => e instanceof SignerUnavailable && /tracekit up/.test(e.message));
  assert.match(readFileSync(join(d, "argv"), "utf8"), /^up --json$/m);
});
