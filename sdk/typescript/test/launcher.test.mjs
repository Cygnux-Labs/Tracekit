// bin/tracekit.mjs and src/v2/launcher.ts: PATH first, then the platform signer package, else an install hint and exit 1;
// the v2 client's dev auto-spawn runs the same command. The launcher runs from a copy in a temp node_modules, so only
// the fake platform package can resolve. Fake `tracekit`s are shell scripts.   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Client, SignerUnavailable } from "../dist/v2/client.js";
import { platformKey } from "../dist/v2/launcher.js";

const SDK = resolve(import.meta.dirname, "..");
const POSIX = process.platform === "win32" ? "fake commands are shell scripts" : false;

function fixture(t, { platformPackage = true } = {}) {
  const d = mkdtempSync("/tmp/tkl-");
  t.after(() => rmSync(d, { recursive: true, force: true }));
  const script = (path, body) => {
    mkdirSync(resolve(path, ".."), { recursive: true });
    writeFileSync(path, `#!/bin/sh\n${body}\n`);
    chmodSync(path, 0o755);
  };
  const sdk = join(d, "node_modules/@cygnux/tracekit");
  mkdirSync(join(sdk, "bin"), { recursive: true });
  mkdirSync(join(sdk, "dist/v2"), { recursive: true });
  writeFileSync(join(sdk, "package.json"), '{"type": "module"}');
  copyFileSync(join(SDK, "bin/tracekit.mjs"), join(sdk, "bin/tracekit.mjs"));
  copyFileSync(join(SDK, "dist/v2/launcher.js"), join(sdk, "dist/v2/launcher.js"));
  const bin = join(sdk, "bin/tracekit.mjs");
  script(join(d, "path/tracekit"), 'echo "path $*"; exit 3');
  if (platformPackage) {
    const pkg = join(d, `node_modules/@cygnux/tracekit-signer-${platformKey()}`);
    script(join(pkg, "python/bin/python3"), 'echo "pkg $*"');
    writeFileSync(join(pkg, "package.json"), "{}");
  }
  mkdirSync(join(d, "self"));
  symlinkSync(bin, join(d, "self/tracekit"));   // npm's .bin link to the launcher itself
  script(join(d, "shim/tracekit"), `exec "${process.execPath}" "${bin}" "$@"`);   // pnpm's .bin shim
  mkdirSync(join(d, "node"));
  symlinkSync(process.execPath, join(d, "node/node"));   // for the launcher's `#!/usr/bin/env node`
  const launch = (...path) => {
    const { TRACEKIT_PYTHON, TRACEKIT_LAUNCHER_TRIED, NODE_PATH, ...env } = process.env;
    return spawnSync(process.execPath, [bin, "up", "--json"],
      { env: { ...env, PATH: [...path, "node"].map((p) => join(d, p)).join(":") }, encoding: "utf8", timeout: 10_000 });
  };
  return launch;
}

test("launcher: a tracekit on PATH wins, argv and exit code forwarded", { skip: POSIX || !platformKey() }, (t) => {
  const r = fixture(t)("path");
  assert.equal(r.stdout, "path up --json\n");
  assert.equal(r.status, 3);
});

test("launcher: else the platform package's bundled Python, looking past its own link and shim", { skip: POSIX || !platformKey() }, (t) => {
  const r = fixture(t)("self", "shim");
  assert.equal(r.stdout, "pkg -m tracekit up --json\n");
  assert.equal(r.status, 0);
});

test("launcher: a tracekit on PATH after its own shim still wins", { skip: POSIX || !platformKey() }, (t) => {
  const r = fixture(t)("shim", "path");
  assert.equal(r.stdout, "path up --json\n");
  assert.equal(r.status, 3);
});

test("launcher: neither -> both install routes and exit 1", { skip: POSIX }, (t) => {
  const r = fixture(t, { platformPackage: false })("self", "shim");
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
  delete process.env.TRACEKIT_LAUNCHER_TRIED;
  await assert.rejects(new Client().registerRun("a"), (e) => e instanceof SignerUnavailable && /tracekit up/.test(e.message));
  assert.match(readFileSync(join(d, "argv"), "utf8"), /^up --json$/m);
});
