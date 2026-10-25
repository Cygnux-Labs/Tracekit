// Run the generated OpenCode plugin under Node with Bun's process API stood in.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(import.meta.dirname, "../../..");
const PY = process.env.TRACEKIT_PYTHON ?? "python3";

test("OpenCode: the generated plugin refuses undecided calls and its after hook never throws", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "tk-opencode-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const generated = spawnSync(PY, ["-c",
    "from tracekit.agent_hooks import _opencode_plugin; print(_opencode_plugin(None, False))"],
  { env: { ...process.env, PYTHONPATH: ROOT }, encoding: "utf8" });
  assert.equal(generated.status, 0, generated.stderr || generated.error?.message);
  const path = join(dir, "tracekit.mjs");
  writeFileSync(path, generated.stdout);
  const { TracekitPlugin } = await import(pathToFileURL(path).href);
  const hooks = await TracekitPlugin({ directory: dir });
  const bun = globalThis.Bun;
  t.after(() => { globalThis.Bun = bun; });
  t.mock.method(console, "error", () => {});

  for (const [name, exitCode] of [
    ["exit 0", 0], ["exit 2", 2], ["exit 1", 1], ["signal", null], ["spawn throws", new Error("spawn failed")],
  ]) {
    await t.test(name, async () => {
      globalThis.Bun = { spawnSync: () => {
        if (exitCode instanceof Error) throw exitCode;
        return { exitCode, stderr: new Uint8Array() };
      } };
      const input = { tool: "bash", sessionID: "opencode-test", callID: name };
      const args = { command: "echo allowed" };
      let ran = false;
      const execute = async () => {
        await hooks["tool.execute.before"](input, { args });
        ran = true;
      };
      if (exitCode === 0) await assert.doesNotReject(execute);
      else await assert.rejects(execute);
      assert.equal(ran, exitCode === 0);
      await assert.doesNotReject(() => hooks["tool.execute.after"]({ ...input, args }, { output: "done" }));
    });
  }
});
