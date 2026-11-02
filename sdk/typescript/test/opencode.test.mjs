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

// a hook process as Bun.spawn returns it: exit(code) ends it, as kill(signal) does (exit code null)
function hookProcess() {
  let exit;
  const hook = {
    exitCode: null,
    killed: null,
    stderr: new Uint8Array(),
    exited: new Promise((resolve) => { exit = resolve; }),
    exit: (code) => { hook.exitCode = code; exit(code); },
    kill: (signal) => { hook.killed = signal; exit(null); },
  };
  return hook;
}

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
      globalThis.Bun = { spawn: () => {
        if (exitCode instanceof Error) throw exitCode;
        const hook = hookProcess();
        hook.exit(exitCode);
        return hook;
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

  await t.test("parallel calls are decided at once, not one after another", async () => {
    const started = [];
    globalThis.Bun = { spawn: () => { const hook = hookProcess(); started.push(hook); return hook; } };
    const calls = ["a", "b"].map((callID) =>
      hooks["tool.execute.before"]({ tool: "bash", sessionID: "opencode-test", callID }, { args: { command: "ls" } }));
    assert.equal(started.length, 2);   // the second hook runs while the first still decides
    started.forEach((hook) => hook.exit(0));
    await Promise.all(calls);
  });

  await t.test("a hook that never answers is killed after 600 s and its call blocked", async (st) => {
    st.mock.timers.enable({ apis: ["setTimeout"] });
    const hook = hookProcess();
    globalThis.Bun = { spawn: () => hook };
    const call = hooks["tool.execute.before"]({ tool: "bash", sessionID: "opencode-test", callID: "hung" },
      { args: { command: "ls" } });
    st.mock.timers.tick(599_999);
    assert.equal(hook.killed, null);   // above the hook's 540 s approval wait: a held call still gets its answer
    st.mock.timers.tick(1);
    assert.equal(hook.killed, "SIGKILL");
    await assert.rejects(call, /did not answer in 600 s/);
  });
});
