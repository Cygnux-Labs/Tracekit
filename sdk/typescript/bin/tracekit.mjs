#!/usr/bin/env node
// `npx @cygnuxlabs/tracekit up|down|status|view|verify|signer ...`: runs the Tracekit CLI that src/v2/launcher.ts finds.
// `verify BUNDLE --trust trust.json` (a v2 bundle) runs the TypeScript verifier instead, so it needs nothing else,
// unless an option only the Python verifier has is given.
import { spawnSync } from "node:child_process";
import { INSTALL_HINT, signerCommand, signerEnv } from "../dist/v2/launcher.js";

const args = process.argv.slice(2);
// the options only the Python verifier has (monitor reports, revocations, the v1 bridge) still go to it
const PYTHON_ONLY = ["--monitor-report", "--revocations", "--v1-ledger", "--v1-key"];
if (args[0] === "verify" && args.includes("--trust") && !args.some((a) => PYTHON_ONLY.includes(a.split("=")[0]))) {
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 20 || major === 20 && minor < 12) {   // the verifier's JSON imports and deflate-raw
    console.error(`tracekit verify: the TypeScript verifier needs Node >= 20.12 (this is ${process.versions.node})`);
    process.exit(2);
  }
  const { main } = await import("../dist/verify/cli.js");
  // not process.exit(): it would cut off a report still being written to a pipe (past 64 KiB)
  process.exitCode = await main(args.slice(1));
} else {
  const cmd = signerCommand();
  if (!cmd) {
    console.error(`tracekit: ${INSTALL_HINT}`);
    process.exit(1);
  }
  const r = spawnSync(cmd[0], [...cmd.slice(1), ...args], { stdio: "inherit", env: signerEnv(cmd) });
  if (r.error) {
    console.error(`tracekit: ${cmd[0]}: ${r.error.message}`);
    process.exit(1);
  }
  process.exit(r.status ?? 1);
}
