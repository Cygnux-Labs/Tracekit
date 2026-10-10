#!/usr/bin/env node
// `npx @cygnux/tracekit up|down|status|view|verify|signer ...`: runs the Tracekit CLI that src/v2/launcher.ts finds.
// `verify BUNDLE --trust trust.json` (a v2 bundle) runs the TypeScript verifier instead, so it needs nothing else.
import { spawnSync } from "node:child_process";
import { INSTALL_HINT, signerCommand, signerEnv } from "../dist/v2/launcher.js";

const args = process.argv.slice(2);
if (args[0] === "verify" && args.includes("--trust")) {
  const { main } = await import("../dist/verify/cli.js");
  process.exit(await main(args.slice(1)));
}
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
