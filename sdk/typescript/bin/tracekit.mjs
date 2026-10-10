#!/usr/bin/env node
// `npx @cygnux/tracekit up|down|status|view|verify|signer ...`: runs the Tracekit CLI that src/v2/launcher.ts finds.
import { spawnSync } from "node:child_process";
import { INSTALL_HINT, signerCommand } from "../dist/v2/launcher.js";

const cmd = signerCommand();
if (!cmd) {
  console.error(`tracekit: ${INSTALL_HINT}`);
  process.exit(1);
}
const r = spawnSync(cmd[0], [...cmd.slice(1), ...process.argv.slice(2)], { stdio: "inherit" });
if (r.error) {
  console.error(`tracekit: ${cmd[0]}: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status ?? 1);
