/**
 * `npx @cygnux/tracekit verify BUNDLE --trust trust.json [--json] [--strict]`: the TypeScript verifier, with the reference
 * CLI's report and exit codes (0 verified, 1 failed, 2 unusable or unverifiable, 3 a warning under --strict).
 */
import { readFile } from "node:fs/promises";
import { EXIT_BAD, EXIT_OK, EXIT_WARN, formatReport, verify } from "./index.js";

const USAGE = "usage: tracekit verify BUNDLE --trust TRUST.json [--json] [--strict]";

export async function main(argv: string[]): Promise<number> {
  let bundle: string | undefined, trust: string | undefined, json = false, strict = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--trust" && i + 1 < argv.length) trust = argv[++i];
    else if (a === "--json") json = true;
    else if (a === "--strict") strict = true;
    else if (!a.startsWith("-") && bundle === undefined) bundle = a;
    else {
      console.error(`tracekit verify: ${a} is not supported by the TypeScript verifier (the format bridge, monitor reports `
        + `and revocations need the reference verifier: pip install tracekit)\n${USAGE}`);
      return EXIT_BAD;
    }
  }
  if (!bundle || !trust) {
    console.error(USAGE);
    return EXIT_BAD;
  }
  let data: [Uint8Array, Uint8Array];
  try {
    data = [await readFile(bundle), await readFile(trust)];
  } catch (e) {
    console.error(`tracekit verify: ${(e as Error).message}`);
    return EXIT_BAD;
  }
  const { report, code: verdict } = await verify(...data);
  const code = verdict === EXIT_OK && strict && report.warnings.length ? EXIT_WARN : verdict;
  if (json)
    console.log(JSON.stringify({ exit_code: code, checks: report.checks, failures: report.failures,
      warnings: report.warnings, integrity: report.integrity, assurance: report.assurance, notes: report.notes }, null, 2));
  else process.stdout.write(formatReport(report));
  return code;
}
