/**
 * `npx @cygnuxlabs/tracekit verify BUNDLE --trust trust.json [--json] [--strict]`: the TypeScript verifier, with the reference
 * CLI's report and exit codes (0 verified, 1 failed, 2 unusable or unverifiable, 3 a warning under --strict).
 */
import { readFile } from "node:fs/promises";
import { getSystemErrorMap } from "node:util";
import { asJson } from "./explain.js";
import { EXIT_BAD, EXIT_OK, EXIT_WARN, Report, TRUST_UNUSABLE, formatReport, verify } from "./index.js";

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
        + `and revocations need the reference verifier: pip install tracekit-ai)\n${USAGE}`);
      return EXIT_BAD;
    }
  }
  if (!bundle || !trust) {
    console.error(USAGE);
    return EXIT_BAD;
  }
  // a file that can't be read: its path and the system's reason, in the report the reference CLI prints for it
  const read = (path: string) => readFile(path).catch((e: NodeJS.ErrnoException) =>
    `${path}: ${(getSystemErrorMap().get(e.errno ?? 0)?.[1] ?? e.message).replace(/^./, (c) => c.toUpperCase())}`);
  const b = await read(bundle), t = await read(trust);
  let report = new Report(), verdict = EXIT_BAD;
  if (typeof t === "string") {
    report.integrity = TRUST_UNUSABLE;
    report.check("trust config", false, t);
  } else if (typeof b === "string") report.check("bundle readable", false, `cannot read bundle: ${b}`);
  else ({ report, code: verdict } = await verify(b, t, { bundle, trust }));
  const code = verdict === EXIT_OK && strict && report.warnings.length ? EXIT_WARN : verdict;
  if (json) console.log(JSON.stringify(asJson(report, code), null, 2));
  else process.stdout.write(formatReport(report));
  return code;
}
