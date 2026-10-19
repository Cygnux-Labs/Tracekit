/**
 * The browser verifier: verify.html, which scripts/verify-page.mjs builds from this module, the verifier it imports and
 * page.html. The bundle and trust config a person chooses are read and verified in the page, whose Content Security
 * Policy lets it load and send nothing, so neither file leaves the browser. It reports what the TypeScript CLI does: a
 * bundle that relies on a check this verifier doesn't implement is UNVERIFIABLE, never VERIFIED.
 */
import { EXIT_OK, VERSION, formatReport, verify } from "./index.js";

const input = (id: string) => document.getElementById(id) as HTMLInputElement;
const out = document.getElementById("report")!;
document.getElementById("version")!.textContent = VERSION;
let turn = 0;   // the latest choice of files: an earlier, slower verification never overwrites its report

async function run() {
  const [bundle, trust] = [input("bundle").files?.[0], input("trust").files?.[0]];
  if (!bundle || !trust) return;
  const mine = ++turn;
  out.textContent = "verifying...";
  let text: string;
  try {
    const { report, code } = await verify(new Uint8Array(await bundle.arrayBuffer()),
      new Uint8Array(await trust.arrayBuffer()), { bundle: bundle.name, trust: trust.name });
    text = formatReport(report) + `\nExit code ${code}`
      + (code === EXIT_OK && report.warnings.length ? ` (3 with --strict: ${report.warnings.length} warning(s))` : "")
      + ".\n";
  } catch (e) {
    text = `cannot read the files: ${(e as Error).message}\n`;
  }
  if (mine === turn) out.textContent = text;
}

for (const id of ["bundle", "trust"]) input(id).addEventListener("change", run);
