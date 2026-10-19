/**
 * What the browser verifier (web.ts) says about a report, in plain words: the verdict and what it does and doesn't
 * mean, what to do next, a line per check on what it means (docs/verdicts.md, shortened), and a summary of the bundle's
 * runs. The report itself is the CLI's, unchanged: this module only reads it. No DOM, so Node tests it.
 */
import { EXIT_FAIL, EXIT_OK, type Report, VERSION, clean, formatReport, runFiles } from "./index.js";

type J = any;
export type Names = { bundle: string; trust: string | null };
export type Verdict = { word: "VERIFIED" | "FAILED" | "UNVERIFIABLE"; means: string; notMeans: string };
/** A step: what to do, and the command to run for it, if any. */
export type Step = { text: string; command?: string };

/** `s` as one shell argument (POSIX shells; the page doesn't know the reader's). */
const sh = (s: string) => /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'"'"'`)}'`;
const TRUST_FILE = "the sender's trust file: a small .json that names their signer's log key (tracekit last writes it next "
  + "to the bundle, as <name>.trust.json)";

/** The report as `tracekit verify --json` prints it (cli.ts prints this). */
export const asJson = (rep: Report, code: number) => ({ exit_code: code, checks: rep.checks, failures: rep.failures,
  warnings: rep.warnings, integrity: rep.integrity, assurance: rep.assurance, notes: rep.notes,
  ...rep.findings ? { findings: rep.findings } : {} });

/** The report as `tracekit verify` prints it, then its exit code. */
export const asText = (rep: Report, code: number) => formatReport(rep) + `\nExit code ${code}`
  + (code === EXIT_OK && rep.warnings.length ? ` (3 with --strict: ${rep.warnings.length} warning(s))` : "") + ".\n";

const failed = (rep: Report, name: string) => rep.checks.find((c) => c.check === name && c.status === "fail");
const anchored = (rep: Report) => !rep.checks.some((c) => c.check === "trust config" && c.status === "warn");
const v1 = (rep: Report) => rep.checks.some((c) => c.check === "bundle readable"
  && c.problems.some((p) => p.startsWith("a format v1 bundle")));

/** What the command-line verifiers exit with for the same files, where that is known: they refuse a v2 bundle without a
 * trust file, and the Python one checks what this verifier doesn't (and v1 bundles, against signer.pub). */
export function cliExit(rep: Report): string {
  if (v1(rep)) return "";
  if (!anchored(rep)) return " The command-line verifiers need the trust file: without one they exit 2.";
  return rep.unsupported.length ? " The TypeScript command-line verifier exits with the same code; the Python one checks "
    + "what this page doesn't." : " The command-line verifiers exit with the same code.";
}

export function verdict(rep: Report, code: number): Verdict {
  const behaved = "It doesn't mean the agent behaved well, or that the record holds everything it did: the summary, "
    + "findings and warnings below tell you that.";
  if (code === EXIT_OK) {
    const head = rep.integrity.match(/^VERIFIED TO HEAD (\d+)/);
    return { word: "VERIFIED", means: "The record is intact and signed by the signer your trust file names: nothing was "
      + "edited, removed, reordered or added after signing."
      + (head ? ` The run was still open when it was exported: its records up to number ${head[1]} are verified.` : ""),
    notMeans: behaved };
  }
  if (code === EXIT_FAIL) {
    if (failed(rep, "checkpoint") && anchored(rep))
      return { word: "FAILED", means: "This bundle is not signed by the signer your trust file names, or its checkpoint "
        + "was changed.", notMeans: "It doesn't say who made the bundle. If the trust file is the right one, don't rely "
        + "on the bundle." };
    return { word: "FAILED", means: "This bundle doesn't match what was signed: something in it was changed, removed or "
      + `added after signing. Failed: ${rep.failures.join(", ")}.`,
    notMeans: "It doesn't say who changed it or why: the failed lines below show what doesn't match." };
  }
  const readable = rep.checks.find((c) => c.check === "bundle readable");
  const nothing = "Nothing failed: it doesn't mean the bundle is bad.";
  if (failed(rep, "trust config"))
    return { word: "UNVERIFIABLE", means: "The trust file couldn't be used, so nothing was checked.", notMeans: nothing };
  if (v1(rep))
    return { word: "UNVERIFIABLE", means: "This is a format v1 bundle (from Tracekit's laptop signer); this page checks "
      + "format v2 bundles, so nothing was checked.", notMeans: nothing };
  if (rep.integrity.startsWith("UNVERIFIABLE (needs"))
    return { word: "UNVERIFIABLE", means: `This bundle needs a newer verifier than this page (Tracekit ${VERSION}).`,
      notMeans: nothing };
  if (readable)
    return { word: "UNVERIFIABLE", means: "This file couldn't be read as a Tracekit bundle, so nothing in it was checked.",
      notMeans: "Nothing in it can be relied on until a readable copy verifies." };
  if (!anchored(rep))
    return { word: "UNVERIFIABLE", means: "Signatures are intact, but you haven't said whose signer you trust.",
      notMeans: "It doesn't mean the bundle is genuine: anyone can sign a bundle with keys of their own. The sender's "
        + "trust file says whose signer made it." };
  return { word: "UNVERIFIABLE", means: "This page doesn't implement a check this bundle relies on: "
    + `${rep.integrity.replace(/^UNVERIFIABLE \(not checked by this verifier: (.*)\)$/, "$1")}.`, notMeans: nothing };
}

/** What to do after a result that isn't plainly VERIFIED: what to check or ask for, with the commands that do it. */
export function nextSteps(rep: Report, code: number, names: Names): Step[] {
  const b = sh(names.bundle), t = sh(names.trust ?? "trust.json");
  const cli: Step = { text: "Check the same files with the command-line verifier (it needs Node.js, nothing else):",
    command: `npx -y @cygnuxlabs/tracekit@latest verify ${b} --trust ${t}` };
  const readable = rep.checks.find((c) => c.check === "bundle readable");
  if (code === EXIT_OK)
    return rep.warnings.length ? [{ text: `Read the ${rep.warnings.length} warning(s) below: each says what to look at. `
      + "They don't change the verdict (with --strict the command line exits 3)." }] : [];
  if (failed(rep, "trust config"))
    return [{ text: `Choose the trust file again: it must be a Tracekit v2 trust config (a .json with "logs"). Ask for ${
      TRUST_FILE}.` }];
  if (readable?.problems.length)
    return readable.problems.map((p) => {
      const at = p.search(/(npx|uvx) /);
      const text = at < 0 ? p.replace(/^or open (\S+) /, "open the latest page, $1, ")
        : at ? p.slice(0, at).trimEnd() : p.startsWith("npx") ? "with Node.js:" : "or with Python, using uv:";
      return { text: text[0].toUpperCase() + text.slice(1), ...at < 0 ? {} : { command: p.slice(at) } };
    });
  if (readable)
    return [{ text: `Check that you chose the .tkb file itself (not a renamed archive or a saved web page), then ask the `
      + "sender to export it again: a damaged or cut-short copy reads like this." }];
  if (code === EXIT_FAIL) {
    const steps: Step[] = [];
    if (failed(rep, "checkpoint") && anchored(rep))
      steps.push({ text: `Make sure the trust file is ${TRUST_FILE.replace("the sender's", "the sender's own")}. With `
        + "the right one, this bundle isn't theirs: don't rely on it." });
    else
      steps.push({ text: "Don't rely on this bundle's contents. Ask the sender for the original and compare its SHA-256 "
        + "with theirs:", command: `shasum -a 256 ${b}` });
    if (anchored(rep)) steps.push(cli);
    else steps.push({ text: `Add ${TRUST_FILE}, to see whose signer made it.` });
    return steps;
  }
  if (!anchored(rep))
    return [{ text: `Ask for ${TRUST_FILE}, and add it above. Get it from the sender directly, not inside the bundle's `
      + "own folder or message: the trust file is what makes the check mean something." }];
  return [{ text: "Verify it with the reference verifier, which checks this:",
    command: `uvx --from tracekit-ai tracekit verify ${b} --trust ${t}` }];
}

/** One line per check: what it means (docs/verdicts.md#lines). */
export const MEANING: Record<string, string> = {
  "trust config": "Your trust file: the log key and witnesses you trust, never ones the bundle brings.",
  "bundle readable": "The file is a Tracekit v2 bundle this verifier can read.",
  "bundle structure": "The bundle is well formed; a failure here means it is malformed in a way no other line covers.",
  "manifest": "The files in the bundle are exactly those its manifest lists, with those hashes.",
  "checkpoint": "The log's checkpoint (the signed root of every record) is signed by the log key your trust file pins.",
  "witness quorum": "Enough witnesses your trust file pins cosigned the checkpoint: they vouch it was not rolled back.",
  "keys": "The record keys were declared by records the checkpoint includes, in order, and retired keys stop signing.",
  "run parts": "A long run comes in numbered parts: none is missing, extra or out of order, so they read as one run.",
  "signatures": "Every record's signature verifies under a key valid at its position: no record was edited after signing.",
  "run chain": "Each run's records follow one another without a gap from the first: none deleted, swapped or added.",
  "inclusion": "Each run's first and last records are in the checkpointed tree: the run wasn't rebuilt.",
  "policy snapshot": "The bundled policy file is named by its own hash: it wasn't edited.",
  "policy": "A tool call ran against a deny, or an ask nobody approved, and the signer recorded it.",
  "held calls": "A call held for a gateway or executor got no result before its run ended.",
  "gaps": "The signer recorded something a person should read: a gap, a tamper attempt or a mismatched approval.",
  "external decisions": "Decisions imported from another policy system, and whether they disagreed with the signer's.",
  "coverage": "Which capture layers reported, and calls the signer could not match across them.",
  "coverage matrix": "How each kind of action was covered: enforced, observed, only reported by the agent, or not at all.",
  "observers": "An observer outside the agent went silent or restarted while the run was open.",
  "reviews": "Signed findings about the run, each labelled by who wrote it: independent, unpinned or self-asserted.",
  "reviews counted": "Findings whose analysed run isn't in the bundle, so their citations weren't checked.",
  "incidents": "Detections the signer opened, recomputed from the run's records where the bundle allows.",
  "incident policies": "Policies an incident cites that aren't in the bundle: those incidents are the signer's word.",
  "content vault": "Who read or erased retained content, as the signer recorded it.",
  "tiers": "Tool calls by how they were captured: T2 gateway or executor, T1 adapter, T3 import (receipt only).",
  "args source": "Whether recorded arguments are the model's exact bytes (raw), parsed, or changed by a framework.",
  "isolation": "How the signer measured its separation from the agent: separate-user and remote are out of its reach.",
  "principals": "The person or service each run acted for, attested by the signer or asserted by the app.",
  "harness": "The agent harness the signer bound each run to.",
  "fail-open classes": "Tool classes allowed to run while the signer is down, so such calls may be unrecorded.",
  "key assurance": "Whether the record keys are only declared by the log (asserted) or certified by an issuer.",
  "approvals by people": "Held calls approved by people.",
  "approvals by agents": "Held calls approved by agents (model output), checked against the rules that allow it.",
  "break-glass approvals": "Approvals given under the break-glass role, with who and why.",
  "not interpreted": "Records carry an extension this verifier doesn't read. They verified like every other record.",
  "gateway amendments": "Requests the LLM gateway changed so the provider shows its reasoning; each record commits to "
    + "the request as sent.",
  "openshell policy": "Changes of the sandbox's policy or configuration that NVIDIA OpenShell reported, signed into "
    + "the run as OpenShell's report.",
  "constraints": "What the person's request said not to do, added while the run was open, and the calls it held.",
  "run-set": "Every run of the tenant in the registry range is in the bundle (COMPLETE), or what is missing.",
  "tenant-level gaps": "Signer gaps in the range that concern every tenant, such as witness failures.",
  "log tail": "Whether records after the checkpoint are proven absent (a log.closed) or simply unproven.",
  "rekor anchor": "A Rekor transparency-log anchor of the checkpoint, which this page can't check.",
  "SLH-DSA-SHA2-128s checkpoint signature": "A post-quantum checkpoint signature, which browsers can't check yet.",
  "record-key certificates": "Certificates of the record keys, which this page doesn't check.",
  "tracekit why findings": "tracekit why investigation findings, which this page doesn't check.",
};

const day = (ts: string) => ts.slice(0, 19).replace("T", " ") + " UTC";

/** A few plain facts about the bundle's runs, from their records ({name: bytes}, the runs/ files, a run's parts read as
 * one), cleaned as the report is; names an agent chose are quoted, so they can't read as the signer's words around them. */
export function summarize(files: Map<string, Uint8Array>, rep: Report): [string, string][] {
  const text = new TextDecoder();
  const runs = [...runFiles(files.keys()).values()].map((parts) => parts.flatMap((n) => text.decode(files.get(n))
    .split("\n").filter(Boolean).map((l) => JSON.parse(l).event as J)));
  const events = runs.flat(), of = (t: string) => events.filter((e) => e.type === t);
  const times: string[] = events.map((e) => e.ts).filter((t) => typeof t === "string").sort();
  const out: [string, string][] = [];
  const [first, end] = [times[0], times[times.length - 1]], secs = (Date.parse(end) - Date.parse(first)) / 1000;
  out.push(["Records", `${events.length} signed record(s) in ${runs.length} run(s)` + (times.length ? `, ${day(first)}`
    + ` to ${day(end)} (${secs < 120 ? `${Math.round(secs)} s` : secs < 7200 ? `${Math.round(secs / 60)} min`
      : `${Math.round(secs / 3600)} h`})` : "")]);
  const cp = rep.checks.find((c) => c.check === "checkpoint")?.detail.split(" at tree size")[0];
  if (cp)
    out.push(["Signer", `log ${cp}` + (anchored(rep) ? ", the key your trust file pins" : ", not checked (no trust file)")]);
  const level = rep.assurance.split(";")[0];
  out.push(["Assurance", level === "witnessed" ? "witnessed: independent witnesses cosigned the checkpoint"
    : level === "local" ? "local: only witnesses the log's operator runs cosigned the checkpoint"
      : level === "dev" ? "dev: no independent witness vouches for the checkpoint (or a run holds a self-approval)"
        : level]);
  const agents = runs.map((rs) => rs[0]).filter((e) => e?.type === "run.registered").map((e) => {
    const id = e.data?.identity;
    return `${JSON.stringify(String(e.data?.agent?.name ?? "agent"))}` + (id ? ` (${id.scheme}:${id.subject})` : "");
  });
  const named = [...new Set(agents)];
  if (named.length) out.push(["Agents", named.slice(0, 5).join(", ") + (named.length > 5 ? ", ..." : "")]);
  const decisions = of("policy.decision").map((e) => e.data?.decision);
  out.push(["Tool calls", `${decisions.length} decided` + (decisions.length ? ": " + ["allow", "deny", "ask"]
    .map((d) => `${decisions.filter((x) => x === d).length} ${d}`).join(", ") : "")]);
  const answers = new Map(of("approval").map((e) => [e.data?.approval_id, e.data]));
  const held = of("approval.request").map((e) => {
    const a = answers.get(e.data?.approval_id);
    const who = a ? `${a.decision === "approve" ? "approved" : a.decision === "reject" ? "rejected" : a.decision} by `
      + `${a.person ?? a.approver}` + (a.approver_kind === "agent" ? " (an agent)" : "")
      + (a.self_approved ? " (self-approved)" : "") + (a.break_glass ? " (break-glass)" : "") : "no answer recorded";
    const tool = e.data?.binding?.tool ?? e.tool_call_id;
    return `${tool == null ? "a call" : JSON.stringify(String(tool))}: ${who}`;
  });
  out.push(["Held for approval", held.length ? held.slice(0, 10).join("; ") + (held.length > 10 ? "; ..." : "") : "none"]);
  const gaps = new Map<string, number>();
  for (const e of of("capture.gap")) gaps.set(e.data?.kind, (gaps.get(e.data?.kind) ?? 0) + 1);
  out.push(["Gaps", gaps.size ? [...gaps].map(([k, n]) => `${k} ${n}`).join(", ") : "none recorded"]);
  const findings = ["reviews", "incidents"].map((n) => rep.checks.find((c) => c.check === n)?.detail).filter(Boolean);
  out.push(["Findings", findings.length ? findings.join("; ") : "none recorded"]);
  return out.map(([k, v]) => [k, clean(v)]);
}
