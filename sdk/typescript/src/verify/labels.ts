/**
 * tracekit/signer/labels.py's Sources and tracekit/verify/v2.py's _run_labels: which run labels a run's records set,
 * replayed under its compiled policy, for the verifier's `run labels` check (docs/policy-v2.md#run-conditions). A port
 * kept in step with the reference by tests/test_run_conditions.py.
 */
import { Detector, glob } from "./detect.js";

type J = any;
const SECTIONS = ["deny", "ask", "flag"];
const UNTRUSTED = "untrusted_content";
const UNREAD = "TK-OVERSIZE";   // a call the policy couldn't read: it sets every label a run condition reads
// tracekit/policy2/compile.py CLASSES: an `untrusted` entry that names one is a class, any other a tool name glob
const CLASSES = ["shell", "fs", "http", "sql", "payment", "email", "mcp", "browser", "a2a", "app", "unknown", "harness"];
const cut = (s: string, n: number) => [...s].slice(0, n).join("");
const str = (v: unknown): string => v === null || v === undefined ? "None" : v === true ? "True" : v === false ? "False"
  : typeof v === "string" ? v : JSON.stringify(v);
const key = (v: unknown) => typeof v === "string" ? v : null;   // a schema-invalid id names nothing
const byCodePoint = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

/** A tool name as CrewAI's sanitize_tool_name leaves it, without its `_` (tracekit/policy2/engine.py _spelling). */
function spelling(name: string): string {
  return name.normalize("NFKD").replace(/[^\x00-\x7f]/g, "").toLowerCase().replace(/[^0-9a-z]/g, "");
}

export class Sources {
  when = new Map<string, Set<string>>();
  tracked = new Set<string>();
  label = new Map<string, string>();
  untrusted: string[];
  tools: Record<string, string>;
  spelled = new Map<string, string[]>();
  classes: Detector;

  constructor(policy: J) {
    const rules: J[] = SECTIONS.flatMap((sec) => policy[sec] ?? []);
    for (const r of rules) if (Object.hasOwn(r, "when")) this.when.set(r.id, new Set(r.when.run_has));
    for (const ls of this.when.values()) for (const x of ls) this.tracked.add(x);
    for (const r of rules) if (this.tracked.has(r.label)) this.label.set(r.id, r.label);
    this.untrusted = policy.untrusted ?? [];
    this.tools = policy.tools ?? {};
    this.classes = new Detector(policy);
    for (const t of Object.keys(this.tools))
      if (!/[*?[]/.test(t) && spelling(t)) this.spelled.set(spelling(t), [...this.spelled.get(spelling(t)) ?? [], t]);
  }

  /** The names `tools:` lists that `tool` spells, when it lists neither the tool nor a glob that takes it. */
  listed(tool: string): string[] {
    if (Object.hasOwn(this.tools, tool) || this.classes.toolClass(tool) !== "unknown") return [];
    return this.spelled.get(spelling(tool)) ?? [];
  }

  untrustedResults(tool: string): boolean {
    return [tool, ...this.listed(tool)].some((name) => this.untrusted.some((u) =>
      CLASSES.includes(u) ? u === this.classes.toolClass(name) : glob(u).test(name)));
  }

  ofCall(tool: J, ruleIds: string[]): Set<string> {
    if (typeof tool === "string" && this.classes.toolClass(tool) === "harness") return new Set();
    if (ruleIds.includes(UNREAD)) return new Set(this.tracked);
    const out = new Set(ruleIds.filter((i) => this.label.has(i)).map((i) => this.label.get(i)!));
    if (this.tracked.has(UNTRUSTED) && typeof tool === "string" && this.untrustedResults(tool)) out.add(UNTRUSTED);
    return out;
  }

  /** The labels record `e` sets; `requested`, `decided`: {tool, rule_ids} of an approval's call and a call's latest
   * decision, or undefined. */
  sets(e: J, requested: (k: J) => J, decided: (k: J) => J): Set<string> {
    const t = e.type, d = e.data;
    if (t === "policy.decision" && (d.decision === "allow" || d.decision === "flag")) return this.ofCall(d.tool, d.rule_ids);
    const call = t === "approval.consumed" ? requested(d.approval_id ?? null)
      : t === "capture.gap" && d.kind === "executed_against_policy" ? decided(e.tool_call_id ?? null) : undefined;
    if (call) return this.ofCall(call.tool, call.rule_ids);
    if (t === "input.observed" && d.trust === "untrusted" && this.tracked.has(UNTRUSTED)) return new Set([UNTRUSTED]);
    return new Set();
  }
}

/** The problems of one run's labels under `src` (tracekit/verify/v2.py _run_labels); each inherited add of a label its
 * policy reads goes to `inherited` as [where, label, the add it cites]. */
export function runLabels(events: J[], src: Sources, inherited: [string, string, J][]): string[] {
  const problems: string[] = [], carried = new Set<string>(), asked = new Map<J, J>(), decided = new Map<J, J>();
  const seqs = new Map<number, J>();
  let owed = new Map<string, number>(), owner: string | null = null;
  for (const e of events) {
    const t = e.type, d = e.data, where = `seq ${str(e.seq)}`;
    if (!Number.isInteger(e.run_seq)) continue;   // schema-invalid: its schema check fails it
    seqs.set(e.run_seq, e.seq ?? null);
    if (t === "run.registered" && typeof d.identity === "object" && d.identity !== null && !Array.isArray(d.identity))
      owner = `${str(d.identity.scheme ?? null)}:${str(d.identity.subject ?? null)}`;
    if (t === "run.label") {
      const x = key(d.label);
      if (d.action === "add") {
        if (x !== null && carried.has(x)) problems.push(`${where}: adds ${cut(str(x), 32)}, which the run carries already`);
        else if (Object.hasOwn(d, "inherited") && x !== null && src.tracked.has(x))
          inherited.push([where, x, d.inherited]);
        else if (Object.hasOwn(d, "inherited"))
          problems.push(`${where}: inherits ${cut(str(x), 32)}, which no run condition of the run's policy reads`);
        else if (x === null || !owed.has(x) || owed.get(x) !== d.source)
          problems.push(`${where}: adds ${cut(str(x), 32)} citing run_seq ${cut(str(d.source ?? null), 20)}, which doesn't `
            + "set it under the run's policy");
        if (x !== null) {
          owed.delete(x);
          carried.add(x);
        }
      } else if (x === null || !carried.has(x)) problems.push(`${where}: clears ${cut(str(x), 32)}, which the run doesn't carry`);
      else if ((d.identity ?? null) === owner) problems.push(`${where}: ${cut(str(x), 32)} cleared by the run's own owner`);
      else carried.delete(x);
      continue;
    }
    if (owed.size && (t === "policy.decision" || t === "approval.consumed")) {
      for (const [x, s] of owed) problems.push(`seq ${str(seqs.get(s) ?? null)}: sets ${x}, which no run.label adds before ${where}`);
      for (const x of owed.keys()) carried.add(x);
      owed = new Map();
    }
    const ids: string[] = Array.isArray(d.rule_ids) ? d.rule_ids.filter((i: J) => typeof i === "string") : [];
    if (t === "policy.decision") {
      const have = new Set([...carried, ...ids.filter((i) => src.label.has(i)).map((i) => src.label.get(i)!)]);
      const used = new Set<string>(Array.isArray(d.run_labels) ? d.run_labels.filter((x: J) => typeof x === "string") : []);
      for (const x of [...used].filter((x) => !have.has(x)).sort(byCodePoint))
        problems.push(`${where}: run_labels names ${cut(x, 32)}, which the run didn't carry`);
      for (const i of ids)
        if (src.when.has(i) && ![...src.when.get(i)!].every((x) => used.has(x)))
          problems.push(`${where}: ${i} applied without run_labels naming ${[...src.when.get(i)!].sort(byCodePoint).join(", ")}`);
      decided.set(key(e.tool_call_id ?? null), { tool: d.tool ?? null, rule_ids: ids });
    } else if (t === "approval.request" && typeof d.binding === "object" && d.binding !== null && !Array.isArray(d.binding))
      asked.set(key(d.approval_id ?? null), { tool: d.binding.tool ?? null, rule_ids: ids });
    const call = t === "policy.decision" ? { ...d, rule_ids: ids } : d;
    const set = src.sets({ ...e, data: call }, (a) => asked.get(key(a)), (c) => decided.get(key(c)));
    for (const x of [...set].filter((x) => !carried.has(x) && !owed.has(x)).sort(byCodePoint)) owed.set(x, e.run_seq);
  }
  for (const [x, s] of owed) problems.push(`seq ${str(seqs.get(s) ?? null)}: sets ${x}, which no run.label adds`);
  return problems;
}
