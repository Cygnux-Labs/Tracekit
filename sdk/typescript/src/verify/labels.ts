/**
 * tracekit/signer/labels.py's Sources and tracekit/verify/v2.py's _run_labels: which run labels a run's records set,
 * replayed under its compiled policy, for the verifier's `run labels` check (docs/policy-v2.md#run-conditions). A port
 * kept in step with the reference by tests/test_run_conditions.py.
 */
import { Detector, glob } from "./detect.js";
import { Budget, Pattern, PolicyError } from "./rx.js";

type J = any;
const SECTIONS = ["deny", "ask", "flag"];
const UNTRUSTED = "untrusted_content";
const UNREAD = "TK-OVERSIZE";   // a call the policy couldn't read: it sets every label the policy reads
// tracekit/signer/labels.py LOST: the gaps of calls the signer never decided
const LOST = ["client_counter_gap", "signer_unavailable", "tailer_lost", "observer_lost"];
// tracekit/policy2/compile.py CLASSES: an `untrusted` entry that names one is a class, any other a tool name glob
const CLASSES = ["shell", "fs", "http", "sql", "payment", "email", "mcp", "browser", "a2a", "app", "unknown", "harness"];
const cut = (s: string, n: number) => [...s].slice(0, n).join("");
const str = (v: unknown): string => v === null || v === undefined ? "None" : v === true ? "True" : v === false ? "False"
  : typeof v === "string" ? v : JSON.stringify(v);
const key = (v: unknown) => typeof v === "string" ? v : null;   // a schema-invalid id names nothing
/** Python's order of strings, by code point (JavaScript's `<` and sort() compare UTF-16 code units, which put a
 * character above U+FFFF before one in U+E000..U+FFFF). */
export const byCodePoint = (a: string, b: string) => {
  const unit = (u: number) => u >= 0xd800 && u < 0xe000 ? u + 0x2000 : u >= 0xe000 ? u - 0x800 : u;
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a.charCodeAt(i) !== b.charCodeAt(i)) return unit(a.charCodeAt(i)) - unit(b.charCodeAt(i));
  return a.length - b.length;
};

/** tracekit/policy2/compile.py subject_labels: {rule id: label} of the rules whose labels a rule on the labels field
 * reads, each rule's non-empty label but a run condition rule's and another labels field rule's. */
export function subjectLabels(policy: J): Map<string, string> {
  return new Map(SECTIONS.flatMap((sec) => policy[sec] ?? []).filter((r: J) => typeof r.label === "string" && r.label
    && !Object.hasOwn(r, "when") && r.field !== "labels").map((r: J) => [r.id, r.label]));
}

/** tracekit/policy2/compile.py labels_subject: the labels `labels` gives `ids`, each once, sorted by code point and
 * joined by a space; "" when none has one. */
export const labelsSubject = (ids: string[], labels: Map<string, string>) =>
  [...new Set(ids.filter((i) => labels.has(i)).map((i) => labels.get(i)!))].sort(byCodePoint).join(" ");

/** A tool name as CrewAI's sanitize_tool_name leaves it, without its `_` (tracekit/policy2/engine.py _spelling). */
function spelling(name: string): string {
  return name.normalize("NFKD").replace(/[^\x00-\x7f]/g, "").toLowerCase().replace(/[^0-9a-z]/g, "");
}

export class Sources {
  when = new Map<string, Set<string>>();
  tracked = new Set<string>();
  label = new Map<string, string>();
  subjectLabels: Map<string, string>;
  onLabels: [string, Pattern, Pattern | null, string | null][] = [];
  refused = new Map<string, string>();   // rule id -> why its labels pattern can't be compiled as the signer does
  untrusted: string[];
  tools: Record<string, string>;
  spelled = new Map<string, string[]>();
  classes: Detector;

  constructor(policy: J) {
    const rules: J[] = SECTIONS.flatMap((sec) => policy[sec] ?? []);
    for (const r of rules) if (Object.hasOwn(r, "when")) this.when.set(r.id, new Set(r.when.run_has));
    for (const ls of this.when.values()) for (const x of ls) this.tracked.add(x);
    for (const x of policy.approval_agent?.run?.clean ?? []) this.tracked.add(x);   // the AI approver's run bound
    for (const r of rules) if (this.tracked.has(r.label)) this.label.set(r.id, r.label);
    this.subjectLabels = subjectLabels(policy);
    const compiled = (p: J) => {
      if (typeof p !== "string") throw new PolicyError("the pattern is not a string");
      return new Pattern(p);
    };
    for (const r of rules)
      if (r.field === "labels" && Object.hasOwn(r, "when") && !Object.hasOwn(r, "tool")) {
        try {   // a bundle's own policy may hold any pattern: searched in linear time, as RE2 reads it (rx.ts)
          this.onLabels.push([r.id, compiled(r.pattern), Object.hasOwn(r, "unless") ? compiled(r.unless) : null,
            r.class ?? null]);
        } catch (e) {
          if (!(e instanceof PolicyError)) throw e;
          this.refused.set(r.id, e.message);
        }
      }
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
    if (t === "capture.gap" && LOST.includes(d.kind) || t === "reconcile.hook_missing") return new Set(this.tracked);
    return new Set();
  }
}

/** The policies each of a run's records is replayed under (tracekit/verify/v2.py _policies_at): a decision's own; another
 * record's, that of the decision before it (the first one's before any) and, between two decisions under different
 * policies, the next one's too. */
export function policiesAt(events: J[], srcs: Map<string, Sources>): Sources[][] {
  if (srcs.size === 1) return events.map(() => [...srcs.values()]);
  const named = events.map((e) => e.type === "policy.decision" && Object.hasOwn(e.data, "policy_hash")
    ? str(e.data.policy_hash) : null);
  const next: (string | null)[] = [];
  let after: string | null = null, before: string | null = null;
  for (let i = named.length - 1; i >= 0; i--) next[i] = after = named[i] ?? after;
  return named.map((h, i) => {
    before = h ?? before;
    return [...new Set([before ?? next[i], next[i] ?? before])].map((x) => srcs.get(x!)!);
  });
}

/** The problems of one run's labels under `srcs` (policy_hash -> Sources), each record under its policy
 * (tracekit/verify/v2.py _run_labels); each inherited add of a label its policy reads goes to `inherited` as [where,
 * label, the add it cites]. */
export function runLabels(events: J[], srcs: Map<string, Sources>, inherited: [string, string, J][],
  budget = new Budget()): string[] {
  const problems: string[] = [], carried = new Set<string>(), asked = new Map<J, J>(), decided = new Map<J, J>();
  const seqs = new Map<number, J>(), at = policiesAt(events, srcs);
  let owed = new Map<string, number>(), may = new Map<string, number>(), owner: string | null = null;
  const callers = new Set<J>();
  for (const [n, e] of events.entries()) {
    const t = e.type, d = e.data, where = `seq ${str(e.seq)}`, cands = at[n], src = cands[0];
    if (!Number.isInteger(e.run_seq)) continue;   // schema-invalid: its schema check fails it
    seqs.set(e.run_seq, e.seq ?? null);
    if (t === "run.registered" && typeof d.identity === "object" && d.identity !== null && !Array.isArray(d.identity))
      owner = `${str(d.identity.scheme ?? null)}:${str(d.identity.subject ?? null)}`;
    // the client a gateway registered it for, a writer: requesters of the run
    if (t === "run.registered" || t === "run.writer") callers.add(t === "run.registered" ? d.caller : d.identity);
    if (t === "run.label" && d.action === "clear" && Object.hasOwn(d, "run_id")) continue;   // an ended run's
    if (t === "run.label") {
      const x = key(d.label);
      if (d.action === "add") {
        if (x !== null && carried.has(x)) problems.push(`${where}: adds ${cut(str(x), 32)}, which the run carries already`);
        else if (Object.hasOwn(d, "inherited") && x !== null && cands.some((c) => c.tracked.has(x)))
          inherited.push([where, x, d.inherited]);
        else if (Object.hasOwn(d, "inherited"))
          problems.push(`${where}: inherits ${cut(str(x), 32)}, which the run's policy doesn't read`);
        else if (x === null || d.source === undefined || d.source === null
          || (owed.get(x) !== d.source && may.get(x) !== d.source))
          problems.push(`${where}: adds ${cut(str(x), 32)} citing run_seq ${cut(str(d.source ?? null), 20)}, which doesn't `
            + "set it under the run's policy");
        if (x !== null) {
          owed.delete(x);
          may.delete(x);
          carried.add(x);
        }
      } else if (x === null || !carried.has(x)) problems.push(`${where}: clears ${cut(str(x), 32)}, which the run doesn't carry`);
      else if ((d.identity ?? null) === owner && d.self_cleared !== true)
        problems.push(`${where}: ${cut(str(x), 32)} cleared by the run's own owner`);
      else if (callers.has(d.identity) && d.self_cleared !== true)
        problems.push(`${where}: ${cut(str(x), 32)} cleared by a requester of the run (a writer or a gateway's caller)`);
      else carried.delete(x);
      continue;
    }
    if (t === "policy.decision" || t === "approval.consumed") {
      for (const [x, s] of owed) problems.push(`seq ${str(seqs.get(s) ?? null)}: sets ${x}, which no run.label adds before ${where}`);
      for (const x of owed.keys()) carried.add(x);
      owed = new Map();
      may = new Map();
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
      // a run condition on the labels field, replayed from the call's rule ids as Engine.condition matches it
      // (labels.py, verify/v2.py _run_labels)
      const subject = labelsSubject(ids, src.subjectLabels);
      const tool = typeof d.tool === "string" ? d.tool : null;
      if (subject && !decided.has(key(e.tool_call_id ?? null)) && tool && src.classes.toolClass(tool) !== "harness")
        for (const [rid, rx, unless, cls] of src.onLabels)
          if (!ids.includes(rid) && [...src.when.get(rid)!].every((x) => have.has(x))
            && (cls === null || cls === src.classes.toolClass(tool)) && rx.search(subject, budget)
            && !(unless && unless.search(subject, budget)))
            problems.push(`${where}: ${rid} applies (the call's labels ${subject}; the run carried `
              + `${[...src.when.get(rid)!].sort(byCodePoint).join(", ")}) but the decision doesn't name it`);
      if (typeof d.caller === "string") callers.add(d.caller);
      decided.set(key(e.tool_call_id ?? null), { tool: d.tool ?? null, rule_ids: ids });
    } else if (t === "approval.request" && typeof d.binding === "object" && d.binding !== null && !Array.isArray(d.binding))
      asked.set(key(d.approval_id ?? null), { tool: d.binding.tool ?? null, rule_ids: ids });
    const call = t === "policy.decision" ? { ...d, rule_ids: ids } : d;
    const sets = cands.map((c) => c.sets({ ...e, data: call }, (a) => asked.get(key(a)), (c) => decided.get(key(c))));
    const need = [...sets[0]].filter((x) => sets.every((s) => s.has(x)));
    for (const x of need.filter((x) => !carried.has(x) && !owed.has(x)).sort(byCodePoint)) owed.set(x, e.run_seq);
    for (const x of [...new Set(sets.flatMap((s) => [...s]))].filter((x) => !need.includes(x) && !carried.has(x)
      && !owed.has(x) && !may.has(x)).sort(byCodePoint)) may.set(x, e.run_seq);
  }
  for (const [x, s] of owed) problems.push(`seq ${str(seqs.get(s) ?? null)}: sets ${x}, which no run.label adds`);
  return problems;
}
