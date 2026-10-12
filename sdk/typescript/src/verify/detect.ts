/**
 * tracekit/signer/detect.py's Detector, without the decision's `detect` view: which incidents a run's records fire,
 * for the verifier's `incidents` check. A port kept in step with the reference by tests/test_ts_verifier.py.
 */
type J = any;
const RUN_CAP = 100, TENANT_CAP = 60, RUN_SHARE = 20, IDLE_S = 3600, UPDATE_S = 60;
const NOT_COUNTED = ["TK-ARGS-INVALID", "TK-OVERSIZE", "TK-QUARANTINE"];
const SECTIONS = ["deny", "ask", "flag"];
const cut = (s: string, n: number) => [...s].slice(0, n).join("");

/** Seconds since the epoch of a record's `ts`, as Python's datetime.timestamp() computes it. */
function ts(t: string): number {
  const m = /^(.{19})(?:\.(\d{1,6}))?Z$/.exec(t);
  if (!m) throw new TypeError(`not a timestamp: ${t}`);
  return (Date.parse(m[1] + "Z") / 1000 * 1e6 + Number((m[2] ?? "").padEnd(6, "0"))) / 1e6;
}

/** fnmatch.fnmatchcase's pattern as a RegExp: `*`, `?` and `[...]` (`[!...]` negated). */
function glob(pat: string): RegExp {
  let out = "";
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i], end = c === "[" ? pat.indexOf("]", i + 2) : -1;
    if (c === "*") out += "[\\s\\S]*";
    else if (c === "?") out += "[\\s\\S]";
    else if (end > 0) {
      const body = pat.slice(i + 1, end);
      out += "[" + (body[0] === "!" ? "^" + body.slice(1) : body).replace(/\\/g, "\\\\") + "]";
      i = end;
    } else out += c.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  }
  return new RegExp(`^${out}$`, "u");
}

type Fired = [string, string[], string, { kind: string; id: string }, [string, number][]];

export class Detector {
  label = new Map<string, string>();
  untrusted = new Set<string>();
  deny = new Set<string>();
  sequences: J[];
  limits: J[];
  respond = new Map<string, J>();
  every = new Map<string, number>();
  idle: number;
  tools: Record<string, string>;

  constructor(policy: J) {
    for (const sec of SECTIONS) for (const r of policy[sec] ?? []) {
      if (Object.hasOwn(r, "label")) this.label.set(r.id, r.label);
      if (Object.hasOwn(r, "from")) this.untrusted.add(r.id);
    }
    for (const r of policy.deny ?? []) this.deny.add(r.id);
    if (policy.unknown_tools === "deny") this.deny.add("TK-UNKNOWN-TOOL");
    this.sequences = policy.sequences ?? [];
    this.limits = policy.limits ?? [];
    for (const r of policy.respond ?? []) this.respond.set(r.trigger, r);
    for (const x of [...this.sequences, ...this.limits]) this.every.set(x.id, x.window);
    if (this.respond.has("denied_calls")) this.every.set("denied_calls", this.respond.get("denied_calls").window);
    this.idle = Math.max(IDLE_S, 0, ...this.every.values());
    this.tools = policy.tools ?? {};
  }

  toolClass(tool: string): string {
    if (Object.hasOwn(this.tools, tool)) return this.tools[tool];
    const hits = Object.keys(this.tools).filter((p) => glob(p).test(tool))
      .map((p) => [-p.replace(/[*?]/g, "").length, p] as [number, string])
      .sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
    return hits.length ? this.tools[hits[0][1]] : "unknown";
  }

  names(ids: string[]) {
    return new Set([...ids, ...ids.filter((i) => this.label.has(i)).map((i) => this.label.get(i)!), "*"]);
  }

  on(trigger: string) {
    return (this.respond.get(trigger)?.mode ?? "off") !== "off";
  }

  static state() {
    return { runs: new Map<string, J>(), scopes: new Map<string, J>(), minute: new Map<string, number[]>() };
  }

  scope(det: J, e: J, run: J, kind: string): [string, { kind: string; id: string }, J] {
    if (kind === "principal" && !(run && run.principal)) kind = "owner";
    if (!run) kind = "run";
    const val = cut(kind === "run" ? e.run_id : run[kind], 256), key = `${kind}\0${e.tenant}\0${val}`;
    const old = det.scopes.get(key);
    if (!old || ts(e.ts) - ts(old.t) > this.idle)
      det.scopes.set(key, { seq: new Map(), lim: new Map(), den: null, open: new Map(), t: e.ts });
    const st = det.scopes.get(key);
    st.t = e.ts;
    return [key, { kind, id: val }, st];
  }

  /** The incident records (type, data without ids) record `e` fires, after indexing it into `det`. */
  observe(det: J, e: J): [string, J][] {
    const typ = e.type, d = e.data, rk = `${e.tenant}\0${e.run_id}`, t = ts(e.ts), fired: Fired[] = [];
    const run = det.runs.get(rk) ?? null;
    if (typ === "run.registered") {
      det.runs.set(rk, { session: d.session ?? e.run_id, owner: `${d.identity.scheme}:${d.identity.subject}`,
        principal: e.principal_attested ? e.principal ?? null : null, pending: new Map(), n: new Map(),
        capped: new Map(), minute: [0, 0, false] });
    } else if (typ === "run.final") {
      det.runs.delete(rk);
      det.scopes.delete("run\0" + rk);
    } else if (typ === "incident.opened" || typ === "incident.capped") this.countIncident(det, e, run, t);
    else if (typ === "policy.decision") {
      const inp = d.detect ?? {}, ids: string[] = inp.rule_ids ?? d.rule_ids, cite: [string, number] = [e.run_id, e.run_seq];
      const names = this.names(ids), unknown = this.toolClass(d.tool) === "unknown";
      if (run) {
        const k = `call\0${e.tool_call_id}`;
        if (d.decision === "ask") run.pending.set(k, [d.decision_id ?? null, [...names], unknown, inp.sums ?? {},
          Object.hasOwn(inp, "rule_ids")]);
        else run.pending.delete(k);
      }
      if (d.decision === "allow" || d.decision === "flag")   // detect.rule_ids: a client's class hint read it too
        this.count(det, e, run, names, unknown, inp.sums ?? {}, Object.hasOwn(inp, "rule_ids"), cite, fired);
      else if (d.decision === "deny") this.denied(det, e, run, t, cite, fired);
      if (d.decision !== "allow" && this.on("provenance") && d.rule_ids.some((i: string) => this.untrusted.has(i))
          && (Array.isArray(d.provenance) ? d.provenance.length : d.provenance) && d.provenance_state === "complete")
        fired.push(["provenance", d.rule_ids, ...this.scope(det, e, run, "run").slice(0, 2) as [string, J], [cite]]);
    } else if (typ === "approval.request" && run) {
      const k = `call\0${e.tool_call_id ?? null}`, p = run.pending.get(k);
      if (p && p[0] === d.decision_id) {
        run.pending.delete(k);
        run.pending.set(d.approval_id, p.slice(1));
      }
    } else if (["approval.consumed", "approval.abandoned", "approval.expired"].includes(typ) && run) {
      const p = run.pending.get(d.approval_id);
      if (p) {
        run.pending.delete(d.approval_id);
        if (typ === "approval.consumed")
          this.count(det, e, run, new Set(p[0]), p[1], p[2], Boolean(p[3]), [e.run_id, e.run_seq], fired);
      }
    } else {
      let trigger: string | undefined = ({ "trace.tamper": "tamper", "refusal.summary": "refusal_burst" } as J)[typ];
      if (typ === "capture.gap" && ["executed_against_policy", "class_mismatch"].includes(d.kind)) trigger = d.kind;
      if (trigger && this.on(trigger) && (trigger !== "refusal_burst" || d.count > this.respond.get(trigger).max))
        fired.push([trigger, [], ...this.scope(det, e, run, "run").slice(0, 2) as [string, J], [[e.run_id, e.run_seq]]]);
    }
    return this.incidents(det, e, run, t, fired);
  }

  /** As detect.py's _count: `unless` exempts only a call the policy's own reading names, never one a hint added. */
  count(det: J, e: J, run: J, names: Set<string>, unknown: boolean, sums: J, hinted: boolean, cite: [string, number],
        fired: Fired[]) {
    const own = unknown ? new Set<string>() : new Set([...names].filter((n) => n !== "*"));
    const at = ts(e.ts);
    for (const s of this.sequences) {
      if (!unknown && !hinted && (s.unless ?? []).some((n: string) => names.has(n))) continue;
      const steps: string[] = s.steps, last = steps.length - 1;
      if (!(unknown || steps.some((n) => names.has(n)))) continue;
      const [key, scope, st] = this.scope(det, e, run, s.scope ?? "run");
      const old: J[] = st.seq.get(s.id) ?? Array(last).fill(null), next = [...old];
      let done: J = null;
      for (let j = 0; j <= last; j++) {
        if (!(unknown || names.has(steps[j]))) continue;
        const prev = j ? old[j - 1] : null;
        if (j && (prev === null || at - ts(prev[0]) > s.window)) continue;
        const [start, cites] = j ? [prev[0], [...prev[1], cite]] : [e.ts, [cite]];
        const used = new Set<string>();
        for (let k = j; ; k++) {
          if (k === last) {
            if (done === null || ts(start) >= ts(done[0])) done = [start, cites];
            break;
          }
          if (next[k] === null || ts(start) >= ts(next[k][0])) next[k] = [start, cites];
          used.add(steps[k]);
          if (!own.has(steps[k]) || !own.has(steps[k + 1]) || used.has(steps[k + 1])) break;
        }
      }
      st.seq.set(s.id, next);
      if (done) fired.push(["sequence", [s.id], key, scope, done[1]]);
    }
    for (const lim of this.limits) {
      if (!(unknown || names.has(lim.match)) || Object.hasOwn(lim, "sum") && !Object.hasOwn(sums, lim.id)) continue;
      const [key, scope, st] = this.scope(det, e, run, lim.scope ?? "run");
      let [start, val] = st.lim.get(lim.id) ?? [null, null], before: number, after: number;
      if (start === null || at - ts(start) > lim.window) [start, val] = [e.ts, Object.hasOwn(lim, "sum") ? {} : 0];
      if (Object.hasOwn(lim, "sum")) {
        const [amount, cur] = sums[lim.id];
        before = val[cur] ?? 0;
        val = { ...val, [cur]: Math.min(before + amount, Number.MAX_SAFE_INTEGER) };   // saturated, as detect.py
        after = val[cur];
      } else [before, val, after] = [val, val + 1, val + 1];
      st.lim.set(lim.id, [start, val]);
      if (before <= lim.max && lim.max < after) fired.push(["limit", [lim.id], key, scope, [cite]]);
    }
  }

  denied(det: J, e: J, run: J, t: number, cite: [string, number], fired: Fired[]) {
    const r = this.respond.get("denied_calls"), d = e.data, ids: string[] = d.rule_ids;
    if (!this.on("denied_calls") || d.nondeterministic
        || ids.some((i) => NOT_COUNTED.includes(i)) && !ids.some((i) => this.deny.has(i))) return;
    const [key, scope, st] = this.scope(det, e, run, r.scope ?? "run");
    if (st.den === null || t - ts(st.den[0]) > r.window) st.den = [e.ts, new Set()];
    const seen: Set<string> = st.den[1], call = `${e.tool_call_id}\0${e.attempt ?? 0}`;
    if (seen.has(call) || seen.size > r.max) return;
    seen.add(call);
    if (seen.size > r.max) fired.push(["denied_calls", ids, key, scope, [cite]]);
  }

  incidents(det: J, e: J, run: J, t: number, fired: Fired[]): [string, J][] {
    if (!fired.length) return [];
    const out: [string, J][] = [], minute = Math.floor(t / 60), m = det.minute.get(e.tenant);
    let nTen = m && m[0] === minute ? m[1] : 0;
    const nRun = new Map<string, number>(run ? run.n : []), capped = new Map<string, boolean>(run ? run.capped : []);
    let [nMine, shared] = run && run.minute[0] === minute ? [run.minute[1], run.minute[2]] : [0, false];
    for (const [trigger, ruleIds, key, scope, cites] of fired) {
      const rule = ["sequence", "limit"].includes(trigger) ? ruleIds[0] : trigger;
      const r = this.respond.get(rule) ?? { mode: "shadow" };
      if (r.mode === "off") continue;
      const st = det.scopes.get(key), k = `${trigger}\0${rule}`, cited = cites.map(([a, b]) => ({ run_id: a, run_seq: b }));
      if (st.open.has(k)) {
        const [inc, last] = st.open.get(k);
        if (t - ts(last) >= (this.every.get(rule) ?? UPDATE_S)) {
          st.open.set(k, [inc, e.ts]);
          out.push(["incident.updated", { incident_id: inc, cites: cited }]);
        }
        continue;
      }
      if (run && (nRun.get(trigger) ?? 0) >= RUN_CAP) {
        if (capped.get(trigger)) continue;
        capped.set(trigger, true);
        out.push(["incident.capped", { trigger }]);
      } else if (nTen >= TENANT_CAP || nMine >= RUN_SHARE) {
        if (shared) continue;
        shared = true;
        out.push(["incident.capped", { trigger }]);
      } else {
        nRun.set(trigger, (nRun.get(trigger) ?? 0) + 1);
        nTen++;
        nMine++;
        out.push(["incident.opened", { trigger, rule_ids: ruleIds, scope, cites: cited, mode: r.mode }]);
      }
    }
    return out;
  }

  countIncident(det: J, e: J, run: J, t: number) {
    const d = e.data, minute = Math.floor(t / 60);
    if (e.type === "incident.capped") {
      if (run && d.cap === "run") run.capped.set(d.trigger, true);
      else if (run) run.minute = [minute, run.minute[0] === minute ? run.minute[1] : 0, true];
      return;
    }
    const m = det.minute.get(e.tenant);
    det.minute.set(e.tenant, [minute, (m && m[0] === minute ? m[1] : 0) + 1]);
    if (run) {
      run.n.set(d.trigger, (run.n.get(d.trigger) ?? 0) + 1);
      const mine = run.minute;
      run.minute = mine[0] === minute ? [minute, mine[1] + 1, mine[2]] : [minute, 1, false];
    }
    const st = det.scopes.get(`${d.scope.kind}\0${e.tenant}\0${d.scope.id}`);
    const rule = ["sequence", "limit"].includes(d.trigger) ? d.rule_ids[0] : d.trigger;
    if (st) st.open.set(`${d.trigger}\0${rule}`, [d.incident_id, e.ts]);
  }
}
