/**
 * An independent verifier of `tracekit.bundle.v2` bundles, written from docs/format-v2.md (§11 is the algorithm) and
 * checked against the reference (tracekit/verify/v2.py) by tests/test_ts_verifier.py: same checks, integrity, assurance
 * and exit codes. Web Crypto and DecompressionStream only, so it runs in Node ≥ 20 and current browsers.
 *
 *     import { verify } from "@cygnux/tracekit/verify";
 *     const { report, code } = await verify(bundleBytes, trustConfigBytes);
 *
 * Not implemented here, so never VERIFIED when a bundle relies on them (integrity `UNVERIFIABLE (...)` names them):
 * SLH-DSA-SHA2-128s hybrid checkpoint lines (Web Crypto has no SLH-DSA), Rekor v2 anchors, record-key certificates.
 * Monitor reports, revocations and the v1 format bridge are inputs of the reference's CLI that this one doesn't take.
 */
import { type Floats, canonicalize, strictParseBytes } from "./jcs.js";
import {
  HYBRID, NoteError, SIGNER_LEAVES, b64decode, bytes, equal, keyAlg, leafHash, openNote, parseLeaf, parseVkey,
  registryOrigin, runHash, sha256hex, spkiKid, unhex, verifyConsistency, verifyInclusion, verifyV2, vkey,
} from "./primitives.js";
import { same, validateEvent } from "./schema.js";
import { readZip } from "./zip.js";

export { MAX_ENTRIES, MAX_ENTRY, MAX_TOTAL, Unusable, readZip } from "./zip.js";
export { StrictJSONError, canonicalize, strictParse, strictParseBytes } from "./jcs.js";

/** The bundle format version this verifier implements: a bundle needing a later one is UNVERIFIABLE. */
export const VERSION = "1.0.0";
export const EXIT_OK = 0, EXIT_FAIL = 1, EXIT_BAD = 2, EXIT_WARN = 3;
const FORMAT = "tracekit.bundle.v2";
const MAX_LINE = 1 << 20;
const CLASSES = ["public", "customer", "tracekit", "operator"];
const KEY_TYPES = ["signer.epoch", "key.retire"];
const ZERO_HASH = "sha256:" + "0".repeat(64);

export type Check = { check: string; status: "pass" | "warn" | "fail"; detail: string; problems: string[] };

export class Report {
  checks: Check[] = [];
  failures: string[] = [];
  warnings: string[] = [];
  notes: string[] = [];
  integrity = "UNUSABLE BUNDLE";
  assurance = "none";
  /** Checks the bundle needs that this verifier does not implement. */
  unsupported: string[] = [];

  check(check: string, ok: boolean, detail = "", problems: string[] = [], warn = false) {
    this.checks.push({ check, status: ok ? "pass" : warn ? "warn" : "fail", detail, problems });
    if (!ok) (warn ? this.warnings : this.failures).push(check);
  }

  unsupport(what: string) {
    if (this.unsupported.includes(what)) return;
    this.unsupported.push(what);
    this.check(what, false, "not implemented by this verifier", [], true);
  }
}

// JSON access with the reference's failure modes: a missing key or a wrong container throws (a malformed bundle)
type J = any;
const isObj = (v: unknown): v is Record<string, J> => typeof v === "object" && v !== null && !Array.isArray(v);
const kind = (v: unknown) => v === null ? "null" : Array.isArray(v) ? "array" : typeof v;
function at(o: unknown, k: string): J {
  if (!isObj(o)) throw new TypeError(`${kind(o)} is not an object`);
  if (!Object.hasOwn(o, k)) throw new TypeError(`missing ${JSON.stringify(k)}`);
  return o[k];
}
function get(o: unknown, k: string, missing: J = null): J {
  if (!isObj(o)) throw new TypeError(`${kind(o)} is not an object`);
  return Object.hasOwn(o, k) ? o[k] : missing;
}
function has(o: unknown, k: string): boolean {
  if (isObj(o)) return Object.hasOwn(o, k);
  if (Array.isArray(o)) return o.some((x) => x === k);
  if (typeof o === "string") return o.includes(k);
  throw new TypeError(`${kind(o)} is not a container`);
}
function list(v: unknown): J[] {
  if (!Array.isArray(v)) throw new TypeError(`${kind(v)} is not a list`);
  return v;
}
function num(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return Number(v);
  throw new TypeError(`${kind(v)} is not a number`);
}
function text(v: unknown): string {
  if (typeof v !== "string") throw new TypeError(`${kind(v)} is not a string`);
  return v;
}
const truthy = (v: unknown) => Array.isArray(v) ? v.length > 0 : isObj(v) ? Object.keys(v).length > 0 : !!v;
const str = (v: unknown): string => v === null ? "None" : v === true ? "True" : v === false ? "False"
  : typeof v === "string" ? v : JSON.stringify(v);
const repr = (v: unknown) => typeof v === "string" ? `'${v.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'` : str(v);
const cut = (s: string, n: number) => [...s].slice(0, n).join("");
const count = (xs: string[]) => {
  const m = new Map<string, number>();
  for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
  return [...m].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
};
const fmt = (ts: bigint | number) => {
  if (ts > 253402300799) throw new RangeError("year is out of range");
  return new Date(Number(ts) * 1000).toISOString().slice(0, 19) + "Z";
};

type Trust = { logs: string[]; witnesses: { vkey: string; class: string }[]; algs: string[]; witnesses_required: number;
  rekor?: Record<string, J>; issuers: J[] };

async function loadTrust(data: Uint8Array): Promise<Trust> {
  const floats: Floats = new WeakMap();
  const t: J = strictParseBytes(data.subarray(0, MAX_LINE), floats);
  const int = (o: Record<string, J>, k: string, d: number) => !Object.hasOwn(o, k) ? d
    : Number.isInteger(o[k]) && !floats.get(o)?.has(k) ? o[k] : NaN;
  const exactly = (o: unknown, ks: string[]) => isObj(o) && Object.keys(o).length === ks.length && ks.every((k) => Object.hasOwn(o, k));
  const strings = (a: unknown) => Array.isArray(a) && a.length > 0 && a.every((x) => typeof x === "string");
  const opt = (o: Record<string, J>, k: string) => Object.hasOwn(o, k) ? o[k] : [];
  const r = isObj(t) ? get(t, "rekor", {}) : null;
  const ok = isObj(t) && Object.keys(t).every((k) => ["logs", "witnesses", "algs", "witnesses_required", "rekor",
    "monitors", "issuers"].includes(k))
    && isObj(r) && (!Object.keys(r).length || exactly(r, ["trusted_root", "publishing_key", "class"])
      && isObj(r.trusted_root) && typeof r.publishing_key === "string" && CLASSES.includes(r.class))
    && strings(t.logs)
    && Array.isArray(opt(t, "witnesses")) && opt(t, "witnesses").every((w: J) => exactly(w, ["vkey", "class"])
      && typeof w.vkey === "string" && CLASSES.includes(w.class))
    && strings(t.algs) && int(t, "witnesses_required", 0) >= 0
    && Array.isArray(opt(t, "monitors")) && opt(t, "monitors").every((m: J) => exactly(m, ["vkey", "class", "max_age_s"])
      && typeof m.vkey === "string" && CLASSES.includes(m.class) && int(m, "max_age_s", 0) > 0)
    && Array.isArray(opt(t, "issuers")) && opt(t, "issuers").every((i: J) => exactly(i, ["vkey", "issuance_log_vkey"])
      && Object.values(i).every((v) => typeof v === "string"));
  if (!ok) throw new Error("not a v2 trust config (logs, witnesses, algs, witnesses_required, rekor, monitors, issuers)");
  for (const k of [...t.logs, ...opt(t, "witnesses").map((w: J) => w.vkey), ...opt(t, "monitors").map((m: J) => m.vkey),
    ...opt(t, "issuers").flatMap((i: J) => Object.values(i))]) await parseVkey(k);
  t.witnesses ??= [];
  t.witnesses_required ??= 0;
  t.issuers ??= [];
  return t as Trust;
}

function newer(need: string, have: string) {
  const a = need.split(".").map(Number), b = have.split(".").map(Number);
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] > b[i];
  return a.length > b.length;
}

const errorText = (e: unknown) => `${(e as Error)?.constructor?.name ?? "Error"}: ${(e as Error)?.message ?? e}`;

/** Verify a v2 bundle (zip bytes) against the verifier's own pinned trust config (JSON bytes). Never throws. */
export async function verify(bundle: Uint8Array, trust: Uint8Array): Promise<{ report: Report; code: number }> {
  const rep = new Report();
  let t: Trust, files: Map<string, Uint8Array>, manifest: J;
  try {
    t = await loadTrust(trust);
  } catch (e) {
    rep.check("trust config", false, errorText(e));
    return { report: rep, code: EXIT_BAD };
  }
  const floats: Floats = new WeakMap();
  try {
    files = await readZip(bundle);
    const m = files.get("manifest.json");
    if (!m) throw new Error("no manifest.json");
    files.delete("manifest.json");
    manifest = strictParseBytes(m, floats);
    if (!isObj(manifest) || manifest.format !== FORMAT) throw new Error(`format is not ${FORMAT}`);
    const need = manifest.verifier_min_version;
    if (!(typeof need === "string" && /^\d{1,9}(\.\d{1,9}){0,2}$/.test(need)))
      throw new Error("verifier_min_version is not a version number");
    if (newer(need, VERSION)) {
      rep.integrity = `UNVERIFIABLE (needs tracekit >= ${need})`;
      rep.check("bundle readable", false, rep.integrity);
      return { report: rep, code: EXIT_BAD };
    }
  } catch (e) {
    rep.check("bundle readable", false, `cannot read bundle: ${errorText(e)}`);
    return { report: rep, code: EXIT_BAD };
  }
  try {
    await check(rep, manifest, files, t, floats);
  } catch (e) {
    rep.check("bundle structure", false, "", [`malformed and could not be fully checked: ${errorText(e)}`]);
  }
  if (rep.failures.length) rep.integrity = "FAILED";
  else if (rep.unsupported.length) rep.integrity = `UNVERIFIABLE (not checked by this verifier: ${rep.unsupported.join(", ")})`;
  return { report: rep, code: rep.failures.length ? EXIT_FAIL : rep.integrity.startsWith("UNVERIFIABLE") ? EXIT_BAD : EXIT_OK };
}

type Key = { spki: Uint8Array; from: number; until: number | null };

async function check(rep: Report, manifest: J, files: Map<string, Uint8Array>, trust: Trust, floats: Floats) {
  const file = (name: string) => {
    const f = files.get(name);
    if (!f) throw new TypeError(`no ${name}`);
    return f;
  };
  const json = (name: string) => strictParseBytes(file(name), floats);
  const jsonl = (name: string) => {
    const data = file(name);
    if (data.length && data.at(-1) !== 0x0a) throw new Error("a JSON lines file must end in a newline");
    const lines: Uint8Array[] = [];
    for (let i = 0, j; (j = data.indexOf(0x0a, i)) >= 0; i = j + 1) lines.push(data.subarray(i, j));
    if (lines.some((l) => l.length > MAX_LINE)) throw new Error("line longer than the bundle limits");
    return lines.map((l) => strictParseBytes(l, floats) as J);
  };

  const listed = manifest.files, hashes = new Map<string, string>();
  for (const [n, b] of files) hashes.set(n, await sha256hex(b));
  rep.check("manifest", isObj(listed) && Object.keys(listed).length === hashes.size
    && [...hashes].every(([n, h]) => Object.hasOwn(listed, n) && listed[n] === h),
  "every file is listed with its SHA-256 and nothing else is in the bundle");

  // the checkpoint: the only thing the records' trust hangs on
  const proofs = json("proofs/records.json");
  const name = at(proofs, "checkpoint");
  if (!(typeof name === "string" && name.startsWith("checkpoints/") && name.endsWith(".note")))
    throw new Error("proofs name no checkpoint note");
  const witnesses = new Map(trust.witnesses.map((w) => [w.vkey, w.class]));
  let note;
  try {
    note = await openNote(file(name), trust.logs, [...witnesses.keys()]);
  } catch (e) {
    if (!(e instanceof NoteError)) throw e;
    rep.check("checkpoint", false, e.message);
    return;
  }
  const { origin, size, root, cosigs } = note;
  rep.check("checkpoint", same(size, at(proofs, "tree_size")), `${origin} at tree size ${size}, signed by its pinned log key`);
  if (note.unchecked) rep.unsupport("SLH-DSA-SHA2-128s checkpoint signature");
  rep.check("witness quorum", cosigs.length >= trust.witnesses_required,
    `${cosigs.length} pinned cosignature(s), ${trust.witnesses_required} required`);
  if (truthy(trust.rekor) && files.has(`rekor/${size}.json`)) rep.unsupport("rekor anchor");

  const included = async (r: J) => {
    const seq = at(at(r, "event"), "seq");
    const path = get(at(proofs, "inclusion"), str(seq));
    return path !== null && verifyInclusion(num(seq), size, await leafHash(unhex(text(at(r, "hash")).slice(7))),
      list(path).map(b64decode), root);
  };

  // keys: declared and retired by records the checkpointed tree includes, so the log key vouches for them
  const keyRecords = jsonl("keys/records.jsonl"), keyProblems: string[] = [], timeline = new Map<J, Key>();
  const logId = keyRecords.length ? get(at(keyRecords[0], "event"), "log_id") : null;
  const keysAt = (seq: number) => [...timeline.values()].filter((k) => num(k.from) <= seq
    && (k.until === null || seq <= num(k.until))).map((k) => k.spki);

  /** Signature, schema and log membership of one record under `keys`, the SPKIs valid at its position. */
  const checkRecord = async (r: J, keys: Uint8Array[], problems: string[]) => {
    const err = await verifyRecord(r, keys, trust.algs);
    if (err) {
      const seq = err === "unknown kid" ? get(r.event, "seq") : null;   // a well-formed record by then
      const retired = [...timeline.values()].filter((k) => Number.isInteger(seq) && k.until !== null && k.until < seq);
      if (retired.length && !await verifyRecord(r, retired.map((k) => k.spki), trust.algs))
        problems.push(`seq ${seq}: signed by key ${cut(r.kid, 80)} after its key.retire`);
      else problems.push(`seq ${repr(get(get(r, "event", {}), "seq"))}: ${err}`);
      return;
    }
    const e = r.event;
    const errs = get(e, "schema_version") === "tracekit.event.v2" ? validateEvent(e, floats) : ["not a tracekit.event.v2 event"];
    problems.push(...errs.map((x) => `seq ${repr(get(e, "seq"))}: ${x}`));
    if (!errs.length && !same(get(e, "log_id"), logId)) problems.push(`seq ${e.seq}: another log's record`);
  };

  let last = -1;
  for (const r of keyRecords) {
    const e = at(r, "event");
    if (!KEY_TYPES.includes(at(e, "type")) || num(at(e, "seq")) <= last || !await included(r)) {
      keyProblems.push(`seq ${str(at(e, "seq"))}: not a key record of the checkpointed tree, in order`);
      continue;
    }
    last = e.seq;
    const declared = new Map<J, Key>();
    if (e.type === "signer.epoch") {
      for (const k of list(get(at(e, "data"), "keys", []))) {
        const der = b64decode(at(k, "spki"));
        if (await spkiKid(der) !== at(k, "kid") || keyAlg(der) !== at(k, "alg"))
          keyProblems.push(`seq ${e.seq}: key ${str(k.kid)} does not match its SPKI`);
        if (!has(k, "cert") && trust.issuers.length && !truthy(get(e.data, "bridge"))) {
          keyProblems.push(`seq ${e.seq}: key ${cut(str(k.kid), 80)} has no certificate, and the trust config pins issuers`);
          continue;
        }
        // lean: a certified key is taken as declared and the bundle left UNVERIFIABLE; port docs/issuer.md's checks
        // (issuance log notes, validity, tenants, revocations) when certified record keys are in use
        if (has(k, "cert")) rep.unsupport("record-key certificates");
        declared.set(k.kid, { spki: der, from: e.seq, until: null });
      }
    }
    await checkRecord(r, [...keysAt(e.seq), ...[...declared.values()].map((k) => k.spki)], keyProblems);
    if (e.type === "key.retire") {
      const kid = at(at(e, "data"), "kid");
      if (!timeline.has(kid)) keyProblems.push(`seq ${e.seq}: retires an unknown key`);
      else timeline.get(kid)!.until = at(e.data, "last_seq");
    }
    for (const [kid, k] of declared) timeline.set(kid, k);
  }

  // the runs: one, or with a run-set any number
  const names = [...files.keys()].filter((n) => n.startsWith("runs/")).sort();
  const runSet = files.has("registry/run-set.json");
  if (names.length !== 1 && !runSet) throw new Error("a v2 bundle holds exactly one run, or a run-set");
  const runs = new Map<string, J[]>(), problems: string[] = [], chain: string[] = [], outside: string[] = [];
  for (const name of names) {
    const records = jsonl(name);
    runs.set(name, records);
    if (!records.length) throw new Error("a run has no records");
    const head = at(records[0], "event");
    for (const [i, r] of records.entries()) {
      await checkRecord(r, keysAt(num(at(at(r, "event"), "seq"))), problems);
      const e = r.event, prev = i ? records[i - 1] : null;
      if (!same(get(e, "run_seq"), i) || !same(get(e, "run_prev_hash"), prev ? at(prev, "hash") : ZERO_HASH)
          || !same([get(e, "tenant"), get(e, "run_id")], [get(head, "tenant"), get(head, "run_id")])
          || prev && (num(at(e, "seq")) <= num(at(at(prev, "event"), "seq")) || get(prev.event, "type") === "run.final"))
        chain.push(`run ${repr(cut(str(get(head, "run_id")), 200))} run_seq ${i} (seq ${repr(get(e, "seq"))}) does not `
          + "continue the run");
    }
    if (!(await included(records[0]) && await included(records.at(-1)))) outside.push(`run ${repr(cut(str(get(head, "run_id")), 200))}`);
  }
  let retired: [number, string][] = [], provenTo = -1, regCosigs: [string, bigint][][] = [];
  if (runSet) {
    [retired, provenTo, regCosigs] = await checkRunSet(rep, json("registry/run-set.json"), jsonl, file, trust, witnesses,
      origin, size, runs, included, (r, p) => checkRecord(r, keysAt(num(at(at(r, "event"), "seq"))), p));
    const keyed = new Set(keyRecords.map((r) => `${at(at(r, "event"), "seq")} ${at(r, "hash")}`));
    keyProblems.push(...retired.filter(([seq, h]) => !keyed.has(`${seq} ${h}`))
      .map(([seq]) => `seq ${seq}: key.retire withheld (the registry log has it)`));
  }
  rep.check("keys", timeline.size > 0 && !keyProblems.length, `${timeline.size} record key(s) from ${keyRecords.length} key `
    + "record(s)", keyProblems);
  const every = [...runs.values()].flat();
  const seqs = [...keyRecords, ...every].map((r) => num(at(at(r, "event"), "seq")));
  if (!seqs.length) throw new Error("max() arg is an empty sequence");
  const relied = Math.max(...seqs);
  if (provenTo < relied)
    rep.check("keys", false, "retirements not proven complete",
      [`no run-set from registry size 0 reaches seq ${relied}, so a withheld key.retire would not show`], true);
  const bridge = keyRecords.map((r) => r.event).find((e) => e.type === "signer.epoch" && has(at(e, "data"), "bridge"));
  if (bridge && truthy(bridge.data.bridge))
    rep.notes.push(`this log continues the v1 ledger of key ${str(at(bridge.data.bridge, "v1_kid"))}; pass the v1 ledger and `
      + "its signer.pub to the reference verifier to check the format bridge");
  rep.check("signatures", !problems.length, `${every.length} record(s), keys valid at their position`, problems);
  const only = runs.size === 1 ? [...runs.values()][0][0].event : null;
  rep.check("run chain", !chain.length, only ? `run ${repr(cut(str(get(only, "run_id")), 200))} of tenant `
    + `${repr(get(only, "tenant"))}, contiguous from run_seq 0` : `${runs.size} run(s), each contiguous from run_seq 0`, chain);
  rep.check("inclusion", !outside.length, `first and last records of ${runs.size} run(s) are in the checkpointed tree of `
    + `size ${size}`, outside);
  for (const p of [...files.keys()].filter((n) => n.startsWith("policies/")).sort())
    rep.check("policy snapshot", p === `policies/${await sha256hex(file(p))}.json`, p);

  const open = [...runs.values()].filter((rs) => get(rs.at(-1).event, "type") !== "run.final");
  rep.integrity = !open.length ? "VERIFIED" : only ? `VERIFIED TO HEAD ${str(get(open[0].at(-1).event, "run_seq"))} (open)`
    : `VERIFIED (${open.length} run(s) open)`;
  const events = every.map((r) => r.event), typed = (t: string) => events.filter((e) => get(e, "type") === t);
  const selfApproved = typed("approval").some((e) => get(at(e, "data"), "self_approved") === true);
  const gaps = (k: string) => typed("capture.gap").filter((e) => get(at(e, "data"), "kind") === k)
    .map((e) => `seq ${e.seq}: ${cut(str(get(e.data, "reason")), 200)}`);
  const against = gaps("executed_against_policy");
  if (against.length)
    rep.check("policy", false, `${against.length} tool call(s) ran against a deny or an unapproved ask`, against.slice(0, 20), true);
  const external = typed("policy.external").map((e) => at(e, "data")), mismatched = gaps("decision_mismatch");
  if (external.length || mismatched.length) {
    const systems = count(external.map((d) => cut(str(at(d, "system")), 64)));
    const verified = external.filter((d) => at(d, "signature") === "verified").length;
    rep.check("external decisions", !mismatched.length, `${external.length} imported: `
      + (systems.map(([k, n]) => `${k} ${n}`).join(", ") || "none") + `; signatures verified ${verified}, unverified `
      + `${external.length - verified}; ${mismatched.length} disagree with the signer`, mismatched.slice(0, 20), true);
  }
  const finals = [...runs.values()].map((rs) => rs.at(-1).event)
    .filter((e) => get(e, "type") === "run.final" && has(at(e, "data"), "coverage")).map((e) => e.data.coverage);
  const reconciles = events.filter((e) => str(get(e, "type")).startsWith("reconcile."));
  if (finals.length || reconciles.length) {
    const unreconciled = count(reconciles.map((e) => e.type.slice("reconcile.".length)));
    const layers = [...new Set(finals.flatMap((c) => list(at(c, "layers"))))].sort();
    rep.check("coverage", !reconciles.length, `layers ${layers.join("+") || "none"}` + (layers.includes("L3") ? "" : " (L3 absent)")
      + `; ${finals.reduce((n, c) => n + num(at(c, "reconciled")), 0)} call(s) reconciled; unreconciled: `
      + (unreconciled.map(([k, n]) => `${k} ${n}`).join(", ") || "none"),
    reconciles.map((e) => `seq ${e.seq}: ${e.type} ${cut(str(get(e, "tool_call_id")), 200)}: `
      + cut(str(get(at(e, "data"), "detail")), 200)).slice(0, 20), true);
  }
  const tiers = new Map<string, J>();   // (run, tool_call_id) -> the tier any of its records names
  for (const e of events) {
    if (get(e, "tool_call_id") === null) continue;
    const k = JSON.stringify([get(e, "run_id"), e.tool_call_id]);
    tiers.set(k, truthy(tiers.get(k)) ? tiers.get(k) : get(e, "tier"));
  }
  if (tiers.size) {
    const n = (t: J) => [...tiers.values()].filter((x) => x === t).length;
    rep.check("tiers", true, `${tiers.size} tool call(s): ` + ["T1", "T2", "T3"].map((t) => `${t} ${n(t)}`).join(", ")
      + (n(null) ? `, untiered ${n(null)}` : ""));
  }
  const sources = events.filter((e) => has(e, "args_source")).map((e) => e.args_source);
  if (sources.length)
    rep.check("args source", true, `${sources.length} record(s): `
      + ["raw", "parsed", "coerced"].map((s) => `${s} ${sources.filter((x) => x === s).length}`).join(", "));
  const firsts = [...runs.values()].map((rs) => rs[0].event);
  const registered = firsts.map((e) => get(e, "type") === "run.registered" ? at(e, "data") : {});
  rep.check("isolation", true, "signer-reported: " + count(registered.map((d) => cut(str(get(d, "signer_isolation",
    "unreported")), 64))).map(([k, n]) => `${k} ${n} run(s)`).join(", "));
  const principals = firsts.filter((e) => get(e, "type") === "run.registered" && has(e, "principal"))
    .map((e) => `${cut(str(e.principal), 256)} (${get(e, "principal_attested") === true ? "attested" : "app-asserted"})`);
  if (principals.length)
    rep.check("principals", true, principals.slice(0, 20).join(", ") + (principals.length > 20 ? ", ..." : ""));
  if (registered.some((d) => has(d, "harness"))) {
    const bound = firsts.map((e, i) => `${cut(str(get(e, "run_id")), 200)} `
      + (isObj(get(registered[i], "harness")) ? cut(str(get(registered[i].harness, "name")), 64) : "none"));
    rep.check("harness", true, "signer-attested: " + bound.slice(0, 20).join(", ") + (bound.length > 20 ? ", ..." : ""));
  }
  const failOpen = [...new Set(registered.flatMap((d) => {
    const modes = get(d, "fail_modes");
    if (!truthy(modes)) return [];
    if (!isObj(modes)) throw new TypeError("fail_modes is not an object");
    return Object.entries(modes).filter(([, m]) => m === "open").map(([c]) => cut(c, 64));
  }))].sort();
  rep.check("fail-open classes", true, failOpen.join(", ") || "none");
  rep.check("key assurance", true, "asserted: the log declares its record keys; none is attested");
  const algs = new Set([...every, ...keyRecords].map((r) => text(at(r, "alg"))));
  rep.assurance = await assurance(origin, cosigs, witnesses, trust, algs, selfApproved, regCosigs)
    + (provenTo < relied ? "; key retirements not proven complete" : "");
  const glass = typed("approval").filter((e) => get(at(e, "data"), "break_glass") === true);
  if (glass.length)
    rep.check("break-glass approvals", false, `${glass.length} approval(s) answered under the break-glass role`,
      glass.map((e) => `seq ${e.seq}: ${str(at(e.data, "decision"))} ${str(get(e.data, "approval_id"))} by `
        + `${cut(text(at(e.data, "approver")), 256)}: ${repr(cut(str(get(e.data, "reason")), 200))}`).slice(0, 20), true);
}

/** §4: null when `r` is a v2 record signed by one of `keys` (SPKI DER) with an allowed algorithm that is the key's own,
 * else why not. */
export async function verifyRecord(r: J, keys: Uint8Array[], algs: string[]): Promise<string | null> {
  if (!isObj(r) || Object.keys(r).length !== 6 || !["v", "event", "hash", "alg", "kid", "sig"].every((k) => Object.hasOwn(r, k))
      || !same(r.v, 2) || !isObj(r.event) || !["hash", "alg", "kid", "sig"].every((k) => typeof r[k] === "string"))
    return "not a v2 record";
  let h: string;
  try {
    h = "sha256:" + await sha256hex(bytes(canonicalize(r.event)));
  } catch (e) {
    return `event is not canonical JSON: ${(e as Error).message}`;
  }
  if (r.hash !== h) return "hash does not match the event";
  if (!algs.includes(r.alg)) return `algorithm ${repr(r.alg)} is not allowed`;
  let key: Uint8Array | undefined;
  for (const k of keys) if (await spkiKid(k) === r.kid) key = k;
  if (!key) return "unknown kid";
  if (keyAlg(key) !== r.alg) return `algorithm ${repr(r.alg)} is not the key's algorithm`;
  let sig: Uint8Array;
  try {
    sig = b64decode(r.sig);
  } catch {
    return "sig is not base64";
  }
  const position = Object.fromEntries(["log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash"]
    .map((k) => [k, Object.hasOwn(r.event, k) ? r.event[k] : null]));
  const message = canonicalize({ ...position, alg: r.alg, kid: r.kid, hash: h, t: "tracekit.record.v2" });
  return await verifyV2(r.alg, key, bytes(message), sig) ? null : "bad signature";
}

/** §7: the run-set line (COMPLETE or INCOMPLETE) and the log tail line. Returns the (seq, hash) of every key.retire the
 * range points to, the highest seq it points to when it starts at registry size 0 (else -1), and the pinned
 * cosignatures of each registry note. */
async function checkRunSet(rep: Report, rs: J, jsonl: (n: string) => J[], file: (n: string) => Uint8Array, trust: Trust,
  witnesses: Map<string, string>, origin: string, size: number, runs: Map<string, J[]>,
  included: (r: J) => Promise<boolean>, checkRecord: (r: J, p: string[]) => Promise<void>,
): Promise<[[number, string][], number, [string, bigint][][]]> {
  const problems: string[] = [], tsalt = b64decode(at(rs, "tenant_salt"));
  const lo = at(rs, "from"), hi = at(rs, "to"), regOrigin = await registryOrigin(origin, tsalt);
  const span = `registry ${str(lo)}..${str(hi)}`;
  // the registry notes are signed by the record log's own pinned key, under the registry origin
  const vkeys: string[] = [];
  for (const k of trust.logs) {
    const p = await parseVkey(k);
    if (p.name === origin) vkeys.push(await vkey(regOrigin, p.type, p.pub));
  }
  const roots = new Map<number, Uint8Array>(), regCosigs: [string, bigint][][] = [];
  for (const n of [...new Set([num(lo), num(hi)])].filter((n) => n !== 0).sort((a, b) => a - b)) {
    let got: J;
    try {
      const note = await openNote(file(`checkpoints/registry-${n}.note`), vkeys, [...witnesses.keys()]);
      got = note.size;
      roots.set(n, note.root);
      regCosigs.push(note.cosigs);
      if (note.unchecked) rep.unsupport("SLH-DSA-SHA2-128s checkpoint signature");
      if (note.cosigs.length < trust.witnesses_required)
        problems.push(`registry checkpoint at size ${n}: ${note.cosigs.length} pinned cosignature(s), `
          + `${trust.witnesses_required} required`);
    } catch (e) {
      got = `unusable (${errorText(e)})`;
    }
    if (got !== n) problems.push(`registry checkpoint at size ${n}: ${got}`);
  }
  if (problems.length || !(0 <= lo && lo <= hi) || hi === 0) {
    rep.check("run-set", false, `INCOMPLETE, ${span}`, problems.length ? problems : [`bad registry range ${lo}..${hi}`]);
    return [[], -1, regCosigs];
  }
  if (0 < lo && lo < hi && !await verifyConsistency(lo, hi, roots.get(lo)!, roots.get(hi)!, list(at(rs, "consistency")).map(b64decode)))
    problems.push(`registry checkpoint ${lo} is not a prefix of ${hi}`);
  const leaves = list(at(rs, "leaves"));
  const pointed = new Map<number, J>(jsonl("registry/records.jsonl").map((r) => [at(at(r, "event"), "seq"), r]));
  if (leaves.length !== hi - lo) problems.push(`${hi - lo} leaves in ${lo}..${hi}, ${leaves.length} in the bundle: a leaf is missing`);
  const registered = new Map<J, J>(), finals = new Map<J, J>(), retired: [number, string][] = [], targets = new Set<string>();
  const gaps = new Map<string, number>();
  let closed: J = null, tenant: J = null, top = -1;
  for (const [j, x] of leaves.slice(0, hi - lo).entries()) {
    const i = lo + j, leaf = b64decode(at(x, "leaf"));
    if (!await verifyInclusion(i, hi, await leafHash(leaf), list(at(x, "inclusion")).map(b64decode), roots.get(hi))) {
      problems.push(`leaf ${i} is not in the registry tree of size ${hi}`);
      continue;
    }
    const { type, runHash: rh, logId, seq, hash } = parseLeaf(leaf);
    const r = pointed.get(seq) ?? null, e = r && truthy(r) ? at(r, "event") : r;
    if (r === null || at(r, "hash") !== hash || at(e, "type") !== type || at(e, "log_id") !== logId || !await included(r)
        || !equal(await runHash(tsalt, text(at(e, "run_id"))), rh)
        || !SIGNER_LEAVES.includes(type) && tenant !== null && !same(tenant, at(e, "tenant"))) {
      problems.push(`leaf ${i} points to a missing or different record (seq ${seq})`);
      continue;
    }
    await checkRecord(r, problems);
    top = Math.max(top, seq);
    if (type === "run.registered" || type === "run.final") targets.add(await runName(at(e, "tenant"), e.run_id));
    if (type === "run.registered") {
      tenant = e.tenant;
      registered.set(e.run_id, r);
    } else if (type === "run.final") {
      tenant = e.tenant;
      if (finals.has(e.run_id)) problems.push(`a second run.final for run ${repr(cut(e.run_id, 200))} (seq ${seq})`);
      finals.set(e.run_id, r);
    } else if (type === "key.retire") retired.push([seq, hash]);
    else if (type === "log.closed") closed = e;
    else {
      const k = at(at(e, "data"), "kind");
      gaps.set(k, (gaps.get(k) ?? 0) + 1);
    }
  }
  for (const [runId, final] of finals) {
    const recs = runs.get(await runName(tenant, runId));
    if (!recs?.length || at(recs.at(-1), "hash") !== at(final, "hash")
        || registered.has(runId) && at(recs[0], "hash") !== at(registered.get(runId), "hash"))
      problems.push(`run ${repr(cut(runId, 200))} is final in the range but its records are not in the bundle`);
  }
  if ([...runs.values()].some((rs) => !same(get(at(rs[0], "event"), "tenant"), tenant)))
    problems.push("a run in the bundle is not of the run-set's tenant");
  const untargeted = [...runs.keys()].filter((n) => !targets.has(n)).length;
  if (untargeted > 1) problems.push(`${untargeted} runs in the bundle, but only the selected run may be in no leaf of the range`);
  if (truthy(closed) && size > num(at(at(closed, "data"), "final_seq")) + 1)
    problems.push(`records after log.closed at seq ${str(at(closed, "seq"))}`);
  const counted = [...gaps].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, n]) => `${k} ${n}`).join(", ");
  const named = tenant === null ? "" : ` of tenant ${repr(cut(tenant, 64))}`;
  const open = [...registered.keys()].filter((k) => !finals.has(k)).length;
  rep.check("run-set", !problems.length, !problems.length ? `COMPLETE, ${span}${named} (${registered.size} runs registered, `
    + `${finals.size} final, ${open} open` + (gaps.size ? `; tenant-level gaps: ${counted}` : "") + ")" : `INCOMPLETE, ${span}`,
  problems);
  if (gaps.size) rep.check("tenant-level gaps", false, `${[...gaps.values()].reduce((a, b) => a + b, 0)} in the range: ${counted}`,
    [], true);
  rep.check("log tail", truthy(closed), truthy(closed) ? `none: log.closed at seq ${str(closed.seq)} is the last record`
    : `records after tree size ${size} are unproven (no log.closed in the range)`, [], true);
  return [retired, lo === 0 ? top : -1, regCosigs];
}

const runName = async (tenant: J, runId: J) => `runs/${(await sha256hex(bytes(`${str(tenant)}/${str(runId)}`))).slice(0, 32)}.jsonl`;

const LEVELS = ["dev", "local", "witnessed"];

function level(cosigs: [string, bigint][], witnesses: Map<string, string>, trust: Trust) {
  const independent = cosigs.filter(([k]) => witnesses.get(k) !== "operator").length;
  return independent >= Math.max(1, trust.witnesses_required) ? "witnessed" : cosigs.length ? "local" : "dev";
}

/** dev: no pinned witness cosigned, or a self-approval in the run; local: only operator-run ones; witnessed: enough
 * independent ones. A run-set's registry notes cap the level by the same rule. */
async function assurance(origin: string, cosigs: [string, bigint][], witnesses: Map<string, string>, trust: Trust,
  algs: Set<string>, selfApproved: boolean, registryNotes: [string, bigint][][]) {
  let hybrid = false;
  for (const k of trust.logs) {
    const p = await parseVkey(k);
    hybrid ||= p.name === origin && p.type === HYBRID;
  }
  const times = cosigs.filter(([k]) => witnesses.get(k) !== "operator").map(([, ts]) => ts);
  let lvl = selfApproved ? "dev" : level(cosigs, witnesses, trust);
  let capped: string | null = registryNotes.map((c) => level(c, witnesses, trust))
    .reduce((a, b) => LEVELS.indexOf(b) < LEVELS.indexOf(a) ? b : a, "witnessed");
  if (LEVELS.indexOf(capped) < LEVELS.indexOf(lvl)) lvl = capped;
  else capped = null;
  const cosigned = [...cosigs].sort((a, b) => a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0)
    .map(([k, ts]) => `${k.split("+")[0]} (${witnesses.get(k)}) at ${fmt(ts)}`).join(", ");
  return `${lvl}; records ${[...algs].sort().join("+")}; checkpoint ${hybrid ? "Ed25519 + SLH-DSA-SHA2-128s" : "Ed25519 only"} `
    + `(${origin})` + (cosigned ? `; cosigned ed25519 by ${cosigned}` : "; no witness cosignature")
    + (times.length ? `; earliest independent anchor ${fmt(times.reduce((a, b) => b < a ? b : a))}` : "")
    + (capped ? `; capped by the run-set's registry notes (${capped})` : "") + (selfApproved ? "; approvals: self" : "");
}

/** The report as text, as the reference CLI prints it; control characters in bundle-derived strings are dropped. */
export function formatReport(rep: Report): string {
  const clean = (x: string) => x.replace(/[\x00-\x1f\x7f-\x9f]/g, "");
  let s = "";
  for (const c of rep.checks) {
    s += `[${c.status.toUpperCase()}] ${c.check}` + (c.detail ? ` — ${clean(c.detail)}` : "") + "\n";
    for (const p of c.problems) s += `        ${clean(p)}\n`;
  }
  return s + `\nIntegrity: ${clean(rep.integrity)}.\nAssurance: ${clean(rep.assurance)}.\n`;
}

