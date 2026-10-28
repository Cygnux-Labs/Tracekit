/**
 * An independent verifier of `tracekit.bundle.v2` bundles, written from docs/format-v2.md (§11 is the algorithm) and
 * checked against the reference (tracekit/verify/v2.py) by tests/test_ts_verifier.py: same checks, integrity, assurance
 * and exit codes. Web Crypto and DecompressionStream only, so it runs in Node ≥ 20 and current browsers.
 *
 *     import { verify } from "@cygnuxlabs/tracekit/verify";
 *     const { report, code } = await verify(bundleBytes, trustConfigBytes);
 *
 * Not implemented here, so never VERIFIED when a bundle relies on them (integrity `UNVERIFIABLE (...)` names them):
 * SLH-DSA-SHA2-128s hybrid checkpoint lines (Web Crypto has no SLH-DSA), Rekor v2 anchors, record-key certificates,
 * tracekit why findings and replay runs.
 * Monitor reports, revocations and the v1 format bridge are inputs of the reference's CLI that this one doesn't take.
 * A bundle that needs a newer verifier is UNVERIFIABLE, with the commands that verify it; one whose records carry ext
 * names this verifier doesn't interpret (format 1.4's non-critical slot) verifies, with a `not interpreted` warning
 * per name; it interprets `amended` (the fields an LLM gateway changed in a request to show reasoning) and
 * `openshell.policy` (OpenShell's sandbox policy changes, from the OpenShell middleware's OCSF import).
 * `verify(bundle, null)` (no trust config) checks what needs no pinned key and is never VERIFIED. web.ts is this
 * verifier as a browser page (verify.html).
 */
import { type Floats, canonicalize, repr as quoted, strictParseBytes } from "./jcs.js";
import {
  HYBRID, NoteError, SIGNER_LEAVES, b64decode, bytes, equal, keyAlg, leafHash, openNote, parseLeaf, parseVkey,
  registryOrigin, runHash, sha256hex, spkiKid, unhex, verifyConsistency, verifyInclusion, verifyV2, vkey,
} from "./primitives.js";
import { Detector } from "./detect.js";
import { same, validateEvent } from "./schema.js";
import { MAX_ENTRY, Unusable, readZip } from "./zip.js";

export { MAX_ENTRIES, MAX_ENTRY, MAX_TOTAL, Unusable, readZip } from "./zip.js";
export { StrictJSONError, canonicalize, strictParse, strictParseBytes } from "./jcs.js";

/** The bundle format version this verifier implements: a bundle needing a later one is UNVERIFIABLE. */
export const VERSION = "1.5.0";
/** The browser verifier of the latest release (docs/RELEASING.md). */
const PAGE = "https://cygnux-labs.github.io/Tracekit/verify/";
export const EXIT_OK = 0, EXIT_FAIL = 1, EXIT_BAD = 2, EXIT_WARN = 3;
const FORMAT = "tracekit.bundle.v2";
const MAX_LINE = 1 << 20;
const MIN_RECORD = 256;   // no signed record's line is shorter: its hash, signature, ids and timestamp alone are longer
const MAX_LINES = MAX_ENTRY / MIN_RECORD;   // per JSON lines file
const CLASSES = ["public", "customer", "tracekit", "operator"];
const KEY_TYPES = ["signer.epoch", "key.retire"];
const ZERO_HASH = "sha256:" + "0".repeat(64);
const MATRIX = ["model_calls", "tool_calls", "network", "processes", "services"];
const COVERED = ["none", "reported", "observed", "enforced"];   // weakest first
const SEVERITIES = ["critical", "high", "medium", "low", "info"];   // a signed finding's, worst first
// the closed fields of a signed finding's verdict (tracekit/signer/rpc_schema.py REVIEW) and the values each may take
const FAMILIES = ["anthropic", "openai", "google", "meta", "mistral", "deepseek", "qwen", "xai"];
const VERDICT: Record<string, J[]> = {
  kind: ["finding", "coverage"], severity: SEVERITIES, tier: ["gateway", "harness", "transcript", "sdk"],
  order: ["signed_before", "transcript_order", "after"], alignment: ["ok", "drift", "misaligned"],
  reason: ["none", "unrequested_action", "unexplained_action", "contradicted_reasoning", "scope_creep", "workaround",
    "false_success", "followed_tool_output", "injection", "other"],
};

/** The reference verifier's exception names, which reports print: a bundle the format refuses, a key it lacks. */
class ValueError extends Error {}
class KeyError extends Error {}

export type Check = { check: string; status: "pass" | "warn" | "fail"; detail: string; problems: string[] };

export class Report {
  checks: Check[] = [];
  failures: string[] = [];
  warnings: string[] = [];
  notes: string[] = [];
  integrity = "UNUSABLE BUNDLE";
  assurance = "none";
  /** The Findings line: signed findings, an opinion of the run kept apart from its integrity (null: none). */
  findings: string | null = null;
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

/** The manifest check's detail: on a failure, the files that differ from the manifest (the first 5) and how. */
function manifestDetail(listed: J | undefined, hashes: Map<string, string>, bad: string[]): string {
  if (!isObj(listed)) return "the manifest lists no files";
  if (bad.length === 0) return "every file is listed with its SHA-256 and nothing else is in the bundle";
  const how = bad.slice(0, 5).map((n) => `${n} (${Object.hasOwn(listed, n) && hashes.has(n) ? "changed"
    : Object.hasOwn(listed, n) ? "missing" : "not listed"})`);
  return "files differ from the manifest: " + how.join(", ") + (bad.length > 5 ? ` and ${bad.length - 5} more` : "");
}
const kind = (v: unknown) => v === null ? "null" : Array.isArray(v) ? "array" : typeof v;
function at(o: unknown, k: string): J {
  if (!isObj(o)) throw new TypeError(`${kind(o)} is not an object`);
  if (!Object.hasOwn(o, k)) throw new KeyError(repr(k));
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
const repr = (v: unknown) => typeof v === "string" ? quoted(v) : str(v);
const cut = (s: string, n: number) => [...s].slice(0, n).join("");
/** `xs` appended to `to` one by one: a spread call (`push(...xs)`, `Math.max(...xs)`) puts every element on the stack,
 * which a bundle of 60k records overflows. */
const extend = <T>(to: T[], xs: Iterable<T>) => {
  for (const x of xs) to.push(x);
};
/** Python's order of strings, by code point (JavaScript's `<` and sort() compare UTF-16 code units, which put a
 * character above U+FFFF before one in U+E000..U+FFFF). */
const byCodePoint = (a: string, b: string) => {
  const unit = (u: number) => u >= 0xd800 && u < 0xe000 ? u + 0x2000 : u >= 0xe000 ? u - 0x800 : u;
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a.charCodeAt(i) !== b.charCodeAt(i)) return unit(a.charCodeAt(i)) - unit(b.charCodeAt(i));
  return a.length - b.length;
};
const byKey = ([a]: [string, unknown], [b]: [string, unknown]) => byCodePoint(a, b);
const count = (xs: string[]) => {
  const m = new Map<string, number>();
  for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
  return [...m].sort(byKey);
};
const fmt = (ts: bigint | number) => {
  if (ts > 253402300799) throw new RangeError("year is out of range");
  return new Date(Number(ts) * 1000).toISOString().slice(0, 19) + "Z";
};

type Trust = { logs: string[]; witnesses: { vkey: string; class: string }[]; algs: string[]; witnesses_required: number;
  rekor?: Record<string, J>; issuers: J[]; analyzers: string[] };

async function loadTrust(data: Uint8Array, name: string): Promise<Trust> {
  const floats: Floats = new WeakMap();
  const t: J = strictParseBytes(data.subarray(0, MAX_LINE), floats);
  const int = (o: Record<string, J>, k: string, d: number) => !Object.hasOwn(o, k) ? d
    : Number.isInteger(o[k]) && !floats.get(o)?.has(k) ? o[k] : NaN;
  const exactly = (o: unknown, ks: string[]) => isObj(o) && Object.keys(o).length === ks.length && ks.every((k) => Object.hasOwn(o, k));
  const strings = (a: unknown) => Array.isArray(a) && a.length > 0 && a.every((x) => typeof x === "string");
  const opt = (o: Record<string, J>, k: string) => Object.hasOwn(o, k) ? o[k] : [];
  const r = isObj(t) ? get(t, "rekor", {}) : null;
  const ok = isObj(t) && Object.keys(t).every((k) => ["logs", "witnesses", "algs", "witnesses_required", "rekor",
    "monitors", "issuers", "analyzers"].includes(k))
    && isObj(r) && (!Object.keys(r).length || exactly(r, ["trusted_root", "publishing_key", "class"])
      && isObj(r.trusted_root) && typeof r.publishing_key === "string" && CLASSES.includes(r.class))
    && strings(t.logs)
    && Array.isArray(opt(t, "witnesses")) && opt(t, "witnesses").every((w: J) => exactly(w, ["vkey", "class"])
      && typeof w.vkey === "string" && CLASSES.includes(w.class))
    && strings(t.algs) && int(t, "witnesses_required", 0) >= 0
    && Array.isArray(opt(t, "monitors")) && opt(t, "monitors").every((m: J) => exactly(m, ["vkey", "class", "max_age_s"])
      && typeof m.vkey === "string" && CLASSES.includes(m.class) && int(m, "max_age_s", 0) > 0)
    && Array.isArray(opt(t, "issuers")) && opt(t, "issuers").every((i: J) => exactly(i, ["vkey", "issuance_log_vkey"])
      && Object.values(i).every((v) => typeof v === "string"))
    && Array.isArray(opt(t, "analyzers"))
    && opt(t, "analyzers").every((a: J) => typeof a === "string" && /^[a-z0-9_]+:.+$/.test(a));
  if (!ok) throw new ValueError(`${name}: not a v2 trust config (logs, witnesses, algs, witnesses_required, rekor, monitors, `
    + "issuers, analyzers)");
  for (const k of [...t.logs, ...opt(t, "witnesses").map((w: J) => w.vkey), ...opt(t, "monitors").map((m: J) => m.vkey),
    ...opt(t, "issuers").flatMap((i: J) => Object.values(i))]) await parseVkey(k);
  t.witnesses ??= [];
  t.witnesses_required ??= 0;
  t.issuers ??= [];
  t.analyzers ??= [];
  return t as Trust;
}

/** `s` as one shell argument, as the reference quotes it (shlex.quote; on Windows subprocess.list2cmdline). */
function quote(s: string) {
  if ((globalThis as J).process?.platform === "win32") return /[ \t]/.test(s) || !s ? `"${s}"` : s;
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'"'"'`)}'`;
}

/** Ways to verify the bundle with a verifier of version `need` or later, as commands with the user's own paths. */
function upgrade(need: string, names: { bundle: string; trust: string }) {
  const [b, t] = [quote(names.bundle), quote(names.trust)];
  return [`npx -y @cygnuxlabs/tracekit@latest verify ${b} --trust ${t}`,
    `uvx --from "tracekit-ai>=${need}" tracekit verify ${b} --trust ${t}`,
    `or open ${PAGE} and choose both files: the page verifies them in your browser and sends nothing`];
}

function newer(need: string, have: string) {
  const a = need.split(".").map(Number), b = have.split(".").map(Number);
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] > b[i];
  return a.length > b.length;
}

const errorText = (e: unknown) => `${(e as Error)?.constructor?.name ?? "Error"}: ${(e as Error)?.message ?? e}`;

/** Without a trust config: the bundle against its own checkpoint, whose signature no pinned key checks. */
const UNANCHORED = "UNVERIFIABLE (no trust config: the records match their own checkpoint, which no pinned key checked)";

/**
 * Verify a v2 bundle (zip bytes) against the verifier's own pinned trust config (JSON bytes). Never throws. `names`: the
 * files' paths, for the commands a bundle that needs a newer verifier is told to run. `trust` null (the browser page,
 * when no trust config is chosen): every check that needs no pinned key, and never VERIFIED: a changed record still
 * FAILS, and an intact bundle is UNVERIFIABLE, since anyone can sign a bundle and its checkpoint with keys of their own.
 */
export async function verify(bundle: Uint8Array, trust: Uint8Array | null,
  names = { bundle: "BUNDLE", trust: "TRUST.json" }): Promise<{ report: Report; code: number }> {
  const rep = new Report();
  let t: Trust, files: Map<string, Uint8Array>, manifest: J, v1 = false;
  if (trust === null) {
    t = { logs: [], witnesses: [], algs: ["ed25519"], witnesses_required: 0, issuers: [], analyzers: [] };
    rep.check("trust config", false, "none: the checkpoint's signature and its witnesses are not checked, so nothing ties "
      + "these records to a signer you trust", [], true);
  } else try {
    t = await loadTrust(trust, names.trust);
  } catch (e) {
    rep.check("trust config", false, errorText(e));
    return { report: rep, code: EXIT_BAD };
  }
  const floats: Floats = new WeakMap();
  try {
    files = await readZip(bundle);
    const m = files.get("manifest.json");
    if (!m) throw new KeyError(repr("manifest.json"));
    files.delete("manifest.json");
    manifest = strictParseBytes(m, floats);
    v1 = isObj(manifest) && manifest.format === "tracekit.bundle.v1";
    if (!isObj(manifest) || manifest.format !== FORMAT) throw new Unusable(`format is not ${FORMAT}`);
    const need = manifest.verifier_min_version;
    if (!(typeof need === "string" && /^\d{1,9}(\.\d{1,9}){0,2}$/.test(need)))
      throw new Unusable("verifier_min_version is not a version number");
    if (newer(need, VERSION)) {
      rep.integrity = `UNVERIFIABLE (needs tracekit >= ${need})`;
      rep.check("bundle readable", false, rep.integrity, upgrade(need, names));
      return { report: rep, code: EXIT_BAD };
    }
  } catch (e) {
    // a format v1 bundle (the laptop signer's): the reference verifier checks it, against the signer.pub the sender pins
    rep.check("bundle readable", false, `cannot read bundle: ${errorText(e)}`, v1 ? ["a format v1 bundle: verify it with "
      + `the signer's public key (signer.pub, from the sender): uvx --from tracekit-ai tracekit verify ${quote(names.bundle)}`
      + " --key signer.pub"] : []);
    return { report: rep, code: EXIT_BAD };
  }
  try {
    await check(rep, manifest, files, t, floats);
  } catch (e) {
    rep.check("bundle structure", false, "", [`malformed and could not be fully checked: ${errorText(e)}`]);
  }
  if (rep.failures.length) rep.integrity = "FAILED";
  else if (trust === null) rep.integrity = UNANCHORED;
  else if (rep.unsupported.length) rep.integrity = `UNVERIFIABLE (not checked by this verifier: ${rep.unsupported.join(", ")})`;
  return { report: rep, code: rep.failures.length ? EXIT_FAIL : rep.integrity.startsWith("UNVERIFIABLE") ? EXIT_BAD : EXIT_OK };
}

type Key = { spki: Uint8Array; from: number; until: number | null };

async function check(rep: Report, manifest: J, files: Map<string, Uint8Array>, trust: Trust, floats: Floats) {
  const file = (name: string) => {
    const f = files.get(name);
    if (!f) throw new KeyError(repr(name));
    return f;
  };
  const json = (name: string) => strictParseBytes(file(name), floats);
  /** A JSON lines file's texts, each line at least MIN_RECORD bytes: checked before any is parsed, so a bundle's lines
   * can't outnumber MAX_TOTAL / MIN_RECORD, whatever it unzips to. */
  const jsonl = (name: string) => {
    const data = file(name);
    if (data.length && data.at(-1) !== 0x0a) throw new ValueError("a JSON lines file must end in a newline");
    const lines: Uint8Array[] = [];
    for (let i = 0, j; (j = data.indexOf(0x0a, i)) >= 0; i = j + 1) {
      // checked before any is parsed: a run of tiny lines costs no memory
      if (lines.length === MAX_LINES) throw new ValueError("more lines than the bundle limits");
      lines.push(data.subarray(i, j));
    }
    if (lines.some((l) => l.length > MAX_LINE)) throw new ValueError("line longer than the bundle limits");
    if (lines.some((l) => l.length < MIN_RECORD)) throw new ValueError("line shorter than a signed record");
    return lines.map((l) => strictParseBytes(l, floats) as J);
  };

  const listed = manifest.files, hashes = new Map<string, string>();
  for (const [n, b] of files) hashes.set(n, await sha256hex(b));
  const bad = isObj(listed) ? [...new Set([...Object.keys(listed), ...hashes.keys()])]
    .filter((n) => !(Object.hasOwn(listed, n) && hashes.get(n) === listed[n])).sort() : [];
  rep.check("manifest", isObj(listed) && bad.length === 0, manifestDetail(listed, hashes, bad));

  // the checkpoint: the only thing the records' trust hangs on
  const proofs = json("proofs/records.json");
  const name = at(proofs, "checkpoint");
  if (!(typeof name === "string" && name.startsWith("checkpoints/") && name.endsWith(".note")))
    throw new ValueError("proofs name no checkpoint note");
  const witnesses = new Map(trust.witnesses.map((w) => [w.vkey, w.class]));
  const anchored = trust.logs.length > 0;   // a trust config pins at least one log key
  let note;
  try {
    note = await openNote(file(name), trust.logs, [...witnesses.keys()], anchored);
  } catch (e) {
    if (!(e instanceof NoteError)) throw e;
    rep.check("checkpoint", false, e.message);
    return;
  }
  const { origin, size, root, cosigs } = note;
  rep.check("checkpoint", same(size, at(proofs, "tree_size")), `${origin} at tree size ${size}, `
    + (anchored ? "signed by its pinned log key" : "its signature not checked (no trust config)"));
  if (note.unchecked) rep.unsupport("SLH-DSA-SHA2-128s checkpoint signature");
  if (anchored)
    rep.check("witness quorum", cosigs.length >= trust.witnesses_required,
      `${cosigs.length} pinned cosignature(s), ${trust.witnesses_required} required`);
  if (truthy(trust.rekor) && files.has(`rekor/${size}.json`)) rep.unsupport("rekor anchor");

  const included = async (r: J) => {
    const seq = at(at(r, "event"), "seq");
    const path = get(at(proofs, "inclusion"), str(seq));
    return Array.isArray(path) && verifyInclusion(num(seq), size, await leafHash(unhex(text(at(r, "hash")).slice(7))),
      path.map(b64decode), root);
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

  // the runs: one, or with a run-set any number, or one with its findings runs (and replay runs)
  // lean: tracekit why findings (verify/v2.py's _findings) are not checked here: a bundle with a why.finding or a replay
  // run is UNVERIFIABLE; port it when TS users verify tracekit why bundles
  const names = runFiles(files.keys());
  const runSet = files.has("registry/run-set.json");
  const runs = new Map<string, J[]>(), problems: string[] = [], chain: string[] = [], outside: string[] = [];
  const layout: string[] = [], seen = new Set<string>();
  for (const [name, parts] of names) {
    const pieces = parts.map(jsonl), records = pieces.flat(), whole = parts.length === 1 && parts[0] === name;
    runs.set(name, records);
    extend(layout, parted(name, parts, pieces));
    if (!records.length) throw new ValueError("a run has no records");
    const head = at(records[0], "event"), tenant = get(head, "tenant"), runId = get(head, "run_id");
    if (typeof tenant === "string" && typeof runId === "string") {   // a second file of one run would count it twice
      const key = JSON.stringify([tenant, runId]);
      if (seen.has(key)) chain.push(`run ${repr(cut(runId, 200))} of tenant ${repr(cut(tenant, 64))} again in ${name}`);
      seen.add(key);
    }
    for (const [i, r] of records.entries()) {
      await checkRecord(r, keysAt(num(at(at(r, "event"), "seq"))), problems);
      const e = r.event, prev = i ? records[i - 1] : null;
      if (!same(get(e, "run_seq"), i) || !same(get(e, "run_prev_hash"), prev ? at(prev, "hash") : ZERO_HASH)
          || !same([get(e, "tenant"), get(e, "run_id")], [get(head, "tenant"), get(head, "run_id")])
          || prev && (num(at(e, "seq")) <= num(at(at(prev, "event"), "seq")) || get(prev.event, "type") === "run.final"))
        chain.push(`run ${repr(cut(str(get(head, "run_id")), 200))} run_seq ${i} (seq ${repr(get(e, "seq"))}) does not `
          + "continue the run");
    }
    if (!(await included(records[0]) && await included(records.at(-1))))
      outside.push(`run ${repr(cut(str(get(head, "run_id")), 200))}` + (!whole && await included(records[0])
        ? `: the last record of ${parts.at(-1)} is not in the checkpointed tree, so a later part may be missing` : ""));
  }
  const why = [...runs.values()].some((rs) => rs.some((r) => get(r.event, "type") === "why.finding") || about(rs)[1] !== null);
  if (why) rep.unsupport("tracekit why findings");
  else if (runs.size !== 1 && !runSet && !aboutOne(runs))
    throw new ValueError("a v2 bundle holds exactly one run, one run with its findings and replay runs, or a run-set");
  let retired: [number, string][] = [], provenTo = -1, regCosigs: [string, bigint][][] = [];
  if (runSet) {
    [retired, provenTo, regCosigs] = await checkRunSet(rep, json("registry/run-set.json"), jsonl, file, trust, witnesses,
      origin, size, runs, included, (r, p) => checkRecord(r, keysAt(num(at(at(r, "event"), "seq"))), p), floats);
    const keyed = new Set(keyRecords.map((r) => `${at(at(r, "event"), "seq")} ${at(r, "hash")}`));
    extend(keyProblems, retired.filter(([seq, h]) => !keyed.has(`${seq} ${h}`))
      .map(([seq]) => `seq ${seq}: key.retire withheld (the registry log has it)`));
  }
  rep.check("keys", timeline.size > 0 && !keyProblems.length, `${timeline.size} record key(s) from ${keyRecords.length} key `
    + "record(s)", keyProblems);
  const every = [...runs.values()].flat();
  const seqs = [...keyRecords, ...every].map((r) => num(at(at(r, "event"), "seq")));
  if (!seqs.length) throw new ValueError("the bundle holds no key or run records");
  const relied = seqs.reduce((a, b) => b > a ? b : a);
  const rotated = timeline.size > 1 || keyRecords.some((r) => get(r.event, "type") === "key.retire");
  if (provenTo < relied && rotated)   // one key never retired: the assurance line notes it, no warning
    rep.check("keys", false, "retirements not proven complete",
      [`no run-set from registry size 0 reaches seq ${relied}, so a withheld key.retire would not show`], true);
  const bridge = keyRecords.map((r) => r.event).find((e) => e.type === "signer.epoch" && has(at(e, "data"), "bridge"));
  if (bridge && truthy(bridge.data.bridge))
    rep.notes.push(`this log continues the v1 ledger of key ${str(at(bridge.data.bridge, "v1_kid"))}; pass the v1 ledger and `
      + "its signer.pub to the reference verifier to check the format bridge");
  const inParts = [...names].filter(([n, ps]) => !(ps.length === 1 && ps[0] === n)).map(([, ps]) => ps.length);
  if (inParts.length)
    rep.check("run parts", !layout.length, `${inParts.length} run(s) in ${inParts.reduce((a, b) => a + b, 0)} parts, `
      + "each part continuing the one before it", layout);
  rep.check("signatures", !problems.length, `${every.length} record(s), keys valid at their position`, problems);
  const only = runs.size === 1 ? [...runs.values()][0][0].event : null;
  rep.check("run chain", !chain.length, only ? `run ${repr(cut(str(get(only, "run_id")), 200))} of tenant `
    + `${repr(get(only, "tenant"))}, contiguous from run_seq 0` : `${runs.size} run(s), each contiguous from run_seq 0`, chain);
  rep.check("inclusion", !outside.length, `first and last records of ${runs.size} run(s) are in the checkpointed tree of `
    + `size ${size}`, outside);
  // policy_hash -> the bundled snapshot named by it: the one set checkIncidents and approvals check against
  const policies = new Map<string, Uint8Array>();
  for (const p of [...files.keys()].filter((n) => n.startsWith("policies/")).sort()) {
    const hex = await sha256hex(file(p));
    rep.check("policy snapshot", p === `policies/${hex}.json`, p);
    if (p === `policies/${hex}.json`) policies.set(`sha256:${hex}`, file(p));
  }

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
  const unresolved = gaps("held_call_unresolved");   // the signer's word that a held call ended its run without a result
  if (unresolved.length)
    rep.check("held calls", false, `${unresolved.length} tool call(s) a gateway or executor decided have no result`, unresolved.slice(0, 20), true);
  // capture.gap kinds that say nothing against a run's own records, and those warned on lines of their own
  const info = ["witness_late", "witness_failed", "degraded_unanchored", "clock_skew", "format_upgrade", "key_retired",
    "args_coerced", "approval_expired", "executed_against_policy", "held_call_unresolved", "decision_mismatch",
    "observer_lost"];
  const alarms = events.filter((e) => ["approval.binding_mismatch", "trace.tamper"].includes(get(e, "type"))
    || get(e, "type") === "capture.gap" && !info.includes(get(at(e, "data"), "kind")));
  if (alarms.length) {
    const kindOf = (e: J) => e.type === "capture.gap" ? cut(str(get(e.data, "kind")), 64) : e.type;
    rep.check("gaps", false, `${alarms.length} signed gap, tamper or mismatch record(s): `
      + count(alarms.map(kindOf)).map(([k, n]) => `${k} ${n}`).join(", "),
    alarms.map((e) => `seq ${e.seq}: ${kindOf(e)}: ` + (e.type === "approval.binding_mismatch"
      ? `approval ${cut(str(get(e.data, "approval_id")), 200)} of call ${cut(str(get(e.data, "tool_use_id")), 200)}`
        + ": the arguments differ from the approved ones"
      : cut(str(get(e.data, "reason", get(e.data, "path"))), 200))).slice(0, 20), true);
  }
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
  const paired = [...runs.values()].map((rs) => rs.at(-1).event).filter((e) => get(e, "type") === "run.final")
    .reduce((n, e) => n + num(get(e.data, "paired_by_args", 0)), 0);
  if (finals.length || reconciles.length) {
    const unreconciled = count(reconciles.map((e) => e.type.slice("reconcile.".length)));
    const layers = [...new Set(finals.flatMap((c) => list(at(c, "layers"))))].sort();
    rep.check("coverage", !reconciles.length, `layers ${layers.join("+") || "none"}` + (layers.includes("L3") ? "" : " (L3 absent)")
      + `; ${finals.reduce((n, c) => n + num(at(c, "reconciled")), 0)} call(s) reconciled`
      + (paired ? ` (${paired} paired by arguments: no tool-call id)` : "") + "; unreconciled: "
      + (unreconciled.map(([k, n]) => `${k} ${n}`).join(", ") || "none"),
    reconciles.map((e) => `seq ${e.seq}: ${e.type}`
      + (has(e, "tool_call_id") ? ` ${cut(str(e.tool_call_id), 200)}` : "")
      + `: ${cut(str(get(at(e, "data"), "detail")), 200)}`).slice(0, 20), true);
  }
  // the coverage matrix: per action class its weakest status across the runs, the layers behind it; never "complete"
  const matrices = [...runs.values()].map((rs) => rs.at(-1).event)
    .filter((e) => get(e, "type") === "run.final" && has(at(e, "data"), "matrix")).map((e) => e.data.matrix);
  if (matrices.length)
    rep.check("coverage matrix", true, (matrices.length > 1 ? `weakest of ${matrices.length} runs: ` : "")
      + MATRIX.map((k) => {
        const cs = matrices.map((m) => at(m, k));
        const status = cs.map((c) => str(at(c, "status"))).reduce((a, b) => COVERED.indexOf(b) < COVERED.indexOf(a) ? b : a);
        const layers = [...new Set(cs.flatMap((c) => list(at(c, "layers")).map(str)))].sort(byCodePoint)
          .concat(cs.some((c) => get(c, "asserted") === true) ? ["asserted"] : []);
        return `${k.replace("_", " ")} ` + (status === "none" ? "not covered"
          : status + (layers.length ? ` (${layers.join(", ")})` : ""));
      }).join(", "));
  const lost = gaps("observer_lost");
  if (lost.length)
    rep.check("observers", false, `${lost.length} observer gap(s): an observer went silent, restarted or lost events while its run was open`, lost.slice(0, 20), true);
  checkReviews(rep, runs, trust.analyzers);
  checkConstraints(rep, runs);
  checkIncidents(rep, runs, policies, floats);
  const accessed = typed("content.accessed").length, erased = typed("content.erased").length;
  if (accessed || erased)   // signer records of the content vault (docs/privacy.md): who read or erased retained content
    rep.check("content vault", true, `${accessed} access(es), ${erased} erasure(s) of retained content, each signed by the signer`);
  // a tool call's tier is the weakest its records claim (untiered < T3, receipt only, < T1 < T2): each tier a record
  // names, and untiered for a decision or result that names none, so a call decided at T2 and completed elsewhere
  // isn't T2;
  // paths: the (source, tier)s of its decisions and results, which differ only when another layer answered for it
  const order: J[] = [null, "T3", "T1", "T2"];
  const tiers = new Map<string, J>(), claims = new Map<string, J>(), paths = new Map<string, Set<string>>();
  for (const e of events) {
    if (get(e, "tool_call_id") === null) continue;
    const k = JSON.stringify([get(e, "run_id"), e.tool_call_id]);
    const decided = ["policy.decision", "tool.result"].includes(get(e, "type"));
    const tier = order.includes(get(e, "tier")) ? get(e, "tier") : null;
    tiers.set(k, null);
    if (tier !== null || decided) {
      const had = claims.has(k) ? claims.get(k) : tier;
      claims.set(k, order.indexOf(had) <= order.indexOf(tier) ? had : tier);
    }
    if (decided) paths.set(k, (paths.get(k) ?? new Set()).add(`${cut(str(get(e, "source")), 64)} ${tier ?? "untiered"}`));
  }
  for (const [k, t] of claims) tiers.set(k, t);
  const split = [...paths].filter(([, p]) => p.size > 1).map(([k, p]) => {
    const [run, tcid] = JSON.parse(k);
    return `${cut(str(run), 200)} ${cut(str(tcid), 200)}: ${[...p].sort(byCodePoint).join(", ")}`;
  });
  if (tiers.size) {
    const n = (t: J) => [...tiers.values()].filter((x) => x === t).length;
    rep.check("tiers", !split.length, `${tiers.size} tool call(s): ` + ["T1", "T2", "T3"].map((t) => `${t} ${n(t)}`).join(", ")
      + (n(null) ? `, untiered ${n(null)}` : "") + (split.length ? `; ${split.length} decided and completed by different capture paths` : ""),
    split.slice(0, 20), true);
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
  }))].sort(byCodePoint);
  rep.check("fail-open classes", !failOpen.length, failOpen.join(", ") || "none",
    failOpen.length ? ["calls the agent classed as one of these may have run unrecorded while the signer was down"] : [],
    true);
  rep.check("key assurance", true, "asserted: the log declares its record keys; none is attested");
  const algs = new Set([...every, ...keyRecords].map((r) => text(at(r, "alg"))));
  rep.assurance = !anchored ? "none: no trust config pins a log key or witness"
    : await assurance(origin, cosigs, witnesses, trust, algs, selfApproved, regCosigs)
      + (provenTo < relied ? "; key retirements not proven complete" : "");
  approvals(rep, runs, policies, floats);
  const glass = typed("approval").filter((e) => get(at(e, "data"), "break_glass") === true);
  if (glass.length)
    rep.check("break-glass approvals", false, `${glass.length} approval(s) answered under the break-glass role`,
      glass.map((e) => `seq ${e.seq}: ${str(at(e.data, "decision"))} ${str(get(e.data, "approval_id"))} by `
        + `${cut(text(at(e.data, "approver")), 256)}: ${repr(cut(str(get(e.data, "reason")), 200))}`).slice(0, 20), true);
  const pointed = runSet ? jsonl("registry/records.jsonl") : [];   // the records a run-set's leaves name
  checkExt(rep, [...new Map([...keyRecords, ...pointed, ...every].map((r) => [at(at(r, "event"), "seq"), r.event]))
    .values()], get(manifest, "verifier_version"));
}

/**
 * ext.amended: the JSON pointers of the fields an LLM gateway changed in a model request before sending it, to show the
 * reasoning the request has the model do. The signer writes it on a gateway's request record only, whose content digest
 * is of the request as sent; anywhere else, or not a list of pointers, it is a warning.
 */
function checkAmended(rep: Report, events: J[]) {
  const fields = (e: J): string[] | null => {
    const v = isObj(get(e, "ext")) ? get(e.ext, "amended") : null;
    const data = get(e, "data", {});
    return get(e, "type") === "model.exchange" && get(e, "source") === "gateway" && isObj(data)
      && get(data, "phase") === "request" && Array.isArray(v) && v.length > 0 && v.every((p) => typeof p === "string"
        && [...p].length <= 256 && /^(\/([^~/]|~[01])*)+$/u.test(p)) ? v : null;
  };
  const good = events.filter((e) => fields(e)), bad = events.filter((e) => !fields(e));
  const n = new Map<string, number>();
  for (const e of good) for (const p of fields(e)!) n.set(p, (n.get(p) ?? 0) + 1);
  const shown = [...n].sort(byKey).slice(0, 8).map(([p, c]) => `${p}: ${c}`);
  rep.check("gateway amendments", bad.length === 0, `gateway amended ${good.length} request(s) to show reasoning`
    + (shown.length ? ` (${shown.join(", ")})` : "") + "; each record commits to the request as sent",
  bad.map((e) => `seq ${str(get(e, "seq"))}: ext.amended is not a list of JSON pointers on a gateway's model request`)
    .slice(0, 20), true);
}

/**
 * ext.openshell.policy: a change of the sandbox's policy or configuration that OpenShell reported (its name for the
 * change, its hash of the policy, who made it; its message committed), an `ext` record the signer writes from the
 * OpenShell middleware's OCSF import, that observer's assertion; anything else carrying the name is a warning.
 */
function checkOpenshellPolicy(rep: Report, events: J[]) {
  const change = (e: J): string | null => {
    const d = get(e, "data");
    return get(e, "type") === "ext" && get(e, "source") === "signer" && isObj(d)
      && get(d, "name") === "openshell.policy" && typeof get(d, "change") === "string"
      && /^[a-z0-9_.-]{1,64}$/u.test(d.change) && typeof get(d, "observer") === "string" && d.observer !== ""
      ? d.change : null;
  };
  const good = events.filter((e) => change(e)), bad = events.filter((e) => !change(e));
  const n = new Map<string, number>();
  for (const e of good) n.set(change(e)!, (n.get(change(e)!) ?? 0) + 1);
  const shown = [...n].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).slice(0, 8).map(([c, k]) => `${c}: ${k}`);
  rep.check("openshell policy", bad.length === 0, "OpenShell changed the sandbox policy or configuration "
    + `${good.length} time(s)` + (shown.length ? ` (${shown.join(", ")})` : "") + ", as OpenShell reported it",
  bad.map((e) => `seq ${str(get(e, "seq"))}: ext.openshell.policy is not an OpenShell policy change the signer `
    + "recorded").slice(0, 20), true);
}

/**
 * The ext names this verifier interprets (the VERSIONS rows' "ext" in tracekit/bundle_v2.py): name -> its check, whose
 * lines are its own: every other line of the report reads the same without them (docs/format-v2.md §9).
 */
const EXT_CHECKS = new Map<string, (rep: Report, events: J[]) => void>([["amended", checkAmended],
  ["openshell.policy", checkOpenshellPolicy]]);
const MAX_UNREAD = 20;   // `not interpreted` lines, one per ext name; the rest on one line

/** The ext names an event carries: its `ext` field's keys, and an `ext` record's name. */
const extNames = (e: J): J[] => [...Object.keys(isObj(get(e, "ext")) ? e.ext : {}),
  ...get(e, "type") === "ext" ? [at(at(e, "data"), "name")] : []];

/**
 * A line per ext name the records carry: its EXT_CHECKS check, or a `not interpreted` warning. The records were checked
 * like every other (signature, chain, inclusion); `full`: the manifest's advisory verifier_version.
 */
function checkExt(rep: Report, events: J[], full: J) {
  const carry = new Map<string, J[]>();   // name -> the events carrying it
  for (const e of events)
    for (const n of new Set(extNames(e).map((x) => cut(str(x), 64)))) {
      if (!carry.has(n)) carry.set(n, []);
      carry.get(n)!.push(e);
    }
  const later = typeof full === "string" && /^\d{1,9}(\.\d{1,9}){0,2}$/.test(full) && newer(full, VERSION)
    ? `; tracekit >= ${full} checks it` : "";
  let shown = 0, more = 0;
  for (const [n, es] of [...carry].sort(byKey)) {
    const interpret = EXT_CHECKS.get(n);
    if (interpret) interpret(rep, es);
    else if (shown < MAX_UNREAD) {
      shown++;
      rep.check("not interpreted", false, `${es.length} record(s) carry ext.${n}: their signatures, chain and `
        + `inclusion are checked above; what ext.${n} means is not checked${later}`, [], true);
    } else more++;   // a line each would bury the report
  }
  if (more)
    rep.check("not interpreted", false, `${more} more ext name(s), on records whose signatures, chain and inclusion `
      + `are checked above; what they mean is not checked${later}`, [], true);
}

/** Approvals by people and by agents, each on a line of its own. An agent's approval fails the line unless its run
 * holds the approval.request and policy.decision it answered, the signer called the request agent-eligible
 * (agent.eligible) and no approval.escalated or approval.revoked of it comes first, the decision has no provenance and
 * a complete provenance_state (or none: the signer leaves it out then), its approval needs no passkey, and the agent is
 * neither the requester nor the run's owner; with the policy snapshot of the decision's policy_hash in `policies` (the
 * bundle's, each named by its SHA-256), every rule the call was held by is an ask rule that permits agents and needs no
 * passkey (else a warning: bounds unchecked). Argument bounds are never checkable offline (salted commitments). */
function approvals(rep: Report, runs: Map<string, J[]>, policies: Map<string, Uint8Array>, floats: Floats) {
  let people = 0, agents = 0;
  const problems: string[] = [], unchecked: string[] = [];
  for (const rs of runs.values()) {
    const events: J[] = rs.map((r) => r.event);
    const ident = get(events[0], "type") === "run.registered" ? get(at(events[0], "data"), "identity") ?? {} : {};
    const owner = `${str(get(ident, "scheme"))}:${cut(str(get(ident, "subject")), 256)}`;
    const asked = new Map<J, J>(), decided = new Map<J, J>();
    for (const e of events) {
      if (e.type === "approval.request") asked.set(get(e.data, "approval_id"), e.data);
      if (e.type === "policy.decision" && has(e.data, "decision_id")) decided.set(e.data.decision_id, e.data);
    }
    const toPeople = new Set<J>();   // approval ids escalated or revoked so far: only people answer them
    for (const e of events) {
      const d = e.data;
      if (e.type === "approval.escalated" || e.type === "approval.revoked") toPeople.add(get(d, "approval_id"));
      if (e.type !== "approval" || get(d, "decision") !== "approve") continue;
      if (get(d, "approver_kind") !== "agent") { people++; continue; }
      agents++;
      const where = `seq ${e.seq}: ${cut(str(get(d, "approval_id")), 128)}`;
      const req = asked.get(get(d, "approval_id")) ?? {};
      const dec = decided.get(get(req, "decision_id"));
      if (dec === undefined) { problems.push(`${where}: its approval.request and policy.decision are not in the run`); continue; }
      const ai = get(d, "approver_identity") ?? {};
      if (get(get(req, "agent") ?? {}, "eligible") !== true)
        problems.push(`${where}: the signer did not route its approval.request to agents (agent.eligible)`);
      if (toPeople.has(get(d, "approval_id")))
        problems.push(`${where}: it was escalated or revoked before the agent approved it`);
      if (truthy(get(dec, "provenance")) || get(dec, "provenance_state", "complete") !== "complete")
        problems.push(`${where}: the decision's arguments carry provenance or it is incomplete`);
      if (get(req, "passkey") === true) problems.push(`${where}: a rule of the call needs a passkey`);
      if (get(d, "approver") === get(req, "requester") || `${str(get(ai, "scheme"))}:${cut(str(get(ai, "subject")), 256)}` === owner)
        problems.push(`${where}: the agent is the requester or the run's owner`);
      const hash = str(get(dec, "policy_hash")), snap = policies.get(hash);
      if (snap === undefined) {
        unchecked.push(`${where}: no policy snapshot of ${cut(hash, 80)}; export the run with the signer's config, which `
          + "bundles the policies its records cite");
        continue;
      }
      let asks: Map<J, J>, flags: Set<J>;
      try {
        const pol = strictParseBytes(snap, floats);
        asks = new Map(list(get(pol, "ask", [])).map((r: J) => [at(r, "id"), r]));
        flags = new Set(list(get(pol, "flag", [])).map((r: J) => at(r, "id")));
      } catch {
        problems.push(`${where}: the policy snapshot is not a policy`);
        continue;
      }
      for (const rid of get(dec, "rule_ids") ?? []) {
        const approval = get(asks.get(rid) ?? {}, "approval") ?? {};
        if (!flags.has(rid) && (!isObj(approval) || !has(approval, "agent") || approval.passkey === "required"))
          problems.push(`${where}: rule ${cut(str(rid), 64)} does not permit agents`);
      }
    }
  }
  if (!agents) return;   // a bundle without agent approvals keeps the report it always had
  rep.check("approvals by people", true, `${people} approval(s) answered by people`);
  rep.check("approvals by agents", !problems.length && !unchecked.length, `${agents} approval(s) answered by agents (model `
      + "output); argument bounds are not checkable offline (salted commitments): audit one with `tracekit signer reveal`"
      + (unchecked.length ? `; agent approval bounds unchecked for ${unchecked.length}` : ""),
    (problems.length ? problems : unchecked).slice(0, 20), !problems.length);
}

const CONTAINMENT = ["incident.opened", "incident.updated", "run.held", "run.quarantined", "run.resumed"];
const FIRES = ["policy.decision", "approval.consumed", "capture.gap", "trace.tamper", "refusal.summary",
  "reconcile.unexplained_effect"];
const RECOMPUTED = ["sequence", "limit", "denied_calls", "provenance", "executed_against_policy", "class_mismatch"];

/** [analyzes, replay_of, investigation] of a run's run.registered (nulls when it is not one). */
function about(rs: J[]): J[] {
  const e = at(rs[0], "event"), d = get(e, "type") === "run.registered" ? get(e, "data") : null;
  return ["analyzes", "replay_of", "investigation"].map((k) => truthy(d) ? get(d, k) : null);
}

/** Whether every run but one of the same tenant is a findings or replay run of that one. */
function aboutOne(runs: Map<string, J[]>): boolean {
  const all = [...runs.values()], main = all.filter((rs) => about(rs)[0] === null && about(rs)[1] === null);
  if (main.length !== 1) return false;
  const head = main[0][0].event;
  return all.every((rs) => rs === main[0] || same(get(rs[0].event, "tenant"), get(head, "tenant"))
    && about(rs).slice(0, 2).some((x) => same(x, get(head, "run_id"))));
}

/** ["scheme:subject", signer_isolation] of a run's run.registered (nulls when it is not one). */
function author(rs: J[]): J[] {
  const e = at(rs[0], "event"), d = get(e, "type") === "run.registered" ? get(e, "data") : {};
  const i = get(d, "identity");
  return [truthy(i) ? `${str(at(i, "scheme"))}:${str(at(i, "subject"))}` : null, get(d, "signer_isolation")];
}

/**
 * Signed findings (format 1.4, docs/format-v2.md §11): each `review` with `cites`, in a findings run, cites records of
 * the analysed run that are in the bundle with those hashes (else `reviews` fails), and is labelled by its author (the
 * findings run's registered identity), positive-only: independent only when the trust config's `analyzers` pins it;
 * self-asserted (a warning) when it is the analysed run's identity or either run's signer_isolation is same-user; else
 * unpinned. Without its analysed run: not counted, author not checked (`reviews counted`). No cites: imported.
 */
/** What is wrong with a signed finding's verdict `v` (VERDICT; its asserted model, families and window), or null. */
function verdictProblem(v: J): string | null {
  if (!isObj(v) || typeof v.rule !== "string" || !/^TK-[A-Z][0-9]{3}$/.test(v.rule)
      || !["kind", "severity"].every((k) => VERDICT[k].includes(get(v, k))))
    return "its verdict has no kind, rule and severity of a signed finding";
  const a = get(v, "asserted"), f = get(v, "families"), w = get(v, "window");
  const name = (x: J) => typeof x === "string" && /^[A-Za-z0-9._:/@+-]{1,128}$/.test(x);
  const seconds = (x: J) => typeof x === "number" && x >= 0;
  const checks: [string, boolean][] = [
    ["asserted", isObj(a) && name(get(a, "model")) && name(get(a, "version"))
      && typeof get(a, "prompt_hash") === "string" && /^sha256:[0-9a-f]{64}$/.test(str(get(a, "prompt_hash")))],
    ["families", isObj(f) && (get(f, "reviewer") === null || FAMILIES.includes(str(get(f, "reviewer"))))
      && Array.isArray(get(f, "agent")) && list(get(f, "agent")).every((x) => typeof x === "string" && FAMILIES.includes(x))],
    ["window", isObj(w) && seconds(get(w, "grace_s")) && seconds(get(w, "skew_s"))],
  ];
  const bad = [...Object.keys(VERDICT).filter((k) => has(v, k) && !VERDICT[k].includes(v[k])),
    ...checks.filter(([k, ok]) => has(v, k) && !ok).map(([k]) => k)];
  return bad.length ? `its verdict's ${bad.join(", ")} is not what a signed finding holds` : null;
}

function checkReviews(rep: Report, runs: Map<string, J[]>, pinned: string[]) {
  const byId = new Map<J, J[]>([...runs.values()].map((rs) => [get(rs[0].event, "run_id"), rs]));
  const labels: string[] = [], problems: string[] = [], selfs: string[] = [], uncounted: string[] = [];
  const hashesOf = new Map<J, Map<J, J>>();   // analysed run id -> {run_seq: record hash}, built once
  let total = 0;
  for (const rs of runs.values()) {
    const reviews = rs.map((r) => r.event).filter((e) => get(e, "type") === "review");
    const signed = reviews.filter((e) => has(at(e, "data"), "cites"));
    total += reviews.length;
    extend(labels, Array(reviews.length - signed.length).fill("imported"));
    if (!signed.length) continue;
    for (const e of signed) {
      const why = verdictProblem(get(at(e, "data"), "verdict"));
      if (why) problems.push(`seq ${e.seq}: ${why}`);
    }
    const rid = cut(str(get(rs[0].event, "run_id")), 128), analyzes = about(rs)[0];
    if (analyzes === null) {
      extend(problems, signed.map((e) => `seq ${e.seq}: a signed finding outside a findings run`));
      continue;
    }
    const target = byId.get(analyzes);
    if (!target) {
      extend(labels, Array(signed.length).fill("author not checked"));
      uncounted.push(`findings run ${rid}: run ${cut(str(analyzes), 128)} is not in the bundle`);
      continue;
    }
    if (!hashesOf.has(analyzes)) hashesOf.set(analyzes, new Map(target.map((r) => [get(r.event, "run_seq"), r.hash])));
    const hashes = hashesOf.get(analyzes)!;
    for (const e of signed)
      for (const c of list(at(e.data, "cites")))
        if (hashes.get(at(c, "run_seq")) !== at(c, "hash"))
          problems.push(`seq ${e.seq}: cites run_seq ${str(c.run_seq)} of run ${cut(str(analyzes), 128)}, `
            + (hashes.has(c.run_seq) ? "whose hash differs" : "which it does not have"));
    const [mine, isolation] = author(rs), [theirs, theirIsolation] = author(target);
    let label;
    if (mine === theirs || [isolation, theirIsolation].includes("same-user")) {
      label = "self-asserted";
      selfs.push(`findings run ${rid}: ` + (mine === theirs
        ? `its author ${cut(str(mine), 256)} is the analysed run's identity`
        : "the signer runs as the same user as a client (signer_isolation same-user)"));
    } else label = pinned.includes(mine) ? "independent" : `unpinned author ${cut(str(mine), 256)}`;
    extend(labels, Array(signed.length).fill(label));
  }
  if (total) {
    rep.check("reviews", !problems.length && !selfs.length, `${total} review(s): `
      + count(labels).map(([k, n]) => `${n} ${k}`).join(", "), (problems.length ? problems : selfs).slice(0, 20),
    !problems.length);
    const verdicts = [...runs.values()].flatMap((rs) => rs.map((r) => r.event))   // signed findings only
      .filter((e) => get(e, "type") === "review" && has(at(e, "data"), "cites")).map((e) => get(e.data, "verdict"));
    const sev = count(verdicts.filter((v) => isObj(v) && get(v, "kind") === "finding")
      .map((v) => cut(str(get(v, "severity")), 16)));
    const n = sev.reduce((a, [, k]) => a + k, 0), cov = verdicts.filter((v) => isObj(v) && get(v, "kind") === "coverage").length;
    rep.findings = `${n} finding(s)` + (n ? " (" + SEVERITIES.flatMap((s) => sev.filter(([k]) => k === s))
      .map(([k, c]) => `${c} ${k}`).join(", ") + ")" : "") + (cov ? ` and ${cov} coverage review(s)` : "") + "; "
      + count(labels).map(([k, c]) => `${c} ${k}`).join(", ") + " (an opinion of the run, not its integrity)";
  }
  if (uncounted.length)
    rep.check("reviews counted", false, `${labels.filter((l) => l === "author not checked").length} signed finding(s) not `
      + "counted: export the analysed run with `tracekit export --v2 --run <run> --with-findings` to check their citations",
    uncounted.slice(0, 20), true);
}

/** The `constraints` line, as verify/v2.py's _constraints: live constraints added, and the calls they held, each an
 * ask after one in its run. */
function checkConstraints(rep: Report, runs: Map<string, J[]>) {
  let added = 0, held = 0;
  const problems: string[] = [];
  for (const rs of runs.values()) {
    let seen = false;
    for (const r of rs) {
      const e = r.event;
      if (get(e, "type") === "constraint.added") {
        added++;
        seen = true;
      } else if (get(e, "type") === "policy.decision" && Array.isArray(get(at(e, "data"), "rule_ids"))
        && get(e.data, "rule_ids").includes("TK-CONSTRAINT")) {
        held++;
        const decision = get(e.data, "decision");
        if (!seen || decision !== "ask")
          problems.push(`seq ${e.seq}: a ${cut(str(decision), 16)} held by TK-CONSTRAINT `
            + (!seen ? "before any constraint.added in its run" : "is no ask"));
      }
    }
  }
  if (added || held)
    rep.check("constraints", !problems.length, `${added} live constraint(s) added; ${held} call(s) held by them`,
      problems.slice(0, 20));
}

/** The `incidents` line, as verify/v2.py's _incidents: cited records, incidents recomputed from their run under the
 * bundled compiled policy (`policies`, by policy_hash), responses honoured. */
function checkIncidents(rep: Report, runs: Map<string, J[]>, policies: Map<string, Uint8Array>, floats: Floats) {
  const byRun = new Map<J, J[]>([...runs.values()].map((rs) => [get(rs[0].event, "run_id"), rs.map((r) => r.event)]));
  if (![...byRun.values()].some((es) => es.some((e) => CONTAINMENT.includes(get(e, "type"))))) return;
  const problems: string[] = [], pointers = new Set<string>(), opened = new Set<string>(), unbundled = new Set<string>();
  let checked = 0;
  for (const es of byRun.values()) for (const e of es) if (e.type === "incident.opened") opened.add(e.data.incident_id);
  for (const [rid, events] of byRun) {
    const mine: J[] = [];
    for (const e of events) {
      const d = e.data;
      if (!["incident.opened", "incident.updated"].includes(e.type)) continue;
      for (const c of list(d.cites)) {
        const cited = byRun.get(c.run_id);
        if (cited && (c.run_seq >= cited.length || !FIRES.includes(cited[c.run_seq].type)))
          problems.push(`seq ${e.seq}: incident ${d.incident_id} cites ${cut(c.run_id, 128)} run_seq ${c.run_seq}, which is `
            + "not a record that fires a trigger");
      }
      if (e.type === "incident.updated") continue;
      if (d.trigger === "detector_unavailable") {
        const c = d.cites.length === 1 ? d.cites[0] : {}, cited = byRun.get(c.run_id) ?? [];
        const ok = (c.run_seq ?? cited.length) < cited.length && cited[c.run_seq].type === "policy.decision"
          && cited[c.run_seq].data.detect?.state === "unavailable";
        if (ok) checked++;
        else problems.push(`seq ${e.seq}: incident ${d.incident_id} (detector_unavailable) cites no decision whose detection `
          + "state was unavailable");
      } else if (d.scope.kind === "run" && RECOMPUTED.includes(d.trigger) && d.cites.every((c: J) => c.run_id === rid))
        mine.push(e);
    }
    const hashes = new Set(events.filter((e) => e.type === "policy.decision").map((e) => get(e.data, "policy_hash")));
    let det: Detector | null = null;
    if (mine.length && hashes.size === 1) {
      const h = str([...hashes][0]), data = policies.get(h);
      if (!data) unbundled.add(cut(h, 80));
      else det = new Detector(strictParseBytes(data, floats));
      if (det) {
        const st = Detector.state(), expected: J[] = [], key = (d: J) => JSON.stringify([d.trigger, d.rule_ids,
          d.cites.map((c: J) => [c.run_id, c.run_seq]), d.mode]);
        for (const e of events) {
          if (mine.includes(e)) {
            const i = expected.findIndex((x) => key(x) === key(e.data));
            if (i >= 0) {
              const [hit] = expected.splice(i, 1);
              checked++;
              if (hit.mode === "enforce" && hit.would.length && !list(e.data.actions).length && !has(e.data, "reason"))
                problems.push(`seq ${e.seq}: incident ${e.data.incident_id} (${e.data.trigger}) is enforced under policy `
                  + `${cut(h, 80)} but records no response (${hit.would.join(", ")}) and no reason`);
            } else problems.push(`seq ${e.seq}: incident ${e.data.incident_id} (${e.data.trigger}) does not follow from the `
              + `run's records under policy ${cut(h, 80)}`);
          }
          expected.push(...det.observe(st, e).filter(([t]) => t === "incident.opened").map(([, d]) => d));
        }
      }
    }
    extend(problems, honoured(events, pointers));
  }
  const n = opened.size + [...pointers].filter((p) => !opened.has(p)).length;
  rep.check("incidents", !problems.length, `${n} incident(s): ${checked} checked against the bundle, ${n - checked} `
    + "signer-asserted (operator, cross-run, under several policies, or under a policy not in the bundle)",
    problems.slice(0, 20));
  if (unbundled.size)
    rep.check("incident policies", false, `${unbundled.size} cited policy(ies) not in the bundle: their incidents are `
      + "signer-asserted, not recomputed (export the run with the signer's config, which bundles the policies its "
      + "records cite)", [...unbundled].sort(byCodePoint).slice(0, 20), true);
}

/** The problems of one run's records with the holds and quarantines they record (verify/v2.py's _honoured). */
function honoured(events: J[], pointers: Set<string>): string[] {
  const problems: string[] = [], flight = new Set<string>(), asked = new Map<string, J>(), consumed = new Set<J>();
  const due = new Map<string, [J, string]>();
  let held: J[] = [], quarantined: J = null;
  const state = () => quarantined ? "quarantined" : "held";
  const unfollowed = () => [...due].map(([i, [seq, a]]) => `seq ${seq}: incident ${i} enforces ${a} on this run, which `
    + "no run.held or run.quarantined follows");
  for (const e of events) {
    const t = e.type, d = e.data, where = `seq ${e.seq}`, on = quarantined || held.join(" and ");
    if (t === "policy.decision" && due.size && !quarantined) {   // an enforced response is written before the next call
      extend(problems, unfollowed());
      due.clear();
    }
    if (t === "incident.opened" && d.scope.kind === "run" && d.scope.id === str(e.run_id).slice(0, 256)
      && Object.keys(d.scope).length === 2 && d.actions.some((a: J) => a === "hold" || a === "quarantine"))
      due.set(d.incident_id, [e.seq, d.actions.includes("quarantine") ? "quarantine" : "hold"]);
    else if (t === "run.held" || t === "run.quarantined") {
      pointers.add(d.incident_id);
      due.delete(d.incident_id);
      for (const x of d.in_flight ?? []) flight.add(x.decision_id);
      if (t === "run.quarantined") [quarantined, held] = [d.incident_id, []];
      else if (!quarantined && !held.includes(d.incident_id)) held.push(d.incident_id);
    } else if (t === "run.resumed") {
      held = held.filter((i) => i !== d.incident_id);
      if (JSON.stringify([...(d.held_by ?? held)].sort()) !== JSON.stringify([...held].sort()))
        problems.push(`${where}: run.resumed says ${d.held_by.join(" and ") || "no incident"} still holds the run, its `
          + `records ${held.join(" and ") || "none"}`);
    } else if (t === "policy.decision" && on && (quarantined ? d.decision !== "deny"
      : d.decision !== "deny" && (d.decision !== "ask" || !held.includes(d.incident_id ?? null))))
      problems.push(`${where}: ${d.decision} while the run is ${state()} by incident ${on}`);
    else if (t === "approval.request") {
      asked.set(d.approval_id, d.incident_id ?? null);
      if (quarantined || held.length && !held.includes(d.incident_id ?? null))
        problems.push(`${where}: an approval asked while the run is ${state()} by incident ${on}, not as its held call`);
    } else if (t === "approval" && asked.get(d.approval_id ?? null) && d.decision === "approve" && (
      d.approver_kind === "agent" || d.self_approved || !Object.hasOwn(d, "person")
      && !Object.hasOwn(d.approver_identity ?? {}, "person") || (d.incident_id ?? null) !== asked.get(d.approval_id)))
      problems.push(`${where}: a held call approved by other than a person, or without its incident id`);
    else if (t === "approval.consumed") {
      if (quarantined || held.length && !held.includes(asked.get(d.approval_id) ?? null))
        problems.push(`${where}: an approval consumed while the run is ${state()} by incident ${on}`);
      else if (asked.get(d.approval_id)) consumed.add(e.tool_call_id ?? null);
    } else if (t === "tool.result" && on && !flight.has(d.decision_id) && (quarantined || !consumed.has(e.tool_call_id ?? null)))
      problems.push(`${where}: a result while the run is ${state()} by incident ${on}, of a call neither in flight then nor `
        + "approved by a person for it");
  }
  if (!quarantined) extend(problems, unfollowed());
  return problems;
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
  included: (r: J) => Promise<boolean>, checkRecord: (r: J, p: string[]) => Promise<void>, floats: Floats,
): Promise<[[number, string][], number, [string, bigint][][]]> {
  const problems: string[] = [], tsalt = b64decode(at(rs, "tenant_salt"));
  const lo = at(rs, "from"), hi = at(rs, "to"), regOrigin = await registryOrigin(origin, tsalt);
  // a bound as the reference prints it: 2.0 when its token had a fraction or exponent
  // lean: integral floats below 1e16 only; Python's repr of others (1e+16, 1e-05) differs from JavaScript's
  const bound = (k: string, v: J) => floats.get(rs)?.has(k) && Number.isInteger(v) && Math.abs(v) < 1e16 ? `${v}.0` : str(v);
  const span = `registry ${bound("from", lo)}..${bound("to", hi)}`;
  if (![lo, hi].every((n) => Number.isSafeInteger(n)) || floats.get(rs)?.has("from") || floats.get(rs)?.has("to")) {
    rep.check("run-set", false, `INCOMPLETE, ${span}`, ["the registry range is not two integers"]);
    return [[], -1, []];
  }
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
      const note = await openNote(file(`checkpoints/registry-${n}.note`), vkeys, [...witnesses.keys()],
        trust.logs.length > 0);
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
  const counted = [...gaps].sort(byKey).map(([k, n]) => `${k} ${n}`).join(", ");
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

/** A run's part: the run's file name, the part's number (tracekit/bundle_v2.py PART). */
const PART = /^(runs\/.+)\.part-([0-9]+)\.jsonl$/;

/** {run file: its entries in order} of a bundle's `names`: the run's file, runs/<id>.jsonl, or its parts,
 * runs/<id>.part-0001.jsonl, ..., whose records read in that order are the run's (format-v2.md §9). */
export function runFiles(names: Iterable<string>): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const n of [...names].filter((x) => x.startsWith("runs/")).sort()) {
    const m = PART.exec(n), run = m ? `${m[1]}.jsonl` : n;
    if (!out.has(run)) out.set(run, []);
    out.get(run)!.push(n);
  }
  return out;
}

/** What is wrong with the parts of `run` (runFiles): `names`, its files in order, and `pieces`, their records. A run in
 * one file has none; one in parts has part-0001 to part-n and no other file, each holding records, each one's first
 * record the successor of the last of the part before it. */
function parted(run: string, names: string[], pieces: J[][]): string[] {
  if (names.length === 1 && names[0] === run) return [];
  const stem = run.slice(0, -".jsonl".length), digits = names.filter((n) => n !== run).map((n) => [n, PART.exec(n)![2]]);
  const numbered = new Set(digits.filter(([, d]) => d.length === 4 && d !== "0000").map(([, d]) => Number(d)));
  const gaps: number[] = [];
  for (let i = 1; i < Math.max(0, ...numbered); i++) if (!numbered.has(i)) gaps.push(i);
  const held = names.map((n, i) => [n, pieces[i]] as const).filter(([, p]) => p.length);
  return [
    ...names.includes(run) ? [`${run} and ${names[1]}: one run in one file and in parts`] : [],
    ...digits.filter(([, d]) => d.length !== 4 || d === "0000").map(([n]) => `${n}: not a part's name (part-0001, part-0002, ...)`),
    ...gaps.length ? [`${stem}.part-${String(gaps[0]).padStart(4, "0")}.jsonl is missing`
      + (gaps.length > 1 ? `, and ${gaps.length - 1} more part(s)` : "")] : [],
    ...names.filter((_, i) => !pieces[i].length).map((n) => `${n} holds no records`),
    ...held.slice(1).flatMap(([b, y], i) => same(get(at(y[0], "event"), "run_prev_hash"), at(held[i][1].at(-1), "hash"))
      ? [] : [`${b} does not continue ${held[i][0]}`]),
  ];
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
  return `${lvl}; records ${[...algs].sort(byCodePoint).join("+")}; checkpoint ${hybrid ? "Ed25519 + SLH-DSA-SHA2-128s" : "Ed25519 only"} `
    + `(${origin})` + (cosigned ? `; cosigned ed25519 by ${cosigned}` : "; no witness cosignature")
    + (times.length ? `; earliest independent anchor ${fmt(times.reduce((a, b) => b < a ? b : a))}` : "")
    + (capped ? `; capped by the run-set's registry notes (${capped})` : "") + (selfApproved ? "; approvals: self" : "");
}

/** `x` without control characters and the bidirectional and zero-width format characters that would reorder or hide
 * the text around them, as the report prints bundle-derived strings. */
export const clean = (x: string) => x.replace(/[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "");

/** The report as text, as the reference CLI prints it; `clean` drops characters from bundle-derived strings. */
export function formatReport(rep: Report): string {
  let s = "";
  for (const c of rep.checks) {
    s += `[${c.status.toUpperCase()}] ${c.check}` + (c.detail ? ` — ${clean(c.detail)}` : "") + "\n";
    for (const p of c.problems) s += `        ${clean(p)}\n`;
  }
  return s + `\nIntegrity: ${clean(rep.integrity)}.\nAssurance: ${clean(rep.assurance)}.\n`
    + (rep.findings ? `Findings: ${clean(rep.findings)}.\n` : "");
}

