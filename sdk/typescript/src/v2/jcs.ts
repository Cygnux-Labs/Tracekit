/**
 * JCS (RFC 8785) and the strict parser of tracekit/format/canon.py, byte for byte (tests/vectors/jcs.jsonl).
 * Strict: duplicate keys, NaN/±Infinity (and overflow such as 1e400), lone surrogates and integer tokens (no `.` or
 * exponent) outside ±(2^53-1) are refused.
 */
import { createHash } from "node:crypto";

/** `code` is one of: syntax, duplicate_key, non_finite, int_range, lone_surrogate. */
export class StrictJSONError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
  }
}

const WS = /[ \t\n\r]*/y;
const STR = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
const NUM = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/y;
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function strictParse(text: string): unknown {
  let i = 0;
  const fail = (code: string, msg: string): never => { throw new StrictJSONError(code, msg); };
  const match = (re: RegExp) => {
    re.lastIndex = i;
    const m = re.exec(text);
    if (m) i = re.lastIndex;
    return m;
  };
  const str = (): string => {
    const m = match(STR) ?? fail("syntax", `string expected at ${i}`);
    const s: string = JSON.parse(m[0]);
    if (LONE.test(s)) fail("lone_surrogate", m[0]);
    return s;
  };
  const expect = (c: string) => {
    match(WS);
    if (text[i++] !== c) fail("syntax", `${c} expected at ${i - 1}`);
  };
  const value = (): unknown => {
    match(WS);
    const c = text[i];
    if (c === "{") {
      i++;
      const o: Record<string, unknown> = {};
      match(WS);
      if (text[i] === "}") return i++, o;
      do {
        match(WS);
        const k = str();
        if (Object.hasOwn(o, k)) fail("duplicate_key", JSON.stringify(k));
        expect(":");
        Object.defineProperty(o, k, { value: value(), enumerable: true, writable: true, configurable: true });   // "__proto__" too
        match(WS);
      } while (text[i] === "," && ++i);
      expect("}");
      return o;
    }
    if (c === "[") {
      i++;
      const a: unknown[] = [];
      match(WS);
      if (text[i] === "]") return i++, a;
      do a.push(value()); while ((match(WS), text[i] === ",") && ++i);
      expect("]");
      return a;
    }
    if (c === '"') return str();
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]] as const)
      if (text.startsWith(lit, i)) return (i += lit.length), v;
    for (const lit of ["NaN", "Infinity", "-Infinity"]) if (text.startsWith(lit, i)) fail("non_finite", lit);
    const m = match(NUM) ?? fail("syntax", `value expected at ${i}`);
    const n = Number(m[0]);
    if (!Number.isFinite(n)) fail("non_finite", m[0]);
    if (!m[1] && !m[2] && !Number.isSafeInteger(n)) fail("int_range", m[0]);
    return n;
  };
  const v = value();
  match(WS);
  if (i < text.length) fail("syntax", `extra data at ${i}`);
  return v;
}

/** JCS text of a JSON value; StrictJSONError for anything JCS can't encode. */
export function canonicalize(v: unknown): string {
  if (typeof v === "string") {
    if (LONE.test(v)) throw new StrictJSONError("lone_surrogate", JSON.stringify(v));
    return JSON.stringify(v);
  }
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new StrictJSONError("non_finite", String(v));
    return JSON.stringify(v);   // ECMAScript Number::toString, -0 as 0: what JCS specifies
  }
  if (v === null || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${canonicalize(k)}:${canonicalize(o[k])}`).join(",")}}`;   // UTF-16 order
  }
  throw new StrictJSONError("syntax", `${typeof v} is not JSON`);
}

/** sha256(JCS(v)), as tracekit/format/canon.py `event_hash`. */
export function digest(v: unknown): string {
  return "sha256:" + createHash("sha256").update(canonicalize(v), "utf8").digest("hex");
}

/** sha256(JCS({tool, args})): `args` is the model's raw arguments string (strictly parsed first) or a parsed value. */
export function argsDigest(tool: string, args: unknown): string {
  return digest({ tool, args: typeof args === "string" ? strictParse(args) : args });
}
