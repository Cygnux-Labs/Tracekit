/**
 * JCS (RFC 8785) and the strict parser of docs/format-v2.md §1, byte for byte (tests/vectors/jcs.jsonl).
 * Strict: bytes that are not UTF-8, duplicate keys, NaN/±Infinity (and overflow such as 1e400), lone surrogates and
 * integer tokens (no `.` or exponent) outside ±(2^53-1) are refused, and so are arrays and objects nested deeper than
 * MAX_DEPTH. No node: imports: browsers load this too.
 */

/** `code` is one of: invalid_utf8, syntax, duplicate_key, non_finite, int_range, lone_surrogate, depth. */
export class StrictJSONError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
  }
}

const WS = /[ \t\n\r]*/y;
const ESC = /\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})/y;
const NUM = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/y;
export const MAX_DEPTH = 128;
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Where number tokens with a fraction or exponent sit (container -> keys): JSON Schema's "integer" excludes them. */
export type Floats = WeakMap<object, Set<string | number>>;

export function strictParse(text: string, floats?: Floats): unknown {
  let i = 0;
  let float = false;   // the last value read was a number token with a fraction or exponent
  const mark = (o: object, k: string | number) => {
    if (!float || !floats) return;
    if (!floats.has(o)) floats.set(o, new Set());
    floats.get(o)!.add(k);
  };
  const fail = (code: string, msg: string): never => { throw new StrictJSONError(code, msg); };
  const match = (re: RegExp) => {
    re.lastIndex = i;
    const m = re.exec(text);
    if (m) i = re.lastIndex;
    return m;
  };
  const str = (): string => {   // a loop, not one regex: V8 runs out of regex stack on strings of millions of characters
    const start = i;
    if (text[i++] !== '"') fail("syntax", `string expected at ${start}`);
    for (let c; (c = text.charCodeAt(i)) !== 0x22;) {
      if (c === 0x5c) match(ESC) ?? fail("syntax", `bad escape at ${i}`);
      else if (c < 0x20 || Number.isNaN(c)) fail("syntax", `unterminated string at ${start}`);
      else i++;
    }
    const raw = text.slice(start, ++i), s: string = JSON.parse(raw);
    if (LONE.test(s)) fail("lone_surrogate", raw.slice(0, 80));
    return s;
  };
  const expect = (c: string) => {
    match(WS);
    if (text[i++] !== c) fail("syntax", `${c} expected at ${i - 1}`);
  };
  const value = (depth: number): unknown => {
    float = false;
    match(WS);
    const c = text[i];
    if ((c === "{" || c === "[") && depth === MAX_DEPTH) fail("depth", `nesting deeper than ${MAX_DEPTH} at ${i}`);
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
        Object.defineProperty(o, k, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });   // "__proto__" too
        mark(o, k);
        match(WS);
      } while (text[i] === "," && ++i);
      expect("}");
      float = false;
      return o;
    }
    if (c === "[") {
      i++;
      const a: unknown[] = [];
      match(WS);
      if (text[i] === "]") return i++, a;
      do a.push(value(depth + 1)), mark(a, a.length - 1); while ((match(WS), text[i] === ",") && ++i);
      expect("]");
      float = false;
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
    float = !!(m[1] || m[2]);
    return n;
  };
  const v = value(0);
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

/** strictParse of UTF-8 bytes (a byte order mark is not whitespace). */
export function strictParseBytes(data: Uint8Array, floats?: Floats): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  } catch {
    throw new StrictJSONError("invalid_utf8", "not UTF-8");
  }
  return strictParse(text, floats);
}
