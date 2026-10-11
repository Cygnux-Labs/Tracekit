/**
 * The JSON Schema 2020-12 subset tracekit.event.v2.json uses (docs/format-v2.md §3): type, const, enum, required,
 * properties, additionalProperties, items, oneOf, allOf, if/then, $ref to #/$defs, pattern (full match, ASCII),
 * minimum, maximum, minLength, maxLength (code points), maxItems. "integer" excludes number tokens written with a
 * fraction or exponent. Any other keyword throws, so the schema can't silently lose a check.
 */
import type { Floats } from "./jcs.js";
import SCHEMA from "./tracekit.event.v2.json" with { type: "json" };

type Schema = { [keyword: string]: any };

const KEYWORDS = new Set(["type", "const", "enum", "required", "properties", "additionalProperties", "items", "oneOf",
  "allOf", "if", "then", "$ref", "pattern", "minimum", "maximum", "minLength", "maxLength", "maxItems", "$schema", "$id",
  "$defs", "title", "description"]);
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isNumber = (v: unknown): v is number => typeof v === "number";
const PATTERNS = new Map<string, RegExp>();

/** JSON equality with numbers and booleans compared as numbers, as the reference's Python does. */
export function same(a: unknown, b: unknown): boolean {
  if ((isNumber(a) || typeof a === "boolean") && (isNumber(b) || typeof b === "boolean")) return Number(a) === Number(b);
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => same(x, b[i]));
  if (isObject(a) && isObject(b)) {
    const k = Object.keys(a);
    return k.length === Object.keys(b).length && k.every((x) => Object.hasOwn(b, x) && same(a[x], b[x]));
  }
  return a === b;
}

function check(v: unknown, s: Schema, path: string, errs: string[], float: boolean, floats: Floats) {
  const unknown = Object.keys(s).filter((k) => !KEYWORDS.has(k));
  if (unknown.length) throw new Error(`unknown schema keyword(s) ${unknown} at ${path}`);
  if ("$ref" in s) return check(v, SCHEMA.$defs[s.$ref.slice("#/$defs/".length) as keyof typeof SCHEMA.$defs], path,
    errs, float, floats);
  if ("type" in s) {
    const ts: string[] = Array.isArray(s.type) ? s.type : [s.type];
    const is = (t: string) => t === "integer" ? isNumber(v) && Number.isInteger(v) && !float : t === "number" ? isNumber(v)
      : t === "object" ? isObject(v) : t === "array" ? Array.isArray(v) : t === "null" ? v === null : typeof v === t;
    if (!ts.some(is)) return errs.push(`${path}: expected ${ts.join("/")}`);
  }
  if ("const" in s && !same(v, s.const)) errs.push(`${path}: must be ${JSON.stringify(s.const)}`);
  if ("enum" in s && !s.enum.some((x: unknown) => same(v, x))) errs.push(`${path}: ${JSON.stringify(v)} not in ${JSON.stringify(s.enum)}`);
  if (typeof v === "string") {
    if ("pattern" in s) {
      if (!PATTERNS.has(s.pattern)) PATTERNS.set(s.pattern, new RegExp(`^(?:${s.pattern})$`));
      if (!PATTERNS.get(s.pattern)!.test(v)) errs.push(`${path}: does not match ${s.pattern}`);
    }
    const n = [...v].length;
    if ("minLength" in s && n < s.minLength) errs.push(`${path}: shorter than ${s.minLength}`);
    if ("maxLength" in s && n > s.maxLength) errs.push(`${path}: longer than ${s.maxLength}`);
  }
  if (isNumber(v) && "minimum" in s && v < s.minimum) errs.push(`${path}: below ${s.minimum}`);
  if (isNumber(v) && "maximum" in s && v > s.maximum) errs.push(`${path}: above ${s.maximum}`);
  if (Array.isArray(v) && "maxItems" in s && v.length > s.maxItems) errs.push(`${path}: more than ${s.maxItems} items`);
  if (isObject(v)) {
    for (const k of s.required ?? []) if (!Object.hasOwn(v, k)) errs.push(`${path}: missing required '${k}'`);
    const props = s.properties ?? {}, ap = s.additionalProperties ?? true;
    for (const [k, x] of Object.entries(v)) {
      const f = floats.get(v)?.has(k) ?? false;
      if (Object.hasOwn(props, k)) check(x, props[k], `${path}.${k}`, errs, f, floats);
      else if (ap === false) errs.push(`${path}: unexpected field '${k}'`);
      else if (isObject(ap)) check(x, ap, `${path}.${k}`, errs, f, floats);
    }
  }
  if (Array.isArray(v) && "items" in s)
    v.forEach((x, i) => check(x, s.items, `${path}[${i}]`, errs, floats.get(v)?.has(i) ?? false, floats));
  if ("oneOf" in s) {
    const matched = s.oneOf.filter((sub: Schema) => {
      const e: string[] = [];
      check(v, sub, path, e, float, floats);
      return !e.length;
    }).length;
    if (matched !== 1) errs.push(`${path}: must match exactly one alternative (matched ${matched})`);
  }
  for (const sub of s.allOf ?? []) check(v, sub, path, errs, float, floats);
  if ("if" in s) {
    const e: string[] = [];
    check(v, s.if, path, e, float, floats);
    if (!e.length && "then" in s) check(v, s.then, path, errs, float, floats);
  }
}

/** Error strings of a tracekit.event.v2 event (empty when valid); `floats` from strictParse. */
export function validateEvent(event: unknown, floats: Floats): string[] {
  const errs: string[] = [];
  check(event, SCHEMA, "event", errs, false, floats);
  return errs;
}
