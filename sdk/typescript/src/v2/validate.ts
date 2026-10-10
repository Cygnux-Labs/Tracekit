/** The JSON Schema subset of tracekit/schema.py `_check`, as rpc_schema.validate uses it (patterns searched, not anchored). */
export type Schema = { [keyword: string]: any };

const TYPES: Record<string, (v: unknown) => boolean> = {
  object: (v) => typeof v === "object" && v !== null && !Array.isArray(v),
  array: Array.isArray,
  string: (v) => typeof v === "string",
  integer: Number.isInteger,
  number: (v) => typeof v === "number",
  boolean: (v) => typeof v === "boolean",
  null: (v) => v === null,
};

/** Error strings for `v` against `s` (empty when valid). */
export function validate(s: Schema, v: any, path = "$", errs: string[] = []): string[] {
  if ("type" in s) {
    const ts: string[] = Array.isArray(s.type) ? s.type : [s.type];
    if (!ts.some((t) => TYPES[t](v))) {
      errs.push(`${path}: expected ${ts.join("/")}`);
      return errs;
    }
  }
  if ("const" in s && v !== s.const) errs.push(`${path}: must be ${JSON.stringify(s.const)}`);
  if ("enum" in s && !s.enum.includes(v)) errs.push(`${path}: ${JSON.stringify(v)} not in ${JSON.stringify(s.enum)}`);
  if (typeof v === "string") {
    if ("pattern" in s && !new RegExp(s.pattern).test(v)) errs.push(`${path}: does not match ${s.pattern}`);
    const n = [...v].length;   // code points, like Python's len
    if ("minLength" in s && n < s.minLength) errs.push(`${path}: shorter than ${s.minLength}`);
    if ("maxLength" in s && n > s.maxLength) errs.push(`${path}: longer than ${s.maxLength}`);
  }
  if (typeof v === "number" && "minimum" in s && v < s.minimum) errs.push(`${path}: below ${s.minimum}`);
  if (typeof v === "number" && "maximum" in s && v > s.maximum) errs.push(`${path}: above ${s.maximum}`);
  if (Array.isArray(v)) {
    if ("maxItems" in s && v.length > s.maxItems) errs.push(`${path}: more than ${s.maxItems} items`);
    if ("items" in s) v.forEach((it, i) => validate(s.items, it, `${path}[${i}]`, errs));
  }
  if (TYPES.object(v)) {
    for (const k of s.required ?? []) if (!Object.hasOwn(v, k)) errs.push(`${path}: missing required '${k}'`);
    for (const [k, val] of Object.entries(v)) {
      if (s.properties && Object.hasOwn(s.properties, k)) validate(s.properties[k], val, `${path}.${k}`, errs);
      else if (s.additionalProperties === false) errs.push(`${path}: unexpected field '${k}'`);
      else if (typeof s.additionalProperties === "object") validate(s.additionalProperties, val, `${path}.${k}`, errs);
    }
  }
  if ("oneOf" in s) {
    const matched = s.oneOf.filter((sub: Schema) => !validate(sub, v, path).length).length;
    if (matched !== 1) errs.push(`${path}: must match exactly one alternative (matched ${matched})`);
  }
  if ("if" in s && !validate(s.if, v, path).length && "then" in s) validate(s.then, v, path, errs);
  return errs;
}
