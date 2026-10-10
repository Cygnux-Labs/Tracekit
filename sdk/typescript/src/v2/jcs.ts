/** Content digests of the native client; JCS and the strict parser are shared with the verifier (src/verify/jcs.ts). */
import { createHash } from "node:crypto";
import { canonicalize, strictParse } from "../verify/jcs.js";

export { canonicalize, strictParse, StrictJSONError } from "../verify/jcs.js";

/** sha256(JCS(v)), as tracekit/format/canon.py `event_hash`. */
export function digest(v: unknown): string {
  return "sha256:" + createHash("sha256").update(canonicalize(v), "utf8").digest("hex");
}

/** sha256(JCS({tool, args})): `args` is the model's raw arguments string (strictly parsed first) or a parsed value. */
export function argsDigest(tool: string, args: unknown): string {
  return digest({ tool, args: typeof args === "string" ? strictParse(args) : args });
}
