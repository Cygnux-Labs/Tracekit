/**
 * Hashes, base64, strict Ed25519 (docs/format-v2.md §4), RFC 9162 proofs (§5), C2SP checkpoint notes (§6) and registry
 * leaves (§7), on Web Crypto only.
 */
const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();

export const bytes = (s: string) => utf8.encode(s);
export const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) out.set(p, (at += p.length) - p.length);
  return out;
};
export const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export function unhex(s: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(s)) throw new Error(`not hex: ${s.slice(0, 80)}`);
  return Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", concat(...parts)));
}

export const sha256hex = async (data: Uint8Array) => hex(await sha256(data));

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function b64encode(data: Uint8Array): string {
  let s = "";
  for (let i = 0; i < data.length; i += 3) {
    const n = (data[i] << 16) | ((data[i + 1] ?? 0) << 8) | (data[i + 2] ?? 0);
    s += B64[n >> 18] + B64[(n >> 12) & 63] + (i + 1 < data.length ? B64[(n >> 6) & 63] : "=")
      + (i + 2 < data.length ? B64[n & 63] : "=");
  }
  return s;
}

/** Standard base64: only the alphabet, then at most two `=`, padded to whole quads (padding after a whole quad is
 * tolerated); bits past the last byte are ignored. */
export function b64decode(s: unknown): Uint8Array {
  const m = typeof s === "string" ? /^([A-Za-z0-9+/]*)(={0,2})$/.exec(s) : null;
  const r = m ? m[1].length % 4 : 1;
  if (!m || r === 1 || (r && m[1].length % 4 + m[2].length < 4)) throw new Error("bad base64");
  const out: number[] = [];
  let acc = 0, bits = 0;
  for (const c of m[1]) {
    acc = (acc << 6) | B64.indexOf(c);
    if ((bits += 6) >= 8) out.push((acc >> (bits -= 8)) & 255);
  }
  return Uint8Array.from(out);
}

/** Canonical base64 only (checkpoint notes and vkeys). */
export function unb64(s: string): Uint8Array {
  const raw = b64decode(s);
  if (b64encode(raw) !== s) throw new Error("non-canonical base64");
  return raw;
}

// Ed25519: S < L, a canonical public key (y < p) that is not of small order, then Web Crypto's cofactorless check
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const P = (1n << 255n) - 19n;
const SMALL_ORDER = new Set([   // the canonical encodings of the eight points of order dividing 8
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]);
const le = (b: Uint8Array) => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);

export async function ed25519Verify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (pub.length !== 32 || sig.length !== 64 || le(sig.subarray(32)) >= L) return false;
  const y = le(pub) & ((1n << 255n) - 1n);
  // x = 0 with the sign bit set is no encoding at all; y = ±1 are the small-order points with x = 0
  if (y >= P || SMALL_ORDER.has(hex(pub)) || (pub[31] & 0x80 && (y === 1n || y === P - 1n))) return false;
  try {
    const key = await subtle.importKey("raw", pub as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, key, sig as BufferSource, msg as BufferSource);
  } catch {
    return false;   // not a point on the curve
  }
}

const ED25519_SPKI = unhex("302a300506032b6570032100");

/** The algorithm of a DER SubjectPublicKeyInfo, or null when it is not one this format defines. */
export const keyAlg = (spki: Uint8Array) =>
  spki.length === 44 && equal(spki.subarray(0, 12), ED25519_SPKI) ? "ed25519" : null;
export const spkiKid = async (spki: Uint8Array) => "sha256:" + await sha256hex(spki);
export const spkiOf = (pub: Uint8Array) => concat(ED25519_SPKI, pub);

/** §4: false unless `alg` is the key's own algorithm and the signature holds under its v2 rules. */
export const verifyV2 = async (alg: string, spki: Uint8Array, msg: Uint8Array, sig: Uint8Array) =>
  keyAlg(spki) === alg && ed25519Verify(spki.subarray(12), msg, sig);

// RFC 9162 Merkle trees; sizes are below 2^53, so halving is exact in a Number
export const leafHash = (data: Uint8Array) => sha256(Uint8Array.of(0), data);
const nodeHash = (l: Uint8Array, r: Uint8Array) => sha256(Uint8Array.of(1), l, r);
const odd = (n: number) => n % 2 === 1;
const half = (n: number) => Math.floor(n / 2);

/** RFC 9162 §2.1.3.2. */
export async function verifyInclusion(index: number, size: number, leaf: Uint8Array, proof: Uint8Array[],
  root: Uint8Array | undefined): Promise<boolean> {
  if (!(index >= 0 && index < size) || !root) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      r = await nodeHash(p, r);
      if (!odd(fn)) while (fn && !odd(fn)) fn = half(fn), sn = half(sn);
    } else r = await nodeHash(r, p);
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equal(r, root);
}

/** RFC 9162 §2.1.4.2. */
export async function verifyConsistency(first: number, second: number, firstRoot: Uint8Array, secondRoot: Uint8Array,
  proof: Uint8Array[]): Promise<boolean> {
  if (first === 0 || first > second) return false;
  if (first === second) return !proof.length && equal(firstRoot, secondRoot);
  let pow = first;
  while (!odd(pow)) pow = half(pow);
  const path = pow === 1 ? [firstRoot, ...proof] : proof;   // a power of two: its root is the first proof node
  if (!path.length) return false;
  let fn = first - 1, sn = second - 1;
  while (odd(fn)) fn = half(fn), sn = half(sn);
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if (!odd(fn)) while (fn && !odd(fn)) fn = half(fn), sn = half(sn);
    } else sr = await nodeHash(sr, c);
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equal(fr, firstRoot) && equal(sr, secondRoot);
}

// C2SP signed notes: tlog-checkpoint, the log's type 0x01 line, witnesses' type 0x04 cosignatures, the hybrid 0xff line
export const ED25519 = 0x01, COSIGNATURE = 0x04, HYBRID = 0xff;
export const SLH_DSA = bytes("tracekit/slh-dsa-sha2-128s");
const MAX_NOTE = 1 << 20;
const DASH = "— ";
// Unicode whitespace as str.isspace sees it, besides the control characters a name can't hold anyway
const SPACE = /[\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/;

export class NoteError extends Error {}

function checkName(name: string) {
  if (!name || name.includes("+") || bytes(name).length > 255 || SPACE.test(name) || /[\x00-\x1f]/.test(name))
    throw new NoteError(`bad key name ${JSON.stringify(name.slice(0, 64))}`);
}

export const keyId = async (name: string, type: number, pub: Uint8Array) =>
  (await sha256(bytes(name), Uint8Array.of(0x0a, type), pub)).subarray(0, 4);

export async function vkey(name: string, type: number, pub: Uint8Array) {
  checkName(name);
  return `${name}+${hex(await keyId(name, type, pub))}+${b64encode(concat(Uint8Array.of(type), pub))}`;
}

export type VKey = { name: string; id: Uint8Array; type: number; pub: Uint8Array };

/** (name, key id, type, public key) of a vkey `name+hex id+base64(type ‖ key)`. */
export async function parseVkey(text: string): Promise<VKey> {
  const i = text.indexOf("+"), j = text.indexOf("+", i + 1);
  if (i < 0 || j < 0) throw new NoteError("a vkey is name+id+key");
  const name = text.slice(0, i), hid = text.slice(i + 1, j);
  checkName(name);
  let raw: Uint8Array;
  try {
    raw = unb64(text.slice(j + 1));
  } catch (e) {
    throw new NoteError((e as Error).message);
  }
  if (!(raw.length === 33 && (raw[0] === ED25519 || raw[0] === COSIGNATURE)
      || raw.length === 1 + SLH_DSA.length + 32 && raw[0] === HYBRID && equal(raw.subarray(1, 1 + SLH_DSA.length), SLH_DSA)))
    throw new NoteError("not an Ed25519 log, cosignature or SLH-DSA log vkey");
  const id = await keyId(name, raw[0], raw.subarray(1));
  if (hid !== hex(id)) throw new NoteError("vkey id does not match the key");
  return { name, id, type: raw[0], pub: raw.subarray(1) };
}

export type Note = { origin: string; size: number; root: Uint8Array; cosigs: [string, bigint][];
  unchecked: boolean };

/**
 * Open a checkpoint note with pinned vkeys: a pinned Ed25519 log key named after the origin must sign it, and each
 * pinned hybrid key of the origin must have a line. Web Crypto has no SLH-DSA, so a hybrid line is left `unchecked`.
 */
export async function openNote(data: Uint8Array, logKeys: string[], witnessKeys: string[]): Promise<Note> {
  if (data.length > MAX_NOTE) throw new NoteError("note too large");
  let note: string;
  try {
    note = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  } catch {
    throw new NoteError("note is not UTF-8");
  }
  if (!note.endsWith("\n") || /[\x00-\x09\x0b-\x1f]/.test(note)) throw new NoteError("malformed note");
  const i = note.indexOf("\n\n");
  if (i < 0) throw new NoteError("no signature block");
  const text = note.slice(0, i + 1), lines = note.slice(i + 2, -1).split("\n");
  if (lines.length > 64) throw new NoteError("too many signatures");
  const head = text.slice(0, -1).split("\n");
  if (head.length !== 3) throw new NoteError("a checkpoint is origin, size and root");
  const [origin, size] = head;
  checkName(origin);
  if (!/^(0|[1-9][0-9]{0,19})$/.test(size)) throw new NoteError("bad tree size");
  let root: Uint8Array;
  try {
    root = unb64(head[2]);
  } catch (e) {
    throw new NoteError((e as Error).message);
  }
  if (root.length !== 32) throw new NoteError("bad root hash");
  const pinned = new Map<string, [string, VKey]>();
  for (const [keys, want] of [[logKeys, [ED25519, HYBRID]], [witnessKeys, [COSIGNATURE]]] as const)
    for (const k of keys) {
      const p = await parseVkey(k);
      if (!(want as readonly number[]).includes(p.type)) throw new NoteError(`pinned key ${p.name} has the wrong signature type`);
      pinned.set(`${p.name}\n${hex(p.id)}`, [k, p]);
    }
  const hybrids = new Set([...pinned].filter(([, [, p]]) => p.type === HYBRID && p.name === origin).map(([id]) => id));
  const seen = new Set<string>(), cosigs: [string, bigint][] = [], msg = bytes(text);
  let logged = false, unchecked = false;
  for (const line of lines) {
    const parts = line.startsWith(DASH) ? line.slice(DASH.length).split(" ") : [];
    if (parts.length !== 2) throw new NoteError("malformed signature line");
    const [name, blob] = parts;
    checkName(name);
    let raw: Uint8Array;
    try {
      raw = unb64(blob);
    } catch (e) {
      throw new NoteError((e as Error).message);
    }
    if (raw.length < 5) throw new NoteError("short signature");
    const id = `${name}\n${hex(raw.subarray(0, 4))}`;
    if (seen.has(id)) throw new NoteError("two signatures from one key");
    seen.add(id);
    const key = pinned.get(id);
    if (!key) continue;
    const [k, p] = key, sig = raw.subarray(4);
    if (p.type === ED25519) {
      if (!await verifyV2("ed25519", spkiOf(p.pub), msg, sig)) throw new NoteError(`bad signature from pinned key ${name}`);
      logged ||= name === origin;
    } else if (p.type === HYBRID) {
      unchecked = true;
      hybrids.delete(id);
    } else {
      const ts = sig.length === 72 ? new DataView(sig.buffer, sig.byteOffset).getBigUint64(0) : null;
      if (ts === null || !await verifyV2("ed25519", spkiOf(p.pub), bytes(`cosignature/v1\ntime ${ts}\n${text}`), sig.subarray(8)))
        throw new NoteError(`bad cosignature from pinned witness ${name}`);
      cosigs.push([k, ts]);
    }
  }
  if (!logged) throw new NoteError(`no signature from a pinned log key for origin ${origin}`);
  if (hybrids.size) throw new NoteError(`no SLH-DSA signature from the pinned hybrid key for origin ${origin}`);
  return { origin, size: Number(size), root, cosigs, unchecked };
}

// registry leaves: type u8 ‖ H(tenant_salt ‖ run_id) 32B ‖ record log_id 16B ‖ seq u64 ‖ record hash 32B
export const LEAF_TYPES = ["run.registered", "run.final", "log.closed", "key.retire", "capture.gap", "trace.tamper"];
export const SIGNER_LEAVES = ["log.closed", "key.retire", "capture.gap", "trace.tamper"];

export const registryOrigin = async (logOrigin: string, tsalt: Uint8Array) =>
  `${logOrigin}/registry/${(await sha256hex(concat(bytes("registry "), tsalt))).slice(0, 32)}`;
export const runHash = (tsalt: Uint8Array, runId: string) => sha256(tsalt, bytes(runId));

export function parseLeaf(data: Uint8Array) {
  if (data.length !== 89 || !(data[0] >= 1 && data[0] <= LEAF_TYPES.length)) throw new Error("not a registry leaf");
  return { type: LEAF_TYPES[data[0] - 1], runHash: data.subarray(1, 33), logId: hex(data.subarray(33, 49)),
    seq: Number(new DataView(data.buffer, data.byteOffset).getBigUint64(49)), hash: "sha256:" + hex(data.subarray(57)) };
}
