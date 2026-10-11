/**
 * The zip reader of docs/format-v2.md §9: one canonical layout, stored and deflated entries (Web Crypto's sibling
 * DecompressionStream), no zip64, under the bundle limits. Names that could escape a directory, symlinks and duplicate
 * entries are refused.
 */
export const MAX_ENTRIES = 10_000;
export const MAX_ENTRY = 64 << 20;
export const MAX_TOTAL = 512 << 20;
const NAME = /^[A-Za-z0-9_-][A-Za-z0-9._-]*(\/[A-Za-z0-9._-]+)*$/;

export class Unusable extends Error {}

let CRC: Uint32Array | undefined;

function crc32(data: Uint8Array): number {
  if (!CRC) {
    CRC = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const b of data) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** The first `limit` bytes a raw deflate stream inflates to; stops reading there, so a zip bomb costs nothing. */
async function inflate(raw: Uint8Array, limit: number): Promise<Uint8Array> {
  const reader = new Blob([raw as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const parts: Uint8Array[] = [];
  let n = 0;
  while (n < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    n += value.length;
  }
  if (n >= limit) await reader.cancel().catch(() => {});
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) out.set(p, (at += p.length) - p.length);
  return out.subarray(0, limit);
}

/**
 * {name: bytes} of a zip in the one layout of docs/format-v2.md §9, entry by entry under the count and size caps: the
 * end record ends the file, with no comment; the central directory sits between the last entry and it; the entries are
 * contiguous from offset 0, each local header repeating its central entry; no zip64, extra or comment field, or
 * general-purpose flag.
 */
export async function readZip(data: Uint8Array): Promise<Map<string, Uint8Array>> {
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const need = (at: number, n: number) => {
    if (at < 0 || at + n > data.length) throw new Unusable("truncated zip");
  };
  const eocd = data.length - 22;
  if (eocd < 0 || v.getUint32(eocd, true) !== 0x06054b50) throw new Unusable("not a zip file, or bytes after its end record");
  const count = v.getUint16(eocd + 10, true), cdSize = v.getUint32(eocd + 12, true), cdOffset = v.getUint32(eocd + 16, true);
  if (v.getUint16(eocd + 4, true) || v.getUint16(eocd + 6, true) || v.getUint16(eocd + 8, true) !== count
      || v.getUint16(eocd + 20, true) || cdOffset + cdSize !== eocd)
    throw new Unusable("not the canonical zip layout: end record");
  if (count > MAX_ENTRIES) throw new Unusable("too many entries");
  const entries: { name: string; raw: Uint8Array; flags: number; method: number; crc: number; csize: number;
    usize: number; attr: number; local: number }[] = [];
  for (let at = cdOffset; at < eocd;) {
    if (at + 46 > eocd) throw new Unusable("truncated zip");
    const n = v.getUint16(at + 28, true);
    if (v.getUint32(at, true) !== 0x02014b50 || v.getUint16(at + 30, true) || v.getUint16(at + 32, true) || at + 46 + n > eocd)
      throw new Unusable("bad central directory entry");
    const raw = data.subarray(at + 46, at + 46 + n);
    entries.push({ name: new TextDecoder().decode(raw), raw, flags: v.getUint16(at + 8, true),
      method: v.getUint16(at + 10, true), crc: v.getUint32(at + 16, true), csize: v.getUint32(at + 20, true),
      usize: v.getUint32(at + 24, true), attr: v.getUint32(at + 38, true), local: v.getUint32(at + 42, true) });
    at += 46 + n;
  }
  if (entries.length !== count) throw new Unusable("not the canonical zip layout: entry count");
  let pos = 0;
  for (const e of entries) {
    const n = JSON.stringify(e.name.slice(0, 80));
    if (e.csize === 0xffffffff || e.usize === 0xffffffff || e.local === 0xffffffff) throw new Unusable("zip64 is not supported");
    if (e.method !== 0 && e.method !== 8 || e.method === 0 && e.csize !== e.usize)
      throw new Unusable(`${n}: compression method ${e.method} (only stored and deflate)`);
    if (e.flags & 1) throw new Unusable(`${n} is encrypted`);
    if (e.flags) throw new Unusable(`${n}: general-purpose flags 0x${e.flags.toString(16)}`);
    if (e.local !== pos) throw new Unusable(`not the canonical zip layout: ${n} does not follow the entry before it`);
    need(e.local, 30 + e.raw.length);
    const local = data.subarray(e.local + 30, e.local + 30 + e.raw.length);
    if (v.getUint32(e.local, true) !== 0x04034b50 || v.getUint16(e.local + 6, true) !== e.flags
        || v.getUint16(e.local + 8, true) !== e.method || v.getUint32(e.local + 14, true) !== e.crc
        || v.getUint32(e.local + 18, true) !== e.csize || v.getUint32(e.local + 22, true) !== e.usize
        || v.getUint16(e.local + 26, true) !== e.raw.length || v.getUint16(e.local + 28, true)
        || local.some((b, i) => b !== e.raw[i]))
      throw new Unusable(`bad local header for ${n}: it does not repeat the central entry`);
    pos = e.local + 30 + e.raw.length + e.csize;
  }
  if (pos !== cdOffset) throw new Unusable("not the canonical zip layout: bytes before the central directory");
  const files = new Map<string, Uint8Array>();
  let total = 0;
  for (const e of entries) {
    const n = e.name;
    if (!NAME.test(n) || n.split("/").some((p) => /^\.+$/.test(p))) throw new Unusable(`bad entry name ${JSON.stringify(n.slice(0, 80))}`);
    if (files.has(n)) throw new Unusable(`duplicate entry ${n}`);
    if (((e.attr >>> 16) & 0o170000) === 0o120000) throw new Unusable(`symlink entry ${n}`);
    const start = e.local + 30 + e.raw.length;
    need(start, e.csize);
    const body = data.subarray(start, start + e.csize);
    const cap = Math.min(MAX_ENTRY, MAX_TOTAL - total);
    const limit = Math.min(e.usize, cap + 1);
    let out: Uint8Array;
    if (e.method === 0) out = body.subarray(0, limit);
    else {
      try {
        out = await inflate(body, limit);
      } catch (x) {
        throw new Unusable(`${n}: ${(x as Error).message}`);
      }
    }
    if (out.length > cap) throw new Unusable(`${n} is larger than the bundle limits`);
    if (out.length !== e.usize) throw new Unusable(`${n}: ${out.length} bytes, not the ${e.usize} its entry says`);
    if (crc32(out) !== e.crc) throw new Unusable(`${n}: bad CRC-32`);
    files.set(n, out);
    total += out.length;
  }
  return files;
}
