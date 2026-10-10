/**
 * The zip reader of docs/format-v2.md §9: the central directory, stored and deflated entries (Web Crypto's sibling
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

/** {name: bytes} of a zip, entry by entry under the count and size caps. */
export async function readZip(data: Uint8Array): Promise<Map<string, Uint8Array>> {
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const need = (at: number, n: number) => {
    if (at < 0 || at + n > data.length) throw new Unusable("truncated zip");
  };
  let eocd = -1;   // the last end-of-central-directory record, within a maximal comment of the end
  for (let i = data.length - 22; i >= Math.max(0, data.length - 22 - 0xffff) && eocd < 0; i--)
    if (v.getUint32(i, true) === 0x06054b50) eocd = i;
  if (eocd < 0) throw new Unusable("not a zip file");
  const cdSize = v.getUint32(eocd + 12, true), cdOffset = v.getUint32(eocd + 16, true);
  if (cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new Unusable("zip64 is not supported");
  const base = eocd - cdSize - cdOffset;   // bytes before the archive, as zip readers allow
  if (base < 0) throw new Unusable("bad offset for central directory");
  const entries: { name: string; raw: Uint8Array; flags: number; method: number; crc: number; csize: number;
    usize: number; attr: number; local: number }[] = [];
  for (let at = base + cdOffset, end = at + cdSize; at < end;) {
    need(at, 46);
    if (v.getUint32(at, true) !== 0x02014b50) throw new Unusable("bad central directory entry");
    const n = v.getUint16(at + 28, true), m = v.getUint16(at + 30, true), k = v.getUint16(at + 32, true);
    need(at + 46, n);
    const raw = data.subarray(at + 46, at + 46 + n);
    const name = new TextDecoder().decode(raw);
    entries.push({ name: name.split("\0")[0], raw, flags: v.getUint16(at + 8, true), method: v.getUint16(at + 10, true),
      crc: v.getUint32(at + 16, true), csize: v.getUint32(at + 20, true), usize: v.getUint32(at + 24, true),
      attr: v.getUint32(at + 38, true), local: v.getUint32(at + 42, true) + base });
    at += 46 + n + m + k;
  }
  if (entries.length > MAX_ENTRIES) throw new Unusable("too many entries");
  const files = new Map<string, Uint8Array>();
  let total = 0;
  for (const e of entries) {
    const n = e.name;
    if (!NAME.test(n) || n.split("/").some((p) => /^\.+$/.test(p))) throw new Unusable(`bad entry name ${JSON.stringify(n.slice(0, 80))}`);
    if (files.has(n)) throw new Unusable(`duplicate entry ${n}`);
    if (((e.attr >>> 16) & 0o170000) === 0o120000) throw new Unusable(`symlink entry ${n}`);
    if (e.csize === 0xffffffff || e.usize === 0xffffffff || e.local - base === 0xffffffff)
      throw new Unusable("zip64 is not supported");
    if (e.flags & 1) throw new Unusable(`${n} is encrypted`);
    need(e.local, 30);
    if (v.getUint32(e.local, true) !== 0x04034b50) throw new Unusable(`bad local header for ${n}`);
    const ln = v.getUint16(e.local + 26, true), lm = v.getUint16(e.local + 28, true);
    need(e.local + 30, ln);
    const local = data.subarray(e.local + 30, e.local + 30 + ln);
    if (local.length !== e.raw.length || local.some((b, i) => b !== e.raw[i]))
      throw new Unusable(`${n}: the local header names another file`);
    const start = e.local + 30 + ln + lm;
    need(start, e.csize);
    const body = data.subarray(start, start + e.csize);
    const cap = Math.min(MAX_ENTRY, MAX_TOTAL - total);
    const limit = Math.min(e.usize, cap + 1);
    let out: Uint8Array;
    if (e.method === 0) out = body.subarray(0, limit);
    else if (e.method === 8) {
      try {
        out = await inflate(body, limit);
      } catch (x) {
        throw new Unusable(`${n}: ${(x as Error).message}`);
      }
    } else throw new Unusable(`${n}: compression method ${e.method} (only stored and deflate)`);
    if (out.length > cap) throw new Unusable(`${n} is larger than the bundle limits`);
    if (crc32(out) !== e.crc) throw new Unusable(`${n}: bad CRC-32`);
    files.set(n, out);
    total += out.length;
  }
  return files;
}
