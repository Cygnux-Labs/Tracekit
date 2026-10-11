// The TypeScript v2 verifier (src/verify): the shared vectors (tests/vectors) and the worked examples of
// docs/format-v2.md, the zip reader's bounds, the strict parser, and agreement with the reference verifier
// (tests/test_ts_verifier.py, run here when Python has the signer).   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { deflateRawSync } from "node:zlib";
import { MAX_ENTRY, Unusable, canonicalize, readZip, strictParse, strictParseBytes, verifyRecord } from "../dist/verify/index.js";
import {
  COSIGNATURE, ED25519, b64decode, bytes, ed25519Verify, hex, keyId, leafHash, openNote, parseVkey, registryOrigin,
  runHash, sha256, spkiOf, unhex,
} from "../dist/verify/primitives.js";

const ROOT = resolve(import.meta.dirname, "../../..");
const vectors = (name) => readFileSync(join(ROOT, "tests/vectors", name), "utf8").trim().split("\n").map((l) => JSON.parse(l));
const doc = readFileSync(join(ROOT, "docs/format-v2.md"), "utf8");
const PY = process.env.TRACEKIT_PYTHON ?? "python3";
const PY_ENV = { ...process.env, PYTHONPATH: ROOT };
const NO_SIGNER = spawnSync(PY, ["-c", "from tracekit.policy2 import engine; engine._backend(None)"], { env: PY_ENV }).status
  ? `needs ${PY} with the tracekit signer (set TRACEKIT_PYTHON)` : false;

test("JCS and SHA-256: every shared vector (tests/vectors/jcs.jsonl)", async () => {
  for (const v of vectors("jcs.jsonl")) {
    if (v.error) {
      assert.throws(() => strictParse(v.input), (e) => e.code === v.error, v.id);
      continue;
    }
    const out = canonicalize(strictParse(v.input));
    assert.equal(out, v.canonical, v.id);
    assert.equal(hex(await sha256(bytes(out))), v.sha256, v.id);
  }
});

test("records: hash, signature message and signature (tests/vectors/sig_v2.jsonl), and the Ed25519 rules", async () => {
  for (const v of vectors("sig_v2.jsonl")) {
    const spki = spkiOf(unhex(v.public));
    if (v.record) {
      const r = v.record;
      assert.equal(r.hash, "sha256:" + hex(await sha256(bytes(canonicalize(v.event)))), v.id);
      const { alg, kid, hash } = r, e = r.event;
      const msg = canonicalize({ alg, kid, hash, log_id: e.log_id, seq: e.seq, prev_hash: e.prev_hash, tenant: e.tenant,
        run_id: e.run_id, run_seq: e.run_seq, run_prev_hash: e.run_prev_hash, t: "tracekit.record.v2" });
      assert.equal(msg, v.message, v.id);
      assert.equal(await verifyRecord(r, [spki], ["ed25519"]), null, v.id);
      assert.equal(await verifyRecord(r, [spki], ["ed25519ph"]), "algorithm 'ed25519' is not allowed");
      assert.equal(await verifyRecord({ ...r, sig: v.record.sig.replace(/^./, (c) => c === "A" ? "B" : "A") }, [spki],
        ["ed25519"]), "bad signature");
    } else assert.equal(await ed25519Verify(unhex(v.public), unhex(v.msg), unhex(v.sig)), v.valid, `${v.id}: ${v.note}`);
  }
});

test("the event schema the verifier carries is tracekit/schema/tracekit.event.v2.json", () => {
  assert.equal(readFileSync(join(ROOT, "sdk/typescript/src/verify/tracekit.event.v2.json"), "utf8"),
    readFileSync(join(ROOT, "tracekit/schema/tracekit.event.v2.json"), "utf8"));
});

test("trees: the leaf hash and empty tree of §5", async () => {
  const r = vectors("sig_v2.jsonl")[0].record;
  assert.ok(doc.includes(hex(await leafHash(unhex(r.hash.slice(7))))));
  assert.ok(doc.includes(hex(await sha256())));
});

test("checkpoints: the C2SP note, its cosignature and the hybrid line (§6)", async () => {
  const v = JSON.parse(readFileSync(join(ROOT, "tests/vectors/c2sp_checkpoint.json"), "utf8"));
  for (const note of [v.note, v.hybrid]) {
    const n = await openNote(bytes(note), [v.log_vkey], [v.wit_vkey]);
    assert.deepEqual([n.size, n.cosigs, n.unchecked], [13, [[v.wit_vkey, 1760000000n]], false]);
    assert.equal(`${n.origin}\n${n.size}\n${Buffer.from(n.root).toString("base64")}\n`, v.text);
  }
  assert.ok(doc.includes(`key id\n\`${hex((await parseVkey(v.log_vkey)).id)}\``));
  await assert.rejects(openNote(bytes(v.note.replace("\n13\n", "\n14\n")), [v.log_vkey], []), /bad signature/);
  await assert.rejects(openNote(bytes(v.note), [], [v.wit_vkey]), /no signature from a pinned log key/);
  await assert.rejects(openNote(bytes(v.note), [v.log_vkey, v.wit_vkey], []), /wrong signature type/);
  const h = JSON.parse(readFileSync(join(ROOT, "tests/vectors/slh_dsa_note.json"), "utf8"));
  const k = await parseVkey(h.slh_vkey);
  assert.equal(hex(k.id), h.slh_key_id);
  assert.equal((await openNote(bytes(h.note), [h.log_vkey, h.slh_vkey], [])).unchecked, true);   // no SLH-DSA in Web Crypto
  await assert.rejects(openNote(bytes(v.note), [v.log_vkey, h.slh_vkey], []), /no SLH-DSA signature/);
  assert.equal(hex(await keyId("witness.example.org/w1", COSIGNATURE, (await parseVkey(v.wit_vkey)).pub)), "257cc7f1");
  assert.equal((await parseVkey(v.log_vkey)).type, ED25519);
});

test("commitments and registry leaves: the worked examples of §2 and §7", async () => {
  const digest = "sha256:" + hex(await sha256(bytes(canonicalize({ tool: "Bash", args: { command: "ls -la" } }))));
  assert.ok(doc.includes(`digest      ${digest}`));
  const key = await crypto.subtle.importKey("raw", Uint8Array.from({ length: 32 }, (_, i) => i), { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]);
  assert.ok(doc.includes(`commitment  hmac-sha256:${hex(new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes(digest))))}`));
  const tsalt = unhex(/tenant_salt +([0-9a-f]{64})/.exec(doc)[1]);
  assert.ok(doc.includes(`H(salt ‖ "run-1")  ${hex(await runHash(tsalt, "run-1"))}`));
  assert.ok(doc.includes(`registry origin    ${await registryOrigin("tracekit.example.org/log/1", tsalt)}`));
});

test("strict JSON: bytes, byte order marks, and number tokens written as floats", () => {
  assert.throws(() => strictParseBytes(Uint8Array.of(0x22, 0xff, 0x22)), (e) => e.code === "invalid_utf8");
  assert.throws(() => strictParseBytes(Uint8Array.of(0xef, 0xbb, 0xbf, 0x31)), (e) => e.code === "syntax");
  const floats = new WeakMap();
  const v = strictParseBytes(bytes('{"a":1,"b":1.0,"c":[2,2e0]}'), floats);
  assert.deepEqual([...floats.get(v)], ["b"]);
  assert.deepEqual([...floats.get(v.c)], [1]);
  assert.equal(canonicalize(v), '{"a":1,"b":1,"c":[2,2]}');
  assert.equal(canonicalize({ "\u{1F600}": 1, "\uFFFF": 2 }), '{"\u{1F600}":1,"\uFFFF":2}');   // UTF-16 order
  assert.deepEqual([b64decode("AA=="), b64decode("AAAA=")], [Uint8Array.of(0), Uint8Array.of(0, 0, 0)]);
  for (const s of ["A", "AAA", "AA=", "A===", "AA AA"]) assert.throws(() => b64decode(s), /bad base64/, s);
});

/** A zip of `entries` ({name, data, method?, attr?, flags?, crc?, local?}): method 8 deflates. */
function zip(entries) {
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
    return n >>> 0;
  });
  const crc32 = (d) => (d.reduce((c, b) => crcTable[(c ^ b) & 0xff] ^ (c >>> 8), 0xffffffff) ^ 0xffffffff) >>> 0;
  const locals = [], central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name), data = Buffer.from(e.data), method = e.method ?? 0;
    const body = method === 8 ? deflateRawSync(data) : data;
    const head = (sig, size) => {
      const b = Buffer.alloc(size);
      b.writeUInt32LE(sig, 0);
      return b;
    };
    const l = head(0x04034b50, 30);
    l.writeUInt16LE(e.flags ?? 0, 6);
    l.writeUInt16LE(method, 8);
    l.writeUInt32LE(e.crc ?? crc32(data), 14);
    l.writeUInt32LE(body.length, 18);
    l.writeUInt32LE(e.usize ?? data.length, 22);
    l.writeUInt16LE(name.length, 26);
    const c = head(0x02014b50, 46);
    c.writeUInt16LE(e.flags ?? 0, 8);
    c.writeUInt16LE(method, 10);
    c.writeUInt32LE(e.crc ?? crc32(data), 16);
    c.writeUInt32LE(body.length, 20);
    c.writeUInt32LE(e.usize ?? data.length, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(e.attr ?? 0, 38);
    c.writeUInt32LE(offset, 42);
    const parts = [l, e.local ? Buffer.from(e.local) : name, body];
    locals.push(...parts);
    central.push(c, name);
    offset += parts.reduce((n, p) => n + p.length, 0);
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...locals, cd, end]));
}

test("zip reader: stored and deflated entries, and every refusal within the bundle limits", async () => {
  const ok = await readZip(zip([{ name: "a/b.json", data: "{}" }, { name: "c", data: "x".repeat(1000), method: 8 }]));
  assert.deepEqual([...ok.keys()], ["a/b.json", "c"]);
  assert.equal(Buffer.from(ok.get("c")).toString(), "x".repeat(1000));
  const refused = {
    "bad entry name": [{ name: "../evil", data: "x" }],
    "bad entry name ": [{ name: "/etc/evil", data: "x" }],
    "bad entry name  ": [{ name: "a/./b", data: "x" }],
    "duplicate entry": [{ name: "a", data: "x" }, { name: "a", data: "y" }],
    "symlink entry": [{ name: "a", data: "/etc/passwd", attr: 0o120777 * 0x10000 }],
    "bad CRC-32": [{ name: "a", data: "x", crc: 1 }],
    "encrypted": [{ name: "a", data: "x", flags: 1 }],
    "compression method 12": [{ name: "a", data: "x", method: 12 }],
    "names another file": [{ name: "a", data: "x", local: "b" }],
    "too many entries": Array.from({ length: 10_001 }, (_, i) => ({ name: `f${i}`, data: "" })),
    "larger than the bundle limits": [{ name: "big", data: Buffer.alloc(MAX_ENTRY + 1), method: 8 }],
  };
  for (const [why, entries] of Object.entries(refused))
    await assert.rejects(readZip(zip(entries)), (e) => e instanceof Unusable && e.message.includes(why.trim()), why);
  await assert.rejects(readZip(Uint8Array.of(1, 2, 3)), Unusable);
  // a size that lies low stops the inflate there; the CRC then catches it
  await assert.rejects(readZip(zip([{ name: "a", data: "x".repeat(100), method: 8, usize: 10 }])), /bad CRC-32/);
});

test("agreement with the reference verifier (tests/test_ts_verifier.py)", { skip: NO_SIGNER }, () => {
  const r = spawnSync(PY, [join(ROOT, "tests/test_ts_verifier.py")], { env: PY_ENV, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /skipped/);
});
