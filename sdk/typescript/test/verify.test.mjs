// The TypeScript v2 verifier (src/verify): the shared vectors (tests/vectors) and the worked examples of
// docs/format-v2.md, the zip reader's bounds, the strict parser, and agreement with the reference verifier
// (tests/test_ts_verifier.py, run here when Python has the signer).   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { deflateRawSync } from "node:zlib";
import ts from "typescript";
import {
  MAX_ENTRY, StrictJSONError, Unusable, canonicalize, readZip, strictParse, strictParseBytes, verify, verifyRecord,
} from "../dist/verify/index.js";
import { MEANING, asJson, asText, cliExit, nextSteps, summarize, verdict } from "../dist/verify/explain.js";
import {
  COSIGNATURE, ED25519, b64decode, bytes, ed25519Verify, hex, keyId, leafHash, openNote, parseVkey, registryOrigin,
  runHash, sha256, spkiOf, unhex, vkey,
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

test("checkpoints and trust: a witness is one key under one name with one class, and counts once (§10)", async () => {
  const v = JSON.parse(readFileSync(join(ROOT, "tests/vectors/c2sp_checkpoint.json"), "utf8"));
  const text = v.note.slice(0, v.note.indexOf("\n\n") + 1);
  const witness = () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    return { privateKey, pub: new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(12)) };
  };
  const cosign = async (name, w) => {
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(1760000000n);
    const sig = sign(null, Buffer.from(`cosignature/v1\ntime 1760000000\n${text}`), w.privateKey);
    return `— ${name} ${Buffer.concat([await keyId(name, COSIGNATURE, w.pub), ts, sig]).toString("base64")}\n`;
  };
  const [a, b] = [witness(), witness()];
  const pins = [await vkey("witness.example/a", COSIGNATURE, a.pub), await vkey("witness.example/alias", COSIGNATURE, a.pub)];
  const note = bytes(v.note + await cosign("witness.example/a", a) + await cosign("witness.example/alias", a));
  const refused = (names) => `trust pins one witness key under two names (${names}); a key is one witness: keep it under `
    + "the name it cosigns with";
  await assert.rejects(openNote(note, [v.log_vkey], pins), { message: refused("witness.example/a, witness.example/alias") });
  await assert.rejects(openNote(note, [v.log_vkey], [...pins].reverse()),
    { message: refused("witness.example/alias, witness.example/a") });
  const two = bytes(v.note + await cosign("witness.example/a", a) + await cosign("witness.example/b", b));
  const pinned = [pins[0], await vkey("witness.example/b", COSIGNATURE, b.pub)];
  assert.equal((await openNote(two, [v.log_vkey], pinned)).cosigs.length, 2);
  // a trust config that pins one key under two names is refused before the bundle is read
  const sampleDir = join(ROOT, "sdk/typescript/src/verify/sample");
  const trust = JSON.parse(readFileSync(join(sampleDir, "sample.trust.json"), "utf8"));
  const out = await verify(new Uint8Array(readFileSync(join(sampleDir, "sample.tkb"))), bytes(JSON.stringify({ ...trust,
    witnesses: pins.map((k) => ({ vkey: k, class: "customer" })), witnesses_required: 2 })));
  assert.deepEqual([out.code, out.report.failures, out.report.checks[0].detail],
    [2, ["trust config"], "NoteError: " + refused("witness.example/a, witness.example/alias")]);
  // two keys under one name, whichever comes first, are refused too; one vkey listed twice counts once
  const named = [pins[0], await vkey("witness.example/a", COSIGNATURE, b.pub)];
  const twice = bytes(v.note + await cosign("witness.example/a", a) + await cosign("witness.example/a", b));
  const twoKeys = "trust pins two witness keys under one name (witness.example/a); a name is one witness: keep only its "
    + "current key";
  for (const keys of [named, [...named].reverse()])
    await assert.rejects(openNote(twice, [v.log_vkey], keys), { message: twoKeys });
  assert.equal((await openNote(twice, [v.log_vkey], [pins[0], pins[0]])).cosigs.length, 1);
  // in a trust config: two keys under one name, or one witness with two classes, are refused; one class is accepted
  const sample = new Uint8Array(readFileSync(join(sampleDir, "sample.tkb")));
  const under = (ws) => verify(sample, bytes(JSON.stringify({ ...trust, witnesses: ws, witnesses_required: 0 })));
  const as = (k, c) => ({ vkey: k, class: c });
  assert.equal((await under(named.map((k) => as(k, "customer")))).report.checks[0].detail, "NoteError: " + twoKeys);
  assert.equal((await under([as(pins[0], "customer"), as(pins[0], "operator")])).report.checks[0].detail,
    "ValueError: trust pins witness witness.example/a with two classes (customer, operator); a witness has one class: "
    + "list it once, with the class you give it");
  assert.equal((await under([as(pins[0], "customer"), as(pins[0], "customer")])).code, 0);
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
  // nesting: 128 deep parses, 129 deep is refused as `depth`, never a stack overflow
  assert.equal(JSON.stringify(strictParse("[".repeat(128) + "]".repeat(128))).length, 256);
  for (const t of ["[".repeat(129) + "]".repeat(129), '{"a":'.repeat(129) + "1" + "}".repeat(129), "[".repeat(1e6)])
    assert.throws(() => strictParse(t), (e) => e instanceof StrictJSONError && e.code === "depth");
  // a string of millions of characters parses, or fails as strict JSON, never with a RangeError
  assert.equal(strictParse(`"${"a".repeat(9e6)}"`).length, 9e6);
  assert.equal(strictParse(`"${"\\n".repeat(3e6)}"`).length, 3e6);
  for (const t of [`"${"a".repeat(9e6)}`, `"${"a".repeat(9e6)}\\x"`, `"${"a".repeat(9e6)}\n"`])
    assert.throws(() => strictParse(t), (e) => e instanceof StrictJSONError && e.code === "syntax");
});

/** A zip of `entries` ({name, data, method?, attr?, flags?, crc?, local?, extra?, comment?, lflags?}): method 8 deflates;
 * `o` ({prefix?, gap?, comment?, count?}) bends the archive's layout. */
function zip(entries, o = {}) {
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
    return n >>> 0;
  });
  const crc32 = (d) => (d.reduce((c, b) => crcTable[(c ^ b) & 0xff] ^ (c >>> 8), 0xffffffff) ^ 0xffffffff) >>> 0;
  const locals = [], central = [];
  let offset = o.prefix?.length ?? 0;   // offsets count the prefix, as a self-extracting archive's do
  for (const e of entries) {
    const name = Buffer.from(e.name), data = Buffer.from(e.data), method = e.method ?? 0;
    const body = method === 8 ? deflateRawSync(data) : data;
    const head = (sig, size) => {
      const b = Buffer.alloc(size);
      b.writeUInt32LE(sig, 0);
      return b;
    };
    const l = head(0x04034b50, 30);
    l.writeUInt16LE(e.lflags ?? e.flags ?? 0, 6);
    l.writeUInt16LE(method, 8);
    l.writeUInt32LE(e.crc ?? crc32(data), 14);
    l.writeUInt32LE(body.length, 18);
    l.writeUInt32LE(e.usize ?? data.length, 22);
    l.writeUInt16LE(name.length, 26);
    l.writeUInt16LE(e.extra?.length ?? 0, 28);
    const c = head(0x02014b50, 46);
    c.writeUInt16LE(e.flags ?? 0, 8);
    c.writeUInt16LE(method, 10);
    c.writeUInt32LE(e.crc ?? crc32(data), 16);
    c.writeUInt32LE(body.length, 20);
    c.writeUInt32LE(e.usize ?? data.length, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt16LE(e.extra?.length ?? 0, 30);
    c.writeUInt16LE(e.comment?.length ?? 0, 32);
    c.writeUInt32LE(e.attr ?? 0, 38);
    c.writeUInt32LE(offset, 42);
    const extra = Buffer.from(e.extra ?? "");
    const parts = [l, e.local ? Buffer.from(e.local) : name, extra, body, Buffer.from(o.gap ?? "")];
    locals.push(...parts);
    central.push(c, name, extra, Buffer.from(e.comment ?? ""));
    offset += parts.reduce((n, p) => n + p.length, 0);
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(o.count ?? entries.length, 8);
  end.writeUInt16LE(o.count ?? entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(o.comment?.length ?? 0, 20);
  return new Uint8Array(Buffer.concat([Buffer.from(o.prefix ?? ""), ...locals, cd, end, Buffer.from(o.comment ?? "")]));
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
    "Bad CRC-32 for file 'a'": [{ name: "a", data: "x", crc: 1 }],
    "encrypted": [{ name: "a", data: "x", flags: 1 }],
    "compression method 12": [{ name: "a", data: "x", method: 12 }],
    "bad local header for 'a'": [{ name: "a", data: "x", local: "b" }],
    "bad local header for 'a' ": [{ name: "a", data: "x", flags: 0, lflags: 8 }],
    "general-purpose flags 0x800": [{ name: "a", data: "x", flags: 0x800 }],
    "compression method 0": [{ name: "a", data: "xx", usize: 1 }],
    "bad central directory entry": [{ name: "a", data: "x", extra: "\x01\x00\x00\x00" }],
    "bad central directory entry ": [{ name: "a", data: "x", comment: "c" }],
    "bad entry name   ": [{ name: "a\0b", data: "x" }],
    "too many entries": Array.from({ length: 10_001 }, (_, i) => ({ name: `f${i}`, data: "" })),
    "larger than the bundle limits": [{ name: "big", data: Buffer.alloc(MAX_ENTRY + 1), method: 8 }],
  };
  for (const [why, entries] of Object.entries(refused))
    await assert.rejects(readZip(zip(entries)), (e) => e instanceof Unusable && e.message.includes(why.trim()), why);
  await assert.rejects(readZip(Uint8Array.of(1, 2, 3)), Unusable);
  // the one layout of §9: nothing before the first entry, between entries or after the end record; counts that match
  const two = [{ name: "a", data: "x" }, { name: "b", data: "y" }];
  const layouts = {
    "does not follow the entry before it": { prefix: "MZ" },
    "does not follow the entry before it ": { gap: "z" },
    "end record": { comment: "c" },
    "entry count": { count: 1 },
  };
  for (const [why, o] of Object.entries(layouts))
    await assert.rejects(readZip(zip(two, o)), (e) => e instanceof Unusable && e.message.includes(why.trim()), why);
  await assert.rejects(readZip(zip(two.slice(1), { gap: "z" })), /bytes before the central directory/);
  const good = zip(two);
  assert.deepEqual([...(await readZip(good)).keys()], ["a", "b"]);
  await assert.rejects(readZip(Uint8Array.from([...good, 0])), /bytes after its end record/);
  const z64 = Buffer.from(good);   // a zip64 locator where the end record should be
  z64.writeUInt32LE(0x07064b50, z64.length - 22);
  await assert.rejects(readZip(new Uint8Array(z64)), /not a zip file/);
  // a deflate stream shorter than its stated size
  await assert.rejects(readZip(zip([{ name: "a", data: "x".repeat(10), method: 8, usize: 100 }])), /10 bytes, not the 100/);
  // ...and with a wrong CRC as well, the CRC is reported first, as the reference's zipfile does
  await assert.rejects(readZip(zip([{ name: "a", data: "x".repeat(10), method: 8, usize: 100, crc: 1 }])),
    /Bad CRC-32 for file 'a'/);
  // a size that lies low stops the inflate there; the CRC then catches it
  await assert.rejects(readZip(zip([{ name: "a", data: "x".repeat(100), method: 8, usize: 10 }])), /Bad CRC-32 for file 'a'/);
});

test("a bundle of tiny lines is refused before one is parsed, with no trust config too", () => {
  // 1M lines no signed record could be (records are 256 bytes or more): parsed, they'd need gigabytes
  const run = Buffer.from('{"event":{"seq":1}}\n'.repeat(262_144));
  const files = {
    "checkpoints/10.note": `o.example/x\n10\n${Buffer.alloc(32).toString("base64")}\n\n— o.example/x `
      + `${Buffer.alloc(69, 1).toString("base64")}\n`,
    "proofs/records.json": JSON.stringify({ checkpoint: "checkpoints/10.note", tree_size: 10, inclusion: {} }),
    "keys/records.jsonl": "", "registry/run-set.json": "{}",
    ...Object.fromEntries([0, 1, 2, 3].map((i) => [`runs/r${i}.jsonl`, run])),
  };
  const hashes = Object.fromEntries(Object.entries(files).map(([n, d]) => [n, createHash("sha256").update(d).digest("hex")]));
  const bomb = join(mkdtempSync(join(tmpdir(), "tk-bomb-")), "bomb.tkb");
  writeFileSync(bomb, zip([{ name: "manifest.json", data: JSON.stringify({ format: "tracekit.bundle.v2",
    verifier_min_version: "1.0", files: hashes }) }, ...Object.entries(files).map(([name, data]) => ({ name, data, method: 8 }))]));
  const r = spawnSync(process.execPath, ["--max-old-space-size=256", "--input-type=module", "-e", `
    import { readFileSync } from "node:fs";
    import { verify } from ${JSON.stringify(pathToFileURL(resolve(import.meta.dirname, "../dist/verify/index.js")).href)};
    const { report, code } = await verify(readFileSync(${JSON.stringify(bomb)}), null);
    console.log(JSON.stringify([code, report.checks.at(-1).problems]));`], { encoding: "utf8", timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr.slice(0, 300));
  assert.deepEqual(JSON.parse(r.stdout), [1, ["malformed and could not be fully checked: ValueError: line shorter than a "
    + "signed record"]]);
});

const sample = (n) => new Uint8Array(readFileSync(join(ROOT, "sdk/typescript/src/verify/sample", n)));
const file = (p) => new Uint8Array(readFileSync(join(ROOT, p)));

test("the page's samples: the clean one verifies, the tampered copy fails; without a trust config neither verifies",
  async () => {
    const trust = sample("sample.trust.json");
    assert.equal((await verify(sample("sample.tkb"), trust)).code, 0);
    const bad = await verify(sample("sample-tampered.tkb"), trust);
    assert.deepEqual([bad.code, bad.report.failures], [1, ["signatures"]]);
    assert.match(bad.report.checks.find((c) => c.check === "signatures").problems[0], /hash does not match the event/);
    // no trust config: every check that needs no pinned key, never VERIFIED
    const alone = await verify(sample("sample.tkb"), null);
    assert.deepEqual([alone.code, alone.report.warnings, alone.report.failures], [2, ["trust config"], []]);
    assert.match(alone.report.integrity, /^UNVERIFIABLE \(no trust config: /);
    assert.equal(alone.report.assurance, "none: no trust config pins a log key or witness");
    assert.ok(!alone.report.checks.some((c) => c.check === "witness quorum"));
    const changed = await verify(sample("sample-tampered.tkb"), null);
    assert.deepEqual([changed.code, changed.report.failures], [1, ["signatures"]]);
    // a pinned log key still has to sign the checkpoint: another log's key fails it
    const other = await verify(sample("sample.tkb"), file("tests/golden/v2/trust.json"));
    assert.deepEqual([other.code, other.report.failures], [1, ["checkpoint"]]);
  });

test("a trust config's analyzer identity reads as Python's does: anything after the scheme but a line feed", async () => {
  const trust = JSON.parse(new TextDecoder().decode(sample("sample.trust.json")));
  const withAnalyzer = (a) => new TextEncoder().encode(JSON.stringify({ ...trust, analyzers: [a] }));
  for (const a of ["uid:990102\r x", "uid:a b", "uid:a b"]) {
    assert.equal((await verify(sample("sample.tkb"), withAnalyzer(a))).code, 0, JSON.stringify(a));
  }
  const lf = await verify(sample("sample.tkb"), withAnalyzer("uid:a\nb"));
  assert.match(lf.report.checks[0].detail, /not a v2 trust config/);
});

test("the page's words: the verdict, what to do next, and a meaning for every line the verifier writes", async () => {
  const trust = sample("sample.trust.json"), names = { bundle: "my run.tkb", trust: "trust.json" };
  const words = async (bundle, t = trust, n = names) => {
    const { report, code } = await verify(bundle, t, { bundle: n.bundle, trust: n.trust ?? "TRUST.json" });
    return { report, code, v: verdict(report, code), steps: nextSteps(report, code, n) };
  };
  const ok = await words(sample("sample.tkb"));
  assert.equal(ok.v.word, "VERIFIED");
  assert.match(ok.v.notMeans, /doesn't mean the agent behaved well/);
  assert.deepEqual(ok.steps, []);
  const bad = await words(sample("sample-tampered.tkb"));
  assert.deepEqual([bad.v.word, bad.v.means.endsWith("Failed: signatures.")], ["FAILED", true]);
  assert.deepEqual(bad.steps.map((s) => s.command), ["shasum -a 256 'my run.tkb'",
    "npx -y @cygnuxlabs/tracekit@latest verify 'my run.tkb' --trust trust.json"]);
  const wrong = await words(sample("sample.tkb"), file("tests/golden/v2/trust.json"));
  assert.match(wrong.v.means, /^This bundle is not signed by the signer your trust file names/);
  const alone = await words(sample("sample.tkb"), null, { ...names, trust: null });
  assert.deepEqual([alone.v.word, alone.v.means], ["UNVERIFIABLE",
    "Signatures are intact, but you haven't said whose signer you trust."]);
  assert.match(alone.steps[0].text, /^Ask for the sender's trust file/);
  // the exit line: the CLIs refuse without a trust file, and check a v1 bundle, or what this verifier lacks, themselves
  assert.equal(cliExit(alone.report), " The command-line verifiers need the trust file: without one they exit 2.");
  assert.equal(cliExit((await words(sample("sample-tampered.tkb"), null, { ...names, trust: null })).report),
    " The command-line verifiers need the trust file: without one they exit 2.");
  assert.equal(cliExit(ok.report), " The command-line verifiers exit with the same code.");
  const rekor = await words(file("tests/golden/v2/closed.tkb"), file("tests/golden/v2/trust-rekor.json"));
  assert.deepEqual([rekor.code, cliExit(rekor.report)], [2, " The TypeScript command-line verifier exits with the same "
    + "code; the Python one checks what this page doesn't."]);
  const v1 = await words(file("tests/golden/v1/demo-run.tkb"), trust, { bundle: "demo-run.tkb", trust: "t.json" });
  assert.deepEqual([v1.code, v1.v.word], [2, "UNVERIFIABLE"]);
  assert.match(v1.v.means, /format v1 bundle/);
  assert.equal(cliExit(v1.report), "");
  assert.deepEqual(v1.steps.map((s) => s.command), ["uvx --from tracekit-ai tracekit verify demo-run.tkb --key signer.pub"]);
  const newer = await words(file("tests/golden/negative/manifest-newer-verifier.tkb"), file("tests/golden/negative/trust.json"));
  assert.match(newer.v.means, /needs a newer verifier/);
  assert.deepEqual(newer.steps.map((s) => s.command?.split(" ")[0]), ["npx", "uvx", undefined]);
  assert.deepEqual(newer.steps.map((s) => s.text.split(",")[0]),
    ["With Node.js:", "Or with Python", "Open the latest page"]);
  assert.match(v1.steps[0].text, /^A format v1 bundle: verify it with the signer.s public key/);
  assert.match((await words(Uint8Array.of(1, 2, 3))).v.means, /couldn't be read as a Tracekit bundle/);
  const untrusted = await words(sample("sample.tkb"), bytes("{}"));
  assert.match(untrusted.v.means, /trust file couldn't be used/);
  assert.equal(untrusted.report.checks[0].detail, "ValueError: trust.json: not a v2 trust config (logs, witnesses, algs, "
    + "witnesses_required, rekor, monitors, issuers, analyzers)");
  // a meaning for exactly the outcomes each line can have, each its own: rep.check(name, ok, detail, problems, warn)
  // passes when ok, else warns when warn, else fails; rep.unsupport(name) warns
  const can = {}, yes = (n) => n?.kind === ts.SyntaxKind.TrueKeyword;
  const no = (n) => n?.kind === ts.SyntaxKind.FalseKeyword;
  (function visit(n) {
    const f = ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : null;
    const [name, ok, , , warn] = n.arguments ?? [];
    if (["check", "unsupport"].includes(f) && ts.isStringLiteral(name)) {
      const not = f === "unsupport" || yes(warn) ? ["warn"] : !warn || no(warn) ? ["fail"] : ["warn", "fail"];
      for (const s of yes(ok) ? ["pass"] : !ok || no(ok) ? not : ["pass", ...not])
        (can[name.text] ??= new Set()).add(s);
    }
    ts.forEachChild(n, visit);
  })(ts.createSourceFile("index.ts", readFileSync(join(ROOT, "sdk/typescript/src/verify/index.ts"), "utf8"),
    ts.ScriptTarget.Latest));
  assert.deepEqual(Object.keys(MEANING).sort(), Object.keys(can).sort());
  for (const [name, outcomes] of Object.entries(can)) {
    assert.deepEqual(Object.keys(MEANING[name]).sort(), [...outcomes].sort(), name);
    assert.equal(new Set(Object.values(MEANING[name])).size, outcomes.size, `${name}: one text for two outcomes`);
  }
  assert.deepEqual(Object.keys(asJson(ok.report, ok.code)),
    ["exit_code", "checks", "failures", "warnings", "integrity", "assurance", "notes"]);
  // the Findings line, when a bundle has one, as the CLIs' --json carry it
  assert.equal(asJson(Object.assign(new ok.report.constructor(), ok.report, { findings: "1 signed" }), 0).findings,
    "1 signed");
  assert.ok(asText(ok.report, ok.code).endsWith("\nIntegrity: VERIFIED.\n" + `Assurance: ${ok.report.assurance}.\n`
    + "\nExit code 0.\n"));
  const facts = Object.fromEntries(summarize(await readZip(sample("sample.tkb")), ok.report));
  assert.match(facts.Records, /^12 signed record\(s\) in 1 run\(s\), 2026-/);
  assert.deepEqual([facts["Tool calls"], facts["Held for approval"], facts.Gaps, facts.Agents],
    ["3 decided: 2 allow, 0 deny, 1 ask", '"pay": approved by alice', "none recorded", '"support-bot" (uid:1000)']);
});

test("a failed line's meaning says what the failure means, never that the check passed", async () => {
  const { report } = await verify(sample("sample-tampered.tkb"), sample("sample.trust.json"));
  const sig = report.checks.find((c) => c.check === "signatures"), said = MEANING[sig.check][sig.status];
  assert.equal(sig.status, "fail");
  assert.match(said, /edited after signing/);
  assert.doesNotMatch(said, /no record was edited/);
});

test("the CLI sends what it doesn't support to the reference verifier by its PyPI name, tracekit-ai", async () => {
  const { main } = await import("../dist/verify/cli.js");
  const said = [], error = console.error;
  console.error = (m) => said.push(m);
  try {
    assert.equal(await main(["run.tkb", "--bridge"]), 2);
  } finally {
    console.error = error;
  }
  assert.match(said.join("\n"), /reference verifier: pip install tracekit-ai\)/);
});

test("agreement with the reference verifier (tests/test_ts_verifier.py)", { skip: NO_SIGNER }, () => {
  const r = spawnSync(PY, [join(ROOT, "tests/test_ts_verifier.py")], { env: PY_ENV, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /skipped/);
});
