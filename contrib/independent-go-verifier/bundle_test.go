package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"sort"
	"strings"
	"testing"
)

// Write an exact-layout ZIP from scratch. archive/zip's ordinary streaming
// writer sets general-purpose bit 3, which this format explicitly forbids.
func fixtureZip(files map[string][]byte) []byte {
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	buf := new(bytes.Buffer)
	dir := new(bytes.Buffer)
	for _, name := range keys {
		data := files[name]
		offset := buf.Len()
		crc := crc32.ChecksumIEEE(data)
		local := make([]byte, 30)
		binary.LittleEndian.PutUint32(local, 0x04034b50)
		binary.LittleEndian.PutUint16(local[4:], 20)
		binary.LittleEndian.PutUint32(local[14:], crc)
		binary.LittleEndian.PutUint32(local[18:], uint32(len(data)))
		binary.LittleEndian.PutUint32(local[22:], uint32(len(data)))
		binary.LittleEndian.PutUint16(local[26:], uint16(len(name)))
		buf.Write(local)
		buf.WriteString(name)
		buf.Write(data)
		central := make([]byte, 46)
		binary.LittleEndian.PutUint32(central, 0x02014b50)
		binary.LittleEndian.PutUint16(central[4:], 20)
		binary.LittleEndian.PutUint16(central[6:], 20)
		binary.LittleEndian.PutUint32(central[16:], crc)
		binary.LittleEndian.PutUint32(central[20:], uint32(len(data)))
		binary.LittleEndian.PutUint32(central[24:], uint32(len(data)))
		binary.LittleEndian.PutUint16(central[28:], uint16(len(name)))
		binary.LittleEndian.PutUint32(central[42:], uint32(offset))
		dir.Write(central)
		dir.WriteString(name)
	}
	dOffset := buf.Len()
	buf.Write(dir.Bytes())
	end := make([]byte, 22)
	binary.LittleEndian.PutUint32(end, 0x06054b50)
	binary.LittleEndian.PutUint16(end[8:], uint16(len(keys)))
	binary.LittleEndian.PutUint16(end[10:], uint16(len(keys)))
	binary.LittleEndian.PutUint32(end[12:], uint32(dir.Len()))
	binary.LittleEndian.PutUint32(end[16:], uint32(dOffset))
	buf.Write(end)
	return buf.Bytes()
}
func fixtureManifest(files map[string][]byte) {
	hashes := map[string]any{}
	for name, data := range files {
		if name == "manifest.json" {
			continue
		}
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	raw, _ := json.Marshal(map[string]any{"format": "tracekit.bundle.v2", "verifier_min_version": "1.0.0", "files": hashes})
	files["manifest.json"] = raw
}

func bundleFixture(t *testing.T) (map[string][]byte, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("test signer seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	spki, err := x509.MarshalPKIXPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	kid := SHA256Hex(spki)
	logSeed := sha256.Sum256([]byte("test log seed"))
	logPriv := ed25519.NewKeyFromSeed(logSeed[:])
	origin := "tracekit.local/0123456789abcdef0123456789abcdef"
	logPin := fixtureVKey(origin, 1, logPriv.Public().(ed25519.PublicKey))
	tenant := "acme"
	runID := "run-a"
	logID := "0123456789abcdef0123456789abcdef"
	record := func(seq, runSeq int, typ, prev, runPrev, run, tenant string, data map[string]any) ([]byte, string) {
		ev := map[string]any{"schema_version": "tracekit.event.v2", "id": fmt.Sprintf("%032x", seq+1), "seq": float64(seq), "prev_hash": prev, "run_seq": float64(runSeq), "run_prev_hash": runPrev, "ts": "2026-10-09T12:00:00.000000Z", "log_id": logID, "tenant": tenant, "run_id": run, "agent_id": "main", "parent_id": nil, "source": "signer", "type": typ, "data": data}
		canonical, err := Canonical(ev)
		if err != nil {
			t.Fatal(err)
		}
		hash := SHA256Hex(canonical)
		m := map[string]any{"t": "tracekit.record.v2", "alg": "ed25519", "kid": kid, "hash": hash}
		for _, k := range []string{"log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash"} {
			m[k] = ev[k]
		}
		msg, _ := Canonical(m)
		sig := ed25519.Sign(priv, msg)
		raw, _ := json.Marshal(map[string]any{"v": 2, "event": ev, "hash": hash, "alg": "ed25519", "kid": kid, "sig": base64.StdEncoding.EncodeToString(sig)})
		return append(raw, '\n'), hash
	}
	r0, h0 := record(0, 0, "signer.epoch", ZeroHash, ZeroHash, "tracekit/signer", "tracekit", map[string]any{"keys": []any{map[string]any{"kid": kid, "alg": "ed25519", "spki": base64.StdEncoding.EncodeToString(spki)}}})
	r1, h1 := record(1, 0, "run.registered", h0, ZeroHash, runID, tenant, map[string]any{"agent": map[string]any{"name": "demo", "version": "1.0"}, "identity": map[string]any{"scheme": "uid", "subject": "test", "attested": true}})
	r2, h2 := record(2, 1, "run.final", h1, h1, runID, tenant, map[string]any{"head_run_seq": float64(0), "head_hash": h1})
	hashes := []string{h0, h1, h2}
	var leaves [][32]byte
	for _, h := range hashes {
		d, _ := hex.DecodeString(h[7:])
		leaves = append(leaves, leafHash(d))
	}
	root := nodeHash(nodeHash(leaves[0], leaves[1]), leaves[2])
	treeText := fmt.Sprintf("%s\n3\n%s\n", origin, base64.StdEncoding.EncodeToString(root[:]))
	logKey, _ := ParseVKey(logPin)
	note := treeText + "\n— " + origin + " " + base64.StdEncoding.EncodeToString(append(logKey.ID[:], ed25519.Sign(logPriv, []byte(treeText))...)) + "\n"
	siblings := map[string]any{
		"0": []any{base64.StdEncoding.EncodeToString(leaves[1][:]), base64.StdEncoding.EncodeToString(leaves[2][:])},
		"1": []any{base64.StdEncoding.EncodeToString(leaves[0][:]), base64.StdEncoding.EncodeToString(leaves[2][:])},
		"2": []any{},
	}
	// Final leaf is the right sibling of the two-leaf subtree.
	subtree := nodeHash(leaves[0], leaves[1])
	siblings["2"] = []any{base64.StdEncoding.EncodeToString(subtree[:])}
	proofs, _ := json.Marshal(map[string]any{"checkpoint": "checkpoints/3.note", "tree_size": 3, "inclusion": siblings})
	digest := sha256.Sum256([]byte(tenant + "/" + runID))
	path := "runs/" + hex.EncodeToString(digest[:])[:32] + ".jsonl"
	files := map[string][]byte{"keys/records.jsonl": r0, path: append(r1, r2...), "proofs/records.json": proofs, "checkpoints/3.note": []byte(note)}
	fixtureManifest(files)
	trust, _ := json.Marshal(map[string]any{"logs": []any{logPin}, "algs": []any{"ed25519"}, "witnesses_required": 0})
	return files, trust
}
func TestInspectBundleCore(t *testing.T) {
	files, trust := bundleFixture(t)
	archive := fixtureZip(files)
	result, err := InspectBundle(archive, trust)
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyRecords != 1 || result.RunRecords != 2 || result.TreeSize != 3 {
		t.Fatalf("result: %+v", result)
	}
	if ErrUnverifiable == nil {
		t.Fatal("must never report full VERIFIED")
	}
	t.Run("manifest version uses strict parser", func(t *testing.T) {
		bad := copyFiles(files)
		fixtureManifest(bad)
		manifest, err := parseFileObject(bad, "manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		manifest["verifier_min_version"] = "9999999999"
		bad["manifest.json"], _ = json.Marshal(manifest)
		if _, err := InspectBundle(fixtureZip(bad), trust); err == nil {
			t.Fatal("accepted out-of-range verifier_min_version")
		}
	})
	t.Run("modified payload with updated manifest", func(t *testing.T) {
		bad := copyFiles(files)
		for name := range bad {
			if strings.HasPrefix(name, "runs/") {
				bad[name] = bytes.Replace(bad[name], []byte("run-a"), []byte("run-b"), 1)
			}
		}
		fixtureManifest(bad)
		if _, err := InspectBundle(fixtureZip(bad), trust); err == nil {
			t.Fatal("accepted tampered record")
		}
	})
	t.Run("forged inclusion with updated manifest", func(t *testing.T) {
		bad := copyFiles(files)
		bad["proofs/records.json"] = bytes.Replace(bad["proofs/records.json"], []byte(`"tree_size":3`), []byte(`"tree_size":4`), 1)
		fixtureManifest(bad)
		if _, err := InspectBundle(fixtureZip(bad), trust); err == nil {
			t.Fatal("accepted altered Merkle tree size")
		}
	})
	t.Run("bad pinned trust", func(t *testing.T) {
		invalid := bytes.Replace(trust, []byte("ed25519"), []byte("RSA"), 1)
		if _, err := InspectBundle(archive, invalid); err == nil {
			t.Fatal("accepted unpinned algorithm")
		}
	})
	t.Run("trailing ZIP data", func(t *testing.T) {
		if _, err := ReadBundle(append(append([]byte{}, archive...), 0)); err == nil {
			t.Fatal("accepted appended ZIP junk")
		}
	})
	t.Run("Unix symlink entry", func(t *testing.T) {
		archive := fixtureZip(map[string][]byte{"file": []byte("target")})
		central := bytes.Index(archive, []byte{0x50, 0x4b, 0x01, 0x02})
		if central < 0 {
			t.Fatal("fixture has no central directory")
		}
		binary.LittleEndian.PutUint32(archive[central+38:], uint32(0o120777)<<16)
		if _, err := ReadBundle(archive); err == nil {
			t.Fatal("accepted ZIP member marked as a Unix symlink")
		}
	})
	t.Run("missing ZIP entry", func(t *testing.T) {
		bad := copyFiles(files)
		delete(bad, "keys/records.jsonl")
		if _, err := InspectBundle(fixtureZip(bad), trust); err == nil {
			t.Fatal("accepted missing manifest file")
		}
	})
	t.Run("file hash mismatch", func(t *testing.T) {
		bad := copyFiles(files)
		bad["checkpoints/3.note"] = []byte("modified")
		if _, err := InspectBundle(fixtureZip(bad), trust); err == nil {
			t.Fatal("accepted changed manifest hash")
		}
	})
	t.Run("unsupported registry", func(t *testing.T) {
		bad := copyFiles(files)
		bad["registry/run-set.json"] = []byte(`{}`)
		fixtureManifest(bad)
		if _, err := InspectBundle(fixtureZip(bad), trust); err == nil {
			t.Fatal("accepted unverified run-set")
		}
	})
	t.Run("unsupported hybrid", func(t *testing.T) {
		parsed, _ := ParseStrict(trust)
		m := parsed.(map[string]any)
		m["logs"] = []any{logVKey, logVKey}
		v, _ := json.Marshal(m)
		if _, err := InspectBundle(archive, v); err == nil {
			t.Fatal("accepted hybrid trust")
		}
	})
}
func copyFiles(f map[string][]byte) map[string][]byte {
	out := make(map[string][]byte)
	for k, v := range f {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func TestStrictJSONLBounds(t *testing.T) {
	if _, err := readLines([]byte("{}\n")); err == nil {
		t.Fatal("accepted undersized signed record")
	}
	if _, err := readLines(bytes.Repeat([]byte("x"), 1024)); err == nil {
		t.Fatal("accepted unterminated JSONL")
	}
	if _, err := readLines(append(bytes.Repeat([]byte("x"), 1<<20+1), '\n')); err == nil {
		t.Fatal("accepted oversized record")
	}
}

func fixtureVKey(name string, typ byte, pub []byte) string {
	sum := sha256.Sum256(append(append([]byte(name+"\n"), typ), pub...))
	return name + "+" + hex.EncodeToString(sum[:4]) + "+" + base64.StdEncoding.EncodeToString(append([]byte{typ}, pub...))
}
