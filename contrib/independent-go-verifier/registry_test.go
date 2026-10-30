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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoldenRunSetCore(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "golden", "v2")
	bundle, err := os.ReadFile(filepath.Join(root, "run-set.tkb"))
	if os.IsNotExist(err) {
		t.Skip("golden fixtures not available")
	}
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(filepath.Join(root, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectBundle(bundle, trust); err != nil {
		t.Fatalf("valid run-set core: %v", err)
	}
	negative := filepath.Join("..", "..", "tests", "golden", "negative")
	bundle, err = os.ReadFile(filepath.Join(negative, "run-set-foreign-run.tkb"))
	if err != nil {
		t.Fatal(err)
	}
	trust, err = os.ReadFile(filepath.Join(negative, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectBundle(bundle, trust); err == nil {
		t.Fatal("accepted a run from another tenant")
	}
}

func TestRunPartsAndRegistry(t *testing.T) {
	files, trust := bundleFixture(t)
	var name string
	for n := range files {
		if strings.HasPrefix(n, "runs/") {
			name = n
		}
	}
	if name == "" {
		t.Fatal("fixture run missing")
	}
	run := files[name]
	split := bytes.IndexByte(run, '\n') + 1
	baseName := strings.TrimSuffix(name, ".jsonl")
	parts := copyFiles(files)
	delete(parts, name)
	parts[baseName+".part-0001.jsonl"] = run[:split]
	parts[baseName+".part-0002.jsonl"] = run[split:]
	fixtureManifest(parts)
	if _, err := InspectBundle(fixtureZip(parts), trust); err != nil {
		t.Fatalf("valid multipart run: %v", err)
	}
	for caseName, mutate := range map[string]func(map[string][]byte){
		"missing first": func(m map[string][]byte) {
			m[baseName+".part-0000.jsonl"] = m[baseName+".part-0001.jsonl"]
			delete(m, baseName+".part-0001.jsonl")
		},
		"gap": func(m map[string][]byte) {
			m[baseName+".part-0003.jsonl"] = m[baseName+".part-0002.jsonl"]
			delete(m, baseName+".part-0002.jsonl")
		},
		"two layouts": func(m map[string][]byte) { m[name] = run },
		"bad boundary": func(m map[string][]byte) {
			m[baseName+".part-0002.jsonl"] = bytes.Replace(m[baseName+".part-0002.jsonl"], []byte("run-a"), []byte("run-b"), 1)
		},
	} {
		t.Run(caseName, func(t *testing.T) {
			m := copyFiles(parts)
			mutate(m)
			fixtureManifest(m)
			if _, err := InspectBundle(fixtureZip(m), trust); err == nil {
				t.Fatal("accepted corrupted run parts")
			}
		})
	}

	// A two-leaf registry (the run registration and final) with a signed
	// registry checkpoint. No Python or TypeScript verification code is used.
	registry := copyFiles(files)
	salt := sha256.Sum256([]byte("tenant-specific registry test salt"))
	seed := sha256.Sum256([]byte("test log seed"))
	logKey := ed25519.NewKeyFromSeed(seed[:])
	vv, _ := ParseStrict(trust)
	config := vv.(map[string]any)
	logVKey, _ := ParseVKey(config["logs"].([]any)[0].(string))
	digest := sha256.Sum256(append([]byte("registry "), salt[:]...))
	origin := logVKey.Name + "/registry/" + hex.EncodeToString(digest[:])[:32]
	registryLog := renamedLogKey(logVKey, origin)
	lines := bytes.Split(bytes.TrimSuffix(run, []byte{'\n'}), []byte{'\n'})
	leafBytes := make([][]byte, 0, 2)
	for i, line := range lines {
		rec, err := decodeRecord(line)
		if err != nil {
			t.Fatal(err)
		}
		rid := sha256.Sum256(append(append([]byte{}, salt[:]...), []byte("run-a")...))
		logID, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
		hash, _ := hexDigest(rec.hash)
		leaf := make([]byte, 89)
		leaf[0] = byte(i + 1)
		copy(leaf[1:33], rid[:])
		copy(leaf[33:49], logID)
		binary.BigEndian.PutUint64(leaf[49:57], rec.seq)
		copy(leaf[57:], hash)
		leafBytes = append(leafBytes, leaf)
	}
	lh0, lh1 := leafHash(leafBytes[0]), leafHash(leafBytes[1])
	root := nodeHash(lh0, lh1)
	text := fmt.Sprintf("%s\n2\n%s\n", origin, base64.StdEncoding.EncodeToString(root[:]))
	note := text + "\n— " + origin + " " + base64.StdEncoding.EncodeToString(append(registryLog.ID[:], ed25519.Sign(logKey, []byte(text))...)) + "\n"
	registry["checkpoints/registry-2.note"] = []byte(note)
	leaves := []any{
		map[string]any{"leaf": base64.StdEncoding.EncodeToString(leafBytes[0]), "inclusion": []any{base64.StdEncoding.EncodeToString(lh1[:])}},
		map[string]any{"leaf": base64.StdEncoding.EncodeToString(leafBytes[1]), "inclusion": []any{base64.StdEncoding.EncodeToString(lh0[:])}},
	}
	spec, _ := json.Marshal(map[string]any{"tenant_salt": base64.StdEncoding.EncodeToString(salt[:]), "from": 0, "to": 2, "consistency": []any{}, "leaves": leaves})
	registry["registry/run-set.json"] = spec
	registry["registry/records.jsonl"] = run
	fixtureManifest(registry)
	if _, err := InspectBundle(fixtureZip(registry), trust); err != nil {
		t.Fatalf("valid registry: %v", err)
	}
	t.Run("wrong leaf", func(t *testing.T) {
		m := copyFiles(registry)
		spec := bytes.Replace(m["registry/run-set.json"], []byte("\"to\":2"), []byte("\"to\":3"), 1)
		m["registry/run-set.json"] = spec
		fixtureManifest(m)
		if _, err := InspectBundle(fixtureZip(m), trust); err == nil {
			t.Fatal("accepted wrong registry head")
		}
	})
	t.Run("wrong checkpoint", func(t *testing.T) {
		m := copyFiles(registry)
		m["checkpoints/registry-2.note"] = bytes.Replace(m["checkpoints/registry-2.note"], []byte("\n2\n"), []byte("\n3\n"), 1)
		fixtureManifest(m)
		if _, err := InspectBundle(fixtureZip(m), trust); err == nil {
			t.Fatal("accepted altered registry signature")
		}
	})
	t.Run("no final leaf", func(t *testing.T) {
		m := copyFiles(registry)
		m["registry/records.jsonl"] = append([]byte(nil), lines[0]...)
		m["registry/records.jsonl"] = append(m["registry/records.jsonl"], '\n')
		fixtureManifest(m)
		if _, err := InspectBundle(fixtureZip(m), trust); err == nil {
			t.Fatal("accepted missing registry record")
		}
	})
}

// Test a signed registry containing two registrations for the same run.
func TestRunSetRejectsLaterRegistration(t *testing.T) {
	files, trust := bundleFixture(t)
	var runName string
	for name := range files {
		if strings.HasPrefix(name, "runs/") {
			runName = name
		}
	}
	original := bytes.Split(bytes.TrimSpace(files[runName]), []byte{'\n'})
	template, err := decodeRecord(original[0])
	if err != nil {
		t.Fatal(err)
	}
	signerSeed := sha256.Sum256([]byte("test signer seed"))
	signer := ed25519.NewKeyFromSeed(signerSeed[:])
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	kid := SHA256Hex(spki)
	keyRecord, err := decodeRecord(bytes.TrimSpace(files["keys/records.jsonl"]))
	if err != nil {
		t.Fatal(err)
	}
	prev := keyRecord.hash
	var records [][]byte
	hashes := []string{prev}
	for i, kind := range []string{"run.registered", "tool.call", "run.registered", "run.final"} {
		ev := make(map[string]any)
		for k, v := range template.ev {
			ev[k] = v
		}
		ev["id"] = fmt.Sprintf("%032x", i+2)
		ev["seq"] = float64(i + 1)
		ev["run_seq"] = float64(i)
		ev["prev_hash"] = prev
		ev["run_prev_hash"] = ZeroHash
		if i > 0 {
			ev["run_prev_hash"] = prev
		}
		ev["type"] = kind
		if kind == "tool.call" {
			ev["data"] = map[string]any{"tool_use_id": "call", "name": "Read", "input": map[string]any{}}
		}
		if kind == "run.final" {
			ev["data"] = map[string]any{"head_run_seq": float64(i - 1), "head_hash": prev}
		}
		canonical, err := Canonical(ev)
		if err != nil {
			t.Fatal(err)
		}
		hash := SHA256Hex(canonical)
		m := map[string]any{"t": "tracekit.record.v2", "alg": "ed25519", "kid": kid, "hash": hash}
		for _, k := range []string{"log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash"} {
			m[k] = ev[k]
		}
		msg, err := Canonical(m)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{"v": 2, "event": ev, "hash": hash, "alg": "ed25519", "kid": kid, "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(signer, msg))})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, raw)
		hashes = append(hashes, hash)
		prev = hash
	}
	// Build inclusion paths independently by recursively decomposing the tree.
	var tree func([][32]byte) [32]byte
	tree = func(xs [][32]byte) [32]byte {
		if len(xs) == 1 {
			return xs[0]
		}
		k := 1
		for k*2 < len(xs) {
			k *= 2
		}
		return nodeHash(tree(xs[:k]), tree(xs[k:]))
	}
	var path func([][32]byte, int) [][32]byte
	path = func(xs [][32]byte, i int) [][32]byte {
		if len(xs) == 1 {
			return nil
		}
		k := 1
		for k*2 < len(xs) {
			k *= 2
		}
		if i < k {
			return append(path(xs[:k], i), tree(xs[k:]))
		}
		return append(path(xs[k:], i-k), tree(xs[:k]))
	}
	encPath := func(xs [][32]byte) []any {
		out := make([]any, 0, len(xs))
		for _, x := range xs {
			out = append(out, base64.StdEncoding.EncodeToString(x[:]))
		}
		return out
	}
	var recordLeaves [][32]byte
	for _, h := range hashes {
		raw, err := hexDigest(h)
		if err != nil {
			t.Fatal(err)
		}
		recordLeaves = append(recordLeaves, leafHash(raw))
	}
	config, err := ParseStrict(trust)
	if err != nil {
		t.Fatal(err)
	}
	logKey, err := ParseVKey(config.(map[string]any)["logs"].([]any)[0].(string))
	if err != nil {
		t.Fatal(err)
	}
	logSeed := sha256.Sum256([]byte("test log seed"))
	logPrivate := ed25519.NewKeyFromSeed(logSeed[:])
	note := func(key VKey, leaves [][32]byte) []byte {
		root := tree(leaves)
		text := fmt.Sprintf("%s\n%d\n%s\n", key.Name, len(leaves), base64.StdEncoding.EncodeToString(root[:]))
		return []byte(text + "\n— " + key.Name + " " + base64.StdEncoding.EncodeToString(append(key.ID[:], ed25519.Sign(logPrivate, []byte(text))...)) + "\n")
	}
	inclusion := map[string]any{}
	for i := range recordLeaves {
		inclusion[fmt.Sprint(i)] = encPath(path(recordLeaves, i))
	}
	proofs, _ := json.Marshal(map[string]any{"checkpoint": "checkpoints/5.note", "tree_size": 5, "inclusion": inclusion})
	delete(files, "checkpoints/3.note")
	files["checkpoints/5.note"] = note(logKey, recordLeaves)
	files["proofs/records.json"] = proofs
	files[runName] = append(bytes.Join(records, []byte{'\n'}), '\n')
	salt := sha256.Sum256([]byte("tenant-specific registry test salt"))
	origin := registryOrigin(logKey.Name, salt[:])
	registryKey := renamedLogKey(logKey, origin)
	rid := sha256.Sum256(append(append([]byte{}, salt[:]...), []byte("run-a")...))
	logID, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	var leaves [][]byte
	var leafHashes [][32]byte
	for _, i := range []int{0, 2, 3} {
		rec, err := decodeRecord(records[i])
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 89)
		raw[0] = 1
		if i == 3 {
			raw[0] = 2
		}
		copy(raw[1:33], rid[:])
		copy(raw[33:49], logID)
		binary.BigEndian.PutUint64(raw[49:57], rec.seq)
		h, _ := hexDigest(rec.hash)
		copy(raw[57:], h)
		leaves = append(leaves, raw)
		leafHashes = append(leafHashes, leafHash(raw))
	}
	var entries []any
	for i, leaf := range leaves {
		entries = append(entries, map[string]any{"leaf": base64.StdEncoding.EncodeToString(leaf), "inclusion": encPath(path(leafHashes, i))})
	}
	spec, _ := json.Marshal(map[string]any{"tenant_salt": base64.StdEncoding.EncodeToString(salt[:]), "from": 0, "to": 3, "consistency": []any{}, "leaves": entries})
	files["registry/run-set.json"] = spec
	files["registry/records.jsonl"] = append(bytes.Join([][]byte{records[0], records[2], records[3]}, []byte{'\n'}), '\n')
	files["checkpoints/registry-3.note"] = note(registryKey, leafHashes)
	fixtureManifest(files)
	result := VerifyBundle(fixtureZip(files), trust)
	if result.ExitCode == 0 || !strings.Contains(result.Detail, "registry leaf not present in bundled run") {
		t.Fatalf("later registration was not rejected: %+v", result)
	}
}

func TestConsistencyProofs(t *testing.T) {
	a := leafHash([]byte("a"))
	b := leafHash([]byte("b"))
	c := leafHash([]byte("c"))
	ab := nodeHash(a, b)
	abc := nodeHash(ab, c)
	base64Hash := func(x [32]byte) string { return base64.StdEncoding.EncodeToString(x[:]) }
	for _, tc := range []struct {
		label    string
		m, n     uint64
		old, new [32]byte
		proof    []string
		ok       bool
	}{
		{"append one", 2, 3, ab, abc, []string{base64Hash(c)}, true},
		{"one to three", 1, 3, a, abc, []string{base64Hash(b), base64Hash(c)}, true},
		{"same", 2, 2, ab, ab, nil, true},
		{"bad root", 2, 3, ab, ab, []string{base64Hash(c)}, false},
		{"bad proof", 2, 3, ab, abc, []string{base64Hash(b)}, false},
		{"non-empty equal proof", 2, 2, ab, ab, []string{base64Hash(c)}, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			err := VerifyConsistency(tc.m, tc.n, tc.old, tc.new, tc.proof)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected consistency result %v", err)
			}
		})
	}
}

// Cross-check every old/new size pair for small Merkle trees. Proofs here are
// produced by a recursive tree decomposition, independent of VerifyConsistency.
func TestConsistencyAllSmallTreeSizes(t *testing.T) {
	leaves := make([][32]byte, 16)
	for i := range leaves {
		leaves[i] = leafHash([]byte{byte(i)})
	}
	var root func([][32]byte) [32]byte
	root = func(xs [][32]byte) [32]byte {
		if len(xs) == 1 {
			return xs[0]
		}
		k := 1
		for k*2 < len(xs) {
			k *= 2
		}
		return nodeHash(root(xs[:k]), root(xs[k:]))
	}
	var makeProof func(xs [][32]byte, m int, complete bool) [][32]byte
	makeProof = func(xs [][32]byte, m int, complete bool) [][32]byte {
		if m == len(xs) {
			if complete {
				return nil
			}
			return [][32]byte{root(xs)}
		}
		k := 1
		for k*2 < len(xs) {
			k *= 2
		}
		if m <= k {
			return append(makeProof(xs[:k], m, complete), root(xs[k:]))
		}
		return append(makeProof(xs[k:], m-k, false), root(xs[:k]))
	}
	for n := 2; n <= len(leaves); n++ {
		for m := 1; m <= n; m++ {
			var enc []string
			for _, p := range makeProof(leaves[:n], m, true) {
				enc = append(enc, base64.StdEncoding.EncodeToString(p[:]))
			}
			if err := VerifyConsistency(uint64(m), uint64(n), root(leaves[:m]), root(leaves[:n]), enc); err != nil {
				t.Fatalf("valid consistency m=%d n=%d: %v", m, n, err)
			}
		}
	}
}
