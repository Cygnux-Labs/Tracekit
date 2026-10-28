package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedSchemaViolation(t *testing.T) {
	files, _ := bundleFixture(t)
	var line []byte
	for name, raw := range files {
		if strings.HasPrefix(name, "runs/") {
			line = bytes.Split(raw, []byte{'\n'})[0]
		}
	}
	r, err := decodeRecord(line)
	if err != nil {
		t.Fatal(err)
	}
	d := r.ev["data"].(map[string]any)
	delete(d, "identity")
	canonical, _ := Canonical(r.ev)
	r.rec["hash"] = SHA256Hex(canonical)
	seed := sha256.Sum256([]byte("test signer seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	spki, _ := x509.MarshalPKIXPublicKey(priv.Public())
	message := map[string]any{"t": "tracekit.record.v2", "alg": "ed25519", "kid": r.rec["kid"], "hash": r.rec["hash"]}
	for _, k := range []string{"log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash"} {
		message[k] = r.ev[k]
	}
	msg, _ := Canonical(message)
	r.rec["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	raw, _ := json.Marshal(r.rec)
	if _, err := VerifyRecord(raw, spki); err != nil {
		t.Fatalf("mutation must remain cryptographically authentic: %v", err)
	}
	mutated, err := decodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRecord(mutated, raw, map[string]recordedKey{SHA256Hex(spki): {spki: spki}}); err == nil {
		t.Fatal("accepted authenticated event missing required identity")
	}
}

func TestHumanApprovalSchema(t *testing.T) {
	files, err := ReadBundle(readGolden(t, "v2/approval.tkb"))
	if err != nil {
		t.Fatal(err)
	}
	var approval map[string]any
	for name, raw := range files {
		if !strings.HasPrefix(name, "runs/") {
			continue
		}
		lines, e := readLines(raw)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range lines {
			r, e := decodeRecord(line)
			if e != nil {
				t.Fatal(e)
			}
			if r.ev["type"] == "approval" {
				approval = r.ev
			}
		}
	}
	if approval == nil {
		t.Fatal("no approval record")
	}
	if err := ValidateEvent(approval); err != nil {
		t.Fatal(err)
	}
	data := approval["data"].(map[string]any)
	approver := data["approver"]
	delete(data, "approver")
	if err := ValidateEvent(approval); err == nil {
		t.Fatal("accepted human approval without approver")
	}
	data["approver"] = approver
	data["decision"] = "allow"
	if err := ValidateEvent(approval); err == nil {
		t.Fatal("accepted invalid human approval decision")
	}
}

func TestTimestampMalformedDER(t *testing.T) {
	for _, raw := range [][]byte{nil, {0x30}, {0x30, 0x80}, {0x30, 3, 2, 1, 0}, {0x30, 0xff, 0xff}, {0x30, 2, 0x30, 0}} {
		if _, err := verifyTimestamp(raw, []byte("note"), map[string]any{}); err == nil {
			t.Fatalf("accepted malformed timestamp %x", raw)
		}
	}
}

func TestV1CanonicalNumbersAndKeyOrder(t *testing.T) {
	for input, want := range map[string]string{
		`{"n":2.0}`:                     `{"n":2.0}`,
		`{"n":2.0,"s":"1e3"}`:           `{"n":2,"s":"1e3"}`,
		`{"n":1e-5}`:                    `{"n":0.00001}`,
		`{"n":-0.0}`:                    `{"n":-0.0}`,
		`{"\ud83d\ude00":1,"\ue000":2}`: "{\"\ue000\":2,\"😀\":1}",
	} {
		v, err := ParseStrict([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := v1Canonical(v)
		if err != nil || string(raw) != want {
			t.Fatalf("v1 canonical %s: %s, %v; want %s", input, raw, err, want)
		}
	}
}

func TestEmptyV1WitnessCannotAnchor(t *testing.T) {
	bundle := readGolden(t, "v1/demo-run.tkb")
	for _, witness := range [][]byte{[]byte{}, []byte("\n  \n")} {
		r := VerifyV1(bundle, nil, witness)
		if r.ExitCode != 0 || !strings.Contains(r.Integrity, "UNANCHORED") {
			t.Fatalf("empty witness anchored evidence: %+v", r)
		}
		if len(r.Checks) == 0 {
			t.Fatal("missing empty witness warning")
		}
	}
}

func fixtureWithWarning(t *testing.T, typ string, data map[string]any) ([]byte, []byte) {
	t.Helper()
	files, trust := bundleFixture(t)
	var name string
	for n := range files {
		if strings.HasPrefix(n, "runs/") {
			name = n
		}
	}
	lines, err := readLines(files[name])
	if err != nil {
		t.Fatal(err)
	}
	first, err := decodeRecord(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	warning, err := decodeRecord(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("test signer seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	sign := func(r map[string]any) ([]byte, string) {
		ev := r["event"].(map[string]any)
		raw, _ := Canonical(ev)
		hash := SHA256Hex(raw)
		r["hash"] = hash
		msg := map[string]any{"t": "tracekit.record.v2", "alg": "ed25519", "kid": r["kid"], "hash": hash}
		for _, key := range []string{"log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash"} {
			msg[key] = ev[key]
		}
		canonical, _ := Canonical(msg)
		r["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))
		raw, _ = json.Marshal(r)
		return append(raw, '\n'), hash
	}
	warning.ev["type"], warning.ev["data"] = typ, data
	wraw, whash := sign(warning.rec)
	final, err := decodeRecord(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	final.ev["seq"], final.ev["run_seq"] = json.Number("3"), json.Number("2")
	final.ev["id"] = strings.Repeat("4", 32)
	final.ev["prev_hash"], final.ev["run_prev_hash"] = whash, whash
	final.ev["data"] = map[string]any{"head_run_seq": json.Number("1"), "head_hash": whash}
	fraw, fhash := sign(final.rec)
	files[name] = append(append(append(append([]byte(nil), lines[0]...), '\n'), wraw...), fraw...)
	epoch, err := decodeRecord(bytes.TrimSpace(files["keys/records.jsonl"]))
	if err != nil {
		t.Fatal(err)
	}
	var leaves [][32]byte
	for _, h := range []string{epoch.hash, first.hash, whash, fhash} {
		raw, _ := hex.DecodeString(h[7:])
		leaves = append(leaves, leafHash(raw))
	}
	left, right := nodeHash(leaves[0], leaves[1]), nodeHash(leaves[2], leaves[3])
	root := nodeHash(left, right)
	proofs := map[string]any{}
	for i := 0; i < 4; i++ {
		other := right
		if i >= 2 {
			other = left
		}
		proofs[fmt.Sprint(i)] = []any{base64.StdEncoding.EncodeToString(leaves[i^1][:]), base64.StdEncoding.EncodeToString(other[:])}
	}
	raw, _ := json.Marshal(map[string]any{"checkpoint": "checkpoints/4.note", "tree_size": 4, "inclusion": proofs})
	files["proofs/records.json"] = raw
	logSeed := sha256.Sum256([]byte("test log seed"))
	logPriv := ed25519.NewKeyFromSeed(logSeed[:])
	v, _ := ParseStrict(trust)
	pin, _ := ParseVKey(v.(map[string]any)["logs"].([]any)[0].(string))
	text := fmt.Sprintf("%s\n4\n%s\n", pin.Name, base64.StdEncoding.EncodeToString(root[:]))
	files["checkpoints/4.note"] = []byte(text + "\n— " + pin.Name + " " + base64.StdEncoding.EncodeToString(append(pin.ID[:], ed25519.Sign(logPriv, []byte(text))...)) + "\n")
	delete(files, "checkpoints/3.note")
	fixtureManifest(files)
	return fixtureZip(files), trust
}

func TestSignedV2WarningEvidenceRemainsVisible(t *testing.T) {
	commitment := "hmac-sha256:" + strings.Repeat("0", 64)
	for _, tc := range []struct {
		typ, check string
		data       map[string]any
	}{
		{"capture.gap", "gaps", map[string]any{"kind": "decided_not_completed", "reason": "missing result"}},
		{"capture.gap", "policy", map[string]any{"kind": "executed_against_policy", "reason": "call ran despite deny"}},
		{"trace.tamper", "gaps", map[string]any{"path": "transcript.jsonl", "before": map[string]any{}, "after": map[string]any{}, "kind": "edited"}},
		{"approval.binding_mismatch", "gaps", map[string]any{"approval_id": "approval", "tool_use_id": "call", "approved_commitment": commitment, "args_commitment": commitment}},
	} {
		t.Run(tc.typ+"/"+tc.check, func(t *testing.T) {
			bundle, trust := fixtureWithWarning(t, tc.typ, tc.data)
			r := VerifyBundle(bundle, trust)
			if r.ExitCode != 0 || r.Integrity != "VERIFIED" {
				t.Fatalf("signed warning bundle failed: %+v", r)
			}
			found := false
			for _, c := range r.Checks {
				if c.Check == tc.check && c.Status == "warn" {
					found = true
				}
			}
			if !found {
				t.Fatalf("signed warning was hidden: %+v", r)
			}
		})
	}
}

func TestSignedV1TamperingRemainsVisible(t *testing.T) {
	files, err := readV1Bundle(readGolden(t, "v1/demo-run.tkb"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := parseV1Lines(files["records.jsonl"])
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("v1 tampering warning fixture"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	kid := v1Kid(pub)
	prev := strings.Repeat("0", 64)
	mutated := false
	var ledger bytes.Buffer
	for _, r := range records {
		ev := r["event"].(map[string]any)
		if !mutated && ev["type"] == "tool.call" {
			ev["type"] = "trace.tamper"
			ev["data"] = map[string]any{"path": "transcript.jsonl", "before": map[string]any{}, "after": map[string]any{}}
			mutated = true
		}
		ev["prev_hash"] = prev
		hash := v1Hash(ev)
		r["hash"], r["kid"] = hash, kid
		msg, _ := v1Canonical(map[string]any{"hash": hash, "prev_hash": prev, "seq": ev["seq"]})
		r["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
		raw, _ := json.Marshal(r)
		ledger.Write(raw)
		ledger.WriteByte('\n')
		prev = hash
	}
	if !mutated {
		t.Fatal("fixture has no tool call")
	}
	files["records.jsonl"] = ledger.Bytes()
	files["signer.pub"] = pub
	cp := map[string]any{"type": "tracekit.checkpoint.v1", "head_seq": json.Number(fmt.Sprint(len(records) - 1)), "head_hash": prev, "ts": "2026-10-09T12:00:00.000000Z", "kid": kid}
	msg, _ := v1Canonical(cp)
	cp["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	files["checkpoints.jsonl"], _ = json.Marshal(cp)
	manifest, err := parseFileObject(files, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest["kid"] = kid
	listed := manifest["files"].(map[string]any)
	for name, raw := range files {
		if name != "manifest.json" {
			sum := sha256.Sum256(raw)
			listed[name] = hex.EncodeToString(sum[:])
		}
	}
	files["manifest.json"], _ = json.Marshal(manifest)
	r := VerifyV1(fixtureZip(files), pub, nil)
	if r.ExitCode != 0 {
		t.Fatalf("authenticated tamper report failed: %+v", r)
	}
	found := false
	for _, c := range r.Checks {
		if c.Check == "harness transcript unchanged" && c.Status == "warn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("signed v1 tampering was hidden: %+v", r)
	}
}

func TestSemanticFailClosed(t *testing.T) {
	record := func(typ string, data map[string]any) validatedRecord {
		return validatedRecord{ev: map[string]any{"type": typ, "data": data}}
	}
	for _, r := range []validatedRecord{
		record("review", map[string]any{}), record("why.finding", map[string]any{}), record("incident.opened", map[string]any{}), record("ext", map[string]any{}),
		record("approval", map[string]any{"decision": "approve", "approver_kind": "agent"}),
	} {
		t.Run(r.ev["type"].(string), func(t *testing.T) {
			err := checkSemantics(nil, []runEvidence{{records: []validatedRecord{r}}}, nil)
			if _, ok := err.(unsupportedEvidence); !ok {
				t.Fatalf("unsupported semantics accepted: %v", err)
			}
		})
	}
	for _, decision := range []string{"allow", "deny", "ask"} {
		err := checkSemantics(nil, []runEvidence{{records: []validatedRecord{record("policy.decision", map[string]any{"rule_ids": []any{"TK-CONSTRAINT"}, "decision": decision})}}}, nil)
		if err == nil {
			t.Fatalf("accepted %s constraint before constraint.added", decision)
		}
	}
	held := []validatedRecord{record("constraint.added", map[string]any{}), record("policy.decision", map[string]any{"rule_ids": []any{"TK-CONSTRAINT"}, "decision": "ask"})}
	if err := checkSemantics(nil, []runEvidence{{records: held}}, nil); err != nil {
		t.Fatal(err)
	}
	held[1].ev["data"].(map[string]any)["decision"] = "allow"
	if err := checkSemantics(nil, []runEvidence{{records: held}}, nil); err == nil {
		t.Fatal("constraint allowed rather than asked")
	}
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "golden", filepath.FromSlash(name)))
	if os.IsNotExist(err) {
		t.Skip("upstream golden corpus unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAnchorSecurityMutations(t *testing.T) {
	bundle := readGolden(t, "v2/closed.tkb")
	trust := readGolden(t, "v2/trust-rekor.json")
	if r := VerifyBundle(bundle, trust); r.ExitCode != 0 {
		t.Fatalf("valid anchor failed: %+v", r)
	}
	files, err := ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{"tsa/6.tsr", "rekor/6.json"} {
		// The fixture's tree size is discovered rather than assumed.
		prefix := strings.Split(component, "/")[0] + "/"
		for name := range files {
			if strings.HasPrefix(name, prefix) {
				component = name
				break
			}
		}
		t.Run(component, func(t *testing.T) {
			bad := copyFiles(files)
			raw := bad[component]
			if len(raw) == 0 {
				t.Fatal("missing anchor component")
			}
			raw[len(raw)-1] ^= 1
			bad[component] = raw
			fixtureManifest(bad)
			if r := VerifyBundle(fixtureZip(bad), trust); r.ExitCode == 0 || strings.HasPrefix(r.Integrity, "VERIFIED") {
				t.Fatalf("accepted corrupt anchor: %+v", r)
			}
		})
	}
	for _, mutation := range []string{"unpinned TSA", "wrong publisher", "expired shard", "bad inclusion", "bad checkpoint"} {
		t.Run(mutation, func(t *testing.T) {
			parsed, _ := ParseStrict(trust)
			pin := parsed.(map[string]any)["rekor"].(map[string]any)
			root := pin["trusted_root"].(map[string]any)
			bad := copyFiles(files)
			switch mutation {
			case "unpinned TSA":
				root["timestampAuthorities"] = []any{}
			case "wrong publisher":
				pin["publishing_key"] = base64.StdEncoding.EncodeToString([]byte("untrusted publishing key"))
			case "expired shard":
				logs := root["tlogs"].([]any)
				logs[0].(map[string]any)["publicKey"].(map[string]any)["validFor"] = map[string]any{"start": "2020-01-01T00:00:00Z", "end": "2020-01-02T00:00:00Z"}
			case "bad inclusion", "bad checkpoint":
				for name, raw := range bad {
					if !strings.HasPrefix(name, "rekor/") {
						continue
					}
					v, e := ParseStrict(raw)
					if e != nil {
						t.Fatal(e)
					}
					ip := v.(map[string]any)["inclusionProof"].(map[string]any)
					if mutation == "bad inclusion" {
						ip["rootHash"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
					} else {
						cp := ip["checkpoint"].(map[string]any)
						cp["envelope"] = strings.Replace(cp["envelope"].(string), "—", "-", 1)
					}
					bad[name], _ = json.Marshal(v)
				}
			}
			config, _ := json.Marshal(parsed)
			fixtureManifest(bad)
			r := VerifyBundle(fixtureZip(bad), config)
			if r.ExitCode == 0 || strings.HasPrefix(r.Integrity, "VERIFIED") {
				t.Fatalf("accepted %s: %+v", mutation, r)
			}
		})
	}
}

func TestAnchorUsesRenamedVerifiedCheckpointNote(t *testing.T) {
	bundle := readGolden(t, "v2/closed.tkb")
	trust := readGolden(t, "v2/trust-rekor.json")
	files, err := ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := parseFileObject(files, "proofs/records.json")
	if err != nil {
		t.Fatal(err)
	}
	noteName := proofs["checkpoint"].(string)
	verifiedNote := append([]byte(nil), files[noteName]...)
	log, _, _, err := loadTrust(trust)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := VerifyCheckpoint(verifiedNote, log, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	renamedName := fmt.Sprintf("checkpoints/%d.note", cp.Size+1)
	files[renamedName] = verifiedNote
	proofs["checkpoint"] = renamedName
	files["proofs/records.json"], _ = json.Marshal(proofs)
	files[fmt.Sprintf("checkpoints/%d.note", cp.Size)] = []byte("foreign checkpoint note\n")
	fixtureManifest(files)
	r := VerifyBundle(fixtureZip(files), trust)
	if r.ExitCode != 0 {
		t.Fatalf("anchor did not use the verified renamed checkpoint note: %+v", r)
	}
}

func TestAnchorDigestBindsSelectedCheckpointBodyAndSignature(t *testing.T) {
	files, err := ReadBundle(readGolden(t, "v2/closed.tkb"))
	if err != nil {
		t.Fatal(err)
	}
	trust := readGolden(t, "v2/trust-rekor.json")
	log, _, _, err := loadTrust(trust)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := parseFileObject(files, "proofs/records.json")
	if err != nil {
		t.Fatal(err)
	}
	noteName := proofs["checkpoint"].(string)
	selectedNote := append([]byte(nil), files[noteName]...)
	cp, err := VerifyCheckpoint(selectedNote, log, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPath := fmt.Sprintf("checkpoints/%d.note", cp.Size)
	canonicalNote, ok := files[canonicalPath]
	if !ok {
		t.Fatalf("missing legacy anchor note path %s", canonicalPath)
	}
	if _, err := verifyAnchor(files, trust, log, cp, canonicalNote); err != nil {
		t.Fatalf("legacy canonical-note anchor should verify: %v", err)
	}
	sections := bytes.SplitN(selectedNote, []byte("\n\n"), 2)
	header := bytes.Split(sections[0], []byte("\n"))
	if len(header) != 3 {
		t.Fatal("invalid selected checkpoint header")
	}
	changedRoot := append([]byte(nil), header[2]...)
	if changedRoot[0] == 'A' {
		changedRoot[0] = 'B'
	} else {
		changedRoot[0] = 'A'
	}
	selectedNote = bytes.Replace(selectedNote, header[2], changedRoot, 1)
	if _, err := verifyAnchor(files, trust, log, cp, selectedNote); err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("foreign checkpoint body did not fail the bound timestamp digest: %v", err)
	}
}

func TestMalformedTrustAndEmptyEvidenceDoNotPanic(t *testing.T) {
	files, trust := bundleFixture(t)
	bundle := fixtureZip(files)
	for _, raw := range []string{`null`, `[]`, `{"logs":[]}`, `{"logs":[null],"algs":["ed25519"]}`, `{"logs":[],"witnesses":[null]}`} {
		if r := VerifyBundle(bundle, []byte(raw)); r.ExitCode == 0 {
			t.Fatalf("accepted malformed trust %s", raw)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "runs/") {
			files[name] = nil
		}
	}
	fixtureManifest(files)
	if r := VerifyBundle(fixtureZip(files), trust); r.ExitCode == 0 {
		t.Fatal("accepted empty run")
	}
}

func TestVerifierMinVersionUsesStrictDigitBounds(t *testing.T) {
	for _, version := range []string{"9999999999", "99999999999999999999"} {
		t.Run(version, func(t *testing.T) {
			files, trust := bundleFixture(t)
			manifest, err := parseFileObject(files, "manifest.json")
			if err != nil {
				t.Fatal(err)
			}
			manifest["verifier_min_version"] = version
			files["manifest.json"], _ = json.Marshal(manifest)
			r := VerifyBundle(fixtureZip(files), trust)
			if r.Integrity != "UNUSABLE BUNDLE" || r.Detail != "invalid manifest format or version" {
				t.Fatalf("accepted out-of-range version component: %+v", r)
			}
		})
	}
}

func TestV1SecurityMutations(t *testing.T) {
	bundle := readGolden(t, "v1/demo-run.tkb")
	key := readGolden(t, "v1/signer.pub")
	if r := VerifyV1(bundle, key, nil); r.ExitCode != 0 {
		t.Fatalf("valid v1 failed: %+v", r)
	}
	for _, pin := range [][]byte{[]byte(base64.StdEncoding.EncodeToString(key) + "\n"), []byte(v1Kid(key))} {
		if r := VerifyV1(bundle, pin, nil); r.ExitCode != 0 {
			t.Fatalf("valid alternate v1 key pin rejected: %+v", r)
		}
	}
	for _, mutation := range []string{"wrong key", "record signature", "checkpoint signature", "policy rule"} {
		t.Run(mutation, func(t *testing.T) {
			files, e := readV1Bundle(bundle)
			if e != nil {
				t.Fatal(e)
			}
			pin := append([]byte(nil), key...)
			if mutation == "wrong key" {
				pin[0] ^= 1
			} else if mutation == "policy rule" {
				for name, raw := range files {
					if strings.HasPrefix(name, "policies/") {
						files[name] = bytes.ReplaceAll(raw, []byte(`"id"`), []byte(`"not_id"`))
					}
				}
			} else {
				name := "records.jsonl"
				if mutation == "checkpoint signature" {
					name = "checkpoints.jsonl"
				}
				lines, e := parseV1Lines(files[name])
				if e != nil {
					t.Fatal(e)
				}
				if len(lines) == 0 {
					t.Fatal("empty mutation target")
				}
				lines[0]["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
				var raw bytes.Buffer
				for _, r := range lines {
					line, _ := json.Marshal(r)
					raw.Write(line)
					raw.WriteByte('\n')
				}
				files[name] = raw.Bytes()
			}
			// Update the unsigned manifest, ensuring cryptographic/policy checks must
			// reject the forged content even when ZIP checksums and file hashes agree.
			manifest, e := parseFileObject(files, "manifest.json")
			if e != nil {
				t.Fatal(e)
			}
			listed := manifest["files"].(map[string]any)
			for name, raw := range files {
				if name != "manifest.json" {
					sum := sha256.Sum256(raw)
					listed[name] = hex.EncodeToString(sum[:])
				}
			}
			files["manifest.json"], _ = json.Marshal(manifest)
			r := VerifyV1(fixtureZip(files), pin, nil)
			if r.ExitCode == 0 || strings.HasPrefix(r.Integrity, "VERIFIED") {
				t.Fatalf("accepted forged v1 evidence: %+v", r)
			}
		})
	}
}
