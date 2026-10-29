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
	"strings"
	"testing"
)

// These constants are copied from the published format-v2 test vectors,
// not from either verifier implementation.
const checkpointNote = "tracekit.example.org/log/0190f3a0-test\n13\nMi7CJiZLruMIePTlzHPx4mYt0B1o8dZ+0VjPECnCnOY=\n\n— tracekit.example.org/log/0190f3a0-test Bwll1vSm1GBu/u3FzyhOMXK1fwzvztQj15+2YVxT2JheD9i+UdVmejDz2e+M4AtxUuJpen36NSGqXemdYiILAxETUQU=\n— witness.example.org/w1 JXzH8QAAAABo53gAZglDLueWaKJVPcnyj3WBkywAF6aWpFAGHa4yMEkQYe/u9Gvb6/T13SPTtayVz0RIPUTq64LAPxavF/mraKi2Cg==\n"
const logVKey = "tracekit.example.org/log/0190f3a0-test+070965d6+AZsfhHkc/HZjBFhU04netcqVRJ2HXydqg4QLBgqznPxx"
const witnessVKey = "witness.example.org/w1+257cc7f1+BGG3op9v3HIXXDPBmFc/0CioJHhGCXc+pyvvFPlBZdYO"

func TestPublishedCheckpointVector(t *testing.T) {
	log, err := ParseVKey(logVKey)
	if err != nil {
		t.Fatal(err)
	}
	wit, err := ParseVKey(witnessVKey)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := VerifyCheckpoint([]byte(checkpointNote), log, []VKey{wit}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 13 || cp.Witnesses != 1 {
		t.Fatalf("checkpoint %+v", cp)
	}
	for _, tc := range []struct {
		name   string
		note   string
		quorum int
	}{
		{"missing log", strings.Replace(checkpointNote, "— tracekit.example.org/log/0190f3a0-test Bwll1vSm1GBu/u3FzyhOMXK1fwzvztQj15+2YVxT2JheD9i+UdVmejDz2e+M4AtxUuJpen36NSGqXemdYiILAxETUQU=\n", "", 1), 1},
		{"tampered root", strings.Replace(checkpointNote, "Mi7CJi", "Mi8CJi", 1), 1},
		{"duplicate signer", checkpointNote + strings.Split(checkpointNote, "\n")[4] + "\n", 1},
		{"duplicate unpinned signer", checkpointNote + "— unknown.example AAAAAAE=\n— unknown.example AAAAAAE=\n", 1},
		{"control in unpinned name", checkpointNote + "— unknown\t.example AAAAAAE=\n", 1},
		{"quorum", checkpointNote, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyCheckpoint([]byte(tc.note), log, []VKey{wit}, tc.quorum); err == nil {
				t.Fatal("accepted invalid note")
			}
		})
	}
}

// cosignLine is the witness key `name` of seed `seed` and its cosignature line
// over the published checkpoint's text.
func cosignLine(t *testing.T, name string, seed byte) (VKey, string) {
	t.Helper()
	text := strings.SplitN(checkpointNote, "\n\n", 2)[0] + "\n"
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	key, err := ParseVKey(fixtureVKey(name, 4, priv.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	ts := binary.BigEndian.AppendUint64(nil, 1760000000)
	sig := ed25519.Sign(priv, []byte("cosignature/v1\ntime 1760000000\n"+text))
	blob := append(append(append([]byte(nil), key.ID[:]...), ts...), sig...)
	return key, "— " + name + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
}

// trustWith is the bundle fixture's trust config pinning `witnesses`
// ({vkey, class} objects) and requiring `required` of them.
func trustWith(t *testing.T, trust []byte, witnesses []any, required int) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(trust, &m); err != nil {
		t.Fatal(err)
	}
	m["witnesses"], m["witnesses_required"] = witnesses, required
	raw, _ := json.Marshal(m)
	return raw
}

// A cosignature signs no key name and a witness cosigns with one key (C2SP
// tlog-cosignature), so a witness is one key under one name: one key under two
// names, or two keys under one name, is refused in the checkpoint and in the
// trust config. Two witnesses with keys and names of their own count two.
func TestWitnessCountsOnce(t *testing.T) {
	log, err := ParseVKey(logVKey)
	if err != nil {
		t.Fatal(err)
	}
	a, lineA := cosignLine(t, "witness.example/a", 7)
	alias, lineAlias := cosignLine(t, "witness.example/alias", 7)
	a2, lineA2 := cosignLine(t, "witness.example/a", 9) // a second key under a's name
	b, lineB := cosignLine(t, "witness.example/b", 8)
	aliased := "one witness key under two names (%s, %s); a key is one witness: keep it under the name it cosigns with"
	twoKeys := "two witness keys under one name (witness.example/a); a name is one witness: keep only its current key"
	cases := []struct {
		pins  []VKey
		lines string
		want  string
	}{
		{[]VKey{a, alias}, lineA + lineAlias, fmt.Sprintf(aliased, a.Name, alias.Name)},
		{[]VKey{alias, a}, lineA + lineAlias, fmt.Sprintf(aliased, alias.Name, a.Name)},
		{[]VKey{a, a2}, lineA + lineA2, twoKeys},
		{[]VKey{a2, a}, lineA + lineA2, twoKeys},
		{[]VKey{a, b}, lineA + lineB, ""},
	}
	files, trust := bundleFixture(t)
	for _, tc := range cases {
		cp, err := VerifyCheckpoint([]byte(checkpointNote+tc.lines), log, tc.pins, 2)
		if tc.want == "" && (err != nil || cp.Witnesses != 2) || tc.want != "" && (err == nil || err.Error() != tc.want) {
			t.Fatalf("checkpoint under %v: %+v %v", tc.pins, cp, err)
		}
		var ws []any
		for _, k := range tc.pins {
			ws = append(ws, map[string]any{"vkey": fixtureVKey(k.Name, 4, k.Pub), "class": "customer"})
		}
		raw := trustWith(t, trust, ws, 1)
		if _, _, _, err := loadTrust(raw); (tc.want == "") != (err == nil) {
			t.Fatalf("trust %v: %v", tc.pins, err)
		}
		if r := VerifyBundle(fixtureZip(files), raw); tc.want != "" && (r.ExitCode != 2 || r.Detail != "trust: "+tc.want) {
			t.Fatalf("bundle under trust %v: %+v", tc.pins, r)
		}
	}
}

// As the Python and TypeScript verifiers: a witness listed twice counts once
// and must have one class, and a quorum above the pinned witnesses fails the
// checkpoint (exit 1) rather than the trust config.
func TestWitnessListedTwiceAndQuorum(t *testing.T) {
	log, err := ParseVKey(logVKey)
	if err != nil {
		t.Fatal(err)
	}
	a, lineA := cosignLine(t, "witness.example/a", 7)
	if cp, err := VerifyCheckpoint([]byte(checkpointNote+lineA), log, []VKey{a, a}, 1); err != nil || cp.Witnesses != 1 {
		t.Fatalf("one witness pinned twice: %+v %v", cp, err)
	}
	if _, err := VerifyCheckpoint([]byte(checkpointNote+lineA), log, []VKey{a, a}, 2); err == nil || err.Error() != "witness quorum not met" {
		t.Fatalf("one witness pinned twice counts once: %v", err)
	}
	files, trust := bundleFixture(t)
	pin := func(class string) any { return map[string]any{"vkey": fixtureVKey(a.Name, 4, a.Pub), "class": class} }
	for _, tc := range []struct {
		witnesses []any
		required  int
		exit      int
		detail    string
	}{
		{[]any{pin("customer"), pin("customer")}, 0, 0, ""},
		{[]any{pin("customer"), pin("operator")}, 0, 2, "trust: witness witness.example/a with two classes (customer, operator); a witness has one class: list it once, with the class you give it"},
		{[]any{pin("customer")}, 2, 1, "checkpoint: witness quorum not met"},
	} {
		if r := VerifyBundle(fixtureZip(files), trustWith(t, trust, tc.witnesses, tc.required)); r.ExitCode != tc.exit || r.Detail != tc.detail {
			t.Fatalf("bundle under %v, %d required: %+v", tc.witnesses, tc.required, r)
		}
	}
}

func TestStrictCanonicalJSON(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"b":1,"a":[1.0,"é",1e21]}`, `{"a":[1,"é",1e+21],"b":1}`},
		{`{"\ue000":2,"\ud800\udc00":1}`, `{"𐀀":1,"":2}`},
		{`{"x":"<>&\n\u2028"}`, "{\"x\":\"<>&\\n\u2028\"}"},
		{`-0`, `0`},
		{`1e-7`, `1e-7`},
		{`0.000001`, `0.000001`},
		{`1e20`, `100000000000000000000`},
	} {
		v, err := ParseStrict([]byte(tc.in))
		if err != nil {
			t.Fatalf("parse %s: %v", tc.in, err)
		}
		got, err := Canonical(v)
		if err != nil || string(got) != tc.want {
			t.Errorf("canonical %s = %s, %v; want %s", tc.in, got, err, tc.want)
		}
	}
	for _, input := range []string{
		`{"a":1,"a":2}`, `{"a":1} {"b":2}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`, `9007199254740992`, `10000000000000000`, `1e999`,
		strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129),
	} {
		if _, err := ParseStrict([]byte(input)); err == nil {
			t.Errorf("accepted invalid JSON: %s", input)
		}
	}
	if _, err := ParseStrict([]byte{0xff}); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestPublishedRecordSignerEpoch(t *testing.T) {
	// Published tests/vectors/sig_v2.jsonl record-signer-epoch.
	const event = `{"schema_version":"tracekit.event.v2","id":"00000000000000000000000000000001","seq":0,"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","ts":"2026-10-09T12:00:00.000000Z","run_id":"run-1","agent_id":"main","parent_id":null,"source":"signer","type":"signer.epoch","data":{"keys":[{"kid":"sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9","alg":"ed25519","spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="}]},"log_id":"0123456789abcdef0123456789abcdef","tenant":"acme","run_seq":0,"run_prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`
	v, err := ParseStrict([]byte(event))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if h := SHA256Hex(canonical); h != "sha256:db5045e1f08ce84b3f4af68706546c4db460adbef48568a7206ba5cc73f73dc6" {
		t.Fatalf("wrong published hash: %s", h)
	}
	rec := map[string]any{"v": float64(2), "event": v, "hash": SHA256Hex(canonical), "alg": "ed25519", "kid": "sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9", "sig": "vvO32GjQqHTBxGrogevjqDyESNhwvyzyvx2FLAWockF13y9g/44ufmrLbMz+enUX2SLFahs9S3F4FWxn7xFzAA=="}
	raw, _ := json.Marshal(rec)
	spki, _ := base64.StdEncoding.DecodeString("MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
	if _, err := VerifyRecord(raw, spki); err != nil {
		t.Fatal(err)
	}
	rec["sig"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	raw, _ = json.Marshal(rec)
	if _, err := VerifyRecord(raw, spki); err == nil {
		t.Fatal("accepted forged signature")
	}
}

func TestRecordSignatureDomainSeparation(t *testing.T) {
	seed := sha256.Sum256([]byte("test-only seed"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	kid := SHA256Hex(spki)
	event := map[string]any{"seq": float64(0), "run_seq": float64(0), "prev_hash": ZeroHash, "run_prev_hash": ZeroHash, "log_id": "log", "tenant": "tenant", "run_id": "run", "type": "run.registered"}
	eb, _ := Canonical(event)
	hash := SHA256Hex(eb)
	msg := map[string]any{"t": "tracekit.record.v2", "alg": "ed25519", "kid": kid, "hash": hash}
	for _, k := range []string{"seq", "run_seq", "prev_hash", "run_prev_hash", "log_id", "tenant", "run_id"} {
		msg[k] = event[k]
	}
	m, _ := Canonical(msg)
	signature := ed25519.Sign(private, m)
	rec := map[string]any{"v": float64(2), "event": event, "hash": hash, "kid": kid, "alg": "ed25519", "sig": base64.StdEncoding.EncodeToString(signature)}
	raw, _ := json.Marshal(rec)
	if _, err := VerifyRecord(raw, spki); err != nil {
		t.Fatal(err)
	}
	rec["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte("other purpose")))
	raw, _ = json.Marshal(rec)
	if _, err := VerifyRecord(raw, spki); err == nil {
		t.Fatal("cross-purpose signature accepted")
	}
	// The order-two Edwards point is a valid encoding but not an acceptable key.
	order2 := make([]byte, 32)
	for i := range order2 {
		order2[i] = 0xff
	}
	order2[0] = 0xec
	order2[31] = 0x7f
	if validEd25519PublicKey(order2) {
		t.Fatal("accepted order-two Ed25519 public key")
	}
}

func TestMerkleRFC6962(t *testing.T) {
	records := []string{}
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		records = append(records, SHA256Hex([]byte(s)))
	}
	var leaves [][32]byte
	for _, r := range records {
		d, _ := hex.DecodeString(r[7:])
		leaves = append(leaves, leafHash(d))
	}
	var root func([][32]byte) [32]byte
	root = func(nodes [][32]byte) [32]byte {
		if len(nodes) == 1 {
			return nodes[0]
		}
		split := 1
		for 2*split < len(nodes) {
			split *= 2
		}
		return nodeHash(root(nodes[:split]), root(nodes[split:]))
	}
	var proof func([][32]byte, int) [][32]byte
	proof = func(nodes [][32]byte, i int) [][32]byte {
		if len(nodes) == 1 {
			return nil
		}
		split := 1
		for 2*split < len(nodes) {
			split *= 2
		}
		if i < split {
			return append(proof(nodes[:split], i), root(nodes[split:]))
		}
		return append(proof(nodes[split:], i-split), root(nodes[:split]))
	}
	for n := 1; n <= len(leaves); n++ {
		for i := 0; i < n; i++ {
			path := []string{}
			for _, p := range proof(leaves[:n], i) {
				path = append(path, base64.StdEncoding.EncodeToString(p[:]))
			}
			if err := VerifyInclusion(records[i], uint64(i), uint64(n), path, root(leaves[:n])); err != nil {
				t.Fatalf("size %d index %d: %v", n, i, err)
			}
			wrong := sha256.Sum256([]byte("wrong"))
			if err := VerifyInclusion(records[i], uint64(i), uint64(n), path, wrong); err == nil {
				t.Fatal("accepted invalid root")
			}
		}
	}
}

func TestPublishedSmallOrderEd25519Keys(t *testing.T) {
	vectors := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	}
	for i, key := range vectors {
		pub, err := hex.DecodeString(key)
		if err != nil {
			t.Fatal(err)
		}
		if validEd25519PublicKey(pub) {
			t.Errorf("accepted published small-order Ed25519 key %d", i)
		}
	}
}

func TestPublicKeyIsCanonical(t *testing.T) {
	var one [32]byte
	one[0] = 1
	if validEd25519PublicKey(one[:]) {
		t.Fatal("accepted Edwards identity")
	}
	if _, err := ParseVKey(strings.Replace(logVKey, "070965d6", "070965d7", 1)); err == nil {
		t.Fatal("accepted forged key id")
	}
	var buf bytes.Buffer
	jcsString(&buf, "\x00\b\n")
	if buf.String() != `"\u0000\b\n"` {
		t.Fatal(buf.String())
	}
}

func TestNonFiniteTokens(t *testing.T) {
	for _, raw := range []string{"NaN", "[Infinity]", "[-Infinity]", `{"a":NaN}`, "[1, NaN]", "1e400"} {
		_, err := ParseStrict([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), "non_finite") {
			t.Errorf("%q: wanted non_finite, got %v", raw, err)
		}
	}
}

func TestNonFiniteTokensInStrings(t *testing.T) {
	for _, raw := range []string{`"NaN"`, `{"NaN":"-Infinity","a":"Infinity"}`, `["NaN", "Infinity", "-Infinity", "\"NaN\""]`} {
		if _, err := ParseStrict([]byte(raw)); err != nil {
			t.Errorf("quoted token in %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{"NaNx", "[InfinityExtra]", "-InfinityX"} {
		_, err := ParseStrict([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), "syntax") {
			t.Errorf("%q: expected syntax, got %v", raw, err)
		}
	}
}
