package verifier

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed event-v1.schema.json
var v1SchemaBytes []byte
var v1Schema = func() map[string]any {
	var s map[string]any
	if err := json.Unmarshal(v1SchemaBytes, &s); err != nil {
		panic(err)
	}
	return s
}()

func v1Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	jsFloats := false
	var write func(any) error
	write = func(v any) error {
		switch x := v.(type) {
		case json.Number:
			if !strings.ContainsAny(string(x), ".eE") {
				if x == "-0" {
					b.WriteByte('0')
				} else {
					b.WriteString(string(x))
				}
				return nil
			}
			f, err := x.Float64()
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return fmt.Errorf("invalid v1 number")
			}
			if jsFloats {
				return writeJCS(&b, f)
			}
			abs := math.Abs(f)
			if abs != 0 && (abs < 1e-4 || abs >= 1e16) {
				b.WriteString(strconv.FormatFloat(f, 'e', -1, 64))
			} else {
				s := strconv.FormatFloat(f, 'f', -1, 64)
				b.WriteString(s)
				if !strings.Contains(s, ".") {
					b.WriteString(".0")
				}
			}
		case map[string]any:
			names := make([]string, 0, len(x))
			for n := range x {
				names = append(names, n)
			}
			sort.Strings(names)
			b.WriteByte('{')
			for i, n := range names {
				if i > 0 {
					b.WriteByte(',')
				}
				jcsString(&b, n)
				b.WriteByte(':')
				if err := write(x[n]); err != nil {
					return err
				}
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, e := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := write(e); err != nil {
					return err
				}
			}
			b.WriteByte(']')
		default:
			return writeJCS(&b, v)
		}
		return nil
	}
	if err := write(v); err != nil {
		return nil, err
	}
	// v1's historical Python serializer switches every float to ECMAScript
	// formatting if its first rendering contains an exponent, even in a string.
	if regexp.MustCompile(`[0-9][eE][+-]?[0-9]`).Match(b.Bytes()) {
		b.Reset()
		jsFloats = true
		if err := write(v); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}
func v1Hash(v any) string {
	raw, err := v1Canonical(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func v1Kid(pub []byte) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:])[:16]
}

func readV1Bundle(raw []byte) (map[string][]byte, error) {
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	if len(z.File) > 10000 {
		return nil, fmt.Errorf("ZIP entry count limit")
	}
	files := map[string][]byte{}
	var total uint64
	for _, f := range z.File {
		if f.Flags&1 != 0 {
			return nil, fmt.Errorf("encrypted ZIP member")
		}
		offset, err := f.DataOffset()
		if err != nil {
			return nil, err
		}
		if offset < 0 || offset > int64(len(raw)) {
			return nil, fmt.Errorf("ZIP local data out of bounds")
		}
		start := max(int64(0), offset-30-2*65535)
		found := false
		for pos := start; pos+30 <= offset; {
			i := bytes.Index(raw[pos:offset-26], []byte{'P', 'K', 3, 4})
			if i < 0 {
				break
			}
			pos += int64(i)
			h := raw[pos : pos+30]
			n := int64(binary.LittleEndian.Uint16(h[26:]))
			extra := int64(binary.LittleEndian.Uint16(h[28:]))
			if pos+30+n+extra == offset {
				found = true
				if string(raw[pos+30:pos+30+n]) != f.Name {
					return nil, fmt.Errorf("ZIP local/central name mismatch")
				}
			}
			pos++
		}
		if !found {
			return nil, fmt.Errorf("invalid ZIP local header")
		}
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		if _, ok := files[f.Name]; ok {
			return nil, fmt.Errorf("duplicate ZIP member")
		}
		total += f.UncompressedSize64
		if total > 512<<20 {
			return nil, fmt.Errorf("ZIP expansion limit")
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, e := io.ReadAll(io.LimitReader(r, int64(f.UncompressedSize64)+1))
		r.Close()
		if e != nil || uint64(len(data)) != f.UncompressedSize64 {
			return nil, fmt.Errorf("ZIP content failure")
		}
		files[f.Name] = data
	}
	return files, nil
}
func parseV1Lines(raw []byte) ([]map[string]any, error) {
	return parseV1JSONL(raw, false)
}

func parseV1JSONL(raw []byte, skipBlank bool) ([]map[string]any, error) {
	var out []map[string]any
	lines := bytes.Split(raw, []byte{'\n'})
	if len(raw) == 0 {
		return out, nil
	}
	if raw[len(raw)-1] == '\n' {
		lines = lines[:len(lines)-1]
	}
	for _, line := range lines {
		if skipBlank && len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		v, err := ParseStrict(line)
		if err != nil {
			return nil, err
		}
		m, err := object(v)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}
func verifyV1Checkpoint(cp map[string]any, pub []byte, kid string) bool {
	if cp["type"] != "tracekit.checkpoint.v1" || cp["kid"] != kid {
		return false
	}
	sigText, ok := cp["sig"].(string)
	if !ok {
		return false
	}
	sig, err := b64(sigText)
	if err != nil {
		return false
	}
	body := map[string]any{}
	for k, v := range cp {
		if k != "sig" {
			body[k] = v
		}
	}
	raw, err := v1Canonical(body)
	return err == nil && ed25519.Verify(pub, raw, sig)
}

// VerifyV1 checks the original ledger envelope and its independent witness copy.
// key may be a raw/base64 public key or an ed25519: key-id pin; witness is the
// contents of the caller-selected file witness, never a bundle-provided path.
func VerifyV1(bundle, key, witness []byte) Verification {
	rep := Verification{ExitCode: 2, Integrity: "UNUSABLE BUNDLE", Assurance: "unknown (no run.start checked)", Checks: []VerificationCheck{}}
	// problems are reported under the reference verifier's check they fail, one line per check
	var problems []string
	failedAt := map[string]int{}
	fail := func(check, s string) {
		problems = append(problems, s)
		if i, ok := failedAt[check]; ok {
			rep.Checks[i].Detail += "; " + s
			return
		}
		failedAt[check] = len(rep.Checks)
		rep.Checks = append(rep.Checks, VerificationCheck{check, "fail", s})
	}
	stop := func() Verification {
		rep.Detail = strings.Join(problems, "; ")
		return rep
	}
	files, err := readV1Bundle(bundle)
	if err != nil {
		fail("bundle readable", err.Error())
		return stop()
	}
	manifest, err := parseFileObject(files, "manifest.json")
	if err != nil || manifest["format"] != "tracekit.bundle.v1" {
		fail("bundle readable", "invalid v1 manifest")
		return stop()
	}
	rep.ExitCode, rep.Integrity = 1, "VERIFICATION FAILED"
	listed, err := object(manifest["files"])
	if err != nil {
		fail("files match manifest", "invalid manifest file list")
	} else {
		for name, digest := range listed {
			if name == "replay.html" {
				continue
			}
			raw, ok := files[name]
			sum := sha256.Sum256(raw)
			if !ok || digest != hex.EncodeToString(sum[:]) {
				fail("files match manifest", "manifest hash mismatch: "+name)
			}
		}
		for name := range files {
			if name != "manifest.json" && name != "replay.html" {
				if _, ok := listed[name]; !ok {
					fail("files match manifest", "unlisted file: "+name)
				}
			}
		}
	}
	pub := files["signer.pub"]
	if len(pub) != 32 || !validEd25519PublicKey(pub) {
		fail("signatures valid", "invalid signer key")
		return stop()
	}
	kid := v1Kid(pub)
	if manifest["kid"] != kid {
		fail("signatures valid", "manifest signer key mismatch")
	}
	records, err := parseV1Lines(files["records.jsonl"])
	if err != nil {
		fail("chain intact", err.Error())
		return stop()
	}
	hashes := map[uint64]string{}
	prev := strings.Repeat("0", 64)
	var events []map[string]any
	stubs := 0
	for i, r := range records {
		var ev map[string]any
		var seq uint64
		var ph any
		if r["elided"] == true {
			stubs++
			seq, err = fieldInt(r, "seq")
			ph = r["prev_hash"]
		} else {
			ev, err = object(r["event"])
			if err != nil {
				fail("chain intact", "invalid event")
				continue
			}
			seq, err = fieldInt(ev, "seq")
			ph = ev["prev_hash"]
			events = append(events, ev)
			if v1Hash(ev) != r["hash"] {
				fail("chain intact", fmt.Sprintf("record seq %v: event hash mismatch", ev["seq"]))
			}
			if err := validateSchema(ev, v1Schema, v1Schema, "event", 0); err != nil {
				fail("events match schema v1", err.Error())
			}
		}
		if err != nil || seq != uint64(i) || ph != prev {
			fail("chain intact", "ledger chain mismatch")
		}
		hash, ok := r["hash"].(string)
		if !ok {
			fail("chain intact", "invalid record hash")
		}
		hashes[seq] = hash
		prev = hash
		sigText, _ := r["sig"].(string)
		sig, e := b64(sigText)
		msg, _ := v1Canonical(map[string]any{"hash": hash, "prev_hash": ph, "seq": json.Number(fmt.Sprint(seq))})
		if e != nil || r["kid"] != kid || !ed25519.Verify(pub, msg, sig) {
			fail("signatures valid", "invalid record signature")
		}
	}
	if len(records) == 0 {
		fail("chain intact", "empty ledger")
	}
	if r, ok := manifest["seq_range"].([]any); ok && len(r) == 2 && len(records) > 0 {
		if n, ok := r[1].(json.Number); !ok || string(n) != fmt.Sprint(len(records)-1) {
			fail("manifest range", "manifest sequence range mismatch")
		}
	}
	cps, err := parseV1JSONL(files["checkpoints.jsonl"], true)
	if err != nil {
		fail("head matches a witness checkpoint", "invalid checkpoint file")
	}
	for _, cp := range cps {
		seq, e := fieldInt(cp, "head_seq")
		if e != nil || !verifyV1Checkpoint(cp, pub, kid) || hashes[seq] != cp["head_hash"] {
			fail("head matches a witness checkpoint", "invalid bundled checkpoint")
		}
	}
	anchored := false
	if len(key) > 0 {
		if strings.HasPrefix(string(key), "ed25519:") {
			if string(key) != kid {
				fail("trust root", "trusted signer key mismatch")
			} else {
				anchored = true
			}
		} else {
			pin := key
			if len(pin) != 32 {
				var e error
				pin, e = b64(strings.TrimSpace(string(key)))
				if e != nil {
					fail("trust root", "invalid trusted key")
				}
			}
			if !bytes.Equal(pin, pub) {
				fail("trust root", "trusted signer key mismatch")
			} else {
				anchored = true
			}
		}
	}
	witnessSeqs := map[uint64]bool{}
	if witness != nil {
		ws, e := parseV1JSONL(witness, true)
		if e != nil {
			fail("head matches a witness checkpoint", "invalid witness JSONL")
		}
		matching := 0
		consistent := 0
		for _, cp := range ws {
			if cp["kid"] != kid {
				continue
			}
			matching++
			seq, e := fieldInt(cp, "head_seq")
			if e != nil || !verifyV1Checkpoint(cp, pub, kid) {
				fail("head matches a witness checkpoint", "invalid witness checkpoint")
				continue
			}
			if h, ok := hashes[seq]; ok {
				if cp["head_hash"] != h {
					fail("head matches a witness checkpoint", "witness head mismatch")
				} else {
					consistent++
				}
			}
			witnessSeqs[seq] = true
		}
		if len(ws) > 0 && matching == 0 {
			fail("head matches a witness checkpoint", "witness has no checkpoints for signer")
		}
		if e == nil && consistent > 0 {
			anchored = true
		} else if e == nil && matching == 0 && len(ws) == 0 {
			rep.Checks = append(rep.Checks, VerificationCheck{"trust root", "warn", "witness holds no checkpoint; it cannot anchor this bundle"})
		}
	}
	selected := map[string]bool{}
	if sel, ok := manifest["selection"].(map[string]any); ok {
		if rs, ok := sel["runs"].([]any); ok {
			for _, r := range rs {
				if id, ok := r.(string); ok {
					selected[id] = true
				}
			}
		}
	}
	for _, e := range events {
		if run, ok := e["run_id"].(string); ok && run != "_signer" {
			selected[run] = true
		}
	}
	starts := map[string]bool{}
	ends := map[string]uint64{}
	var startEvents []map[string]any
	capture, rejected := false, false
	for _, e := range events {
		run, _ := e["run_id"].(string)
		d, _ := e["data"].(map[string]any)
		typ, _ := e["type"].(string)
		if typ == "capture.gap" && (selected[run] || run == "_signer") {
			capture = true
			rep.Checks = append(rep.Checks, VerificationCheck{"capture gaps", "warn", fmt.Sprintf("seq %v: %v", e["seq"], d["reason"])})
		}
		if typ == "trace.tamper" && (selected[run] || run == "_signer") {
			rep.Checks = append(rep.Checks, VerificationCheck{"harness transcript unchanged", "warn", fmt.Sprintf("seq %v: TRACE TAMPERING DETECTED: %v", e["seq"], d["path"])})
		}
		if typ == "error" && run == "_signer" {
			target, _ := d["client_run_id"].(string)
			if selected[target] {
				rejected = true
				rep.Checks = append(rep.Checks, VerificationCheck{"rejected writes", "warn", fmt.Sprintf("seq %v: %v", e["seq"], d["message"])})
			}
		}
		if !selected[run] {
			continue
		}
		if typ == "run.start" {
			starts[run] = true
			startEvents = append(startEvents, e)
		}
		if typ == "run.end" {
			seq, _ := fieldInt(e, "seq")
			ends[run] = seq
		}
		if typ == "review" && strings.HasPrefix(run, "findings:") {
			rep.ExitCode, rep.Integrity, rep.Detail = 2, "UNVERIFIABLE", "v1 findings semantics are not implemented"
			return rep
		}
	}
	if err := checkV1Policies(files, events, selected); err != nil {
		fail("policy hash consistent", err.Error())
	}
	var unbounded, unwitnessed []string // why a run's boundaries are unproven; runs whose last checkpoint no witness holds
	if len(selected) == 0 {
		unbounded = append(unbounded, "no selected run has a record in the bundle")
	}
	for run := range selected {
		if v1CompanionRun(run) {
			continue
		}
		end, ok := ends[run]
		if !starts[run] {
			unbounded = append(unbounded, "run "+run+": no run.start in the bundle")
		}
		if !ok {
			unbounded = append(unbounded, "run "+run+": no signed run.end in the bundle; the run may have continued")
		}
		if witness != nil && ok {
			var first uint64
			found := false
			for n := range witnessSeqs {
				if n >= end && (!found || n < first) {
					first, found = n, true
				}
			}
			if found && first >= uint64(len(records)) {
				atHead := false
				for _, cp := range cps {
					n, _ := fieldInt(cp, "head_seq")
					if n == uint64(len(records)-1) && n >= end && verifyV1Checkpoint(cp, pub, kid) {
						atHead = true
					}
				}
				if !atHead {
					fail("run tail witnessed", "run tail not covered by witnessed checkpoint")
				} else {
					unwitnessed = append(unwitnessed, fmt.Sprintf("run %s: checkpoint not on the witness (the bundle "+
						"ends at its signed checkpoint seq %d, after run.end at seq %d; the witness holds seq %d)",
						run, len(records)-1, end, first))
				}
			}
		}
	}
	if witness != nil && len(records) > 0 {
		later := false
		for n := range witnessSeqs {
			if n >= uint64(len(records)) {
				later = true
			}
		}
		if later {
			head := uint64(len(records) - 1)
			has := witnessSeqs[head]
			for _, cp := range cps {
				n, e := fieldInt(cp, "head_seq")
				if e == nil && n == head {
					has = true
				}
			}
			if !has {
				fail("head matches a witness checkpoint", "bundle ends between witnessed checkpoints")
			}
		}
	}
	isoSet := map[string]bool{}
	attested := true
	for _, e := range startEvents {
		d, _ := e["data"].(map[string]any)
		iso, ok := d["signer_isolation"].(string)
		if !ok {
			iso = "None"
		}
		isoSet[iso] = true
		if d["os_user_attested"] != true {
			attested = false
		}
	}
	isoNames := make([]string, 0, len(isoSet))
	for iso := range isoSet {
		isoNames = append(isoNames, iso)
	}
	sort.Strings(isoNames)
	iso := strings.Join(isoNames, ", ")
	if len(startEvents) == 0 || strings.Contains(iso, "same-user") {
		rep.Assurance = "dev (signer ran as the agent's own user: the agent could have rewritten the ledger)"
	} else if attested {
		rep.Assurance = "signer_isolation=" + iso + " (stamped by the signer since 0.3.0; earlier bundles: client-reported)"
	} else {
		rep.Assurance = "unknown (client-reported signer_isolation=" + iso + ")"
	}
	if stubs > 0 {
		rep.Checks = append(rep.Checks, VerificationCheck{"run completeness", "warn",
			fmt.Sprintf("%d elided record(s): v1 signatures do not bind a stub to its run", stubs)})
	}
	if len(unwitnessed) > 0 && !hasCheck(rep.Checks, "run tail witnessed") {
		sort.Strings(unwitnessed)
		rep.Checks = append(rep.Checks, VerificationCheck{"run tail witnessed", "warn", strings.Join(unwitnessed, "; ")})
	}
	if len(unbounded) > 0 {
		sort.Strings(unbounded)
		rep.Checks = append(rep.Checks, VerificationCheck{"run boundaries", "warn", strings.Join(unbounded, "; ")})
	}
	if !anchored && !hasCheck(rep.Checks, "trust root") {
		rep.Checks = append(rep.Checks, VerificationCheck{"trust root", "warn", "UNANCHORED: nothing outside the " +
			"bundle vouches for its signer key or checkpoints; pass -key <signer.pub> and/or -witness file:<copy>"})
	}
	if len(problems) > 0 {
		return stop()
	}
	rep.ExitCode, rep.Integrity = 0, "VERIFIED"
	var gaps []string
	if capture {
		gaps = append(gaps, "capture gaps")
	}
	if rejected {
		gaps = append(gaps, "rejected writes")
	}
	if stubs > 0 {
		gaps = append(gaps, "run completeness")
	}
	if len(unbounded) > 0 {
		gaps = append(gaps, "run boundaries")
	}
	if len(gaps) > 0 {
		rep.Integrity = "VERIFIED WITH GAPS (" + strings.Join(gaps, ", ") + ")"
	}
	if !anchored {
		rep.Integrity += " BUT UNANCHORED (internally consistent only; no trusted key or witness was checked)"
	}
	return rep
}

func hasCheck(checks []VerificationCheck, name string) bool {
	for _, c := range checks {
		if c.Check == name {
			return true
		}
	}
	return false
}

func v1CompanionRun(run string) bool {
	return strings.HasPrefix(run, "findings:") || strings.HasPrefix(run, "anchors:")
}

func checkV1Policies(files map[string][]byte, events []map[string]any, selected map[string]bool) error {
	start := map[string]string{}
	snapshots := map[string]map[string]any{}
	snapshot := func(h string) (map[string]any, error) {
		if p, ok := snapshots[h]; ok {
			return p, nil
		}
		if !strings.HasPrefix(h, "sha256:") {
			return nil, fmt.Errorf("invalid policy hash")
		}
		p, err := parseFileObject(files, "policies/"+strings.TrimPrefix(h, "sha256:")+".json")
		if err != nil {
			return nil, err
		}
		if "sha256:"+v1Hash(p) != h {
			return nil, fmt.Errorf("policy snapshot hash mismatch")
		}
		snapshots[h] = p
		return p, nil
	}
	for _, e := range events {
		run, _ := e["run_id"].(string)
		if !selected[run] {
			continue
		}
		d, _ := e["data"].(map[string]any)
		if e["type"] == "run.start" {
			p, _ := d["policy"].(map[string]any)
			h, _ := p["hash"].(string)
			start[run] = h
			if _, err := snapshot(h); err != nil {
				return err
			}
		}
	}
	for _, e := range events {
		run, _ := e["run_id"].(string)
		if !selected[run] || e["type"] != "policy.decision" {
			continue
		}
		d, _ := e["data"].(map[string]any)
		h, _ := d["policy_hash"].(string)
		if h == "" {
			h = start[run]
		}
		if h == "" {
			continue
		}
		p, err := snapshot(h)
		if err != nil {
			return err
		}
		ids := map[string]bool{"TK-SCOPE": true}
		for _, section := range []string{"deny", "ask", "flag"} {
			if rules, ok := p[section].([]any); ok {
				for _, r := range rules {
					if m, ok := r.(map[string]any); ok {
						if id, ok := m["id"].(string); ok {
							ids[id] = true
						}
					}
				}
			}
		}
		if rules, ok := d["rule_ids"].([]any); ok {
			for _, r := range rules {
				id, ok := r.(string)
				if !ok || !ids[id] {
					return fmt.Errorf("decision cites unknown policy rule")
				}
			}
		}
	}
	return nil
}
