package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Verification struct {
	ExitCode  int                 `json:"exit_code"`
	Integrity string              `json:"integrity"`
	Assurance string              `json:"assurance"`
	Detail    string              `json:"detail,omitempty"`
	Checks    []VerificationCheck `json:"checks"`
}

type VerificationCheck struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

var versionPattern = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,9}){0,2}$`)

func registryOrigin(origin string, salt []byte) string {
	digest := sha256.Sum256(append([]byte("registry "), salt...))
	return origin + "/registry/" + hex.EncodeToString(digest[:])[:32]
}

// VerifyBundle verifies self-contained Ed25519 v2 evidence. Features requiring
// additional cryptographic protocols remain explicitly UNVERIFIABLE.
func VerifyBundle(bundle, trustBytes []byte) Verification {
	rep := Verification{ExitCode: 2, Integrity: "UNUSABLE BUNDLE", Assurance: "none", Checks: []VerificationCheck{}}
	log, witnesses, quorum, err := loadTrust(trustBytes)
	if err != nil {
		rep.Detail = "trust: " + err.Error()
		return rep
	}
	files, err := ReadBundle(bundle)
	if err != nil {
		rep.Detail = err.Error()
		return rep
	}
	manifest, err := parseFileObject(files, "manifest.json")
	if err != nil {
		rep.Detail = err.Error()
		return rep
	}
	version, ok := manifest["verifier_min_version"].(string)
	newer, versionErr := newerVersion(version, "1.4.2")
	if manifest["format"] != "tracekit.bundle.v2" || !ok || versionErr != nil {
		rep.Detail = "invalid manifest format or version"
		return rep
	}
	if newer {
		rep.Integrity = "UNVERIFIABLE (needs tracekit >= " + version + ")"
		return rep
	}
	rep.ExitCode, rep.Integrity = 1, "FAILED"
	proofs, err := parseFileObject(files, "proofs/records.json")
	if err != nil {
		rep.Detail = err.Error()
		return rep
	}
	name, ok := proofs["checkpoint"].(string)
	if !ok {
		rep.Detail = "missing checkpoint"
		return rep
	}
	cp, err := VerifyCheckpoint(files[name], log, witnesses, 0)
	if err != nil {
		rep.Detail = err.Error()
		return rep
	}
	// Reports may retain assurance on failed evidence, but only authenticated
	// checkpoint signatures are allowed to contribute to that assurance.
	runs, keyRecords, err := reportRecords(files)
	if err != nil {
		rep.Detail = err.Error()
		return rep
	}
	if len(runs) != 1 {
		if _, ok := files["registry/run-set.json"]; !ok {
			if !aboutOne(runs) {
				rep.Detail = "multiple runs without run-set"
				return rep
			}
		}
	}
	anchors, anchorErr := verifyAnchor(files, trustBytes, log, cp, files[name])
	rep.Assurance = assuranceFor(files, trustBytes, log, witnesses, quorum, cp, runs, keyRecords, anchors)
	if anchorErr != nil {
		rep.Detail = anchorErr.Error()
		return rep
	}
	_, err = inspectFiles(files, log, witnesses, quorum)
	if err != nil {
		rep.Detail = err.Error()
		return rep
	}
	if err = checkSemantics(files, runs, keyRecords); err != nil {
		rep.Detail = err.Error()
		if _, ok := err.(unsupportedEvidence); ok {
			rep.ExitCode, rep.Integrity = 2, "UNVERIFIABLE"
		}
		return rep
	}
	rep.Checks = warningChecks(files, runs)
	open := 0
	var head uint64
	for _, run := range runs {
		last := run.records[len(run.records)-1]
		if last.ev["type"] != "run.final" {
			open++
			head = last.runSeq
		}
	}
	rep.ExitCode, rep.Integrity = 0, "VERIFIED"
	if open > 0 {
		if len(runs) == 1 {
			rep.Integrity = fmt.Sprintf("VERIFIED TO HEAD %d (open)", head)
		} else {
			rep.Integrity = fmt.Sprintf("VERIFIED (%d run(s) open)", open)
		}
	}
	return rep
}

// Signed gaps do not invalidate intact evidence. They must remain visible in
// the report so cryptographic integrity cannot be mistaken for complete capture.
func warningChecks(files map[string][]byte, runs []runEvidence) []VerificationCheck {
	checks := []VerificationCheck{}
	info := map[string]bool{"witness_late": true, "witness_failed": true, "degraded_unanchored": true, "clock_skew": true, "format_upgrade": true, "key_retired": true, "args_coerced": true, "approval_expired": true}
	own := map[string]string{"executed_against_policy": "policy", "held_call_unresolved": "held calls", "decision_mismatch": "external decisions", "observer_lost": "observers"}
	for _, run := range runs {
		for _, r := range run.records {
			typ, _ := r.ev["type"].(string)
			d, _ := r.ev["data"].(map[string]any)
			name, kind := "", typ
			switch typ {
			case "trace.tamper", "approval.binding_mismatch":
				name = "gaps"
			case "capture.gap":
				kind, _ = d["kind"].(string)
				if info[kind] {
					continue
				}
				name = own[kind]
				if name == "" {
					name = "gaps"
				}
			}
			if name != "" {
				detail := fmt.Sprintf("seq %d: %s", r.seq, kind)
				if reason, ok := d["reason"].(string); ok && reason != "" {
					detail += ": " + reason
				}
				checks = append(checks, VerificationCheck{name, "warn", detail})
			}
		}
	}
	if raw, ok := files["registry/records.jsonl"]; ok {
		if lines, err := readLines(raw); err == nil {
			for _, line := range lines {
				r, err := decodeRecord(line)
				if err == nil && (r.ev["type"] == "capture.gap" || r.ev["type"] == "trace.tamper") {
					checks = append(checks, VerificationCheck{"tenant-level gaps", "warn", fmt.Sprintf("seq %d: %s", r.seq, r.ev["type"])})
				}
			}
		}
	}
	return checks
}

func newerVersion(a, b string) (bool, error) {
	aa, err := parseVersion(a)
	if err != nil {
		return false, err
	}
	bb, err := parseVersion(b)
	if err != nil {
		return false, err
	}
	for i := 0; i < 3; i++ {
		if aa[i] != bb[i] {
			return aa[i] > bb[i], nil
		}
	}
	return false, nil
}

func parseVersion(version string) ([3]uint64, error) {
	var parts [3]uint64
	if !versionPattern.MatchString(version) {
		return parts, fmt.Errorf("invalid version")
	}
	for i, component := range strings.Split(version, ".") {
		value, err := strconv.ParseUint(component, 10, 64)
		if err != nil {
			return parts, err
		}
		parts[i] = value
	}
	return parts, nil
}

// reportRecords parses without granting validity. It permits the report to
// describe failed signatures while verification itself remains fail closed.
func reportRecords(files map[string][]byte) ([]runEvidence, []validatedRecord, error) {
	read := func(raw []byte) ([]validatedRecord, error) {
		lines, err := readLines(raw)
		if err != nil {
			return nil, err
		}
		out := make([]validatedRecord, 0, len(lines))
		for _, line := range lines {
			r, err := decodeRecord(line)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	var keys []validatedRecord
	var err error
	if len(files["keys/records.jsonl"]) != 0 {
		keys, err = read(files["keys/records.jsonl"])
	}
	if err != nil {
		return nil, nil, err
	}
	groups := map[string][][]byte{}
	var names []string
	for name := range files {
		if strings.HasPrefix(name, "runs/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	pattern := regexp.MustCompile(`^runs/([0-9a-f]{32})(?:\.part-([0-9]+))?\.jsonl$`)
	for _, name := range names {
		m := pattern.FindStringSubmatch(name)
		if m == nil {
			return nil, nil, fmt.Errorf("invalid run filename")
		}
		lines, e := readLines(files[name])
		if e != nil {
			return nil, nil, e
		}
		groups[m[1]] = append(groups[m[1]], lines...)
	}
	if len(groups) == 0 {
		if _, ok := files["registry/run-set.json"]; !ok {
			return nil, nil, fmt.Errorf("no run files")
		}
	}
	var runs []runEvidence
	for _, lines := range groups {
		var run runEvidence
		for _, line := range lines {
			r, err := decodeRecord(line)
			if err != nil {
				return nil, nil, err
			}
			run.records = append(run.records, r)
		}
		first := run.records[0]
		run.tenant, _ = first.ev["tenant"].(string)
		run.id, _ = first.ev["run_id"].(string)
		runs = append(runs, run)
	}
	return runs, keys, nil
}

func aboutOne(runs []runEvidence) bool {
	var main *runEvidence
	for _, run := range runs {
		first := run.records[0]
		d, _ := first.ev["data"].(map[string]any)
		target, _ := d["analyzes"].(string)
		replay, _ := d["replay_of"].(string)
		if target == "" && replay == "" {
			if main != nil {
				return false
			}
			copy := run
			main = &copy
		}
	}
	if main == nil {
		return false
	}
	for _, run := range runs {
		if run.tenant != main.tenant {
			return false
		}
		d, _ := run.records[0].ev["data"].(map[string]any)
		if run.id != main.id && d["analyzes"] != main.id && d["replay_of"] != main.id {
			return false
		}
	}
	return true
}

func assuranceFor(files map[string][]byte, trustBytes []byte, log VKey, witnesses []VKey, quorum int, cp Checkpoint, runs []runEvidence, keys []validatedRecord, anchors []verifiedAnchor) string {
	v, _ := ParseStrict(trustBytes)
	trust := v.(map[string]any)
	classes := map[string]string{}
	if ws, ok := trust["witnesses"].([]any); ok {
		for _, w := range ws {
			m := w.(map[string]any)
			k, _ := ParseVKey(m["vkey"].(string))
			classes[k.Name+fmt.Sprintf("/%x", k.ID)] = m["class"].(string)
		}
	}
	class := func(k VKey) string { return classes[k.Name+fmt.Sprintf("/%x", k.ID)] }
	levelFor := func(cp Checkpoint) string {
		n := 0
		for _, c := range cp.Cosignatures {
			if class(c.Key) != "operator" {
				n++
			}
		}
		required := quorum
		if required < 1 {
			required = 1
		}
		if n >= required {
			return "witnessed"
		}
		if cp.Witnesses > 0 {
			return "local"
		}
		return "dev"
	}
	level := levelFor(cp)
	independent := 0
	for _, c := range cp.Cosignatures {
		if class(c.Key) != "operator" {
			independent++
		}
	}
	for _, a := range anchors {
		if a.Class != "operator" {
			independent++
		}
	}
	required := quorum
	if required < 1 {
		required = 1
	}
	if independent >= required {
		level = "witnessed"
	} else if cp.Witnesses > 0 || len(anchors) > 0 {
		level = "local"
	}
	self := false
	algs := map[string]bool{}
	var relied uint64
	for _, r := range keys {
		if a, ok := r.rec["alg"].(string); ok {
			algs[a] = true
		}
		if r.seq > relied {
			relied = r.seq
		}
	}
	for _, run := range runs {
		for _, r := range run.records {
			if a, ok := r.rec["alg"].(string); ok {
				algs[a] = true
			}
			if r.seq > relied {
				relied = r.seq
			}
			d, _ := r.ev["data"].(map[string]any)
			if r.ev["type"] == "approval" && d["self_approved"] == true {
				self = true
			}
		}
	}
	if self {
		level = "dev"
	}
	proven := false
	capped := ""
	if spec, err := parseFileObject(files, "registry/run-set.json"); err == nil {
		lo, e1 := fieldInt(spec, "from")
		hi, e2 := fieldInt(spec, "to")
		saltText, _ := spec["tenant_salt"].(string)
		salt, e3 := b64(saltText)
		if e1 == nil && e2 == nil && e3 == nil {
			origin := registryOrigin(log.Name, salt)
			pin := renamedLogKey(log, origin)
			rank := map[string]int{"dev": 0, "local": 1, "witnessed": 2}
			rangeUsable := lo <= hi && hi > 0
			for _, n := range []uint64{lo, hi} {
				if n == 0 {
					continue
				}
				if reg, e := VerifyCheckpoint(files[fmt.Sprintf("checkpoints/registry-%d.note", n)], pin, witnesses, 0); e == nil {
					if reg.Size != n || reg.Witnesses < quorum {
						rangeUsable = false
					}
					l := levelFor(reg)
					if rank[l] < rank[level] {
						level, capped = l, l
					}
				} else {
					rangeUsable = false
				}
			}
			if lo == 0 && rangeUsable {
				lines, e := readLines(files["registry/records.jsonl"])
				var top uint64
				for _, line := range lines {
					r, e := decodeRecord(line)
					if e == nil && r.seq > top {
						top = r.seq
					}
				}
				proven = e == nil && top >= relied
			}
		}
	}
	aa := make([]string, 0, len(algs))
	for a := range algs {
		aa = append(aa, a)
	}
	sort.Strings(aa)
	result := level + "; records " + strings.Join(aa, "+") + "; checkpoint Ed25519 only (" + log.Name + ")"
	cosigs := append([]Cosignature(nil), cp.Cosignatures...)
	sort.SliceStable(cosigs, func(i, j int) bool { return cosigs[i].Time < cosigs[j].Time })
	var descriptions []string
	var earliest uint64
	haveTime := false
	for _, c := range cosigs {
		at := time.Unix(int64(c.Time), 0).UTC().Format("2006-01-02T15:04:05Z")
		descriptions = append(descriptions, c.Key.Name+" ("+class(c.Key)+") at "+at)
		if class(c.Key) != "operator" && (!haveTime || c.Time < earliest) {
			earliest, haveTime = c.Time, true
		}
	}
	if len(descriptions) > 0 {
		result += "; cosigned ed25519 by " + strings.Join(descriptions, ", ")
	} else {
		result += "; no witness cosignature"
	}
	for _, a := range anchors {
		result += "; anchored in Rekor " + a.Origin + " (" + a.Class + ") at " + a.At.UTC().Format("2006-01-02T15:04:05Z") + " (ECDSA P-256 entry, RFC 3161 time)"
		ts := uint64(a.At.Unix())
		if a.Class != "operator" && (!haveTime || ts < earliest) {
			earliest, haveTime = ts, true
		}
	}
	if haveTime {
		result += "; earliest independent anchor " + time.Unix(int64(earliest), 0).UTC().Format("2006-01-02T15:04:05Z")
	}
	if capped != "" {
		result += "; capped by the run-set's registry notes (" + capped + ")"
	}
	if self {
		result += "; approvals: self"
	}
	if !proven {
		result += "; key retirements not proven complete"
	}
	return result
}

type unsupportedEvidence string

func (e unsupportedEvidence) Error() string { return string(e) }

func checkSemantics(files map[string][]byte, runs []runEvidence, keys []validatedRecord) error {
	for name, raw := range files {
		if strings.HasPrefix(name, "policies/") && name != "policies/"+strings.TrimPrefix(SHA256Hex(raw), "sha256:")+".json" {
			return fmt.Errorf("policy snapshot name does not match digest: %s", name)
		}
	}
	for _, r := range keys {
		d, _ := r.ev["data"].(map[string]any)
		if _, ok := d["bridge"]; ok {
			return unsupportedEvidence("v1 bridge verification is not implemented")
		}
	}
	for _, run := range runs {
		constraint := false
		for _, r := range run.records {
			typ, _ := r.ev["type"].(string)
			d, _ := r.ev["data"].(map[string]any)
			switch typ {
			case "constraint.added":
				constraint = true
			case "policy.decision":
				if ids, ok := d["rule_ids"].([]any); ok {
					for _, id := range ids {
						if id == "TK-CONSTRAINT" && (!constraint || d["decision"] != "ask") {
							return fmt.Errorf("invalid constraint decision at seq %d", r.seq)
						}
					}
				}
			case "approval":
				// Human approvals are signer assertions authenticated by their
				// record and schema; only agent approvals need offline eligibility checks.
				if d["decision"] == "approve" && d["approver_kind"] == "agent" {
					return unsupportedEvidence("agent approval semantics are not implemented")
				}
			case "run.registered", "run.start", "run.end", "run.closing", "run.final", "tool.call", "tool.result", "error", "trace.tamper", "capture.gap", "checkpoint", "user.prompt", "model.message", "model.exchange", "approval.request", "approval.consumed", "approval.expired", "approval.refused", "approval.binding_mismatch", "approval.abandoned", "approval.escalated", "approval.revoked", "approval.suggested", "approval.agents", "input.observed", "state.write", "reconcile.hook_missing", "reconcile.fabricated", "reconcile.args_mismatch", "reconcile.result_without_call", "reconcile.unexplained_effect", "reconcile.args_unparseable", "reconcile.result_mismatch", "refusal.summary", "policy.external", "content.accessed", "content.erased", "run.child", "effect.observed":
			default:
				return unsupportedEvidence("event semantics not implemented: " + typ)
			}
			if _, ok := r.ev["ext"]; ok {
				return unsupportedEvidence("extension semantics are not implemented")
			}
		}
	}
	return nil
}
