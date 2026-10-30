package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type runEvidence struct {
	tenant, id string
	records    []validatedRecord
}

var runFilePattern = regexp.MustCompile(`^runs/([0-9a-f]{32})(?:\.part-([0-9]{4}))?\.jsonl$`)

// collectRuns identifies each run once and joins its numbered parts in order.
// A group has either one .jsonl file or parts numbered 0001, 0002, ... .
// Validated record-chain continuity across part boundaries is checked later.
func collectRuns(files map[string][]byte) (map[string][][]byte, error) {
	type entry struct {
		part     int
		filename string
	}
	groups := make(map[string][]entry)
	for name := range files {
		if !strings.HasPrefix(name, "runs/") {
			continue
		}
		parts := runFilePattern.FindStringSubmatch(name)
		if parts == nil {
			return nil, fmt.Errorf("invalid run part path: %s", name)
		}
		number := 0
		if parts[2] != "" {
			n, _ := strconv.Atoi(parts[2])
			if n < 1 {
				return nil, errors.New("invalid run part number")
			}
			number = n
		}
		groups[parts[1]] = append(groups[parts[1]], entry{number, name})
	}
	if len(groups) == 0 {
		return nil, errors.New("no run files")
	}
	result := make(map[string][][]byte)
	for id, entries := range groups {
		sort.Slice(entries, func(i, j int) bool { return entries[i].part < entries[j].part })
		if len(entries) > 1 && entries[0].part == 0 {
			return nil, fmt.Errorf("run %s has both file and parts", id)
		}
		if entries[0].part > 0 && entries[0].part != 1 {
			return nil, fmt.Errorf("run %s missing part-0001", id)
		}
		joined := make([][]byte, 0)
		for i, e := range entries {
			if e.part == 0 && len(entries) != 1 {
				return nil, fmt.Errorf("mixed run layouts: %s", id)
			}
			if e.part > 0 && e.part != i+1 {
				return nil, fmt.Errorf("nonconsecutive run parts: %s", id)
			}
			lines, err := readLines(files[e.filename])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.filename, err)
			}
			joined = append(joined, lines...)
		}
		result[id] = joined
	}
	return result, nil
}

// checkRunEvidence authenticates every bundled run's records, including the
// boundary from one part to the next. It never equates an open run with finality.
func checkRunEvidence(files map[string][]byte, keys map[string]recordedKey, logID string,
	inclusion func(validatedRecord) error) ([]runEvidence, int, error) {
	groups, err := collectRuns(files)
	if err != nil {
		return nil, 0, err
	}
	keysSorted := make([]string, 0, len(groups))
	for id := range groups {
		keysSorted = append(keysSorted, id)
	}
	sort.Strings(keysSorted)
	runs := make([]runEvidence, 0, len(groups))
	total := 0
	seen := make(map[string]bool)
	for _, group := range keysSorted {
		lines := groups[group]
		var run runEvidence
		var prevHash string = ZeroHash
		var prevSeq uint64
		isFinal := false
		for i, line := range lines {
			rec, err := decodeRecord(line)
			if err != nil {
				return nil, 0, fmt.Errorf("run record: %w", err)
			}
			if err := checkRecord(rec, line, keys); err != nil {
				return nil, 0, fmt.Errorf("run record %d: %w", i, err)
			}
			tenant, err := fieldString(rec.ev, "tenant")
			if err != nil {
				return nil, 0, err
			}
			id, err := fieldString(rec.ev, "run_id")
			if err != nil {
				return nil, 0, err
			}
			chain, err := fieldString(rec.ev, "run_prev_hash")
			if err != nil {
				return nil, 0, err
			}
			if rec.ev["log_id"] != logID {
				return nil, 0, errors.New("run log_id mismatch")
			}
			if i == 0 {
				if rec.ev["type"] != "run.registered" {
					return nil, 0, errors.New("run must start with run.registered")
				}
				digest := sha256.Sum256([]byte(tenant + "/" + id))
				if hex.EncodeToString(digest[:])[:32] != group {
					return nil, 0, errors.New("run filename mismatches identity")
				}
				run.tenant, run.id = tenant, id
				if seen[tenant+"/"+id] {
					return nil, 0, errors.New("duplicate bundled run identity")
				}
				seen[tenant+"/"+id] = true
			} else if rec.seq <= prevSeq {
				return nil, 0, errors.New("run seq out of order")
			}
			if isFinal || rec.runSeq != uint64(i) || tenant != run.tenant || id != run.id || chain != prevHash {
				return nil, 0, fmt.Errorf("run chain mismatch at record %d", i)
			}
			if i > 0 && rec.seq == prevSeq+1 && rec.ev["prev_hash"] != prevHash {
				return nil, 0, errors.New("contiguous log chain mismatch")
			}
			prevHash, prevSeq = rec.hash, rec.seq
			if rec.ev["type"] == "run.final" {
				if i == 0 {
					return nil, 0, errors.New("run final cannot be its first record")
				}
				data, err := object(rec.ev["data"])
				if err != nil {
					return nil, 0, err
				}
				head, err := fieldInt(data, "head_run_seq")
				if err != nil || head != uint64(i-1) || data["head_hash"] != run.records[len(run.records)-1].hash {
					return nil, 0, errors.New("run.final head disagrees with signed run tail")
				}
				isFinal = true
			}
			if i == 0 || i == len(lines)-1 {
				if err := inclusion(rec); err != nil {
					return nil, 0, fmt.Errorf("run inclusion: %w", err)
				}
			}
			run.records = append(run.records, rec)
			total++
		}
		runs = append(runs, run)
	}
	return runs, total, nil
}
