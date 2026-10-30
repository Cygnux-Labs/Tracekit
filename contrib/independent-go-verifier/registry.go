package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// Reinterpret a pinned Ed25519 key under the registry's origin. C2SP key IDs
// commit to the name, so copying the record-log key ID would be insecure.
func renamedLogKey(key VKey, origin string) VKey {
	key.Name = origin
	preimage := append(append([]byte(origin+"\n"), byte(1)), key.Pub...)
	digest := sha256.Sum256(preimage)
	copy(key.ID[:], digest[:4])
	return key
}

func proofPath(value any) ([]string, error) {
	a, err := array(value)
	if err != nil {
		return nil, err
	}
	path := make([]string, 0, len(a))
	for _, v := range a {
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("proof node must be base64 string")
		}
		path = append(path, s)
	}
	return path, nil
}

// RFC 9162 §2.1.4.2. This checks that the tree at oldSize is a prefix
// of the new tree; equal-sized roots require an empty proof.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot [32]byte, proof []string) error {
	if oldSize > newSize || newSize == 0 {
		return errors.New("invalid consistency sizes")
	}
	if oldSize == 0 {
		if len(proof) != 0 {
			return errors.New("unexpected proof for empty tree")
		}
		return nil
	}
	if oldSize == newSize {
		if oldRoot != newRoot || len(proof) != 0 {
			return errors.New("equal-size consistency mismatch")
		}
		return nil
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	oldHash, newHash := oldRoot, oldRoot
	index := 0
	if fn != 0 {
		if len(proof) == 0 {
			return errors.New("missing consistency path")
		}
		raw, err := b64(proof[0])
		if err != nil || len(raw) != 32 {
			return errors.New("invalid consistency node")
		}
		copy(oldHash[:], raw)
		newHash = oldHash
		index = 1
	}
	for _, node := range proof[index:] {
		raw, err := b64(node)
		if err != nil || len(raw) != 32 {
			return errors.New("invalid consistency node")
		}
		if sn == 0 {
			return errors.New("oversized consistency path")
		}
		var sibling [32]byte
		copy(sibling[:], raw)
		if fn&1 == 1 || fn == sn {
			oldHash = nodeHash(sibling, oldHash)
			newHash = nodeHash(sibling, newHash)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			newHash = nodeHash(newHash, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if fn != 0 || sn != 0 || oldHash != oldRoot || newHash != newRoot {
		return errors.New("consistency proof mismatch")
	}
	return nil
}

func verifyLeafProof(data []byte, index, size uint64, path []string, root [32]byte) error {
	if size == 0 || index >= size {
		return errors.New("out-of-range leaf")
	}
	acc := leafHash(data)
	fn, sn := index, size-1
	for _, node := range path {
		raw, err := b64(node)
		if err != nil || len(raw) != 32 {
			return errors.New("invalid inclusion sibling")
		}
		if sn == 0 {
			return errors.New("oversized inclusion proof")
		}
		var sibling [32]byte
		copy(sibling[:], raw)
		if fn&1 == 1 || fn == sn {
			acc = nodeHash(sibling, acc)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			acc = nodeHash(acc, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if fn != 0 || sn != 0 || acc != root {
		return errors.New("registry inclusion proof mismatch")
	}
	return nil
}

func verifyRunSet(files map[string][]byte, log VKey, witnesses []VKey, quorum int,
	recordInclusion func(validatedRecord) error, keys map[string]recordedKey, runs []runEvidence, logID string, recordTreeSize uint64) error {
	spec, err := parseFileObject(files, "registry/run-set.json")
	if err != nil {
		return err
	}
	a, err := fieldInt(spec, "from")
	if err != nil {
		return err
	}
	b, err := fieldInt(spec, "to")
	if err != nil {
		return err
	}
	if b <= a {
		return errors.New("run-set registry range must grow")
	}
	saltText, err := fieldString(spec, "tenant_salt")
	if err != nil {
		return err
	}
	salt, err := b64(saltText)
	if err != nil || len(salt) != 32 {
		return errors.New("bad registry tenant salt")
	}
	prefix := append([]byte("registry "), salt...)
	saltDigest := sha256.Sum256(prefix)
	origin := log.Name + "/registry/" + hex.EncodeToString(saltDigest[:])[:32]
	pinned := renamedLogKey(log, origin)
	note, ok := files["checkpoints/registry-"+strconv.FormatUint(b, 10)+".note"]
	if !ok {
		return errors.New("missing registry head checkpoint")
	}
	head, err := VerifyCheckpoint(note, pinned, witnesses, quorum)
	if err != nil {
		return fmt.Errorf("registry head checkpoint: %w", err)
	}
	if head.Size != b {
		return errors.New("registry checkpoint size mismatches range")
	}
	var oldRoot [32]byte
	if a > 0 {
		oldNote, ok := files["checkpoints/registry-"+strconv.FormatUint(a, 10)+".note"]
		if !ok {
			return errors.New("missing registry prior checkpoint")
		}
		older, err := VerifyCheckpoint(oldNote, pinned, witnesses, quorum)
		if err != nil {
			return fmt.Errorf("registry prior checkpoint: %w", err)
		}
		if older.Size != a {
			return errors.New("registry prior size mismatch")
		}
		oldRoot = older.Root
	}
	proof, err := proofPath(spec["consistency"])
	if err != nil {
		return err
	}
	if err := VerifyConsistency(a, b, oldRoot, head.Root, proof); err != nil {
		return err
	}
	leaves, err := array(spec["leaves"])
	if err != nil {
		return err
	}
	if uint64(len(leaves)) != b-a {
		return errors.New("registry leaves don't cover range")
	}
	recordLines, err := readLines(files["registry/records.jsonl"])
	if err != nil {
		return err
	}
	if len(recordLines) != len(leaves) {
		return errors.New("registry record count mismatch")
	}
	runIndex := make(map[string]runEvidence)
	for _, run := range runs {
		runIndex[run.tenant+"/"+run.id] = run
	}
	keyRecords := make(map[string]bool)
	keyLines, err := readLines(files["keys/records.jsonl"])
	if err != nil {
		return err
	}
	for _, raw := range keyLines {
		rec, err := decodeRecord(raw)
		if err != nil {
			return err
		}
		keyRecords[fmt.Sprintf("%d/%s", rec.seq, rec.hash)] = true
	}
	seenFinal := make(map[string]bool)
	targeted := make(map[string]bool)
	var rangeTenant string
	for i, leafValue := range leaves {
		leaf, err := object(leafValue)
		if err != nil {
			return err
		}
		encoded, err := fieldString(leaf, "leaf")
		if err != nil {
			return err
		}
		raw, err := b64(encoded)
		if err != nil || len(raw) != 89 {
			return errors.New("bad registry leaf width")
		}
		path, err := proofPath(leaf["inclusion"])
		if err != nil {
			return err
		}
		if err := verifyLeafProof(raw, a+uint64(i), b, path, head.Root); err != nil {
			return err
		}
		rec, err := decodeRecord(recordLines[i])
		if err != nil {
			return err
		}
		if err := checkRecord(rec, recordLines[i], keys); err != nil {
			return fmt.Errorf("registry record signature: %w", err)
		}
		if err := recordInclusion(rec); err != nil {
			return fmt.Errorf("registry record inclusion: %w", err)
		}
		seq := binary.BigEndian.Uint64(raw[49:57])
		digest, err := hexDigest(rec.hash)
		if err != nil {
			return err
		}
		logBytes, err := hex.DecodeString(logID)
		if err != nil || len(logBytes) != 16 {
			return errors.New("bad log id")
		}
		if rec.seq != seq || !bytes.Equal(raw[33:49], logBytes) || !bytes.Equal(raw[57:89], digest) || rec.ev["log_id"] != logID {
			return errors.New("registry leaf record does not match")
		}
		kind, err := fieldString(rec.ev, "type")
		if err != nil {
			return err
		}
		types := map[string]byte{"run.registered": 1, "run.final": 2, "log.closed": 3, "key.retire": 4, "capture.gap": 5, "trace.tamper": 6}
		if want, ok := types[kind]; !ok || raw[0] != want {
			return errors.New("registry leaf type mismatch")
		}
		tenant, err := fieldString(rec.ev, "tenant")
		if err != nil {
			return err
		}
		id, err := fieldString(rec.ev, "run_id")
		if err != nil {
			return err
		}
		runHash := sha256.Sum256(append(append([]byte{}, salt...), []byte(id)...))
		if !bytes.Equal(raw[1:33], runHash[:]) {
			return errors.New("registry run-id commitment mismatch")
		}
		if kind == "key.retire" && !keyRecords[fmt.Sprintf("%d/%s", rec.seq, rec.hash)] {
			return errors.New("registry key.retire absent from bundled key records")
		}
		if kind == "log.closed" && rec.seq != recordTreeSize-1 {
			return errors.New("log.closed not at checkpointed record-tree head")
		}
		if kind == "log.closed" {
			data, err := object(rec.ev["data"])
			if err != nil {
				return err
			}
			final, err := fieldInt(data, "final_seq")
			if err != nil || final < recordTreeSize-1 {
				return errors.New("records after declared log.closed final_seq")
			}
		}
		if kind == "capture.gap" || kind == "trace.tamper" {
			data, err := object(rec.ev["data"])
			if err != nil || data["tenant_level"] != true {
				return errors.New("non-tenant-level gap or tamper in registry")
			}
		}
		if kind == "run.registered" || kind == "run.final" {
			if rangeTenant == "" {
				rangeTenant = tenant
			} else if rangeTenant != tenant {
				return errors.New("registry crosses tenants")
			}
			key := tenant + "/" + id
			targeted[key] = true
			run, found := runIndex[key]
			if !found {
				if kind == "run.final" {
					return errors.New("registry final points to missing run")
				}
				continue
			}
			if kind == "run.final" {
				if seenFinal[key] {
					return errors.New("duplicate run.final registry leaf")
				}
				seenFinal[key] = true
			}
			matched := false
			records := run.records
			if kind == "run.registered" && len(records) > 0 {
				records = records[:1]
			}
			for _, r := range records {
				if r.seq == seq && r.hash == rec.hash && r.ev["type"] == kind {
					matched = true
					break
				}
			}
			if !matched {
				return errors.New("registry leaf not present in bundled run")
			}
		}
	}
	if rangeTenant == "" {
		return errors.New("run-set registry has no run leaves")
	}
	unmatched := 0
	for _, run := range runs {
		if run.tenant != rangeTenant {
			return errors.New("bundled run outside registry tenant")
		}
		if len(run.records) == 0 {
			return errors.New("empty bundled run")
		}
		last := run.records[len(run.records)-1]
		if seenFinal[run.tenant+"/"+run.id] && last.ev["type"] != "run.final" {
			return errors.New("registry final is not bundled run tail")
		}
		if !targeted[run.tenant+"/"+run.id] {
			// A run-set may additionally carry its selected run, which need not
			// have a final leaf in this registry interval.
			unmatched++
		}
	}
	if unmatched > 1 {
		return errors.New("multiple bundled runs without registry leaves in run-set")
	}
	return nil
}
