package verifier

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Inspection contains foundational cryptographic counts, not a verdict.
type Inspection struct {
	Files      int
	KeyRecords int
	RunRecords int
	Runs       int
	TreeSize   uint64
	Witnesses  int
}

func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("expected JSON object")
	}
	return m, nil
}
func array(v any) ([]any, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, errors.New("expected JSON array")
	}
	return a, nil
}

// ReadBundle enforces the single-layout constraints of format-v2 section 9,
// rather than relying on ZIP's permissive default reader behavior.
func ReadBundle(input []byte) (map[string][]byte, error) {
	if len(input) < 22 || binary.LittleEndian.Uint32(input[len(input)-22:]) != 0x06054b50 {
		return nil, errors.New("missing final ZIP EOCD")
	}
	eocd := input[len(input)-22:]
	if binary.LittleEndian.Uint16(eocd[4:]) != 0 || binary.LittleEndian.Uint16(eocd[6:]) != 0 || binary.LittleEndian.Uint16(eocd[20:]) != 0 {
		return nil, errors.New("nonzero ZIP disk or comment")
	}
	count := int(binary.LittleEndian.Uint16(eocd[10:]))
	if count != int(binary.LittleEndian.Uint16(eocd[8:])) || count == 0 || count > 10000 {
		return nil, errors.New("invalid ZIP entry count")
	}
	dirSize := uint64(binary.LittleEndian.Uint32(eocd[12:]))
	dirOffset := uint64(binary.LittleEndian.Uint32(eocd[16:]))
	if dirOffset+dirSize != uint64(len(input)-22) || dirOffset > uint64(len(input)) {
		return nil, errors.New("ZIP directory offset mismatch")
	}
	reader, err := zip.NewReader(bytes.NewReader(input), int64(len(input)))
	if err != nil || len(reader.File) != count {
		return nil, errors.New("invalid ZIP directory")
	}
	validName := regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*$`)
	content := make(map[string][]byte)
	var size int64
	pos := uint64(0)
	for _, f := range reader.File {
		if !validName.MatchString(f.Name) || strings.Contains("/"+f.Name+"/", "/../") || strings.Contains("/"+f.Name+"/", "/./") {
			return nil, fmt.Errorf("unsafe ZIP path: %q", f.Name)
		}
		for _, part := range strings.Split(f.Name, "/") {
			if strings.Trim(part, ".") == "" {
				return nil, errors.New("dot-only ZIP path component")
			}
		}
		if _, ok := content[f.Name]; ok {
			return nil, errors.New("duplicate ZIP entry")
		}
		if len(f.Extra) != 0 || len(f.Comment) != 0 || f.Flags != 0 || (f.Method != zip.Store && f.Method != zip.Deflate) || f.ExternalAttrs>>16&0o170000 == 0o120000 {
			return nil, errors.New("unsupported ZIP entry properties")
		}
		if f.UncompressedSize64 > 64<<20 || f.CompressedSize64 > 64<<20 {
			return nil, errors.New("entry exceeds 64 MiB")
		}
		size += int64(f.UncompressedSize64)
		if size > 512<<20 {
			return nil, errors.New("ZIP expansion limit")
		}
		if pos+30 > uint64(len(input)) || binary.LittleEndian.Uint32(input[pos:]) != 0x04034b50 {
			return nil, errors.New("ZIP local header offset mismatch")
		}
		h := input[pos : pos+30]
		nameLen := int(binary.LittleEndian.Uint16(h[26:]))
		extraLen := int(binary.LittleEndian.Uint16(h[28:]))
		end := pos + uint64(30+nameLen+extraLen) + f.CompressedSize64
		if extraLen != 0 || end > dirOffset || pos+uint64(30+nameLen) > uint64(len(input)) {
			return nil, errors.New("ZIP local data out of bounds")
		}
		if string(input[pos+30:pos+30+uint64(nameLen)]) != f.Name ||
			binary.LittleEndian.Uint16(h[6:]) != f.Flags || binary.LittleEndian.Uint16(h[8:]) != f.Method ||
			binary.LittleEndian.Uint32(h[14:]) != f.CRC32 ||
			uint64(binary.LittleEndian.Uint32(h[18:])) != f.CompressedSize64 ||
			uint64(binary.LittleEndian.Uint32(h[22:])) != f.UncompressedSize64 {
			return nil, errors.New("ZIP local/central header mismatch")
		}
		offset, err := f.DataOffset()
		if err != nil || offset != int64(pos+30+uint64(nameLen)) {
			return nil, errors.New("ZIP data offset mismatch")
		}
		file, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, int64(f.UncompressedSize64)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || uint64(len(data)) != f.UncompressedSize64 {
			return nil, errors.New("ZIP content/CRC failure")
		}
		content[f.Name] = data
		pos = end
	}
	if pos != dirOffset {
		return nil, errors.New("gap before ZIP directory")
	}
	// Verify central records are tightly packed, without comments, extra fields,
	// ZIP64 records, or offsets that refer to other local entries.
	dpos := dirOffset
	for _, f := range reader.File {
		if dpos+46 > uint64(len(input)) || binary.LittleEndian.Uint32(input[dpos:]) != 0x02014b50 {
			return nil, errors.New("invalid central directory")
		}
		header := input[dpos : dpos+46]
		n := uint64(binary.LittleEndian.Uint16(header[28:]))
		extra := uint64(binary.LittleEndian.Uint16(header[30:]))
		comment := uint64(binary.LittleEndian.Uint16(header[32:]))
		if extra != 0 || comment != 0 || dpos+46+n > uint64(len(input)) || string(input[dpos+46:dpos+46+n]) != f.Name {
			return nil, errors.New("invalid central entry fields")
		}
		if binary.LittleEndian.Uint32(header[42:]) == 0xffffffff {
			return nil, errors.New("ZIP64 is unsupported")
		}
		dpos += 46 + n
	}
	if dpos != dirOffset+dirSize {
		return nil, errors.New("trailing central directory bytes")
	}
	return content, nil
}

func parseFileObject(files map[string][]byte, name string) (map[string]any, error) {
	raw, ok := files[name]
	if !ok {
		return nil, fmt.Errorf("missing %s", name)
	}
	v, err := ParseStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return object(v)
}

func checkManifest(files map[string][]byte) error {
	manifest, err := parseFileObject(files, "manifest.json")
	if err != nil {
		return err
	}
	if manifest["format"] != "tracekit.bundle.v2" {
		return errors.New("unsupported manifest format")
	}
	version, err := fieldString(manifest, "verifier_min_version")
	if err != nil {
		return err
	}
	if _, err := parseVersion(version); err != nil {
		return errors.New("invalid verifier_min_version")
	}
	declared, err := object(manifest["files"])
	if err != nil {
		return err
	}
	if len(declared) != len(files)-1 {
		return errors.New("manifest files differ from ZIP files")
	}
	for name, bytes := range files {
		if name == "manifest.json" {
			continue
		}
		digest, ok := declared[name].(string)
		sum := sha256.Sum256(bytes)
		if !ok || digest != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("manifest hash mismatch: %s", name)
		}
	}
	if _, exists := declared["manifest.json"]; exists {
		return errors.New("manifest may not index itself")
	}
	return nil
}

func readLines(data []byte) ([][]byte, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("JSONL must end with newline")
	}
	chunks := bytes.Split(data[:len(data)-1], []byte{'\n'})
	if len(chunks) == 0 {
		return nil, errors.New("empty JSONL")
	}
	for _, line := range chunks {
		if len(line) < 256 || len(line) > 1<<20 {
			return nil, errors.New("record line out of bounds")
		}
	}
	return chunks, nil
}

type recordedKey struct {
	spki   []byte
	from   uint64
	retire *uint64
}
type validatedRecord struct {
	rec    map[string]any
	ev     map[string]any
	seq    uint64
	runSeq uint64
	hash   string
}

func decodeRecord(raw []byte) (validatedRecord, error) {
	val, err := ParseStrict(raw)
	if err != nil {
		return validatedRecord{}, err
	}
	rec, err := object(val)
	if err != nil {
		return validatedRecord{}, err
	}
	ev, err := object(rec["event"])
	if err != nil {
		return validatedRecord{}, err
	}
	seq, err := fieldInt(ev, "seq")
	if err != nil {
		return validatedRecord{}, err
	}
	runSeq, err := fieldInt(ev, "run_seq")
	if err != nil {
		return validatedRecord{}, err
	}
	hash, err := fieldString(rec, "hash")
	if err != nil {
		return validatedRecord{}, err
	}
	return validatedRecord{rec, ev, seq, runSeq, hash}, nil
}
func checkRecord(r validatedRecord, raw []byte, keys map[string]recordedKey) error {
	kid, err := fieldString(r.rec, "kid")
	if err != nil {
		return err
	}
	k, ok := keys[kid]
	if !ok {
		return fmt.Errorf("undeclared record key %s", kid)
	}
	if r.seq < k.from || (k.retire != nil && r.seq > *k.retire) {
		return errors.New("record key not valid at seq")
	}
	_, err = VerifyRecord(raw, k.spki)
	if err != nil {
		return err
	}
	return ValidateEvent(r.ev)
}

func loadTrust(raw []byte) (VKey, []VKey, int, error) {
	v, err := ParseStrict(raw)
	if err != nil {
		return VKey{}, nil, 0, err
	}
	trust, err := object(v)
	if err != nil {
		return VKey{}, nil, 0, err
	}
	for key := range trust {
		switch key {
		case "logs", "algs", "witnesses", "witnesses_required":
		case "rekor":
			pin, err := object(trust[key])
			if err != nil {
				return VKey{}, nil, 0, err
			}
			if len(pin) != 0 {
				if len(pin) != 3 {
					return VKey{}, nil, 0, errors.New("invalid Rekor trust")
				}
				if _, err := object(pin["trusted_root"]); err != nil {
					return VKey{}, nil, 0, err
				}
				if _, err := fieldString(pin, "publishing_key"); err != nil {
					return VKey{}, nil, 0, err
				}
				switch pin["class"] {
				case "public", "customer", "tracekit", "operator":
				default:
					return VKey{}, nil, 0, errors.New("invalid Rekor class")
				}
			}
		case "monitors", "issuers", "analyzers":
			return VKey{}, nil, 0, fmt.Errorf("trust feature %s is not supported", key)
		default:
			return VKey{}, nil, 0, fmt.Errorf("unknown trust field %s", key)
		}
	}
	algs, err := array(trust["algs"])
	if err != nil {
		return VKey{}, nil, 0, err
	}
	if len(algs) != 1 || algs[0] != "ed25519" {
		return VKey{}, nil, 0, errors.New("only ed25519 trust is supported")
	}
	logs, err := array(trust["logs"])
	if err != nil {
		return VKey{}, nil, 0, err
	}
	if len(logs) != 1 {
		return VKey{}, nil, 0, errors.New("exactly one Ed25519 log key is required; hybrid unsupported")
	}
	str, ok := logs[0].(string)
	if !ok {
		return VKey{}, nil, 0, errors.New("non-string log key")
	}
	log, err := ParseVKey(str)
	if err != nil || log.Type != 1 {
		return VKey{}, nil, 0, errors.New("invalid log vkey")
	}
	var witnesses []VKey
	if value, ok := trust["witnesses"]; ok {
		arr, err := array(value)
		if err != nil {
			return VKey{}, nil, 0, err
		}
		for _, item := range arr {
			m, err := object(item)
			if err != nil {
				return VKey{}, nil, 0, err
			}
			if len(m) != 2 {
				return VKey{}, nil, 0, errors.New("invalid witness trust object")
			}
			class, err := fieldString(m, "class")
			if err != nil {
				return VKey{}, nil, 0, err
			}
			switch class {
			case "public", "customer", "tracekit", "operator":
			default:
				return VKey{}, nil, 0, errors.New("invalid witness class")
			}
			name, err := fieldString(m, "vkey")
			if err != nil {
				return VKey{}, nil, 0, err
			}
			vkey, err := ParseVKey(name)
			if err != nil || vkey.Type != 4 {
				return VKey{}, nil, 0, errors.New("invalid witness vkey")
			}
			witnesses = append(witnesses, vkey)
		}
	}
	quorum := 0
	if _, ok := trust["witnesses_required"]; ok {
		n, err := fieldInt(trust, "witnesses_required")
		if err != nil {
			return VKey{}, nil, 0, err
		}
		if n > uint64(len(witnesses)) {
			return VKey{}, nil, 0, errors.New("impossible witness quorum")
		}
		quorum = int(n)
	}
	return log, witnesses, quorum, nil
}

// InspectBundle checks signatures, schemas, chains and tree membership. Use
// VerifyBundle for semantic checks, optional anchors and a verification verdict.
func InspectBundle(bundle, trustBytes []byte) (Inspection, error) {
	result := Inspection{}
	log, witnesses, quorum, err := loadTrust(trustBytes)
	if err != nil {
		return result, fmt.Errorf("trust: %w", err)
	}
	files, err := ReadBundle(bundle)
	if err != nil {
		return result, err
	}
	return inspectFiles(files, log, witnesses, quorum)
}

func inspectFiles(files map[string][]byte, log VKey, witnesses []VKey, quorum int) (Inspection, error) {
	result := Inspection{Files: len(files)}
	if err := checkManifest(files); err != nil {
		return result, err
	}
	proofs, err := parseFileObject(files, "proofs/records.json")
	if err != nil {
		return result, err
	}
	noteName, err := fieldString(proofs, "checkpoint")
	if err != nil {
		return result, err
	}
	if !regexp.MustCompile(`^checkpoints/[0-9]+\.note$`).MatchString(noteName) {
		return result, errors.New("invalid checkpoint path")
	}
	cp, err := VerifyCheckpoint(files[noteName], log, witnesses, quorum)
	if err != nil {
		return result, fmt.Errorf("checkpoint: %w", err)
	}
	n, err := fieldInt(proofs, "tree_size")
	if err != nil || n != cp.Size {
		return result, errors.New("checkpoint tree size mismatch")
	}
	result.TreeSize = n
	result.Witnesses = cp.Witnesses
	incl, err := object(proofs["inclusion"])
	if err != nil {
		return result, err
	}
	inclusion := func(r validatedRecord) error {
		arr, err := array(incl[strconv.FormatUint(r.seq, 10)])
		if err != nil {
			return fmt.Errorf("missing inclusion proof at seq %d", r.seq)
		}
		path := make([]string, 0, len(arr))
		for _, entry := range arr {
			s, ok := entry.(string)
			if !ok {
				return errors.New("non-string inclusion node")
			}
			path = append(path, s)
		}
		return VerifyInclusion(r.hash, r.seq, n, path, cp.Root)
	}
	keyLines, err := readLines(files["keys/records.jsonl"])
	if err != nil {
		return result, fmt.Errorf("keys: %w", err)
	}
	keys := make(map[string]recordedKey)
	var firstLog string
	var prevSeq uint64
	for i, line := range keyLines {
		r, err := decodeRecord(line)
		if err != nil {
			return result, err
		}
		if i > 0 && r.seq <= prevSeq {
			return result, errors.New("key seq not increasing")
		}
		prevSeq = r.seq
		logID, err := fieldString(r.ev, "log_id")
		if err != nil {
			return result, err
		}
		if i == 0 {
			firstLog = logID
		} else if firstLog != logID {
			return result, errors.New("key log_id mismatch")
		}
		typ, err := fieldString(r.ev, "type")
		if err != nil {
			return result, err
		}
		data, err := object(r.ev["data"])
		if err != nil {
			return result, err
		}
		switch typ {
		case "signer.epoch":
			declared, err := array(data["keys"])
			if err != nil {
				return result, err
			}
			if len(declared) == 0 {
				return result, errors.New("empty signer epoch")
			}
			for _, v := range declared {
				k, err := object(v)
				if err != nil {
					return result, err
				}
				kid, err := fieldString(k, "kid")
				if err != nil {
					return result, err
				}
				if k["alg"] != "ed25519" {
					return result, errors.New("unsupported epoch key algorithm")
				}
				s, err := fieldString(k, "spki")
				if err != nil {
					return result, err
				}
				der, err := b64(s)
				if err != nil || SHA256Hex(der) != kid {
					return result, errors.New("invalid epoch SPKI")
				}
				if _, ok := k["cert"]; ok {
					return result, errors.New("issuer certificates unsupported")
				}
				if _, exists := keys[kid]; exists {
					return result, errors.New("key redeclared")
				}
				keys[kid] = recordedKey{spki: der, from: r.seq}
			}
		case "key.retire":
			kid, err := fieldString(data, "kid")
			if err != nil {
				return result, err
			}
			last, err := fieldInt(data, "last_seq")
			if err != nil {
				return result, err
			}
			key, exists := keys[kid]
			if !exists || key.retire != nil || last < key.from {
				return result, errors.New("invalid retirement")
			}
			key.retire = &last
			keys[kid] = key
		default:
			return result, errors.New("non-key record in keys/records.jsonl")
		}
		if err := checkRecord(r, line, keys); err != nil {
			return result, fmt.Errorf("key record seq %d: %w", r.seq, err)
		}
		if err := inclusion(r); err != nil {
			return result, fmt.Errorf("key inclusion: %w", err)
		}
		result.KeyRecords++
	}
	runs, count, err := checkRunEvidence(files, keys, firstLog, inclusion)
	if err != nil {
		return result, err
	}
	result.Runs, result.RunRecords = len(runs), count
	if _, present := files["registry/run-set.json"]; present {
		if err := verifyRunSet(files, log, witnesses, quorum, inclusion, keys, runs, firstLog, n); err != nil {
			return result, fmt.Errorf("run-set: %w", err)
		}
	} else if len(runs) != 1 {
		return result, errors.New("multiple runs without run-set")
	}
	return result, nil
}

// Unsupported features MUST be surfaced, never silently turned into an integrity
// success. A caller may use this function to distinguish malformed evidence.
var ErrUnverifiable = errors.New("UNVERIFIABLE: evidence uses an unsupported verification feature")
