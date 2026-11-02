package verifier

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestV1AnchorCompanionDoesNotCreateBoundaryGap(t *testing.T) {
	files, err := readV1Bundle(readGolden(t, "v1/demo-run.tkb"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseFileObject(files, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest["selection"] = map[string]any{"runs": []any{"anchors:test"}}
	files["manifest.json"], _ = json.Marshal(manifest)
	r := VerifyV1(fixtureZip(files), readGolden(t, "v1/signer.pub"), nil)
	if r.ExitCode != 0 || strings.Contains(r.Integrity, "run boundaries") {
		t.Fatalf("anchor companion was treated as a run missing boundaries: %+v", r)
	}
}

// A manifest whose file list is not an object (null included) can't be checked against the files: the reference names
// that the bundle's structure. A manifest with no list lists no file, so the files don't match it.
func TestV1ManifestFileList(t *testing.T) {
	for _, tc := range []struct {
		files any
		check string
	}{{"records.jsonl", "bundle structure"}, {nil, "bundle structure"}, {"absent", "files match manifest"}} {
		files, err := readV1Bundle(readGolden(t, "v1/demo-run.tkb"))
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := parseFileObject(files, "manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		if manifest["files"] = tc.files; tc.files == "absent" {
			delete(manifest, "files")
		}
		files["manifest.json"], _ = json.Marshal(manifest)
		r := VerifyV1(fixtureZip(files), readGolden(t, "v1/signer.pub"), nil)
		other := map[string]string{"bundle structure": "files match manifest", "files match manifest": "bundle structure"}
		if r.ExitCode != 1 || !hasCheck(r.Checks, tc.check) || hasCheck(r.Checks, other[tc.check]) {
			t.Errorf("file list %v: %+v, want %q", tc.files, r, tc.check)
		}
	}
}

// The manifest's seq_range ends at the highest seq of the records present, as the reference reads it, whatever their
// number: a record deleted or repeated in the middle fails the chain, not the range; a range past the last record fails.
func TestV1ManifestRangeIsTheLastSeqPresent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		edit       func([][]byte) [][]byte
		failsRange bool
	}{
		{"a record deleted", func(l [][]byte) [][]byte { return append(l[:5:5], l[6:]...) }, false},
		{"a record repeated", func(l [][]byte) [][]byte { return append(l[:6:6], l[5:]...) }, false},
		{"the last record cut", func(l [][]byte) [][]byte { return l[:len(l)-1] }, true},
	} {
		files, err := readV1Bundle(readGolden(t, "v1/demo-run.tkb"))
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(bytes.TrimSuffix(files["records.jsonl"], []byte("\n")), []byte("\n"))
		files["records.jsonl"] = append(bytes.Join(tc.edit(lines), []byte("\n")), '\n')
		manifest, err := parseFileObject(files, "manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(files["records.jsonl"])
		manifest["files"].(map[string]any)["records.jsonl"] = hex.EncodeToString(sum[:])
		files["manifest.json"], _ = json.Marshal(manifest)
		r := VerifyV1(fixtureZip(files), readGolden(t, "v1/signer.pub"), nil)
		if r.ExitCode != 1 || hasCheck(r.Checks, "manifest range") != tc.failsRange {
			t.Errorf("%s: %+v, want manifest range failed: %v", tc.name, r, tc.failsRange)
		}
	}
}

func TestV1CompanionRunsDoNotRequireRunBoundaries(t *testing.T) {
	for _, run := range []string{"findings:run-a", "anchors:causeway:run-a"} {
		if !v1CompanionRun(run) {
			t.Errorf("%q was not recognized as a companion run", run)
		}
	}
	if v1CompanionRun("run-a") || v1CompanionRun("review:run-a") {
		t.Fatal("ordinary run was treated as a companion")
	}
}

func TestV1LinesRejectBlankLines(t *testing.T) {
	for _, raw := range []string{"{}\n\n", "{}\n  \n", "\n", " "} {
		if _, err := parseV1Lines([]byte(raw)); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"", "{}", "{}\n"} {
		if _, err := parseV1Lines([]byte(raw)); err != nil {
			t.Errorf("rejected %q: %v", raw, err)
		}
	}
}
func TestV1CheckpointLinesSkipBlankLines(t *testing.T) {
	if lines, err := parseV1JSONL([]byte("\n  \n{}\n"), true); err != nil || len(lines) != 1 {
		t.Fatalf("lines: %v, error: %v", lines, err)
	}
}

func TestV1ZipRejectsEncryptedAndMismatchedNames(t *testing.T) {
	original := fixtureZip(map[string][]byte{"abc": []byte("data")})
	for _, test := range []string{"encrypted", "name"} {
		raw := bytes.Clone(original)
		central := bytes.Index(raw, []byte{'P', 'K', 1, 2})
		if central < 0 {
			t.Fatal("missing central directory")
		}
		if test == "encrypted" {
			binary.LittleEndian.PutUint16(raw[central+8:], binary.LittleEndian.Uint16(raw[central+8:])|1)
		} else {
			raw[30] ^= 1
		}
		if _, err := readV1Bundle(raw); err == nil {
			t.Errorf("accepted %s", test)
		}
	}
}

func TestV1ZipRejectsLocalHeaderLengthOutsideArchive(t *testing.T) {
	raw := fixtureZip(map[string][]byte{"abc": []byte("data")})
	binary.LittleEndian.PutUint16(raw[26:], 65535)
	binary.LittleEndian.PutUint16(raw[28:], 65535)
	if _, err := readV1Bundle(raw); err == nil {
		t.Fatal("accepted out-of-bounds local header")
	}
}

func TestV1ZipEntryLimit(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < 10001; i++ {
		if _, err := w.Create(fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readV1Bundle(buf.Bytes()); err == nil {
		t.Fatal("accepted too many entries")
	}
}

func TestV1ZipAcceptsShortNames(t *testing.T) {
	for _, name := range []string{"a", "ab"} {
		raw := fixtureZip(map[string][]byte{name: []byte("data")})
		if _, err := readV1Bundle(raw); err != nil {
			t.Errorf("rejected %q: %v", name, err)
		}
	}
}
