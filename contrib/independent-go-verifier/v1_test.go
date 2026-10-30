package verifier

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
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
