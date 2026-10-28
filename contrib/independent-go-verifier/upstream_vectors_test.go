package verifier

import (
	"bufio"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These integration tests activate automatically in a full Tracekit checkout.
// They are deliberately not copied from either existing verifier.
func repositoryVectorLines(t *testing.T, file string) [][]byte {
	t.Helper()
	path := filepath.Join("..", "..", "tests", "vectors", file)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		t.Skip("upstream test vectors not accessible in this workspace")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines [][]byte
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 2<<20)
	for s.Scan() {
		lines = append(lines, append([]byte(nil), s.Bytes()...))
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Fatal("empty published vector file")
	}
	return lines
}
func TestRepositoryJCSVectors(t *testing.T) {
	for _, line := range repositoryVectorLines(t, "jcs.jsonl") {
		var row struct {
			ID        string `json:"id"`
			Input     string `json:"input"`
			Canonical string `json:"canonical"`
			SHA       string `json:"sha256"`
			Error     string `json:"error"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		t.Run(row.ID, func(t *testing.T) {
			obj, err := ParseStrict([]byte(row.Input))
			if row.Error != "" {
				if err == nil {
					t.Fatalf("accepted input expected to fail with %s", row.Error)
				}
				if !strings.Contains(err.Error(), row.Error) {
					t.Fatalf("expected %s, got %v", row.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := Canonical(obj)
			if err != nil {
				t.Fatal(err)
			}
			if string(canonical) != row.Canonical {
				t.Fatalf("JCS mismatch: %s versus %s", canonical, row.Canonical)
			}
			if SHA256Hex(canonical) != "sha256:"+row.SHA {
				t.Fatal("JCS digest mismatch")
			}
		})
	}
}
func TestRepositorySignatureVectors(t *testing.T) {
	for _, line := range repositoryVectorLines(t, "sig_v2.jsonl") {
		var row struct {
			ID     string          `json:"id"`
			Public string          `json:"public"`
			Msg    string          `json:"msg"`
			Sig    string          `json:"sig"`
			Valid  bool            `json:"valid"`
			Record json.RawMessage `json:"record"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		t.Run(row.ID, func(t *testing.T) {
			pub, err := hex.DecodeString(row.Public)
			if err != nil {
				t.Fatal(err)
			}
			if len(row.Record) > 0 {
				spki, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
				if err != nil {
					t.Fatal(err)
				}
				_, err = VerifyRecord(row.Record, spki)
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			message, err := hex.DecodeString(row.Msg)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := hex.DecodeString(row.Sig)
			if err != nil {
				t.Fatal(err)
			}
			valid := validEd25519PublicKey(pub) && ed25519.Verify(pub, message, signature)
			if valid != row.Valid {
				t.Fatalf("expected valid=%t got %t", row.Valid, valid)
			}
		})
	}
}
