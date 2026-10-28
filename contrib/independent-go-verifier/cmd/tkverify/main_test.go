package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readLimited(path, 4)
	if err != nil || string(got) != "1234" {
		t.Fatalf("read at limit = %q, %v", got, err)
	}
	if _, err := readLimited(path, 3); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("read over limit error = %v", err)
	}
}

func TestCLIInputLimits(t *testing.T) {
	if bundleReadLimit != 512<<20 {
		t.Fatalf("bundle cap = %d", bundleReadLimit)
	}
	if trustReadLimit != 1<<20 {
		t.Fatalf("trust cap = %d", trustReadLimit)
	}
	if keyReadLimit != 1<<20 {
		t.Fatalf("key cap = %d", keyReadLimit)
	}
	if witnessReadLimit != 512<<20 {
		t.Fatalf("witness cap = %d", witnessReadLimit)
	}
}
