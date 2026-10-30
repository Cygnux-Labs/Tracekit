package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	verifier "github.com/Cygnux-Labs/Tracekit/contrib/independent-go-verifier"
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

// The report reads as the reference CLI's: warning lines, the reason, then the verdict; a failed bundle's assurance is
// not rated.
func TestReportGivesTheReasonBeforeTheVerdict(t *testing.T) {
	var b strings.Builder
	writeReport(&b, report{ExitCode: 1, Integrity: "FAILED", Assurance: "witnessed; records ed25519",
		Detail: "seq 3: invalid Ed25519 record signature",
		Checks: []verifier.VerificationCheck{{Check: "gaps", Status: "warn", Detail: "1 signed gap"}}})
	want := "[WARN] gaps — 1 signed gap\n[FAIL] seq 3: invalid Ed25519 record signature\n\nIntegrity: FAILED.\n" +
		"Assurance: not rated (the bundle failed verification).\n"
	if b.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", b.String(), want)
	}
	b.Reset()
	writeReport(&b, report{ExitCode: 2, Integrity: verifier.TrustUnusable, Assurance: "none", Detail: "trust config: x"})
	if want := "trust config: x\n\nIntegrity: " + verifier.TrustUnusable + ".\nAssurance: none.\n"; b.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", b.String(), want)
	}
}

// A trust file that can't be read: the trust file's problem, with nothing checked, in the words of the other verifiers.
func TestUnreadableTrustFile(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "run.tkb")
	if err := os.WriteFile(bundle, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, args := os.Stdout, os.Args
	os.Stdout, os.Args = w, []string{"tkverify", "-bundle", bundle, "-trust", filepath.Join(dir, "missing.json")}
	flag.CommandLine = flag.NewFlagSet("tkverify", flag.ContinueOnError)
	code := run()
	os.Stdout, os.Args = stdout, args
	w.Close()
	out, _ := io.ReadAll(r)
	if code != 2 || !strings.HasSuffix(string(out), "\nIntegrity: "+verifier.TrustUnusable+".\nAssurance: none.\n") {
		t.Fatalf("exit %d:\n%s", code, out)
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
