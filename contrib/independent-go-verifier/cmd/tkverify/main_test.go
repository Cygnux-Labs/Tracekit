package main

import (
	"encoding/json"
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
	// a failed check line gives the reason: it is not printed twice
	b.Reset()
	writeReport(&b, report{ExitCode: 1, Integrity: "FAILED", Assurance: "dev", Detail: "seq 3: bad signature",
		Checks: []verifier.VerificationCheck{{Check: "signatures", Status: "fail", Detail: "seq 3: bad signature"}}})
	if want := "[FAIL] signatures — seq 3: bad signature\n\nIntegrity: FAILED.\n" +
		"Assurance: not rated (the bundle failed verification).\n"; b.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", b.String(), want)
	}
	// a bundle that failed a check, then reached evidence this verifier doesn't support: the reason it can't be
	// checked is printed too
	b.Reset()
	writeReport(&b, report{ExitCode: 2, Integrity: "UNVERIFIABLE", Assurance: "dev",
		Detail: "v1 findings semantics are not implemented",
		Checks: []verifier.VerificationCheck{{Check: "chain intact", Status: "fail", Detail: "ledger chain mismatch"}}})
	if want := "[FAIL] chain intact — ledger chain mismatch\nv1 findings semantics are not implemented\n\n" +
		"Integrity: UNVERIFIABLE.\nAssurance: dev.\n"; b.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", b.String(), want)
	}
}

// runCLI runs the CLI with args, as a person would, and returns its exit code and output.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, saved := os.Stdout, os.Args
	os.Stdout, os.Args = w, append([]string{"tkverify"}, args...)
	flag.CommandLine = flag.NewFlagSet("tkverify", flag.ContinueOnError)
	code := run()
	os.Stdout, os.Args = stdout, saved
	w.Close()
	out, _ := io.ReadAll(r)
	return code, string(out)
}

// The format comes from the bundle's manifest, not from the flags: a v2 bundle without -trust is told it needs one,
// as the reference CLI says, not that its manifest is an invalid v1 one.
func TestV2BundleWithoutTrust(t *testing.T) {
	bundle := filepath.Join("..", "..", "..", "..", "tests", "golden", "v2", "closed.tkb")
	if _, err := os.Stat(bundle); os.IsNotExist(err) {
		t.Skip("upstream golden corpus unavailable")
	}
	for _, args := range [][]string{{"-bundle", bundle}, {"-bundle", bundle, "-json"}} {
		code, out := runCLI(t, args...)
		if code != 2 || !strings.Contains(out, "a v2 bundle needs -trust") || strings.Contains(out, "v1 manifest") {
			t.Errorf("%v: exit %d:\n%s", args, code, out)
		}
	}
	code, out := runCLI(t, "-bundle", bundle, "-key", "signer.pub")
	if code != 2 || !strings.Contains(out, "-key and -witness are for v1 bundles") {
		t.Errorf("v2 bundle with -key: exit %d:\n%s", code, out)
	}
	v1 := filepath.Join("..", "..", "..", "..", "tests", "golden", "v1", "demo-run.tkb")
	if code, out := runCLI(t, "-bundle", v1); code != 0 || !strings.Contains(out, "Integrity: VERIFIED") {
		t.Errorf("v1 bundle: exit %d:\n%s", code, out)
	}
}

// A trust file that can't be read: the trust file's problem, with nothing checked, in the words of the other verifiers.
func TestUnreadableTrustFile(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "run.tkb")
	if err := os.WriteFile(bundle, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "-bundle", bundle, "-trust", filepath.Join(dir, "missing.json"))
	if code != 2 || !strings.HasSuffix(out, "\nIntegrity: "+verifier.TrustUnusable+".\nAssurance: none.\n") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// A v2 bundle that failed is not rated in -json either, as the reference CLI's --json gives it: a level rates only
// evidence that verified (release QA of 1.6.0).
func TestFailedV2BundleIsNotRatedInJSON(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "tests", "golden", "negative")
	bundle, trust := filepath.Join(dir, "record-edited.tkb"), filepath.Join(dir, "trust.json")
	if _, err := os.Stat(bundle); os.IsNotExist(err) {
		t.Skip("upstream golden corpus unavailable")
	}
	code, out := runCLI(t, "-bundle", bundle, "-trust", trust, "-json")
	var r report
	if err := json.Unmarshal([]byte(out), &r); err != nil || code != 1 || r.ExitCode != 1 ||
		r.Assurance != "not rated (the bundle failed verification)" {
		t.Fatalf("exit %d, %v:\n%s", code, err, out)
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
