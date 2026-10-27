// tkverify verifies supported Tracekit evidence offline, failing closed on
// unsupported security-sensitive features.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	verifier "github.com/Cygnux-Labs/Tracekit/contrib/independent-go-verifier"
)

type report struct {
	ExitCode  int                          `json:"exit_code"`
	Integrity string                       `json:"integrity"`
	Assurance string                       `json:"assurance"`
	Checks    []verifier.VerificationCheck `json:"checks"`
	Detail    string                       `json:"detail,omitempty"`
}

func main() { os.Exit(run()) }
func run() int {
	bundle := flag.String("bundle", "", "v2 .tkb archive")
	trust := flag.String("trust", "", "auditor-pinned trust.json")
	key := flag.String("key", "", "v1 signer public key")
	witness := flag.String("witness", "", "v1 witness checkpoint source")
	bridgeKey := flag.String("v1-key", "", "v1 bridge public key")
	bridgeLedger := flag.String("v1-ledger", "", "v1 bridge ledger")
	jsonOutput := flag.Bool("json", false, "print a machine-readable report")
	flag.Parse()
	finish := func(r report) int {
		if *jsonOutput {
			if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
		} else {
			for _, check := range r.Checks {
				fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", strings.ToUpper(check.Status), check.Check, check.Detail)
			}
			fmt.Fprintln(os.Stdout, "Integrity:", r.Integrity)
			fmt.Fprintln(os.Stdout, "Assurance:", r.Assurance)
			if r.Detail != "" {
				fmt.Fprintln(os.Stdout, r.Detail)
			}
		}
		return r.ExitCode
	}
	fail := func(integrity, detail string) int {
		return finish(report{ExitCode: 2, Integrity: integrity, Assurance: "not checked", Checks: []verifier.VerificationCheck{}, Detail: detail})
	}
	if *bundle == "" {
		return fail("UNVERIFIABLE", "usage: tkverify -bundle file.tkb [-trust trust.json | -key signer.pub]")
	}
	data, err := os.ReadFile(*bundle)
	if err != nil {
		return fail("UNUSABLE BUNDLE", err.Error())
	}
	if *bridgeKey != "" || *bridgeLedger != "" {
		return fail("UNVERIFIABLE", "v1 bridge verification is not implemented")
	}
	var result verifier.Verification
	if *trust != "" {
		if *key != "" || *witness != "" {
			return fail("UNVERIFIABLE", "v1 key/witness options cannot be used with v2 trust")
		}
		config, err := os.ReadFile(*trust)
		if err != nil {
			return fail("UNUSABLE BUNDLE", "trust: "+err.Error())
		}
		result = verifier.VerifyBundle(data, config)
	} else {
		var pin, copy []byte
		if *key != "" {
			if strings.HasPrefix(*key, "ed25519:") {
				pin = []byte(*key)
			} else {
				pin, err = os.ReadFile(*key)
				if err != nil {
					return fail("UNUSABLE BUNDLE", "key: "+err.Error())
				}
			}
		}
		if *witness != "" {
			if !strings.HasPrefix(*witness, "file:") {
				return fail("UNVERIFIABLE", "only file witnesses are supported")
			}
			copy, err = os.ReadFile(strings.TrimPrefix(*witness, "file:"))
			if err != nil {
				return fail("UNUSABLE BUNDLE", "witness: "+err.Error())
			}
		}
		result = verifier.VerifyV1(data, pin, copy)
	}
	return finish(report{ExitCode: result.ExitCode, Integrity: result.Integrity, Assurance: result.Assurance, Detail: result.Detail, Checks: result.Checks})
}
