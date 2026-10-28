package verifier

import (
	"encoding/json"
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
	for _, run := range []string{"findings:run-a", "anchors:causeway:run-a", "review:run-a"} {
		if !v1CompanionRun(run) {
			t.Errorf("%q was not recognized as a companion run", run)
		}
	}
	if v1CompanionRun("run-a") {
		t.Fatal("ordinary run was treated as a companion")
	}
}
