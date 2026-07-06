package compliance

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/leaky-hub/appsec/internal/cloudscan"
	"github.com/leaky-hub/appsec/internal/model"
)

// TestCISPassthroughMatchesProwler is the passthrough proof (locked decision
// 8): for every FAIL record in the recorded fixture, the engine's CIS-AWS
// mapping must equal PROWLER'S OWN CIS-1.5 mapping (carried by the adapter
// in meta.cisAws150) intersected with the controls our data file declares.
// The data file was materialized from prowler 5.31's embedded cis_1.5_aws
// framework data, so the intersection should be total; a mismatch means the
// materialized mapping drifted from what prowler emits.
func TestCISPassthroughMatchesProwler(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(self), "..", "..", "testdata", "cloud", "prowler-aws.json-ocsf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	res, err := cloudscan.ParseOCSF(data)
	if err != nil {
		t.Fatal(err)
	}
	findings := model.Normalize(res.Raw)
	if err := Apply(findings); err != nil {
		t.Fatal(err)
	}

	declared := declaredCISControls(t)
	checkedAny := false
	for _, f := range findings {
		// Engine's CIS-AWS controls for this finding.
		var got []string
		for _, c := range f.ComplianceControls {
			if strings.HasPrefix(c, "CIS-AWS:") {
				got = append(got, strings.TrimPrefix(c, "CIS-AWS:"))
			}
		}
		// Prowler's own mapping ∩ declared controls.
		var want []string
		if csv := f.Meta["cisAws150"]; csv != "" {
			for _, c := range strings.Split(csv, ",") {
				if declared[c] {
					want = append(want, c)
				}
			}
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s (%s): engine CIS-AWS = %v, prowler's own mapping ∩ declared = %v",
				f.RuleID, f.Location.Resource, got, want)
		}
		if len(want) > 0 {
			checkedAny = true
		}
	}
	if !checkedAny {
		t.Fatal("fixture exercised no CIS-mapped finding — the passthrough proof proved nothing")
	}
}

// TestCISAWSProviderScope: cloud findings from another provider must be OUT
// OF SCOPE for the AWS benchmark (never mapped, and assessed as
// out-of-scope rather than unmapped), while IaC findings keep their
// rule-ID-prefix scoping untouched.
func TestCISAWSProviderScope(t *testing.T) {
	azure := model.Finding{
		Category: model.CategoryCloud,
		RuleID:   "accessanalyzer_enabled", // a CIS-1.5-mapped check ID (control 1.20)
		Meta:     map[string]string{"provider": "azure"},
	}
	controls, err := MapFinding(azure)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range controls {
		if strings.HasPrefix(c, "CIS-AWS:") {
			t.Errorf("azure cloud finding mapped to %s — providerScope failed", c)
		}
	}

	aws := azure
	aws.Meta = map[string]string{"provider": "aws"}
	controls, err = MapFinding(aws)
	if err != nil {
		t.Fatal(err)
	}
	var hit bool
	for _, c := range controls {
		if strings.HasPrefix(c, "CIS-AWS:") {
			hit = true
		}
	}
	if !hit {
		t.Error("aws cloud finding with a mapped check did not reach CIS-AWS")
	}
}

func declaredCISControls(t *testing.T) map[string]bool {
	t.Helper()
	fws, err := Frameworks()
	if err != nil {
		t.Fatal(err)
	}
	for i := range fws {
		if fws[i].ID == "CIS-AWS" {
			out := map[string]bool{}
			for _, c := range fws[i].Controls {
				out[c.ID] = true
			}
			return out
		}
	}
	t.Fatal("CIS-AWS framework not embedded")
	return nil
}
