package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/cloudscan"
	"github.com/zer0d4y5/argus/internal/model"
)

// TestCloudCompliancePassthrough proves prowler's full per-finding compliance
// mapping is imported and mapped exactly: for every FAIL finding, the engine's
// allow-listed passthrough controls must equal prowler's OWN mapping
// (unmapped.compliance) filtered to the allow-list and normalized to display
// IDs. No invented mappings — a pure passthrough.
func TestCloudCompliancePassthrough(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(self), "..", "..", "testdata", "cloud", "prowler-aws.json-ocsf"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := cloudscan.ParseOCSF(data)
	if err != nil {
		t.Fatal(err)
	}
	findings := model.Normalize(res.Raw)
	if err := Apply(findings); err != nil {
		t.Fatal(err)
	}

	// Rebuild the expected mapping straight from each finding's raw prowler
	// payload, independently of CloudControls, and compare.
	byKey := map[string]string{}
	for _, cf := range CloudFrameworks() {
		byKey[cf.ProwlerKey] = cf.ID
	}
	checkedFrameworks := map[string]bool{}
	var sawAny bool
	for _, f := range findings {
		var rec struct {
			Unmapped struct {
				Compliance map[string][]string `json:"compliance"`
			} `json:"unmapped"`
		}
		json.Unmarshal(f.RawPayload, &rec)

		want := map[string]bool{}
		for key, controls := range rec.Unmapped.Compliance {
			id, ok := byKey[key]
			if !ok {
				continue
			}
			checkedFrameworks[id] = true
			for _, c := range controls {
				if c = strings.TrimSpace(c); c != "" {
					want[id+":"+c] = true
				}
			}
		}
		got := map[string]bool{}
		for _, v := range f.ComplianceControls {
			// Only compare the passthrough frameworks (not the engine's
			// CIS-AWS / other curated prefixes).
			for _, cf := range CloudFrameworks() {
				if strings.HasPrefix(v, cf.ID+":") {
					got[v] = true
				}
			}
		}
		if len(want) != len(got) {
			t.Errorf("%s: passthrough controls = %d, want %d\n got=%v\nwant=%v", f.RuleID, len(got), len(want), keysOf(got), keysOf(want))
		}
		for v := range want {
			if !got[v] {
				t.Errorf("%s: missing passthrough control %q", f.RuleID, v)
			}
			sawAny = true
		}
	}
	if !sawAny {
		t.Fatal("no passthrough controls asserted — the fixture proved nothing")
	}
	// The fixture must exercise several well-known frameworks, not just one.
	for _, id := range []string{"NIST-CSF", "ISO-27001"} {
		if !checkedFrameworks[id] {
			t.Errorf("fixture exercised no %s mapping — expected it present", id)
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCloudControlsIgnoresNonCloud: the passthrough is cloud-only and never
// errors on a missing/garbage payload.
func TestCloudControlsIgnoresNonCloud(t *testing.T) {
	if got := CloudControls(model.Finding{Category: model.CategorySAST}); got != nil {
		t.Errorf("non-cloud finding got passthrough %v", got)
	}
	if got := CloudControls(model.Finding{Category: model.CategoryCloud}); got != nil {
		t.Errorf("cloud finding with no payload got %v", got)
	}
	if got := CloudControls(model.Finding{Category: model.CategoryCloud, RawPayload: []byte("{bad")}); got != nil {
		t.Errorf("garbage payload got %v", got)
	}
}

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
