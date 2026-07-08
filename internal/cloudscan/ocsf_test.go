package cloudscan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

// fixture loads the recorded, sanitized prowler json-ocsf slice — a real
// `prowler aws -M json-ocsf` run against a live account, account IDs and
// resource names replaced. The parser is designed from and proven against
// what prowler ACTUALLY emits; CI needs no cloud account.
func fixture(t *testing.T) []byte {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	path := filepath.Join(filepath.Dir(self), "..", "..", "testdata", "cloud", "prowler-aws.json-ocsf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestParseOCSFFixture(t *testing.T) {
	res, err := ParseOCSF(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// The fixture was selected to carry these exact shapes; the counts pin
	// the FAIL-only rule (PASS/MANUAL counted, never findings).
	if res.Failed != 14 || res.Passed != 2 || res.Manual != 1 {
		t.Errorf("counts = %d fail / %d pass / %d manual, want 14/2/1", res.Failed, res.Passed, res.Manual)
	}
	if len(res.Raw) != res.Failed {
		t.Fatalf("%d findings from %d FAIL records — only FAIL becomes a finding", len(res.Raw), res.Failed)
	}

	for _, r := range res.Raw {
		if r.Tool != ToolName || r.Category != model.CategoryCloud {
			t.Fatalf("finding %q: tool/category = %s/%s, want prowler/CLOUD", r.RuleID, r.Tool, r.Category)
		}
		if r.RuleID == "" {
			t.Error("finding with empty rule ID (event_code)")
		}
		if r.Resource == "" {
			t.Errorf("finding %q: empty resource — the fixture records all carry a resource UID", r.RuleID)
		}
		if r.File != "" {
			t.Errorf("finding %q: cloud findings must not carry a file", r.RuleID)
		}
		if r.Title == "" {
			t.Errorf("finding %q: prowler always provides a title", r.RuleID)
		}
		if r.Description == "" {
			t.Errorf("finding %q: status_detail/message must populate the description", r.RuleID)
		}
		if r.Meta[MetaProvider] != "aws" {
			t.Errorf("finding %q: meta.provider = %q, want aws", r.RuleID, r.Meta[MetaProvider])
		}
		if r.Meta[MetaAccount] != "123456789012" {
			t.Errorf("finding %q: meta.account = %q, want the sanitized account", r.RuleID, r.Meta[MetaAccount])
		}
		if len(r.RawPayload) == 0 {
			t.Errorf("finding %q: raw payload must carry the original record", r.RuleID)
		}
	}
}

// TestParseOCSFShapes pins the specific evidence shapes downstream stages
// key on: the internet-exposed category (risk signal), the CIS-AWS 1.5.0
// mapping (compliance passthrough), and severity normalization.
func TestParseOCSFShapes(t *testing.T) {
	res, err := ParseOCSF(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	var exposed, cis, sevCritical int
	for _, r := range res.Raw {
		if strings.Contains(r.Meta[MetaCategories], "internet-exposed") {
			exposed++
		}
		if r.Meta[MetaCISAWS] != "" {
			cis++
		}
		if model.NormalizeSeverity(r.Tool, r.RawSeverity) == model.SeverityCritical {
			sevCritical++
		}
	}
	if exposed != 3 {
		t.Errorf("internet-exposed findings = %d, want 3 (fixture selection)", exposed)
	}
	if cis != 8 {
		t.Errorf("CIS-1.5-mapped findings = %d, want 8 (fixture selection)", cis)
	}
	if sevCritical != 1 {
		t.Errorf("critical findings = %d, want 1", sevCritical)
	}
}

// TestParseOCSFThroughNormalize proves the full path to a normalized
// finding: category CLOUD, resource-slot fingerprint, banded-severity seed,
// and stable identity across a re-parse (cloud deltas depend on it).
func TestParseOCSFThroughNormalize(t *testing.T) {
	res, err := ParseOCSF(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	findings := model.Normalize(res.Raw)
	ids := map[string]bool{}
	for _, f := range findings {
		if f.Location.Resource == "" {
			t.Errorf("%s: normalized cloud finding lost its resource", f.RuleID)
		}
		if ids[f.ID] {
			t.Errorf("duplicate fingerprint %s — resource slot must separate same-check findings", f.ID)
		}
		ids[f.ID] = true
	}

	again := model.Normalize(mustParse(t, fixture(t)).Raw)
	for i := range findings {
		if findings[i].ID != again[i].ID {
			t.Fatalf("fingerprint unstable across parses: %s vs %s", findings[i].ID, again[i].ID)
		}
	}
}

func mustParse(t *testing.T, data []byte) Result {
	t.Helper()
	res, err := ParseOCSF(data)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestParseOCSFRejectsGarbage(t *testing.T) {
	if _, err := ParseOCSF([]byte("not json")); err == nil {
		t.Error("garbage input must error, not return an empty result")
	}
	res, err := ParseOCSF([]byte("[]"))
	if err != nil || len(res.Raw) != 0 {
		t.Errorf("empty document = %v, %v; want clean empty result", res, err)
	}
}

func TestValidateClosedLists(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	creds := filepath.Join(dir, "credentials")
	os.WriteFile(config, []byte("[default]\nregion = us-east-1\n\n[profile security-audit]\nregion = us-east-1\n"), 0o600)
	os.WriteFile(creds, []byte("[legacy]\naws_access_key_id = AKIAFAKEFAKEFAKEFAKE\naws_secret_access_key = fake\n"), 0o600)
	t.Setenv("AWS_CONFIG_FILE", config)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)

	profiles, err := ListAWSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"default", "legacy", "security-audit"}; strings.Join(profiles, ",") != strings.Join(want, ",") {
		t.Fatalf("profiles = %v, want %v", profiles, want)
	}

	// The C2 guard: names outside the discovered closed list never validate,
	// no matter how env-var-shaped or shell-shaped they are.
	for _, bad := range []string{"", "nope", "default; rm -rf /", "$(whoami)", "default\nAWS_X=1"} {
		if err := Validate(Options{Provider: "aws", Profile: bad}); err == nil {
			t.Errorf("profile %q validated — closed-list check failed", bad)
		}
	}
	if err := Validate(Options{Provider: "aws", Profile: "security-audit"}); err != nil {
		t.Errorf("known profile rejected: %v", err)
	}
	if err := Validate(Options{Provider: "azure", Profile: "default"}); err == nil {
		t.Error("unsupported provider must be rejected")
	}
	if err := Validate(Options{Provider: "aws", Profile: "default", Regions: []string{"us-east-1", "BAD REGION"}}); err == nil {
		t.Error("malformed region must be rejected")
	}
}
