package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/llm"
	"github.com/leaky-hub/appsec/internal/triage"
)

func TestRemediateEndpoint(t *testing.T) {
	f := newConsole(t, nil)
	runID, sastID, _ := seedRun(t, f.dir)

	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
			return `{"summary":"Parameterize the query","kind":"code-patch","steps":["Bind the value"],"artifacts":[{"language":"diff","title":"fix","content":"- execute(f\"...{n}\")\n+ execute(\"...=?\", (n,))"}],"warnings":["Review before applying"],"verification":"Re-scan; the sqli rule should no longer fire"}`, nil
		}}
	}
	oper := f.mustLogin("oscar")

	runFile := filepath.Join(f.dir, ".appsec", "runs", runID+".json")
	before, _ := os.ReadFile(runFile)

	body := fmt.Sprintf(`{"runId":%q,"findingId":%q}`, runID, sastID)
	rec := f.do("POST", "/api/remediate", body, oper)
	if rec.Code != http.StatusOK {
		t.Fatalf("remediate: %d %s", rec.Code, rec.Body.String())
	}
	var rem triage.Remediation
	if err := json.Unmarshal(rec.Body.Bytes(), &rem); err != nil {
		t.Fatal(err)
	}
	if rem.Kind != triage.KindCodePatch || rem.Summary == "" || len(rem.Artifacts) != 1 {
		t.Fatalf("remediation malformed: %+v", rem)
	}
	if rem.Verification == "" {
		t.Error("verification (re-scan) must be present — the platform never confirms the fix itself")
	}

	// Ephemeral: run file untouched, remediation text not persisted.
	after, _ := os.ReadFile(runFile)
	if string(before) != string(after) || strings.Contains(string(after), "Parameterize the query") {
		t.Fatal("remediation must not touch or persist into the run file")
	}
	// Audit records the request, never the content.
	auditRaw, _ := os.ReadFile(filepath.Join(f.dir, ".appsec", "audit.jsonl"))
	if !strings.Contains(string(auditRaw), "scan.remediate") {
		t.Error("scan.remediate audit event missing")
	}
	if strings.Contains(string(auditRaw), "Parameterize") {
		t.Error("remediation content leaked into the audit log")
	}

	// Viewer is denied (operator+).
	view := f.mustLogin("vera")
	if r := f.do("POST", "/api/remediate", body, view); r.Code != http.StatusForbidden {
		t.Errorf("viewer remediate got %d, want 403", r.Code)
	}
}

// TestRemediateSafetyGateEndToEnd: a model that returns a destructive command
// must have it withheld by the time it reaches the browser — the endpoint
// applies the deterministic linter, not just the unit test.
func TestRemediateSafetyGateEndToEnd(t *testing.T) {
	f := newConsole(t, nil)
	runID, sastID, _ := seedRun(t, f.dir)

	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
			return `{"summary":"Drop the table","kind":"cli-script","steps":["Remove the data"],"artifacts":[{"language":"bash","title":"x","content":"psql -c 'DROP TABLE users;'"}],"verification":"re-scan"}`, nil
		}}
	}
	oper := f.mustLogin("oscar")
	body := fmt.Sprintf(`{"runId":%q,"findingId":%q}`, runID, sastID)
	rec := f.do("POST", "/api/remediate", body, oper)
	if rec.Code != http.StatusOK {
		t.Fatalf("remediate: %d %s", rec.Code, rec.Body.String())
	}
	var rem triage.Remediation
	json.Unmarshal(rec.Body.Bytes(), &rem)
	if len(rem.Artifacts) != 0 {
		t.Error("destructive artifact must be withheld before reaching the browser")
	}
	if rem.Kind != triage.KindManual || len(rem.SafetyIssues) == 0 {
		t.Errorf("withheld remediation must be manual with safety issues; got kind=%q issues=%v", rem.Kind, rem.SafetyIssues)
	}
	if !strings.Contains(strings.Join(rem.Warnings, " "), "withheld") {
		t.Error("expected a withhold warning to the user")
	}
	// The dangerous command never reaches the response body at all.
	if strings.Contains(rec.Body.String(), "DROP TABLE") {
		t.Error("the destructive command leaked into the response")
	}
}
