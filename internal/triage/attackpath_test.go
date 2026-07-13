package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/llm"
	"github.com/zer0d4y5/argus/internal/model"
)

// apFakeClient returns a canned response and records the prompt it was given.
type apFakeClient struct {
	resp   string
	system string
	user   string
}

func (c *apFakeClient) Name() string  { return "fake/model" }
func (c *apFakeClient) Local() bool    { return true }
func (c *apFakeClient) Complete(_ context.Context, req llm.Request) (string, error) {
	c.system, c.user = req.System, req.User
	return c.resp, nil
}

func dastFinding(cwe string, sev model.Severity, urlStr string) model.Finding {
	return model.Finding{
		Category: model.CategoryDAST, CWEs: []string{cwe}, Severity: sev,
		Location: model.Location{URL: urlStr}, Proof: &model.Proof{Observed: "confirmed"},
	}
}

func TestBuildAttackPathInput(t *testing.T) {
	findings := []model.Finding{
		dastFinding("CWE-918", model.SeverityHigh, "http://t/fetch?url=x"),
		dastFinding("CWE-89", model.SeverityCritical, "http://t/item?id=1"),
		{Category: model.CategorySAST, CWEs: []string{"CWE-89"}, Severity: model.SeverityHigh}, // not DAST -> ignored
		{Category: model.CategoryDAST, CWEs: []string{"CWE-200"}, Severity: model.SeverityInfo},  // not notable -> ignored
	}
	// Mark the SSRF as cloud-metadata reachable.
	findings[0].Meta = map[string]string{"cloud": "aws"}

	in := BuildAttackPathInput("http://t/", findings)
	if len(in.Findings) != 2 {
		t.Fatalf("want 2 notable DAST findings, got %d: %+v", len(in.Findings), in.Findings)
	}
	if !in.CloudMetadataReachable {
		t.Error("expected cloud-metadata-reachable flag from the SSRF finding")
	}
	classes := in.Findings[0].Class + "|" + in.Findings[1].Class
	if !strings.Contains(classes, "SQL injection") || !strings.Contains(classes, "request forgery") {
		t.Errorf("classes not derived from CWEs: %q", classes)
	}
}

func TestAttackPathParsesAndBounds(t *testing.T) {
	c := &apFakeClient{resp: `{"summary":"An attacker can chain SSRF to reach cloud metadata.","chains":["SSRF -> metadata -> role credentials"],"nextSteps":["confirm metadata reachability"]}`}
	in := BuildAttackPathInput("http://t/", []model.Finding{dastFinding("CWE-918", model.SeverityHigh, "http://t/f?url=x")})
	res, err := AttackPath(context.Background(), c, in, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "cloud metadata") || len(res.Chains) != 1 || len(res.NextSteps) != 1 {
		t.Errorf("unexpected result: %+v", res)
	}
	// The prompt must fence the untrusted findings and forbid payload output.
	if !strings.Contains(c.system, "ANALYSIS ONLY") || !strings.Contains(c.user, "UNTRUSTED-DATA-") {
		t.Error("prompt is missing the analysis-only rule or the data fence")
	}
}

func TestAttackPathEmptyInputErrors(t *testing.T) {
	c := &apFakeClient{resp: `{}`}
	_, err := AttackPath(context.Background(), c, AttackPathInput{}, 0)
	if err == nil {
		t.Error("expected an error when there are no findings to analyze")
	}
}
