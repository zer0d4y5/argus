package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leaky-hub/argus/internal/model"
	"github.com/leaky-hub/argus/internal/runstore"
)

// recExec records remediation commands and returns canned output.
type recExec struct {
	calls    [][]string
	profiles []string
	out      string
	err      error
}

func (r *recExec) Run(_ context.Context, argv []string, profile string) (string, error) {
	r.calls = append(r.calls, argv)
	r.profiles = append(r.profiles, profile)
	return r.out, r.err
}

// seedCloudTargetWithS3Finding registers a cloud target and saves a run holding
// one S3 public-access finding on bucket "prod-assets". Returns target id,
// run id, finding id.
func seedCloudTargetWithS3Finding(t *testing.T, f *consoleFixture, admin session) (string, string, string) {
	t.Helper()
	writeAWSConfig(t)
	rec := f.do(http.MethodPost, "/api/targets", `{"name":"prod aws","provider":"aws","profileName":"security-audit","regions":["us-east-1"]}`, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register cloud target: %d %s", rec.Code, rec.Body.String())
	}
	var tgt struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &tgt)
	target, err := f.registry.Get(tgt.ID)
	if err != nil {
		t.Fatal(err)
	}
	finding := model.Finding{
		Category: model.CategoryCloud,
		Tool:     "prowler", Tools: []string{"prowler"},
		RuleID:   "s3_bucket_public_access",
		Title:    "S3 bucket allows public access",
		Severity: model.SeverityHigh,
		Location: model.Location{Resource: "arn:aws:s3:::prod-assets"},
		Meta:     map[string]string{"provider": "aws", "service": "s3", "resourceType": "AwsS3Bucket", "resourceName": "prod-assets", "region": "us-east-1"},
	}
	finding.ID = model.Fingerprint(finding)
	store := runstore.Store{Dir: f.registry.CloudRunStore(target)}
	meta, err := store.Save([]model.Finding{finding}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return tgt.ID, meta.ID, finding.ID
}

func enableRemediation(t *testing.T, f *consoleFixture) {
	t.Helper()
	writeFile(t, f.dir, "appsec.yml", "remediation:\n  enabled: true\n")
}

// TestCloudRemediationsList: an operator can list the curated fixes for a cloud
// finding (no execution), and the applicable one is the S3 block-public-access.
func TestCloudRemediationsList(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	tid, rid, fid := seedCloudTargetWithS3Finding(t, f, admin)

	body := `{"targetId":"` + tid + `","runId":"` + rid + `","findingId":"` + fid + `"}`
	rec := f.do("POST", "/api/cloud/remediations", body, oper)
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Enabled      bool
		Remediations []struct {
			ID    string
			Apply [][]string
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Enabled {
		t.Error("enabled should default false")
	}
	if len(out.Remediations) != 1 || out.Remediations[0].ID != "aws-s3-block-public-access" {
		t.Fatalf("wrong remediations: %+v", out.Remediations)
	}
	if !strings.Contains(strings.Join(out.Remediations[0].Apply[0], " "), "prod-assets") {
		t.Errorf("command not resolved to the bucket: %+v", out.Remediations[0].Apply)
	}
}

// TestCloudRemediateGatedOff: with remediation disabled, execute returns 409
// (not an authz denial) even for an admin.
func TestCloudRemediateGatedOff(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	tid, rid, fid := seedCloudTargetWithS3Finding(t, f, admin)
	body := `{"targetId":"` + tid + `","runId":"` + rid + `","findingId":"` + fid + `","remediationId":"aws-s3-block-public-access","mode":"dryrun","profile":"security-audit"}`
	if rec := f.do("POST", "/api/cloud/remediate", body, admin); rec.Code != 409 {
		t.Errorf("disabled execute = %d, want 409", rec.Code)
	}
}

// TestCloudRemediateDryRunAndApply: enabled, an admin dry-runs then applies the
// fix; the runner executes the catalog's commands via the fake executor, both
// are audited, apply returns the re-scan hint, and NO disposition is written.
func TestCloudRemediateDryRunAndApply(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	tid, rid, fid := seedCloudTargetWithS3Finding(t, f, admin)
	enableRemediation(t, f)
	fx := &recExec{out: "{}"}
	f.srv.remediateExec = fx

	base := `{"targetId":"` + tid + `","runId":"` + rid + `","findingId":"` + fid + `","remediationId":"aws-s3-block-public-access","profile":"security-audit"`
	// Dry-run.
	rec := f.do("POST", "/api/cloud/remediate", base+`,"mode":"dryrun"}`, admin)
	if rec.Code != 200 {
		t.Fatalf("dryrun: %d %s", rec.Code, rec.Body.String())
	}
	if len(fx.calls) != 1 || fx.calls[0][2] != "get-public-access-block" {
		t.Errorf("dryrun ran wrong command: %v", fx.calls)
	}
	if fx.profiles[0] != "security-audit" {
		t.Errorf("write profile not passed: %v", fx.profiles)
	}
	// Apply.
	rec = f.do("POST", "/api/cloud/remediate", base+`,"mode":"apply"}`, admin)
	if rec.Code != 200 {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Applied    bool
		ReScanHint string
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.Applied || out.ReScanHint == "" {
		t.Errorf("apply response wrong: %+v", out)
	}
	if fx.calls[1][2] != "put-public-access-block" {
		t.Errorf("apply ran wrong command: %v", fx.calls[1])
	}
	// A remediation NEVER writes a disposition — the gate stays a re-scan away.
	tg, _ := f.registry.Get(tid)
	dispParent := filepath.Dir(f.registry.CloudRunStore(tg))
	if _, err := os.Stat(filepath.Join(dispParent, "dispositions.json")); err == nil {
		t.Error("remediation wrote a disposition (must not)")
	}
	// Both actions audited as cloud.remediate.
	auditRaw, _ := os.ReadFile(filepath.Join(f.dir, ".appsec", "audit.jsonl"))
	if strings.Count(string(auditRaw), "cloud.remediate") < 2 {
		t.Errorf("remediation actions not audited: %s", auditRaw)
	}
}

// TestCloudRemediateAuthz: an operator cannot execute (admin-only), and an
// unknown/mismatched remediation is refused.
func TestCloudRemediateAuthz(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	tid, rid, fid := seedCloudTargetWithS3Finding(t, f, admin)
	enableRemediation(t, f)
	f.srv.remediateExec = &recExec{out: "{}"}

	base := `{"targetId":"` + tid + `","runId":"` + rid + `","findingId":"` + fid + `","profile":"security-audit","mode":"apply"`
	if rec := f.do("POST", "/api/cloud/remediate", base+`,"remediationId":"aws-s3-block-public-access"}`, oper); rec.Code != 403 {
		t.Errorf("operator execute = %d, want 403", rec.Code)
	}
	// A remediation that does not match this finding is refused.
	if rec := f.do("POST", "/api/cloud/remediate", base+`,"remediationId":"aws-ec2-ebs-encryption-by-default"}`, admin); rec.Code != 400 {
		t.Errorf("mismatched remediation = %d, want 400", rec.Code)
	}
	// An unknown profile is refused by the runner.
	if rec := f.do("POST", "/api/cloud/remediate", `{"targetId":"`+tid+`","runId":"`+rid+`","findingId":"`+fid+`","remediationId":"aws-s3-block-public-access","mode":"apply","profile":"not-a-profile"}`, admin); rec.Code != http.StatusBadGateway {
		t.Errorf("unknown profile = %d, want 502", rec.Code)
	}
}


