package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leaky-hub/argus/internal/cloudscan"
	"github.com/leaky-hub/argus/internal/model"
	"github.com/leaky-hub/argus/internal/runstore"
)

// writeAWSConfig points cloudscan's profile discovery at a temp config with a
// known closed list, so the cloud-target tests need no real ~/.aws.
func writeAWSConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	creds := filepath.Join(dir, "credentials")
	if err := os.WriteFile(cfg, []byte("[default]\nregion=us-east-1\n\n[profile security-audit]\nregion=us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A credentials file with real-looking key material: discovery must read
	// ONLY the section header, never the values.
	if err := os.WriteFile(creds, []byte("[legacy]\naws_access_key_id=AKIAEXAMPLEEXAMPLE12\naws_secret_access_key=verysecretvalue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
}

func TestCloudProfilesDiscovery(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	view := f.mustLogin("vera")

	// Viewer is denied (admin-only, config-disclosing).
	if rec := f.do(http.MethodGet, "/api/cloud/profiles", "", view); rec.Code != http.StatusForbidden {
		t.Errorf("viewer got %d, want 403", rec.Code)
	}

	rec := f.do(http.MethodGet, "/api/cloud/profiles", "", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin got %d: %s", rec.Code, rec.Body.String())
	}
	var resp CloudProfilesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Providers) != 1 || resp.Providers[0].Provider != "aws" {
		t.Fatalf("providers = %+v, want one aws entry", resp.Providers)
	}
	got := strings.Join(resp.Providers[0].Profiles, ",")
	if got != "default,legacy,security-audit" {
		t.Errorf("profiles = %q, want the three section names", got)
	}
	// The credential value must never appear in the response.
	if strings.Contains(rec.Body.String(), "verysecretvalue") || strings.Contains(rec.Body.String(), "AKIA") {
		t.Error("cloud profile discovery leaked credential material into the API response")
	}
}

func TestCloudTargetRegistration(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	// A profile NOT in the discovered closed list is rejected (C1/C2).
	bad := `{"name":"bad cloud","provider":"aws","profileName":"nonexistent"}`
	if rec := f.do(http.MethodPost, "/api/targets", bad, admin); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown profile got %d, want 400", rec.Code)
	}

	// An injection-shaped name is rejected the same way — never reaches an env.
	inj := `{"name":"inj","provider":"aws","profileName":"default; rm -rf /"}`
	if rec := f.do(http.MethodPost, "/api/targets", inj, admin); rec.Code != http.StatusBadRequest {
		t.Errorf("injection profile got %d, want 400", rec.Code)
	}

	// A valid registration binds the NAME, stores no key material.
	ok := `{"name":"prod aws","provider":"aws","profileName":"security-audit","regions":["us-east-1"]}`
	rec := f.do(http.MethodPost, "/api/targets", ok, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid cloud target got %d: %s", rec.Code, rec.Body.String())
	}
	var tgt map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tgt); err != nil {
		t.Fatal(err)
	}
	if tgt["type"] != "cloud" || tgt["provider"] != "aws" || tgt["profileName"] != "security-audit" {
		t.Errorf("registered target = %+v", tgt)
	}

	// The stored targets.json must contain the NAME and never a key.
	raw, err := os.ReadFile(filepath.Join(f.dir, ".appsec", "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "security-audit") {
		t.Error("profile name not persisted")
	}
	if strings.Contains(string(raw), "AKIA") || strings.Contains(string(raw), "verysecretvalue") {
		t.Error("credential material reached targets.json")
	}
}

// TestCloudCredentialNeverInDurableState is the S4-style grep-proof for
// threat rows C1/C3: after registering a cloud target and saving a cloud run
// to its store, no credential-shaped material appears in ANY durable
// artifact the platform writes — targets.json, the audit log, or the run
// file. The credential lives only in the host's cloud config, read by
// prowler's own SDK; the platform touches a NAME.
func TestCloudCredentialNeverInDurableState(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	create := `{"name":"prod aws","provider":"aws","profileName":"security-audit","regions":["us-east-1"]}`
	rec := f.do(http.MethodPost, "/api/targets", create, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register cloud target: %d %s", rec.Code, rec.Body.String())
	}
	var tgt struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tgt)
	target, err := f.registry.Get(tgt.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Save a real cloud run (fixture findings) to the target's cloud store,
	// exactly as the executor does.
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cloud", "prowler-aws.json-ocsf"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := cloudscan.ParseOCSF(fixture)
	if err != nil {
		t.Fatal(err)
	}
	findings := model.Normalize(res.Raw)
	store := runstore.Store{Dir: f.registry.CloudRunStore(target)}
	if _, err := store.Save(findings, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	// The planted secret (from writeAWSConfig's credentials file) and any
	// key-shaped material must not appear in the durable artifacts. Sweep the
	// whole .appsec tree — run file, targets.json, audit.jsonl.
	needles := []string{"verysecretvalue", "AKIAEXAMPLEEXAMPLE12", "aws_secret_access_key"}
	root := filepath.Join(f.dir, ".appsec")
	var checked int
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		checked++
		for _, n := range needles {
			if strings.Contains(string(data), n) {
				t.Errorf("credential material %q leaked into %s", n, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no .appsec files were checked — the grep proved nothing")
	}
}

// TestSummaryIsTargetAware pins the fix for "runs execute but don't show in
// Overview": /api/summary?target=<id> must read the target's own store, not
// the served repo's default store. A cloud target's saved run must surface in
// its summary while the default store stays empty.
func TestSummaryIsTargetAware(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	rec := f.do(http.MethodPost, "/api/targets",
		`{"name":"cloud sum","provider":"aws","profileName":"security-audit"}`, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cloud target: %d %s", rec.Code, rec.Body.String())
	}
	var tgt struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tgt)
	target, err := f.registry.Get(tgt.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Save a run into the target's cloud store (as the executor does).
	fixture, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "cloud", "prowler-aws.json-ocsf"))
	res, _ := cloudscan.ParseOCSF(fixture)
	store := runstore.Store{Dir: f.registry.CloudRunStore(target)}
	if _, err := store.Save(model.Normalize(res.Raw), time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	// Default store: empty summary.
	var def SummaryResponse
	json.Unmarshal(f.do(http.MethodGet, "/api/summary", "", admin).Body.Bytes(), &def)
	if def.RunCount != 0 {
		t.Errorf("default summary runCount = %d, want 0", def.RunCount)
	}
	// Target store: the cloud run shows up, categorized CLOUD.
	var tsum SummaryResponse
	json.Unmarshal(f.do(http.MethodGet, "/api/summary?target="+tgt.ID, "", admin).Body.Bytes(), &tsum)
	if tsum.RunCount != 1 || tsum.Total == 0 || tsum.ByCategory["CLOUD"] == 0 {
		t.Errorf("target summary = runCount %d total %d byCategory %v; want the cloud run", tsum.RunCount, tsum.Total, tsum.ByCategory)
	}
}

// TestRunDeleteAndExport covers the two new run-management endpoints against
// a target's own store: export streams SARIF/JSON, delete removes the run
// (admin only), and the audit records the delete.
func TestRunDeleteAndExport(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")

	rec := f.do(http.MethodPost, "/api/targets",
		`{"name":"cloud del","provider":"aws","profileName":"security-audit"}`, admin)
	var tgt struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tgt)
	target, _ := f.registry.Get(tgt.ID)
	fixture, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "cloud", "prowler-aws.json-ocsf"))
	res, _ := cloudscan.ParseOCSF(fixture)
	store := runstore.Store{Dir: f.registry.CloudRunStore(target)}
	meta, _ := store.Save(model.Normalize(res.Raw), time.Unix(1700000000, 0))

	// Export SARIF.
	ex := f.do(http.MethodGet, "/api/runs/"+meta.ID+"/export?format=sarif&target="+tgt.ID, "", oper)
	if ex.Code != http.StatusOK {
		t.Fatalf("export sarif: %d %s", ex.Code, ex.Body.String())
	}
	if ct := ex.Header().Get("Content-Type"); !strings.Contains(ct, "sarif") {
		t.Errorf("export content-type = %q, want sarif", ct)
	}
	if !strings.Contains(ex.Header().Get("Content-Disposition"), "attachment") {
		t.Error("export must set an attachment Content-Disposition")
	}
	if !strings.Contains(ex.Body.String(), `"version": "2.1.0"`) {
		t.Error("SARIF export body malformed")
	}

	// Delete: operator is forbidden, admin succeeds.
	if r := f.do(http.MethodDelete, "/api/runs/"+meta.ID+"?target="+tgt.ID, "", oper); r.Code != http.StatusForbidden {
		t.Errorf("operator delete got %d, want 403", r.Code)
	}
	if r := f.do(http.MethodDelete, "/api/runs/"+meta.ID+"?target="+tgt.ID, "", admin); r.Code != http.StatusOK {
		t.Fatalf("admin delete got %d: %s", r.Code, r.Body.String())
	}
	// Gone now.
	if r := f.do(http.MethodGet, "/api/runs/"+meta.ID+"?target="+tgt.ID, "", admin); r.Code != http.StatusNotFound {
		t.Errorf("deleted run still loads: %d", r.Code)
	}
	// Audit recorded it.
	auditBody := f.do(http.MethodGet, "/api/audit", "", admin).Body.String()
	if !strings.Contains(auditBody, "run.delete") {
		t.Error("run.delete not in audit log")
	}
}

func TestCloudTargetScanLaunchRejectsFilesystemOptions(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	create := `{"name":"cloud1","provider":"aws","profileName":"security-audit"}`
	rec := f.do(http.MethodPost, "/api/targets", create, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cloud target: %d %s", rec.Code, rec.Body.String())
	}
	var tgt struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tgt)

	// Scope/scanners/profile/frameworks must be rejected for a cloud target.
	for _, opts := range []string{
		`{"scope":"src"}`,
		`{"scanners":["semgrep"]}`,
		`{"profile":"max"}`,
		`{"frameworks":["CIS-AWS"]}`,
	} {
		body := `{"targetId":"` + tgt.ID + `","options":` + opts + `}`
		if r := f.do(http.MethodPost, "/api/scans", body, admin); r.Code != http.StatusBadRequest {
			t.Errorf("options %s got %d, want 400", opts, r.Code)
		}
	}

	// A bare launch (triage toggle only) is accepted into the queue.
	body := `{"targetId":"` + tgt.ID + `","options":{"triage":false}}`
	if r := f.do(http.MethodPost, "/api/scans", body, admin); r.Code != http.StatusAccepted {
		t.Errorf("bare cloud launch got %d, want 202: %s", r.Code, r.Body.String())
	}
}
