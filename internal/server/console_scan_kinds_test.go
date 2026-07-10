package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/targets"
)

func createTargetJSON(t *testing.T, f *consoleFixture, admin session, body string) targets.Target {
	t.Helper()
	rec := f.do("POST", "/api/targets", body, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create target: %d %s", rec.Code, rec.Body.String())
	}
	var tg targets.Target
	if err := json.Unmarshal(rec.Body.Bytes(), &tg); err != nil {
		t.Fatal(err)
	}
	return tg
}

// TestConsoleRegisterDASTAndImage drives the full HTTP registration path for
// the two new scan kinds and pins their shape and validation.
func TestConsoleRegisterDASTAndImage(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	dast := createTargetJSON(t, f, admin, `{"name":"staging","type":"dast","url":"https://staging.example.com"}`)
	if dast.Kind() != targets.TypeDAST || dast.URL != "https://staging.example.com" {
		t.Errorf("dast target wrong: %+v", dast)
	}
	img := createTargetJSON(t, f, admin, `{"name":"web","type":"image","ref":"nginx:1.27-alpine"}`)
	if img.Kind() != targets.TypeImage || img.Ref != "nginx:1.27-alpine" {
		t.Errorf("image target wrong: %+v", img)
	}

	// Validation is enforced at the HTTP boundary.
	for _, bad := range []string{
		`{"name":"x","type":"dast","url":"file:///etc/passwd"}`,
		`{"name":"y","type":"dast","url":"notaurl"}`,
		`{"name":"z","type":"image","ref":"-oEvil"}`,
		`{"name":"w","type":"image","ref":"img;rm"}`,
	} {
		if rec := f.do("POST", "/api/targets", bad, admin); rec.Code != http.StatusBadRequest {
			t.Errorf("bad target %s = %d, want 400", bad, rec.Code)
		}
	}
}

// TestConsoleLaunchDASTAndImage confirms a registered DAST/image target
// launches through the same scan queue, and that inapplicable filesystem
// knobs are rejected rather than silently ignored.
func TestConsoleLaunchDASTAndImage(t *testing.T) {
	launched := make(chan string, 4)
	exec := func(ctx context.Context, job jobs.Job, progress func(string)) (jobs.Result, error) {
		launched <- job.TargetID
		return jobs.Result{RunID: "run-ok"}, nil
	}
	f := newConsole(t, exec)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")

	dast := createTargetJSON(t, f, admin, `{"name":"staging","type":"dast","url":"https://staging.example.com"}`)
	img := createTargetJSON(t, f, admin, `{"name":"web","type":"image","ref":"nginx:1.27-alpine"}`)

	for _, tg := range []targets.Target{dast, img} {
		body := `{"targetId":"` + tg.ID + `","options":{}}`
		if r := f.do("POST", "/api/scans", body, oper); r.Code != http.StatusAccepted {
			t.Fatalf("launch %s: %d %s", tg.Kind(), r.Code, r.Body.String())
		}
		select {
		case gotID := <-launched:
			if gotID != tg.ID {
				t.Errorf("dispatched target %q, want %q", gotID, tg.ID)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s job never ran", tg.Kind())
		}
	}

	// Filesystem knobs do not apply and are rejected, not silently ignored.
	bad := `{"targetId":"` + dast.ID + `","options":{"scanners":["semgrep"]}}`
	if r := f.do("POST", "/api/scans", bad, oper); r.Code != http.StatusBadRequest {
		t.Errorf("dast + scanners = %d, want 400", r.Code)
	}
	badImg := `{"targetId":"` + img.ID + `","options":{"scope":"sub"}}`
	if r := f.do("POST", "/api/scans", badImg, oper); r.Code != http.StatusBadRequest {
		t.Errorf("image + scope = %d, want 400", r.Code)
	}
}

// TestConsoleSBOMRejectsNonFSTargets pins the SBOM endpoint's contract at the
// HTTP layer: a bad format is 400, and a cloud/DAST/image target (no
// component tree) is refused. The success path (spawning trivy) is covered by
// the sbom package's smoke test, not here.
func TestConsoleSBOMRejectsNonFSTargets(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")

	if r := f.do("POST", "/api/sbom", `{"format":"sarif"}`, oper); r.Code != http.StatusBadRequest {
		t.Errorf("bad format = %d, want 400", r.Code)
	}
	img := createTargetJSON(t, f, admin, `{"name":"web","type":"image","ref":"nginx:1.27-alpine"}`)
	body := `{"targetId":"` + img.ID + `","format":"cyclonedx"}`
	if r := f.do("POST", "/api/sbom", body, oper); r.Code != http.StatusBadRequest {
		t.Errorf("sbom of an image target = %d, want 400 (no component tree)", r.Code)
	}
}
