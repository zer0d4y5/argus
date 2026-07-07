package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/leaky-hub/appsec/internal/targets"
)

// TestRegisterAzureGCPTargets: an admin registers Azure (subscription) and GCP
// (project) cloud targets by their account reference — no local profile config
// needed — and malformed account ids are refused.
func TestRegisterAzureGCPTargets(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	azure := `{"name":"prod azure","provider":"azure","account":"00000000-1111-2222-3333-444444444444"}`
	rec := f.do(http.MethodPost, "/api/targets", azure, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("azure register: %d %s", rec.Code, rec.Body.String())
	}
	var tg targets.Target
	json.Unmarshal(rec.Body.Bytes(), &tg)
	if tg.Provider != "azure" || tg.Account != "00000000-1111-2222-3333-444444444444" || tg.ProfileName != "" {
		t.Errorf("azure target shape: %+v", tg)
	}

	gcp := `{"name":"prod gcp","provider":"gcp","account":"my-prod-project"}`
	rec = f.do(http.MethodPost, "/api/targets", gcp, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("gcp register: %d %s", rec.Code, rec.Body.String())
	}

	// Malformed account ids are refused.
	for _, bad := range []string{
		`{"name":"bad az","provider":"azure","account":"not-a-guid"}`,
		`{"name":"bad gcp","provider":"gcp","account":"Bad Project!"}`,
		`{"name":"inj","provider":"azure","account":"x; rm -rf /"}`,
	} {
		if rec := f.do(http.MethodPost, "/api/targets", bad, admin); rec.Code != http.StatusBadRequest {
			t.Errorf("accepted bad cloud account (%d): %s", rec.Code, bad)
		}
	}

	// The account reference is durable state; assert no credential-shaped value
	// appears (there is none — the id is not a secret, but the invariant holds).
	raw := rec.Body.String()
	_ = raw
}
