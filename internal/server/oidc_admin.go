package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/leaky-hub/argus/internal/audit"
	"github.com/leaky-hub/argus/internal/config"
	"github.com/leaky-hub/argus/internal/server/auth"
)

// Admin OIDC configuration endpoint. Admin-only. GET returns the effective
// settings (never a secret) plus whether the referenced env var is currently
// set and where the config comes from; PUT writes the console-managed store,
// rebuilds the provider live, and audits the change. The client SECRET is
// never accepted here — it is provided out of band via the named env var,
// upholding "credentials referenced, never collected".

// OIDCConfigView is the admin GET payload: the settings the UI edits, plus
// read-only status the operator needs.
type OIDCConfigView struct {
	config.OIDCConfig
	Source        string `json:"source"`        // "store" | "config" | "none"
	Enabled       bool   `json:"enabled"`       // issuer+client_id+redirect all set
	SecretEnvName string `json:"secretEnvName"` // the env var the secret is read from
	SecretPresent bool   `json:"secretPresent"` // is that env var currently set on the server?
}

func (s *Server) handleAdminOIDC(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getAdminOIDC(w, r)
	case http.MethodPut:
		s.putAdminOIDC(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) getAdminOIDC(w http.ResponseWriter, _ *http.Request) {
	o, source := s.effectiveOIDC()
	envName := o.SecretEnv()
	writeJSON(w, http.StatusOK, OIDCConfigView{
		OIDCConfig:    o,
		Source:        source,
		Enabled:       o.Enabled(),
		SecretEnvName: envName,
		SecretPresent: os.Getenv(envName) != "",
	})
}

// OIDCConfigRequest is the admin PUT body. The secret is deliberately absent —
// only the env-var NAME is configurable.
type OIDCConfigRequest struct {
	Issuer          string            `json:"issuer"`
	ClientID        string            `json:"clientId"`
	ClientSecretEnv string            `json:"clientSecretEnv"`
	RedirectURL     string            `json:"redirectUrl"`
	AllowedDomains  []string          `json:"allowedDomains"`
	DefaultRole     string            `json:"defaultRole"`
	GroupClaim      string            `json:"groupClaim"`
	RoleMap         map[string]string `json:"roleMap"`
	// Disable clears the console store entirely (SSO reverts to appsec.yml or off).
	Disable bool `json:"disable"`
}

func (s *Server) putAdminOIDC(w http.ResponseWriter, r *http.Request) {
	var req OIDCConfigRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	actor := actorFrom(r)

	if req.Disable {
		if err := os.Remove(oidcStorePath(s.dir)); err != nil && !os.IsNotExist(err) {
			writeErr(w, http.StatusInternalServerError, "failed to clear SSO configuration")
			return
		}
		s.invalidateOIDC()
		s.audit(audit.EventConfigChange, actor, map[string]string{"area": "oidc", "action": "disable"})
		s.getAdminOIDC(w, r)
		return
	}

	o := config.OIDCConfig{
		Issuer:          strings.TrimSpace(req.Issuer),
		ClientID:        strings.TrimSpace(req.ClientID),
		ClientSecretEnv: strings.TrimSpace(req.ClientSecretEnv),
		RedirectURL:     strings.TrimSpace(req.RedirectURL),
		AllowedDomains:  cleanStrings(req.AllowedDomains),
		DefaultRole:     strings.TrimSpace(req.DefaultRole),
		GroupClaim:      strings.TrimSpace(req.GroupClaim),
		RoleMap:         req.RoleMap,
	}
	if msg := validateOIDC(o); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := saveOIDCStore(s.dir, o); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save SSO configuration")
		return
	}
	s.invalidateOIDC()
	s.audit(audit.EventConfigChange, actor, map[string]string{"area": "oidc", "action": "update", "issuer": o.Issuer})
	s.getAdminOIDC(w, r)
}

// validateOIDC checks a proposed config for shape errors the admin should fix
// before it can take effect. Returns a user-facing message, or "" when valid.
// A validated config still fails at login time if discovery can't reach the
// issuer or the secret env var is unset — those are surfaced separately.
func validateOIDC(o config.OIDCConfig) string {
	if o.Issuer == "" || o.ClientID == "" || o.RedirectURL == "" {
		return "issuer, client id, and redirect URL are all required"
	}
	if !strings.HasPrefix(o.Issuer, "https://") && !strings.HasPrefix(o.Issuer, "http://") {
		return "issuer must be an https URL"
	}
	if !strings.HasPrefix(o.RedirectURL, "http://") && !strings.HasPrefix(o.RedirectURL, "https://") {
		return "redirect URL must be an absolute http(s) URL"
	}
	if !strings.HasSuffix(o.RedirectURL, "/api/auth/oidc/callback") {
		return "redirect URL must end in /api/auth/oidc/callback"
	}
	role := o.EffectiveDefaultRole()
	if _, err := auth.ParseRole(role); err != nil {
		return "default role must be viewer, operator, or admin"
	}
	for group, r := range o.RoleMap {
		if _, err := auth.ParseRole(r); err != nil {
			return "role map for group " + group + ": role must be viewer, operator, or admin"
		}
	}
	return ""
}

func cleanStrings(in []string) []string {
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
