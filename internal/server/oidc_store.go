package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/leaky-hub/argus/internal/config"
)

// Console-managed OIDC settings. The admin panel edits these and they persist
// to <dir>/.appsec/oidc.json, taking precedence over appsec.yml's auth.oidc so
// the static file stays a valid fallback for air-gapped/CLI setups. The client
// SECRET is never here — it is referenced by env-var name and read at flow
// time, upholding "credentials referenced, never collected".

const oidcStoreFile = "oidc.json"

func oidcStorePath(dir string) string {
	return filepath.Join(dir, ".appsec", oidcStoreFile)
}

// loadOIDCStore reads the console-managed OIDC settings, if any. ok=false means
// no store file (fall back to appsec.yml). A corrupt file is an error.
func loadOIDCStore(dir string) (config.OIDCConfig, bool, error) {
	data, err := os.ReadFile(oidcStorePath(dir))
	if os.IsNotExist(err) {
		return config.OIDCConfig{}, false, nil
	}
	if err != nil {
		return config.OIDCConfig{}, false, fmt.Errorf("oidc store: read: %w", err)
	}
	var o config.OIDCConfig
	if err := json.Unmarshal(data, &o); err != nil {
		return config.OIDCConfig{}, false, fmt.Errorf("oidc store: parse: %w", err)
	}
	return o, true, nil
}

// saveOIDCStore atomically writes the console-managed OIDC settings (0600 — the
// file names an env var, never a secret, but stays owner-only for hygiene).
func saveOIDCStore(dir string, o config.OIDCConfig) error {
	if err := os.MkdirAll(filepath.Join(dir, ".appsec"), 0o755); err != nil {
		return fmt.Errorf("oidc store: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	path := oidcStorePath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("oidc store: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("oidc store: replace: %w", err)
	}
	return nil
}

// effectiveOIDC returns the OIDC config actually in force and where it came
// from: the console store wins over appsec.yml. source is "store", "config",
// or "none".
func (s *Server) effectiveOIDC() (cfg config.OIDCConfig, source string) {
	if stored, ok, err := loadOIDCStore(s.dir); err == nil && ok {
		return stored, "store"
	}
	rc, err := repoConfig(s.dir)
	if err != nil {
		return config.OIDCConfig{}, "none"
	}
	if rc.Auth.OIDC.Enabled() {
		return rc.Auth.OIDC, "config"
	}
	return rc.Auth.OIDC, "none"
}
