package server

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/targets"
)

func TestApplyDastConfigResolvesEnvCreds(t *testing.T) {
	t.Setenv("TEST_DVWA_USER", "admin")
	t.Setenv("TEST_DVWA_PASS", "password")

	tg := targets.Target{URL: "http://t/", Config: &targets.Config{Dast: &targets.DastConfig{
		Fuzzing:    true,
		Tags:       []string{"sqli"},
		Severities: []string{"high", "critical"},
		RateLimit:  25,
		Auth: &targets.DastAuthConfig{
			UsernameEnv: "TEST_DVWA_USER",
			PasswordEnv: "TEST_DVWA_PASS",
			LoginURL:    "http://t/login",
		},
	}}}

	var opts pipeline.DASTOptions
	applyDastConfig(&opts, tg, func(string) {})

	if !opts.Fuzzing || opts.RateLimit != 25 || len(opts.Tags) != 1 {
		t.Fatalf("scan options not applied: %+v", opts)
	}
	if opts.Auth == nil || opts.Auth.Username != "admin" || opts.Auth.Password != "password" {
		t.Fatalf("auth creds not resolved from env: %+v", opts.Auth)
	}
	if opts.Auth.LoginURL != "http://t/login" {
		t.Errorf("login URL not carried: %q", opts.Auth.LoginURL)
	}
}

// A missing env var must warn and leave that credential empty; with no
// defaults either, no auth is attached so the run still proceeds unauthenticated
// rather than failing.
func TestApplyDastConfigMissingEnvNoAuth(t *testing.T) {
	tg := targets.Target{URL: "http://t/", Config: &targets.Config{Dast: &targets.DastConfig{
		Auth: &targets.DastAuthConfig{UsernameEnv: "DEFINITELY_UNSET_VAR_XYZ"},
	}}}
	var warned bool
	var opts pipeline.DASTOptions
	applyDastConfig(&opts, tg, func(s string) { warned = true })
	if !warned {
		t.Error("missing env var did not warn")
	}
	if opts.Auth != nil {
		t.Errorf("auth attached with no resolvable creds and no defaults: %+v", opts.Auth)
	}
}

func TestApplyDastConfigDefaultsAttachAuth(t *testing.T) {
	tg := targets.Target{URL: "http://t/", Config: &targets.Config{Dast: &targets.DastConfig{
		Auth: &targets.DastAuthConfig{TryDefaults: true},
	}}}
	var opts pipeline.DASTOptions
	applyDastConfig(&opts, tg, func(string) {})
	if opts.Auth == nil || !opts.Auth.TryDefaults {
		t.Fatalf("defaults did not attach auth: %+v", opts.Auth)
	}
}

func TestApplyDastConfigNilIsNoop(t *testing.T) {
	var opts pipeline.DASTOptions
	applyDastConfig(&opts, targets.Target{URL: "http://t/"}, func(string) {})
	if opts.Fuzzing || opts.Auth != nil || opts.Tags != nil {
		t.Errorf("nil config mutated options: %+v", opts)
	}
}
