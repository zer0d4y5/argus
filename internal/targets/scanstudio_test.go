package targets

// Scan Studio security tables (docs/console-ops.md S1/S2/S3): the git URL
// policy, scope confinement, and config bounds. These are the registration-
// and launch-time boundaries — every rejected row here is an attack shape.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGitURLPolicy(t *testing.T) {
	cases := []struct {
		url string
		ok  bool
	}{
		{"https://github.com/org/repo.git", true},
		{"https://gitlab.example.internal/team/repo", true},
		{"HTTPS://github.com/org/repo.git", true}, // scheme case-insensitive

		{"http://github.com/org/repo.git", false},                        // cleartext
		{"ssh://git@github.com/org/repo.git", false},                     // ssh transport
		{"git://github.com/org/repo.git", false},                         // git transport
		{"file:///etc", false},                                           // local file
		{"ext::sh -c whoami", false},                                     // ext transport
		{"git@github.com:org/repo.git", false},                           // scp-style
		{"https://user:token@github.com/org/repo.git", false},            // creds in URL
		{"https://token@github.com/org/repo.git", false},                 // userinfo
		{"https:///no-host", false},                                      // no host
		{"https://", false},                                              // empty host
		{"", false},                                                      // empty
		{"https://github.com/org/repo.git?x=1", false},                   // query
		{"https://github.com/org/repo.git#frag", false},                  // fragment
		{"https://github.com/org/repo.git --upload-pack=/bin/sh", false}, // arg injection
		{"https://github.com/org/\trepo", false},                         // control chars
	}
	for _, c := range cases {
		_, err := ValidateGitURL(c.url)
		if c.ok && err != nil {
			t.Errorf("ValidateGitURL(%q) rejected: %v", c.url, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ValidateGitURL(%q) accepted, want rejection", c.url)
		}
	}
}

func TestValidateBranch(t *testing.T) {
	for _, ok := range []string{"", "main", "release/1.2", "feature_x-y.z"} {
		if err := ValidateBranch(ok); err != nil {
			t.Errorf("branch %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"-oProxyCommand=x", "a..b", "with space", "semi;colon", strings.Repeat("x", 101)} {
		if err := ValidateBranch(bad); err == nil {
			t.Errorf("branch %q accepted, want rejection", bad)
		}
	}
}

func TestAddGitRegistersAndRejectsDuplicates(t *testing.T) {
	r := ForRepo(t.TempDir())
	tg, err := r.AddGit("payments", "https://github.com/org/payments.git", "main", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Kind() != TypeGit || tg.URL == "" || tg.Path != "" {
		t.Fatalf("git target shape wrong: %+v", tg)
	}
	if _, err := r.AddGit("payments2", "https://github.com/org/payments.git", "main", nil, ""); err == nil {
		t.Error("duplicate url+branch accepted")
	}
	if _, err := r.AddGit("payments-dev", "https://github.com/org/payments.git", "dev", nil, ""); err != nil {
		t.Errorf("same url different branch rejected: %v", err)
	}
	// Registered git targets resolve to the server-owned workspace.
	root := r.Root(tg)
	if !strings.Contains(root, filepath.Join(".appsec", "workspace", tg.ID)) {
		t.Errorf("git root = %q, want the .appsec/workspace/<id> path", root)
	}
}

func TestResolveScopeConfinement(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src", "payments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "main.py"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	// A real symlink escape: root/link -> outside.
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	bad := []string{
		"../",                      // traversal
		"..",                       //
		"src/../../etc",            // traversal after clean
		"/etc",                     // absolute
		filepath.Join(root, "src"), // absolute into root (still absolute ⇒ rejected)
		".git/config",              // VCS bookkeeping
		"src/.git",                 //
		".appsec/runs",             // platform bookkeeping
		"does/not/exist",           // nonexistent
		"link",                     // symlink escaping the root
		"link/sub",                 //
	}
	for _, scope := range bad {
		if _, err := ResolveScope(root, scope); err == nil {
			t.Errorf("scope %q accepted, want rejection", scope)
		}
	}

	// Empty/"." scope returns the (trusted) root verbatim; real scopes come
	// back symlink-resolved.
	for _, scope := range []string{"", "."} {
		if got, err := ResolveScope(root, scope); err != nil || got != root {
			t.Errorf("scope %q = (%q, %v), want the root back", scope, got, err)
		}
	}
	good := map[string]string{
		"src":          filepath.Join(root, "src"),
		"src/payments": filepath.Join(root, "src", "payments"),
		"src/main.py":  filepath.Join(root, "src", "main.py"), // single file
		"./src":        filepath.Join(root, "src"),
	}
	for scope, want := range good {
		got, err := ResolveScope(root, scope)
		if err != nil {
			t.Errorf("scope %q rejected: %v", scope, err)
			continue
		}
		wantReal, _ := filepath.EvalSymlinks(want)
		if got != wantReal {
			t.Errorf("scope %q = %q, want %q", scope, got, wantReal)
		}
	}
}

func TestValidateConfigBounds(t *testing.T) {
	tr := true
	ok := []*Config{
		nil,
		{},
		{TimeoutSec: 10},
		{TimeoutSec: 3600, Triage: &tr},
		{IgnorePaths: []string{"vendor/**", "*.min.js"}, IgnoreRules: []string{"G101"}},
	}
	for i, c := range ok {
		if err := ValidateConfig(c); err != nil {
			t.Errorf("valid config %d rejected: %v", i, err)
		}
	}
	bad := []*Config{
		{TimeoutSec: 5},             // below floor
		{TimeoutSec: 4000},          // above ceiling
		{TimeoutSec: -1},            //
		{IgnorePaths: []string{""}}, // empty entry
		{IgnorePaths: []string{strings.Repeat("x", 201)}}, // too long
		{IgnoreRules: []string{"a\x00b"}},                 // control chars
		{IgnorePaths: make50Plus()},                       // too many
	}
	for i, c := range bad {
		if err := ValidateConfig(c); err == nil {
			t.Errorf("invalid config %d accepted", i)
		}
	}
}

func TestValidateDastConfig(t *testing.T) {
	ok := []*Config{
		{Dast: &DastConfig{Fuzzing: true}},
		{Dast: &DastConfig{Severities: []string{"high", "Critical"}, RateLimit: 50}},
		{Dast: &DastConfig{Auth: &DastAuthConfig{TryDefaults: true}}},
		{Dast: &DastConfig{Auth: &DastAuthConfig{UsernameEnv: "APP_USER", PasswordEnv: "APP_PASS", LoginURL: "http://t/login"}}},
	}
	for i, c := range ok {
		if err := ValidateConfig(c); err != nil {
			t.Errorf("valid dast config %d rejected: %v", i, err)
		}
	}
	bad := []*Config{
		{Dast: &DastConfig{RateLimit: -1}},
		{Dast: &DastConfig{Severities: []string{"catastrophic"}}},                    // not a nuclei severity
		{Dast: &DastConfig{Auth: &DastAuthConfig{UsernameEnv: "bad name"}}},           // space in env name
		{Dast: &DastConfig{Auth: &DastAuthConfig{PasswordEnv: "PASS;rm -rf"}}},        // injection-shaped env name
		{Dast: &DastConfig{Auth: &DastAuthConfig{LoginURL: "javascript:alert(1)"}}},   // non-http scheme
		{Dast: &DastConfig{Templates: []string{strings.Repeat("x", 201)}}},           // over the entry cap
	}
	for i, c := range bad {
		if err := ValidateConfig(c); err == nil {
			t.Errorf("invalid dast config %d accepted", i)
		}
	}
}

// A config carrying only a Dast block must survive normalization (not be
// dropped as "all defaults").
func TestNormalizeConfigKeepsDastOnlyBlock(t *testing.T) {
	got := normalizeConfig(&Config{Dast: &DastConfig{Fuzzing: true}})
	if got == nil || got.Dast == nil || !got.Dast.Fuzzing {
		t.Fatalf("dast-only config was normalized away: %+v", got)
	}
}

func make50Plus() []string {
	out := make([]string, 51)
	for i := range out {
		out[i] = "p"
	}
	return out
}

func TestUpdateAppliesPatchAndReportsChanges(t *testing.T) {
	dir := t.TempDir()
	r := ForRepo(dir)
	scan := t.TempDir()
	tg, err := r.Add("app", scan, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	name := "app-renamed"
	prof := "fast"
	scanners := []string{"gitleaks"}
	cfg := &Config{TimeoutSec: 120, IgnoreRules: []string{"RULE-1"}}
	got, changed, err := r.Update(tg.ID, Patch{Name: &name, Profile: &prof, Scanners: &scanners, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != name || got.Profile != prof || len(got.Scanners) != 1 || got.Config == nil || got.Config.TimeoutSec != 120 {
		t.Fatalf("update not applied: %+v", got)
	}
	if strings.Join(changed, ",") != "name,scanners,profile,config" {
		t.Errorf("changed = %v", changed)
	}

	// Identity is immutable: the patch has no way to express path/url/type.
	// Clearing the config drops the block from disk entirely.
	if _, _, err := r.Update(tg.ID, Patch{Config: &Config{}}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, ".appsec", "targets.json"))
	if strings.Contains(string(raw), `"config"`) {
		t.Errorf("cleared config still serialized: %s", raw)
	}

	if _, _, err := r.Update("t-nope", Patch{Name: &name}); err != ErrNotFound {
		t.Errorf("unknown id: err=%v, want ErrNotFound", err)
	}
	badCfg := &Config{TimeoutSec: 1}
	if _, _, err := r.Update(tg.ID, Patch{Config: badCfg}); err == nil {
		t.Error("out-of-bounds config accepted by Update")
	}
}
