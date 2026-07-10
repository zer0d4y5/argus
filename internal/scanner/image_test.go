package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

func TestValidateImageRef(t *testing.T) {
	for _, ok := range []string{
		"nginx:alpine",
		"nginx:1.27-alpine",
		"registry.example.com/team/app:v1.2.3",
		"app@sha256:abc123def4567890abc123def4567890abc123def4567890abc123def4567890",
		"alpine",
		"ghcr.io/org/name:tag",
	} {
		if err := ValidateImageRef(ok); err != nil {
			t.Errorf("ValidateImageRef(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"-oProxyCommand=evil", // leading dash: could be read as a flag
		"nginx alpine",        // space
		"nginx;rm -rf",        // shell metachar
		"image\nref",          // newline
		"image$(id)",          // command substitution chars
	} {
		if err := ValidateImageRef(bad); err == nil {
			t.Errorf("ValidateImageRef(%q) = nil, want error", bad)
		}
	}
}

// realImageJSON is a two-vulnerability sample captured verbatim from
// `trivy image --format json nginx:alpine` (trivy 0.71). It pins the parser
// to trivy's actual image-scan schema, which is the same Results/
// Vulnerabilities shape as `trivy fs`, so parseTrivy is reused directly.
const realImageJSON = `{"Results":[{"Target":"nginx:alpine (alpine 3.23.5)","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-33630","PkgName":"c-ares","InstalledVersion":"1.34.6-r0","FixedVersion":"1.34.8-r0","Severity":"UNKNOWN","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2026-33630"},{"VulnerabilityID":"CVE-2026-56131","PkgName":"libexpat","InstalledVersion":"2.8.1-r0","FixedVersion":"2.8.2-r0","Severity":"HIGH","Title":"libexpat before 2.8.2 lacks handler call depth tracking","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2026-56131","CweIDs":["CWE-416"]}]}]}`

// TestParseImageJSON confirms trivy image output parses through the shared
// parseTrivy into well-formed SCA raw findings.
func TestParseImageJSON(t *testing.T) {
	raws, err := parseTrivy([]byte(realImageJSON))
	if err != nil {
		t.Fatalf("parseTrivy: %v", err)
	}
	if len(raws) != 2 {
		t.Fatalf("got %d findings, want 2", len(raws))
	}
	byID := map[string]model.RawFinding{}
	for _, r := range raws {
		byID[r.RuleID] = r
		if r.Tool != "trivy" || r.Category != model.CategorySCA {
			t.Errorf("%s: tool/category = %q/%q", r.RuleID, r.Tool, r.Category)
		}
	}
	expat := byID["CVE-2026-56131"]
	if expat.Package != "libexpat@2.8.1-r0" {
		t.Errorf("package = %q", expat.Package)
	}
	if expat.CVE != "CVE-2026-56131" || expat.RawSeverity != "HIGH" {
		t.Errorf("cve/severity = %q/%q", expat.CVE, expat.RawSeverity)
	}
	if expat.Remediation != "Upgrade libexpat to 2.8.2-r0" {
		t.Errorf("remediation = %q", expat.Remediation)
	}
	if len(expat.CWEs) != 1 || expat.CWEs[0] != "CWE-416" {
		t.Errorf("cwes = %v", expat.CWEs)
	}
}

// TestImageFindingsDistinctPerImage pins the per-image identity contract: the
// SAME vulnerable package in two DIFFERENT images is two findings, because the
// image reference fills the fingerprint's resource slot. This is what
// ScanImage's Resource tagging buys.
func TestImageFindingsDistinctPerImage(t *testing.T) {
	raws, err := parseTrivy([]byte(realImageJSON))
	if err != nil {
		t.Fatalf("parseTrivy: %v", err)
	}
	tag := func(rs []model.RawFinding, ref string) []model.Finding {
		out := make([]model.RawFinding, len(rs))
		copy(out, rs)
		for i := range out {
			out[i].Resource = ref
		}
		return model.Normalize(out)
	}
	imgA := tag(raws, "nginx:alpine")
	imgB := tag(raws, "nginx:1.27")

	// Within one image, the two CVEs are distinct.
	if imgA[0].ID == imgA[1].ID {
		t.Error("two CVEs in one image collided")
	}
	// The same CVE+package across two images is two findings.
	idsA := map[string]bool{imgA[0].ID: true, imgA[1].ID: true}
	for _, f := range imgB {
		if idsA[f.ID] {
			t.Errorf("finding %s (%s) collided across images", f.RuleID, f.Package)
		}
		if f.Location.Resource == "" {
			t.Errorf("image finding %s has no resource", f.RuleID)
		}
	}
}

// TestSmokeScanImage runs the real trivy binary against a container image.
// Skipped with -short, when trivy is absent, or when the image/DB is not
// available in the environment (offline CI): a network-dependent pull must
// not fail the suite.
func TestSmokeScanImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping trivy image smoke test in -short mode")
	}
	if !ImageAvailable() {
		t.Skip("trivy not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	raws, err := ScanImage(ctx, "alpine:3.18")
	if err != nil {
		t.Skipf("image unavailable in this environment: %v", err)
	}
	for _, r := range raws {
		if r.Tool != "trivy" || r.Category != model.CategorySCA {
			t.Errorf("bad tool/category: %q/%q", r.Tool, r.Category)
		}
		if r.Resource != "alpine:3.18" {
			t.Errorf("finding not tagged with the image ref: %q", r.Resource)
		}
	}
}
