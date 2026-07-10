package scanner

import (
	"context"
	"fmt"
	"regexp"

	"github.com/zer0d4y5/argus/internal/model"
)

// Container image scanning: trivy against an image reference rather than the
// filesystem. It is a distinct surface from the `trivy fs` SCA pass (OS
// packages baked into the image, not just the app's declared dependencies),
// but it produces the SAME trivy JSON, so it reuses parseTrivy verbatim. It
// lives here, in the scanner package, precisely so it can reuse that
// unexported parser; the image command and pipeline call ScanImage.
//
// A container image is not a filesystem path: findings carry the image
// reference as their Location.Resource (the fingerprint place-slot for a
// finding with no file), so the same vulnerable package in two different
// images is two findings, and a report names which image each came from.

// imageRefPattern is a conservative grammar for an OCI image reference:
// registry/name:tag or name@sha256:digest. It exists to reject a reference
// that could be read as a flag (a leading dash) or smuggle shell/space; trivy
// does the real reference parsing. The "--" separator in the argv is the
// primary guard; this is defense in depth plus a friendly early error.
var imageRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:@-]{0,254}$`)

// ImageAvailable reports whether trivy (the image scanner) is on PATH.
func ImageAvailable() bool { return toolOnPath("trivy") }

// ValidateImageRef checks the reference grammar. The returned error is safe
// to show the user.
func ValidateImageRef(ref string) error {
	if !imageRefPattern.MatchString(ref) {
		return fmt.Errorf("invalid image reference %q", ref)
	}
	return nil
}

// ScanImage runs `trivy image` against ref and returns raw findings, tagging
// each with the image reference as its Resource so per-image identity and
// reporting work. The parser (parseTrivy) is shared with the filesystem SCA
// adapter: the two passes speak the same trivy JSON.
func ScanImage(ctx context.Context, ref string) ([]model.RawFinding, error) {
	if err := ValidateImageRef(ref); err != nil {
		return nil, err
	}
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--scanners", "vuln",
		"--", ref,
	}
	data, err := runJSON(ctx, "trivy", args...)
	if err != nil {
		return nil, fmt.Errorf("trivy image scan: %w", err)
	}
	findings, err := parseTrivy(data)
	if err != nil {
		return nil, err
	}
	// The image is the place: no filesystem path exists, so the reference
	// fills the fingerprint's resource slot. trivy's per-result Target (e.g.
	// "img (alpine 3.23)") stays in Meta as context.
	for i := range findings {
		findings[i].Resource = ref
	}
	return findings, nil
}
