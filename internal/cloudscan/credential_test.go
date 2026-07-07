package cloudscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leaky-hub/argus/internal/model"
)

// plantedSecret is a distinctive fake credential value written into the test
// AWS credentials file. Every grep-proof below asserts it NEVER appears in a
// place the platform controls — the S4-style proof for cloud credentials
// (threat rows C1–C3): the value lives only in ~/.aws, read by prowler's own
// SDK inside the child; our code handles a NAME, never the key.
const plantedSecret = "wJalrXUtnFEMI-PLANTED-SECRET-bPxRfiCYEXAMPLEKEY"

func writeCredsWithSecret(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	creds := filepath.Join(dir, "credentials")
	if err := os.WriteFile(cfg, []byte("[profile security-audit]\nregion=us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(creds, []byte(
		"[security-audit]\naws_access_key_id=AKIAPLANTEDPLANTED12\naws_secret_access_key="+plantedSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
}

// TestDiscoveryReadsHeadersOnly: profile discovery must surface the section
// NAME and never the credential value beneath it.
func TestDiscoveryReadsHeadersOnly(t *testing.T) {
	writeCredsWithSecret(t)
	profiles, err := ListAWSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(profiles, "\n")
	if !strings.Contains(joined, "security-audit") {
		t.Fatalf("discovery lost the profile name: %v", profiles)
	}
	if strings.Contains(joined, plantedSecret) || strings.Contains(joined, "AKIA") {
		t.Fatal("discovery leaked credential material — it must read section headers only")
	}
}

// TestChildEnvCarriesOnlyTheReference: the env the platform hands the prowler
// child adds exactly one credential-adjacent entry, AWS_PROFILE=<name>, and
// never the key. This is the C2 invariant at its source.
func TestChildEnvCarriesOnlyTheReference(t *testing.T) {
	// A deliberately clean base env (no AWS_* leaking from the runner).
	base := []string{"PATH=/usr/bin", "HOME=/home/x"}
	env := childEnv(base, ProviderAWS, "security-audit")

	var awsEntries []string
	for _, e := range env {
		if strings.HasPrefix(e, "AWS_") {
			awsEntries = append(awsEntries, e)
		}
		if strings.Contains(e, plantedSecret) {
			t.Fatalf("child env carried the planted secret: %q", e)
		}
	}
	if len(awsEntries) != 1 || awsEntries[0] != "AWS_PROFILE=security-audit" {
		t.Fatalf("child env AWS entries = %v, want exactly [AWS_PROFILE=security-audit]", awsEntries)
	}
}

// TestCloudRunFileHasNoCredential: a saved cloud run (built from the recorded
// fixture) must contain no credential-shaped material. Cloud findings carry a
// resource ARN and metadata, never a secret — this pins that the run-file
// writer cannot smuggle one in.
func TestCloudRunFileHasNoCredential(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cloud", "prowler-aws.json-ocsf"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ParseOCSF(data)
	if err != nil {
		t.Fatal(err)
	}
	findings := model.Normalize(res.Raw)

	// Serialize every finding's fields the way a run file does and grep.
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(f.Title)
		b.WriteString(f.Description)
		b.WriteString(f.Location.Resource)
		b.WriteString(f.Remediation)
		for k, v := range f.Meta {
			b.WriteString(k)
			b.WriteString(v)
		}
	}
	blob := b.String()
	for _, needle := range []string{plantedSecret, "aws_secret_access_key", "AKIAPLANTED"} {
		if strings.Contains(blob, needle) {
			t.Errorf("cloud finding content contained credential-shaped material %q", needle)
		}
	}
}
