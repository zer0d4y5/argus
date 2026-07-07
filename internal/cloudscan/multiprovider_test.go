package cloudscan

import (
	"strings"
	"testing"
)

func TestKnownProviders(t *testing.T) {
	got := KnownProviders()
	if len(got) != 3 {
		t.Fatalf("providers = %v", got)
	}
	for _, p := range []string{"aws", "azure", "gcp"} {
		if !ValidProvider(p) {
			t.Errorf("%s should be valid", p)
		}
	}
	if ValidProvider("oracle") {
		t.Error("oracle should be invalid")
	}
}

func TestValidateAzureGCP(t *testing.T) {
	// Azure: subscription must be a GUID.
	if err := Validate(Options{Provider: ProviderAzure, Account: "00000000-1111-2222-3333-444444444444"}); err != nil {
		t.Errorf("valid azure subscription rejected: %v", err)
	}
	for _, bad := range []string{"", "not-a-guid", "12345", "sub; rm -rf /", "--profile x"} {
		if err := Validate(Options{Provider: ProviderAzure, Account: bad}); err == nil {
			t.Errorf("azure accepted bad subscription %q", bad)
		}
	}
	// GCP: project id grammar.
	if err := Validate(Options{Provider: ProviderGCP, Account: "my-prod-project"}); err != nil {
		t.Errorf("valid gcp project rejected: %v", err)
	}
	for _, bad := range []string{"", "AB", "Uppercase-Project", "-leading-hyphen", "proj; evil", "x"} {
		if err := Validate(Options{Provider: ProviderGCP, Account: bad}); err == nil {
			t.Errorf("gcp accepted bad project %q", bad)
		}
	}
}

func TestBuildArgsPerProvider(t *testing.T) {
	cases := []struct {
		opts     Options
		contains []string
		absent   []string
	}{
		{Options{Provider: ProviderAWS, Regions: []string{"us-east-1", "us-west-2"}},
			[]string{"aws", "-M", "json-ocsf", "-f", "us-east-1", "us-west-2"}, []string{"--subscription-ids", "--project-ids"}},
		{Options{Provider: ProviderAzure, Account: "00000000-1111-2222-3333-444444444444"},
			[]string{"azure", "--subscription-ids", "00000000-1111-2222-3333-444444444444"}, []string{"-f", "--project-ids"}},
		{Options{Provider: ProviderGCP, Account: "my-project"},
			[]string{"gcp", "--project-ids", "my-project"}, []string{"-f", "--subscription-ids"}},
	}
	tokenset := func(toks []string) map[string]bool {
		m := map[string]bool{}
		for _, t := range toks {
			m[t] = true
		}
		return m
	}
	for _, tc := range cases {
		argv := buildArgs(tc.opts, "/tmp/out")
		args := strings.Join(argv, " ")
		toks := tokenset(argv)
		for _, want := range tc.contains {
			if !strings.Contains(args, want) {
				t.Errorf("%s args missing %q: %s", tc.opts.Provider, want, args)
			}
		}
		for _, no := range tc.absent {
			if toks[no] { // exact-token match, not substring
				t.Errorf("%s args should not contain token %q: %s", tc.opts.Provider, no, args)
			}
		}
	}
}

// TestChildEnvAzureGCPCarriesNoInjectedCredential: for Azure/GCP, Argus injects
// NO credential env — auth is the operator's own env, and the account id rides
// in argv. So childEnv must add nothing beyond the base (in particular no
// AWS_PROFILE, no account value).
func TestChildEnvAzureGCPCarriesNoInjectedCredential(t *testing.T) {
	base := []string{"PATH=/usr/bin", "AZURE_CLIENT_ID=set-by-operator"}
	for _, provider := range []string{ProviderAzure, ProviderGCP} {
		env := childEnv(base, provider, "unused-profile")
		if len(env) != len(base) {
			t.Errorf("%s childEnv added entries: %v", provider, env)
		}
		for _, e := range env {
			if strings.HasPrefix(e, "AWS_PROFILE=") {
				t.Errorf("%s childEnv injected AWS_PROFILE: %q", provider, e)
			}
		}
	}
}

func TestAccountLabel(t *testing.T) {
	if AccountLabel(ProviderAzure) != "subscription id" || AccountLabel(ProviderGCP) != "project id" || AccountLabel(ProviderAWS) != "profile" {
		t.Error("account labels wrong")
	}
}
