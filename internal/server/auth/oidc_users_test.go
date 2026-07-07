package auth

import (
	"path/filepath"
	"testing"
)

func newUserStore(t *testing.T) *Store {
	t.Helper()
	return &Store{path: filepath.Join(t.TempDir(), "users.json")}
}

// TestOIDCJITProvisioning: first login creates a passwordless user at the
// default role; a second login for the same subject reuses it (never
// duplicates, never re-roles).
func TestOIDCJITProvisioning(t *testing.T) {
	s := newUserStore(t)
	u, created, err := s.FindOrCreateOIDC("sub-123", "alice@example.com", RoleViewer)
	if err != nil || !created {
		t.Fatalf("first login: created=%v err=%v", created, err)
	}
	if u.Provider != ProviderOIDC || u.Subject != "sub-123" || u.Hash != "" || u.Role != RoleViewer {
		t.Fatalf("bad provisioned user: %+v", u)
	}
	if u.Username != "alice" {
		t.Errorf("username = %q, want alice", u.Username)
	}
	// An admin promotes the user out of band.
	if _, err := s.SetRole(u.ID, RoleOperator); err != nil {
		t.Fatal(err)
	}
	// Second login reuses the record and does NOT reset the role.
	u2, created2, err := s.FindOrCreateOIDC("sub-123", "alice@example.com", RoleViewer)
	if err != nil || created2 {
		t.Fatalf("second login: created=%v err=%v", created2, err)
	}
	if u2.ID != u.ID || u2.Role != RoleOperator {
		t.Errorf("second login re-provisioned or re-roled: %+v", u2)
	}
	if n, _ := s.Count(); n != 1 {
		t.Errorf("user count = %d, want 1", n)
	}
}

// TestOIDCMatchesOnSubjectNotEmail: a recycled email with a different subject
// is a different user; a changed email for the same subject updates in place.
func TestOIDCMatchesOnSubjectNotEmail(t *testing.T) {
	s := newUserStore(t)
	a, _, _ := s.FindOrCreateOIDC("sub-A", "shared@example.com", RoleViewer)
	b, createdB, _ := s.FindOrCreateOIDC("sub-B", "shared@example.com", RoleViewer)
	if !createdB || a.ID == b.ID {
		t.Fatal("same email, different subject must be a distinct user")
	}
	if a.Username == b.Username {
		t.Errorf("usernames collided: both %q", a.Username)
	}
	// Same subject, new email → updates the stored email, same id.
	c, createdC, _ := s.FindOrCreateOIDC("sub-A", "renamed@example.com", RoleViewer)
	if createdC || c.ID != a.ID || c.Email != "renamed@example.com" {
		t.Errorf("email update wrong: %+v (created=%v)", c, createdC)
	}
}

func TestUsernameFromEmail(t *testing.T) {
	cases := map[string]string{
		"alice@example.com":     "alice",
		"a.b-c_d@x.io":          "a.b-c_d",
		"WEIRD+tag@x.io":        "WEIRDtag", // '+' dropped
		"..leading@x.io":        "leading",
		"用户@example.com":        "", // no ASCII → generated (checked below)
	}
	for email, want := range cases {
		got := usernameFromEmail(email)
		if want == "" {
			if got == "" || len(got) < 4 {
				t.Errorf("%q: expected a generated fallback, got %q", email, got)
			}
			continue
		}
		if got != want {
			t.Errorf("usernameFromEmail(%q) = %q, want %q", email, got, want)
		}
	}
}

// TestOIDCBackCompatProvider: a user with no provider field (older file)
// reads as local, so the OIDC match never picks it up.
func TestOIDCBackCompatProvider(t *testing.T) {
	u := User{ID: "u-1", Username: "bob", Hash: "x", Role: RoleAdmin}
	if u.AuthProvider() != ProviderLocal {
		t.Errorf("empty provider should read as local, got %q", u.AuthProvider())
	}
}
