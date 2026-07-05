package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=1,p=4$") {
		t.Errorf("unexpected encoding: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(h, "wrong password!!") {
		t.Error("wrong password accepted")
	}
	// Two hashes of the same password must differ (random salt).
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("identical hashes — salt not random")
	}
}

func TestVerifyPasswordFailsClosedOnGarbage(t *testing.T) {
	for _, enc := range []string{
		"", "not-a-hash", "$argon2id$v=19$m=65536,t=1,p=4$!!$!!",
		"$argon2i$v=19$m=65536,t=1,p=4$AAAA$AAAA",              // wrong variant
		"$argon2id$v=19$m=99999999,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAA", // memory bomb
	} {
		if VerifyPassword(enc, "anything") {
			t.Errorf("garbage hash %q verified", enc)
		}
	}
}

func TestPasswordMinLength(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("7-char password accepted")
	}
}

func TestStoreLifecycleAndLastAdmin(t *testing.T) {
	dir := t.TempDir()
	s := ForRepo(dir)

	if n, err := s.Count(); err != nil || n != 0 {
		t.Fatalf("fresh store: n=%d err=%v", n, err)
	}

	admin, err := s.Add("alice", "password-1", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("alice", "password-2", RoleViewer); err == nil {
		t.Error("duplicate username accepted")
	}
	if _, err := s.Add("bad name!", "password-2", RoleViewer); err == nil {
		t.Error("invalid username accepted")
	}

	// Last-admin protection: delete and demote both refused.
	if _, err := s.Remove("alice"); err != ErrLastAdmin {
		t.Errorf("removing last admin: err=%v, want ErrLastAdmin", err)
	}
	if _, err := s.SetRole(admin.ID, RoleViewer); err != ErrLastAdmin {
		t.Errorf("demoting last admin: err=%v, want ErrLastAdmin", err)
	}

	// With a second admin, the first can go.
	if _, err := s.Add("bob", "password-3", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRole(admin.ID, RoleOperator); err != nil {
		t.Errorf("demote with second admin present: %v", err)
	}
	if _, err := s.Remove("bob"); err != ErrLastAdmin {
		t.Error("bob became the last admin; removal should be refused")
	}

	// File must be 0600.
	fi, err := os.Stat(filepath.Join(dir, ".appsec", "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("users.json mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestAuthenticate(t *testing.T) {
	s := ForRepo(t.TempDir())
	if _, err := s.Add("alice", "password-1", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate("alice", "password-1"); !ok {
		t.Error("valid credentials rejected")
	}
	if _, ok := s.Authenticate("alice", "password-2"); ok {
		t.Error("wrong password accepted")
	}
	if _, ok := s.Authenticate("nobody", "password-1"); ok {
		t.Error("unknown user accepted")
	}
}

// The users file must never contain plaintext passwords, and the store must
// pick up external (CLI-style) file changes without a restart.
func TestStoreFileHygieneAndReload(t *testing.T) {
	dir := t.TempDir()
	s := ForRepo(dir)
	if _, err := s.Add("alice", "super-secret-pw", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".appsec", "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret-pw") {
		t.Fatal("plaintext password on disk")
	}

	// Simulate a second process (the CLI) adding a user: rewrite the file
	// out-of-band with a bumped mtime; the store must see the new user.
	var f usersFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	h, _ := HashPassword("password-x")
	f.Users = append(f.Users, User{ID: "u-external", Username: "carol", Hash: h, Role: RoleViewer, CreatedAt: time.Now()})
	out, _ := json.Marshal(f)
	path := filepath.Join(dir, ".appsec", "users.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if u, ok := s.Lookup("carol"); !ok || u.ID != "u-external" {
		t.Error("store did not reload externally-modified users file")
	}
}

func TestSessionsExpiry(t *testing.T) {
	s := NewSessions()
	now := time.Now()
	s.now = func() time.Time { return now }

	u := User{ID: "u1", Username: "alice", Role: RoleAdmin, Hash: "h"}
	token, sess := s.Create(u)
	if sess.CSRF == "" || token == "" {
		t.Fatal("empty token or CSRF")
	}
	if got, ok := s.Get(token); !ok || got.Username != "alice" || got.HashAtLogin != "h" {
		t.Fatalf("session not resolvable: %+v ok=%v", got, ok)
	}
	if _, ok := s.Get("forged-token"); ok {
		t.Error("forged token resolved")
	}

	// Idle expiry: 2h1m of silence kills it.
	now = now.Add(2*time.Hour + time.Minute)
	if _, ok := s.Get(token); ok {
		t.Error("idle-expired session still valid")
	}

	// Absolute expiry: keep-alive touches every hour still die at 24h.
	token, _ = s.Create(u)
	for i := 0; i < 25; i++ {
		now = now.Add(time.Hour)
		s.Get(token)
	}
	if _, ok := s.Get(token); ok {
		t.Error("session outlived absolute expiry despite activity")
	}
}

func TestSessionsCSRFAndRevocation(t *testing.T) {
	s := NewSessions()
	u := User{ID: "u1", Username: "alice", Role: RoleAdmin}
	token, sess := s.Create(u)

	if !s.CheckCSRF(sess, sess.CSRF) {
		t.Error("valid CSRF rejected")
	}
	if s.CheckCSRF(sess, "wrong") || s.CheckCSRF(sess, "") {
		t.Error("invalid CSRF accepted")
	}

	// DeleteUser kills every session for the user.
	token2, _ := s.Create(u)
	s.DeleteUser("u1")
	if _, ok := s.Get(token); ok {
		t.Error("session survived DeleteUser")
	}
	if _, ok := s.Get(token2); ok {
		t.Error("second session survived DeleteUser")
	}
}

func TestLoginLimiter(t *testing.T) {
	l := NewLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	// 5 failures lock the key; the 6th attempt is refused.
	for i := 0; i < 5; i++ {
		if !l.Allow("ip:1.2.3.4", "user:alice") {
			t.Fatalf("attempt %d refused before limit", i+1)
		}
		l.Failure("ip:1.2.3.4", "user:alice")
	}
	if l.Allow("ip:1.2.3.4", "user:alice") {
		t.Error("6th attempt allowed after 5 failures")
	}
	// A different username from the same IP is also locked (per-IP key)...
	if l.Allow("ip:1.2.3.4", "user:bob") {
		t.Error("locked IP allowed under a different username")
	}
	// ...but the same username from a different IP is locked too (per-user key).
	if l.Allow("ip:9.9.9.9", "user:alice") {
		t.Error("locked username allowed from a different IP")
	}
	// A completely unrelated key is unaffected.
	if !l.Allow("ip:9.9.9.9", "user:bob") {
		t.Error("unrelated key locked")
	}

	// Lockout lapses.
	now = now.Add(5*time.Minute + time.Second)
	if !l.Allow("ip:1.2.3.4", "user:alice") {
		t.Error("still locked after lockout period")
	}

	// Success clears counters.
	l.Failure("ip:5.5.5.5", "user:carol")
	l.Success("ip:5.5.5.5", "user:carol")
	for i := 0; i < 4; i++ {
		l.Failure("ip:5.5.5.5", "user:carol")
	}
	if !l.Allow("ip:5.5.5.5", "user:carol") {
		t.Error("counters not cleared by Success")
	}
}
