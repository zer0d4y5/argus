package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// usersFileName sits inside the repo's .appsec directory, which is expected
// to be gitignored wholesale (the same rule that keeps runs/ out of git).
const usersFileName = "users.json"

// ErrLastAdmin is returned when an operation would leave the console with no
// admin: deleting or demoting the last admin is refused server-side
// (docs/console-ops.md T5).
var ErrLastAdmin = errors.New("refusing to remove or demote the last admin")

// ErrNotFound is returned when a user ID or username does not exist.
var ErrNotFound = errors.New("user not found")

// usernameRe deliberately admits only shell-, log- and JSON-friendly names.
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// Provider identifies how a user authenticates.
const (
	ProviderLocal = "local" // password login (has a Hash)
	ProviderOIDC  = "oidc"  // single sign-on (no Hash; Subject is the IdP sub)
)

// User is the stored form of a console user. The Hash field is the argon2id
// encoded hash; this struct is ONLY for the users file and must never be
// serialized into an API response (the server builds hash-free DTOs).
//
// SSO users carry Provider="oidc", a Subject (the IdP's stable identifier),
// and an Email, and have no Hash. The session-validity check degrades
// correctly for them: an empty Hash matches an empty HashAtLogin, so a
// deprovision (delete) invalidates via not-found and a role change applies
// live, exactly as for local users.
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Hash      string    `json:"hash,omitempty"`
	Role      Role      `json:"role"`
	Provider  string    `json:"provider,omitempty"` // "" = local (back-compat)
	Subject   string    `json:"subject,omitempty"`  // OIDC sub, provider-scoped
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// AuthProvider returns the user's provider, defaulting an empty (pre-SSO)
// value to local so older users files read correctly.
func (u User) AuthProvider() string {
	if u.Provider == "" {
		return ProviderLocal
	}
	return u.Provider
}

// usersFile is the on-disk envelope.
type usersFile struct {
	Schema int    `json:"schema"`
	Users  []User `json:"users"`
}

// Store is the file-backed user store. It re-reads the file when its mtime
// changes, so a user added via the CLI is picked up by a running server (and
// creating the first user flips the console from open to authenticated
// without a restart).
type Store struct {
	path string

	mu      sync.Mutex
	users   []User
	modTime time.Time
	loaded  bool
}

// ForRepo returns the user store for <repoRoot>/.appsec/users.json.
func ForRepo(repoRoot string) *Store {
	return &Store{path: filepath.Join(repoRoot, ".appsec", usersFileName)}
}

// refresh loads the file if it changed since the last read. A missing file is
// zero users; a corrupt file is an error (fail closed — callers treat an
// error as "cannot authenticate anyone", never as "no auth required").
func (s *Store) refresh() error {
	fi, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.users, s.modTime, s.loaded = nil, time.Time{}, true
			return nil
		}
		return fmt.Errorf("auth: stat users file: %w", err)
	}
	if s.loaded && fi.ModTime().Equal(s.modTime) {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("auth: read users file: %w", err)
	}
	var f usersFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("auth: parse users file: %w", err)
	}
	s.users, s.modTime, s.loaded = f.Users, fi.ModTime(), true
	return nil
}

// save atomically rewrites the users file with 0600 permissions.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("auth: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(usersFile{Schema: 1, Users: s.users}, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: marshal users: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("auth: write users file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("auth: replace users file: %w", err)
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.modTime = fi.ModTime()
	}
	return nil
}

// Count returns the number of users. The zero/non-zero distinction is what
// flips the console between open read-only mode and full-auth mode.
func (s *Store) Count() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return 0, err
	}
	return len(s.users), nil
}

// List returns a copy of all users, sorted by username.
func (s *Store) List() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return nil, err
	}
	out := make([]User, len(s.users))
	copy(out, s.users)
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// Add creates a user. The username must be new and well-formed; the password
// is hashed here and never stored.
func (s *Store) Add(username, password string, role Role) (User, error) {
	if !usernameRe.MatchString(username) {
		return User{}, fmt.Errorf("invalid username (allowed: letters, digits, dot, dash, underscore; max 64)")
	}
	if _, err := ParseRole(string(role)); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return User{}, err
	}
	for _, u := range s.users {
		if u.Username == username {
			return User{}, fmt.Errorf("username %q already exists", username)
		}
	}
	u := User{ID: newID("u"), Username: username, Hash: hash, Role: role, CreatedAt: time.Now().UTC()}
	s.users = append(s.users, u)
	if err := s.save(); err != nil {
		s.loaded = false // force re-read; in-memory state may not match disk
		return User{}, err
	}
	return u, nil
}

// FindOrCreateOIDC resolves an SSO identity to a user, provisioning one on
// first login (just-in-time). It matches on (provider=oidc, subject) — never
// on email, which an IdP may recycle — and creates a passwordless user at
// defaultRole when none exists, deriving a unique username from the email.
// Returns the user and whether it was newly created. The caller is
// responsible for the domain allowlist and issuer trust BEFORE calling this;
// this method assumes an already-verified identity.
func (s *Store) FindOrCreateOIDC(subject, email string, defaultRole Role) (User, bool, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return User{}, false, fmt.Errorf("oidc: empty subject")
	}
	if _, err := ParseRole(string(defaultRole)); err != nil {
		return User{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return User{}, false, err
	}
	for i := range s.users {
		if s.users[i].AuthProvider() == ProviderOIDC && s.users[i].Subject == subject {
			// Keep the display email fresh, but never touch role (admins own
			// that) or re-provision.
			if e := strings.TrimSpace(email); e != "" && s.users[i].Email != e {
				s.users[i].Email = e
				if err := s.save(); err != nil {
					s.loaded = false
					return User{}, false, err
				}
			}
			return s.users[i], false, nil
		}
	}
	u := User{
		ID:        newID("u"),
		Username:  s.uniqueUsernameLocked(usernameFromEmail(email)),
		Role:      defaultRole,
		Provider:  ProviderOIDC,
		Subject:   subject,
		Email:     strings.TrimSpace(email),
		CreatedAt: time.Now().UTC(),
	}
	s.users = append(s.users, u)
	if err := s.save(); err != nil {
		s.loaded = false
		return User{}, false, err
	}
	return u, true, nil
}

// uniqueUsernameLocked returns base, or base-2, base-3, … so the username
// stays unique. Caller holds the lock and has refreshed.
func (s *Store) uniqueUsernameLocked(base string) string {
	taken := func(name string) bool {
		for i := range s.users {
			if s.users[i].Username == name {
				return true
			}
		}
		return false
	}
	if !taken(base) {
		return base
	}
	for n := 2; ; n++ {
		cand := fmt.Sprintf("%s-%d", base, n)
		if len(cand) > 64 {
			cand = fmt.Sprintf("%s-%d", base[:64-len(fmt.Sprintf("-%d", n))], n)
		}
		if !taken(cand) {
			return cand
		}
	}
}

// usernameFromEmail derives a console username from an email address, keeping
// only the characters the username grammar allows and falling back to a stable
// generated handle when nothing usable remains.
func usernameFromEmail(email string) string {
	local := email
	if i := strings.IndexByte(email, '@'); i >= 0 {
		local = email[:i]
	}
	var b strings.Builder
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := strings.Trim(b.String(), ".-_")
	if out == "" {
		return newID("sso")
	}
	return out
}

// Remove deletes a user by ID or username, refusing to remove the last admin.
func (s *Store) Remove(idOrUsername string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return User{}, err
	}
	idx := s.find(idOrUsername)
	if idx < 0 {
		return User{}, ErrNotFound
	}
	if s.users[idx].Role == RoleAdmin && s.adminCount() == 1 {
		return User{}, ErrLastAdmin
	}
	removed := s.users[idx]
	s.users = append(s.users[:idx], s.users[idx+1:]...)
	if err := s.save(); err != nil {
		s.loaded = false
		return User{}, err
	}
	return removed, nil
}

// SetRole changes a user's role, refusing to demote the last admin.
func (s *Store) SetRole(idOrUsername string, role Role) (User, error) {
	if _, err := ParseRole(string(role)); err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return User{}, err
	}
	idx := s.find(idOrUsername)
	if idx < 0 {
		return User{}, ErrNotFound
	}
	if s.users[idx].Role == RoleAdmin && role != RoleAdmin && s.adminCount() == 1 {
		return User{}, ErrLastAdmin
	}
	s.users[idx].Role = role
	if err := s.save(); err != nil {
		s.loaded = false
		return User{}, err
	}
	return s.users[idx], nil
}

// SetPassword rehashes a user's password.
func (s *Store) SetPassword(idOrUsername, password string) (User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return User{}, err
	}
	idx := s.find(idOrUsername)
	if idx < 0 {
		return User{}, ErrNotFound
	}
	s.users[idx].Hash = hash
	if err := s.save(); err != nil {
		s.loaded = false
		return User{}, err
	}
	return s.users[idx], nil
}

// Authenticate verifies a username/password pair. An unknown username still
// pays one argon2id verification (against dummyHash) so response timing does
// not distinguish "no such user" from "wrong password".
func (s *Store) Authenticate(username, password string) (User, bool) {
	s.mu.Lock()
	var found *User
	if err := s.refresh(); err == nil {
		for i := range s.users {
			if s.users[i].Username == username {
				u := s.users[i]
				found = &u
				break
			}
		}
	}
	s.mu.Unlock() // argon2id is deliberately slow — never hold the lock across it

	if found == nil {
		VerifyPassword(dummyHash, password)
		return User{}, false
	}
	if !VerifyPassword(found.Hash, password) {
		return User{}, false
	}
	return *found, true
}

// Lookup returns a user by ID or username. The server's auth middleware
// calls this on every request so role changes, password changes, and
// deletions take effect immediately for live sessions.
func (s *Store) Lookup(idOrUsername string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return User{}, false // fail closed: unreadable store authenticates nobody
	}
	idx := s.find(idOrUsername)
	if idx < 0 {
		return User{}, false
	}
	return s.users[idx], true
}

// find locates a user by ID or username. Callers hold s.mu.
func (s *Store) find(idOrUsername string) int {
	for i, u := range s.users {
		if u.ID == idOrUsername || u.Username == idOrUsername {
			return i
		}
	}
	return -1
}

// adminCount counts admins. Callers hold s.mu.
func (s *Store) adminCount() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// newID returns a random, unguessable identifier like "u-9f2c4a1b8d3e6f70".
func newID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}
