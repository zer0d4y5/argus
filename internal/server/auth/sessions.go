package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// Session expiry policy (docs/console-ops.md §6, T9).
const (
	sessionIdleTTL     = 2 * time.Hour
	sessionAbsoluteTTL = 24 * time.Hour
)

// Session is the server-side state behind one cookie. The token itself is
// not stored — sessions are keyed by its SHA-256, so even a memory dump of
// the table does not yield usable cookies.
type Session struct {
	UserID    string
	Username  string
	Role      Role
	CSRF      string // per-session anti-CSRF token, compared constant-time
	CreatedAt time.Time
	LastSeen  time.Time

	// HashAtLogin is the user's password hash when the session was minted.
	// The middleware compares it against the store's current hash so ANY
	// password change (API or CLI) invalidates the user's sessions on their
	// next request. In-memory only; never serialized (API DTOs are built
	// field-by-field and exclude it).
	HashAtLogin string
}

// Sessions is the in-memory session table. State is lost on restart by
// design: users just log in again (docs/console-ops.md §2 residual risk).
type Sessions struct {
	mu  sync.Mutex
	m   map[[sha256.Size]byte]*Session
	now func() time.Time // injectable for expiry tests
}

// NewSessions returns an empty session table.
func NewSessions() *Sessions {
	return &Sessions{m: make(map[[sha256.Size]byte]*Session), now: time.Now}
}

// Create mints a session for user and returns the opaque bearer token that
// goes into the cookie. The token is 32 bytes of crypto/rand, base64url.
func (s *Sessions) Create(user User) (token string, sess Session) {
	token = randToken()
	now := s.now()
	sn := &Session{
		UserID:      user.ID,
		Username:    user.Username,
		Role:        user.Role,
		CSRF:        randToken(),
		CreatedAt:   now,
		LastSeen:    now,
		HashAtLogin: user.Hash,
	}
	s.mu.Lock()
	s.m[sha256.Sum256([]byte(token))] = sn
	s.sweepLocked()
	s.mu.Unlock()
	return token, *sn
}

// Get resolves a cookie token to a live session, enforcing idle and absolute
// expiry and sliding the idle window on success.
func (s *Sessions) Get(token string) (Session, bool) {
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, ok := s.m[key]
	if !ok {
		return Session{}, false
	}
	now := s.now()
	if now.Sub(sn.LastSeen) > sessionIdleTTL || now.Sub(sn.CreatedAt) > sessionAbsoluteTTL {
		delete(s.m, key)
		return Session{}, false
	}
	sn.LastSeen = now
	return *sn, true
}

// CheckCSRF reports whether headerToken matches the session's CSRF token,
// in constant time.
func (s *Sessions) CheckCSRF(sess Session, headerToken string) bool {
	return len(headerToken) > 0 &&
		subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(headerToken)) == 1
}

// Delete revokes one session (logout).
func (s *Sessions) Delete(token string) {
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

// DeleteUser revokes every session belonging to userID — called on password
// change and user deletion so credentials rotate atomically with access.
func (s *Sessions) DeleteUser(userID string) {
	s.mu.Lock()
	for k, sn := range s.m {
		if sn.UserID == userID {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

// sweepLocked drops expired sessions. Called opportunistically under s.mu.
func (s *Sessions) sweepLocked() {
	now := s.now()
	for k, sn := range s.m {
		if now.Sub(sn.LastSeen) > sessionIdleTTL || now.Sub(sn.CreatedAt) > sessionAbsoluteTTL {
			delete(s.m, k)
		}
	}
}

// randToken returns 32 bytes of crypto/rand as unpadded base64url.
func randToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
