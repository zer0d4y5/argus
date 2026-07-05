package auth

import (
	"sync"
	"time"
)

// Login rate limit policy (docs/console-ops.md §6): a fixed one-minute
// window, five failures per key, then the key is locked for five minutes.
// Keys are the client IP and the attempted username, checked independently,
// so neither a single-IP stuffing run nor a distributed attack on one
// account slips under the same counter.
const (
	loginWindow   = time.Minute
	loginMaxFails = 5
	loginLockout  = 5 * time.Minute
)

type rlEntry struct {
	windowStart time.Time
	fails       int
	lockedUntil time.Time
}

// LoginLimiter tracks login failures per key. It answers before credentials
// are checked, so a locked key never costs an argon2id derivation.
type LoginLimiter struct {
	mu      sync.Mutex
	entries map[string]*rlEntry
	now     func() time.Time // injectable for tests
}

// NewLoginLimiter returns an empty limiter.
func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{entries: make(map[string]*rlEntry), now: time.Now}
}

// Allow reports whether a login attempt under these keys may proceed.
func (l *LoginLimiter) Allow(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.pruneLocked(now)
	for _, k := range keys {
		if e, ok := l.entries[k]; ok && now.Before(e.lockedUntil) {
			return false
		}
	}
	return true
}

// Failure records a failed attempt against every key, locking any key that
// reaches the per-window failure cap.
func (l *LoginLimiter) Failure(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, k := range keys {
		e, ok := l.entries[k]
		if !ok || now.Sub(e.windowStart) > loginWindow {
			e = &rlEntry{windowStart: now}
			l.entries[k] = e
		}
		e.fails++
		if e.fails >= loginMaxFails {
			e.lockedUntil = now.Add(loginLockout)
		}
	}
}

// Success clears the counters for every key.
func (l *LoginLimiter) Success(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}

// pruneLocked drops entries whose window and lockout have both lapsed, so
// the map cannot grow without bound under a spray of distinct keys.
func (l *LoginLimiter) pruneLocked(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.windowStart) > loginWindow && !now.Before(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
}
