// Package auth is the console's authentication and authorization core:
// argon2id password hashing, the file-backed user store, opaque-token
// sessions with CSRF binding, and the login rate limiter.
//
// SECURITY-CRITICAL invariants (docs/console-ops.md §2, §6):
//   - Password hashes and session tokens never leave this package in any
//     serializable form except the users file itself (0600). API DTOs are
//     built by the server from explicit fields, never from User structs.
//   - All secret comparisons are constant-time.
//   - Unknown-username login verifies against a dummy hash so timing does
//     not reveal whether a username exists.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (docs/console-ops.md §6). They are recorded in each
// encoded hash, so raising them later only affects newly-set passwords while
// existing ones keep verifying.
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 1
	argonThreads   = 4
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// MinPasswordLen is the only password composition rule.
const MinPasswordLen = 8

// HashPassword derives an argon2id hash and returns it in the standard
// encoded form: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded argon2id hash.
// The parameters come from the encoded string, and the comparison is
// constant-time. Any parse failure is simply "no match" — a corrupt hash
// must fail closed, not panic or error out to a caller who might fail open.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var mem, iters uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par); err != nil {
		return false
	}
	if mem == 0 || iters == 0 || par == 0 || mem > 1024*1024 {
		return false // reject degenerate or memory-bomb parameters
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iters, mem, par, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when a login names an unknown user, so the
// request costs one argon2id derivation either way (anti-enumeration).
// Computed once at startup from random material; it matches no password.
var dummyHash = func() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	h, err := HashPassword(base64.RawStdEncoding.EncodeToString(b[:]))
	if err != nil {
		panic("auth: dummy hash: " + err.Error())
	}
	return h
}()
