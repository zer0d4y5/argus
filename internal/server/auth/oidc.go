package auth

// OpenID Connect single sign-on. This wraps the vetted go-oidc + oauth2
// libraries (JWT signature verification, JWKS fetching, discovery) rather than
// hand-rolling token crypto. The flow is Authorization Code + PKCE with a
// server-side, one-time state/nonce so neither can be replayed, and every
// identity is verified (issuer, audience, expiry, signature, nonce) before it
// can mint a session.
//
// This file owns the protocol and the crypto boundary. The POLICY — which
// domains may auto-provision, which group maps to which role — is pure and
// lives in policy funcs below so it can be tested without a network.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCClaims is the subset of ID-token claims Argus reads, extracted at the
// crypto boundary so all downstream policy runs on a plain struct.
type OIDCClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Groups        []string
}

// OIDCProvider is a configured, discovered OIDC identity provider plus Argus's
// provisioning policy. Build it once at server start; it is safe for
// concurrent use.
type OIDCProvider struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	secret   string // client secret, read from env at construction; used only in Exchange

	allowedDomains []string
	defaultRole    Role
	groupClaim     string
	roleMap        map[string]Role

	pending *pendingStore
}

// OIDCParams are the validated inputs to build a provider. Issuer, ClientID,
// RedirectURL, and ClientSecret are required; the rest shape provisioning.
type OIDCParams struct {
	Issuer         string
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	AllowedDomains []string
	DefaultRole    Role
	GroupClaim     string
	RoleMap        map[string]string
}

// NewOIDCProvider performs OIDC discovery against the issuer (a network call)
// and returns a ready provider. A discovery or role-config error is fatal to
// SSO but never to the server — the caller logs and runs password-only.
func NewOIDCProvider(ctx context.Context, p OIDCParams) (*OIDCProvider, error) {
	if p.Issuer == "" || p.ClientID == "" || p.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: issuer, client_id, and redirect_url are required")
	}
	if p.ClientSecret == "" {
		return nil, fmt.Errorf("oidc: no client secret in the configured env var")
	}
	provider, err := oidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery failed: %w", err)
	}
	role := p.DefaultRole
	if role == "" {
		role = RoleViewer
	}
	if _, err := ParseRole(string(role)); err != nil {
		return nil, fmt.Errorf("oidc: default_role: %w", err)
	}
	roleMap := map[string]Role{}
	for group, r := range p.RoleMap {
		parsed, err := ParseRole(r)
		if err != nil {
			return nil, fmt.Errorf("oidc: role_map[%q]: %w", group, err)
		}
		roleMap[group] = parsed
	}
	return &OIDCProvider{
		oauth: &oauth2.Config{
			ClientID:    p.ClientID,
			Endpoint:    provider.Endpoint(),
			RedirectURL: p.RedirectURL,
			Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier:       provider.Verifier(&oidc.Config{ClientID: p.ClientID}),
		secret:         p.ClientSecret,
		allowedDomains: normalizeDomains(p.AllowedDomains),
		defaultRole:    role,
		groupClaim:     p.GroupClaim,
		roleMap:        roleMap,
		pending:        newPendingStore(),
	}, nil
}

// AuthURL starts a login: it mints one-time state/nonce/PKCE, records them
// server-side, and returns the provider URL to redirect the browser to.
func (p *OIDCProvider) AuthURL() string {
	state := randToken()
	nonce := randToken()
	verifier := randToken() + randToken() // >43 chars, PKCE requirement
	p.pending.put(state, pending{nonce: nonce, verifier: verifier, created: time.Now()})
	challenge := pkceS256(verifier)
	return p.oauth.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange completes the callback: it consumes the one-time state, exchanges
// the code (with the PKCE verifier and client secret), verifies the ID token
// against the provider (signature, issuer, audience, expiry) AND the recorded
// nonce, and returns the extracted claims. Every failure is an error; nothing
// is provisioned here.
func (p *OIDCProvider) Exchange(ctx context.Context, state, code string) (OIDCClaims, error) {
	pend, ok := p.pending.consume(state)
	if !ok {
		return OIDCClaims{}, fmt.Errorf("oidc: unknown or expired login state")
	}
	// Attach the secret for this exchange only.
	conf := *p.oauth
	conf.ClientSecret = p.secret
	tok, err := conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", pend.verifier))
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc: code exchange failed")
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return OIDCClaims{}, fmt.Errorf("oidc: no id_token in token response")
	}
	idTok, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc: id_token verification failed")
	}
	if idTok.Nonce != pend.nonce {
		return OIDCClaims{}, fmt.Errorf("oidc: nonce mismatch")
	}
	var raw struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idTok.Claims(&raw); err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc: cannot read claims")
	}
	claims := OIDCClaims{
		Subject:       idTok.Subject, // the verified sub, not a claim we re-read
		Email:         strings.TrimSpace(raw.Email),
		EmailVerified: raw.EmailVerified,
		Groups:        p.extractGroups(idTok),
	}
	if claims.Subject == "" {
		claims.Subject = raw.Subject
	}
	return claims, nil
}

// extractGroups pulls the configured group claim as a string slice, tolerating
// the provider returning either a JSON array or a single string.
func (p *OIDCProvider) extractGroups(idTok *oidc.IDToken) []string {
	if p.groupClaim == "" {
		return nil
	}
	var all map[string]any
	if err := idTok.Claims(&all); err != nil {
		return nil
	}
	v, ok := all[p.groupClaim]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// --- Pure provisioning policy (no network, unit-tested directly) ---

// Authorize decides whether a verified identity may sign in, and at what role
// for a JIT-provisioned user. It requires a verified email in an allowed
// domain. The returned role is the default (or a group-mapped role) and only
// applies when the user is created; existing users keep their assigned role.
func (p *OIDCProvider) Authorize(claims OIDCClaims) (role Role, err error) {
	if claims.Email == "" || !claims.EmailVerified {
		return "", fmt.Errorf("sign-in requires a verified email from your identity provider")
	}
	if !emailDomainAllowed(claims.Email, p.allowedDomains) {
		return "", fmt.Errorf("your email domain is not permitted to sign in to this console")
	}
	return p.roleForGroups(claims.Groups), nil
}

// roleForGroups returns the highest role any of the user's groups maps to, or
// the default when no group matches.
func (p *OIDCProvider) roleForGroups(groups []string) Role {
	best := p.defaultRole
	for _, g := range groups {
		if r, ok := p.roleMap[g]; ok && roleRank[r] > roleRank[best] {
			best = r
		}
	}
	return best
}

// emailDomainAllowed reports whether email's domain is in the allowlist.
// An empty allowlist denies all JIT provisioning (deny by default): SSO is
// configured but nobody auto-onboards until a domain is named.
func emailDomainAllowed(email string, allowed []string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range allowed {
		if domain == d {
			return true
		}
	}
	return false
}

func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "@")))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- One-time login-state store ---

type pending struct {
	nonce    string
	verifier string
	created  time.Time
}

// pendingStore holds in-flight logins, keyed by state, with a short TTL and
// one-time consumption. In-memory like the session table; a login is seconds
// long, so nothing survives a restart by design.
type pendingStore struct {
	mu  sync.Mutex
	m   map[string]pending
	ttl time.Duration
	now func() time.Time
}

func newPendingStore() *pendingStore {
	return &pendingStore{m: map[string]pending{}, ttl: 10 * time.Minute, now: time.Now}
}

func (s *pendingStore) put(state string, p pending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.m[state] = p
}

// consume returns the pending login for state and removes it (one-time). A
// missing or expired entry returns ok=false.
func (s *pendingStore) consume(state string) (pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[state]
	if !ok {
		return pending{}, false
	}
	delete(s.m, state)
	if s.now().Sub(p.created) > s.ttl {
		return pending{}, false
	}
	return p, true
}

func (s *pendingStore) sweepLocked() {
	cutoff := s.now().Add(-s.ttl)
	for k, v := range s.m {
		if v.created.Before(cutoff) {
			delete(s.m, k)
		}
	}
}

// randToken is defined in sessions.go (32 bytes crypto/rand, base64url).
var _ = rand.Read
