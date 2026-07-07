package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// --- pure policy (no network) ---

func TestEmailDomainAllowed(t *testing.T) {
	allowed := normalizeDomains([]string{"Example.com", "@corp.io ", ""})
	cases := map[string]bool{
		"alice@example.com": true,
		"BOB@EXAMPLE.COM":   true,  // domain compared case-insensitively
		"x@corp.io":         true,
		"y@evil.com":        false,
		"no-at-sign":        false,
		"trailing@":         false,
	}
	for email, want := range cases {
		if got := emailDomainAllowed(email, allowed); got != want {
			t.Errorf("emailDomainAllowed(%q) = %v, want %v", email, got, want)
		}
	}
	// Empty allowlist denies everyone (deny-by-default JIT).
	if emailDomainAllowed("alice@example.com", nil) {
		t.Error("empty allowlist must deny JIT")
	}
}

func TestAuthorizeRequiresVerifiedEmailInDomain(t *testing.T) {
	p := &OIDCProvider{allowedDomains: []string{"example.com"}, defaultRole: RoleViewer}
	if _, err := p.Authorize(OIDCClaims{Email: "a@example.com", EmailVerified: false}); err == nil {
		t.Error("unverified email must be refused")
	}
	if _, err := p.Authorize(OIDCClaims{Email: "a@other.com", EmailVerified: true}); err == nil {
		t.Error("out-of-domain email must be refused")
	}
	if _, err := p.Authorize(OIDCClaims{Email: "", EmailVerified: true}); err == nil {
		t.Error("empty email must be refused")
	}
	role, err := p.Authorize(OIDCClaims{Email: "a@example.com", EmailVerified: true})
	if err != nil || role != RoleViewer {
		t.Errorf("valid identity: role=%v err=%v", role, err)
	}
}

func TestRoleForGroups(t *testing.T) {
	p := &OIDCProvider{
		defaultRole: RoleViewer,
		roleMap:     map[string]Role{"eng": RoleOperator, "admins": RoleAdmin},
	}
	if r := p.roleForGroups(nil); r != RoleViewer {
		t.Errorf("no groups → %v, want viewer", r)
	}
	if r := p.roleForGroups([]string{"eng"}); r != RoleOperator {
		t.Errorf("eng → %v, want operator", r)
	}
	// Highest wins when multiple map.
	if r := p.roleForGroups([]string{"eng", "admins"}); r != RoleAdmin {
		t.Errorf("eng+admins → %v, want admin", r)
	}
	if r := p.roleForGroups([]string{"unknown"}); r != RoleViewer {
		t.Errorf("unmapped group → %v, want viewer default", r)
	}
}

func TestPendingStoreOneTimeAndExpiry(t *testing.T) {
	s := newPendingStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	s.put("st", pending{nonce: "n", verifier: "v", created: now})
	if _, ok := s.consume("bogus"); ok {
		t.Error("unknown state must not resolve")
	}
	got, ok := s.consume("st")
	if !ok || got.nonce != "n" {
		t.Fatalf("consume: %+v ok=%v", got, ok)
	}
	if _, ok := s.consume("st"); ok {
		t.Error("state must be one-time — second consume must fail")
	}
	// Expiry.
	s.put("st2", pending{nonce: "n", created: now})
	now = now.Add(11 * time.Minute)
	if _, ok := s.consume("st2"); ok {
		t.Error("expired state must not resolve")
	}
}

func TestPKCEChallengeIsS256(t *testing.T) {
	sum := sha256.Sum256([]byte("verifier123"))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := pkceS256("verifier123"); got != want {
		t.Errorf("pkceS256 = %q, want %q", got, want)
	}
}

// --- end-to-end verification against a fake IdP (real crypto) ---

type fakeIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	// token controls what the /token endpoint mints for the next exchange.
	claims map[string]any
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		iss := f.server.URL
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 iss,
			"authorization_endpoint": iss + "/auth",
			"token_endpoint":         iss + "/token",
			"jwks_uri":               iss + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(f.key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.PublicKey.E)).Bytes())
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{"kty": "RSA", "use": "sig", "kid": f.kid, "alg": "RS256", "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idToken := f.signJWT(t, f.claims)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "id_token": idToken,
		})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// signJWT hand-builds an RS256 JWT so the test controls every claim.
func (f *fakeIdP) signJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": f.kid}
	seg := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signingInput := seg(header) + "." + seg(claims)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIdP) provider(t *testing.T, params OIDCParams) *OIDCProvider {
	t.Helper()
	params.Issuer = f.server.URL
	if params.ClientID == "" {
		params.ClientID = "argus-client"
	}
	if params.ClientSecret == "" {
		params.ClientSecret = "secret"
	}
	params.RedirectURL = "http://127.0.0.1:8080/api/auth/oidc/callback"
	p, err := NewOIDCProvider(context.Background(), params)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	return p
}

// baseClaims returns a valid claim set for the given provider's expectations.
func (f *fakeIdP) baseClaims(nonce string) map[string]any {
	return map[string]any{
		"iss": f.server.URL, "aud": "argus-client", "sub": "sub-42",
		"email": "alice@example.com", "email_verified": true,
		"nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
}

// stateNonce runs AuthURL and returns the state and the nonce the provider
// stored for it (same-package access to the pending store).
func stateNonce(t *testing.T, p *OIDCProvider) (state, nonce string) {
	t.Helper()
	u, err := url.Parse(p.AuthURL())
	if err != nil {
		t.Fatal(err)
	}
	state = u.Query().Get("state")
	p.pending.mu.Lock()
	nonce = p.pending.m[state].nonce
	p.pending.mu.Unlock()
	if state == "" || nonce == "" {
		t.Fatal("AuthURL did not record state/nonce")
	}
	// The auth request must carry PKCE.
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") == "" {
		t.Error("auth URL missing PKCE challenge")
	}
	return state, nonce
}

func TestOIDCExchangeHappyPath(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t, OIDCParams{AllowedDomains: []string{"example.com"}, DefaultRole: RoleViewer})
	state, nonce := stateNonce(t, p)
	f.claims = f.baseClaims(nonce)

	claims, err := p.Exchange(context.Background(), state, "code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Subject != "sub-42" || claims.Email != "alice@example.com" || !claims.EmailVerified {
		t.Fatalf("claims wrong: %+v", claims)
	}
	role, err := p.Authorize(claims)
	if err != nil || role != RoleViewer {
		t.Errorf("authorize: role=%v err=%v", role, err)
	}
}

func TestOIDCExchangeRejects(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t, OIDCParams{AllowedDomains: []string{"example.com"}})

	// Nonce mismatch: token carries a different nonce than the one recorded.
	state, _ := stateNonce(t, p)
	f.claims = f.baseClaims("attacker-nonce")
	if _, err := p.Exchange(context.Background(), state, "code"); err == nil {
		t.Error("nonce mismatch must be rejected")
	}

	// Wrong audience: go-oidc verification must fail.
	state, nonce := stateNonce(t, p)
	c := f.baseClaims(nonce)
	c["aud"] = "someone-else"
	f.claims = c
	if _, err := p.Exchange(context.Background(), state, "code"); err == nil {
		t.Error("wrong audience must be rejected")
	}

	// Expired token.
	state, nonce = stateNonce(t, p)
	c = f.baseClaims(nonce)
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	f.claims = c
	if _, err := p.Exchange(context.Background(), state, "code"); err == nil {
		t.Error("expired token must be rejected")
	}

	// Unknown state (never issued / replayed): rejected before any crypto.
	f.claims = f.baseClaims("x")
	if _, err := p.Exchange(context.Background(), "never-issued", "code"); err == nil {
		t.Error("unknown state must be rejected")
	}
}

