package server

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
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/conf/configtest"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/tests"
)

// A real discovery/JWKS/code-exchange fixture exercises signature validation and
// PKCE, rather than stubbing the OIDC verifier used in production.
type oidcTestProvider struct {
	server                          *httptest.Server
	key                             *rsa.PrivateKey
	nonce, challenge, redirect      string
	subject, audience, issuer, azp  string
	badNonce, badSignature, expired bool
	exchanges                       int
	lastIDToken                     string
}

func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &oidcTestProvider{key: key, subject: "PocketID-Subject", audience: "navidrome"}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}

func (p *oidcTestProvider) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL,
			"authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token",
			"jwks_uri": p.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/keys":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
		}}})
	case "/token":
		p.exchanges++
		_ = r.ParseForm()
		challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "valid-code" || r.Form.Get("redirect_uri") != p.redirect ||
			base64.RawURLEncoding.EncodeToString(challenge[:]) != p.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		nonce, issuer, expiry := p.nonce, p.server.URL, time.Now().Add(time.Minute)
		if p.badNonce {
			nonce = "wrong-nonce"
		}
		if p.issuer != "" {
			issuer = p.issuer
		}
		if p.expired {
			expiry = time.Now().Add(-time.Hour)
		}
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`))
		claims, _ := json.Marshal(map[string]any{"iss": issuer, "aud": p.audience, "sub": p.subject,
			"iat": time.Now().Unix(), "exp": expiry.Unix(), "nonce": nonce, "azp": p.azp})
		unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(unsigned))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
		if p.badSignature {
			sig[0] ^= 1
		}
		p.lastIDToken = unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-access-token", "token_type": "Bearer",
			"id_token": p.lastIDToken})
	}
}

func setupOIDC(t *testing.T) (*oidcLogin, *oidcTestProvider, *model.User) {
	t.Helper()
	t.Cleanup(configtest.SetupConfig())
	p := newOIDCTestProvider(t)
	conf.Server.BasePath = "/music"
	conf.Server.SessionTimeout = 24 * time.Hour
	conf.Server.OIDC.Enabled = true
	conf.Server.OIDC.IssuerURL = p.server.URL
	conf.Server.OIDC.ClientID = "navidrome"
	conf.Server.OIDC.RedirectURL = "https://music.example/music/auth/oidc/callback"
	conf.Server.OIDC.MaxSessionDuration = time.Hour
	conf.Server.OIDC.Accounts = []conf.OIDCAccount{{Subject: p.subject, UserID: "existing-user"}}
	ds := &tests.MockDataStore{}
	auth.Init(ds)
	user := &model.User{ID: "existing-user", UserName: "alice", Name: "Existing Name", IsAdmin: true, NewPassword: "local-password"}
	if err := ds.User(context.Background()).Put(user); err != nil {
		t.Fatal(err)
	}
	return newOIDCLogin(ds), p, user
}

func startOIDC(t *testing.T, o *oidcLogin, p *oidcTestProvider) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	o.start(w, httptest.NewRequest(http.MethodGet, "/music/auth/oidc/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("scope") != "openid" {
		t.Fatalf("invalid authorization request: %s", u)
	}
	p.nonce, p.challenge, p.redirect = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.Name != "__Host-"+oidcCookie || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe transaction cookie")
	}
	return cookie, q.Get("state")
}

func callbackOIDC(o *oidcLogin, cookie *http.Cookie, state string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/music/auth/oidc/callback?code=valid-code&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	o.callback(w, r)
	return w
}

func sessionOIDC(o *oidcLogin, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/music/auth/oidc/session", strings.NewReader("{}"))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	o.session(w, r)
	return w
}

func TestOIDCLogin(t *testing.T) {
	o, p, user := setupOIDC(t)
	cookie, state := startOIDC(t, o, p)
	w := callbackOIDC(o, cookie, state)
	if w.Header().Get("Location") != "/music/app/#/login?oidc=complete" || strings.Contains(w.Header().Get("Location"), "token") {
		t.Fatalf("callback: %d %s", w.Code, w.Header().Get("Location"))
	}
	if retry := callbackOIDC(o, cookie, state); !strings.HasSuffix(retry.Header().Get("Location"), "oidc=failed") || p.exchanges != 1 {
		t.Fatal("authorization transaction was replayable")
	}
	handoff := w.Result().Cookies()[0]
	if bad := sessionOIDC(o, handoff, "https://evil.example"); bad.Code != http.StatusForbidden {
		t.Fatal("cross-origin handoff accepted")
	}
	session := sessionOIDC(o, handoff, "https://music.example")
	if session.Code != http.StatusOK {
		t.Fatalf("session: %d %s", session.Code, session.Body.String())
	}
	var payload map[string]any
	_ = json.Unmarshal(session.Body.Bytes(), &payload)
	claims, err := auth.Validate(payload["token"].(string))
	if err != nil || claims.UserID != user.ID || !claims.IsAdmin || claims.Subject != "alice" || claims.SessionExpiresAt.IsZero() {
		t.Fatalf("invalid Navidrome session: %+v, %v", claims, err)
	}
	if user.Name != "Existing Name" || user.Password != "local-password" || user.AuthType != "" {
		t.Fatal("OIDC modified the linked account")
	}
	if strings.Contains(session.Body.String(), "provider-access-token") {
		t.Fatal("provider token exposed to browser")
	}
	if _, err := auth.Validate(p.lastIDToken); err == nil {
		t.Fatal("identity-provider token was accepted as a Navidrome session")
	}
	if replay := sessionOIDC(o, handoff, "https://music.example"); replay.Code != http.StatusUnauthorized {
		t.Fatal("handoff replay accepted")
	}
}

func TestOIDCRejectsInvalidLogin(t *testing.T) {
	for _, scenario := range []string{"missing browser cookie", "wrong state", "wrong nonce", "wrong audience", "wrong issuer", "expired token", "bad signature", "unlinked subject", "subject case mismatch", "wrong authorized party", "expired transaction", "deleted user"} {
		t.Run(scenario, func(t *testing.T) {
			o, p, user := setupOIDC(t)
			cookie, state := startOIDC(t, o, p)
			switch scenario {
			case "missing browser cookie":
				cookie = nil
			case "wrong state":
				state = "attacker-state"
			case "wrong nonce":
				p.badNonce = true
			case "wrong audience":
				p.audience = "another-client"
			case "wrong issuer":
				p.issuer = "https://another-issuer.example"
			case "expired token":
				p.expired = true
			case "bad signature":
				p.badSignature = true
			case "unlinked subject":
				p.subject = "unknown"
			case "subject case mismatch":
				p.subject = strings.ToLower(p.subject)
			case "wrong authorized party":
				p.azp = "another-client"
			case "expired transaction":
				tx := o.pending[cookie.Value]
				tx.expires = time.Now().Add(-time.Second)
				o.pending[cookie.Value] = tx
			case "deleted user":
				user.ID = "different-id"
			}
			w := callbackOIDC(o, cookie, state)
			if w.Header().Get("Location") != "/music/app/#/login?oidc=failed" {
				t.Fatalf("invalid identity accepted: %s", w.Header().Get("Location"))
			}
		})
	}
}

func TestOIDCHandoffRejectsCredentialChange(t *testing.T) {
	o, p, user := setupOIDC(t)
	cookie, state := startOIDC(t, o, p)
	w := callbackOIDC(o, cookie, state)
	user.TokenEpoch++
	if got := sessionOIDC(o, w.Result().Cookies()[0], "https://music.example"); got.Code != http.StatusUnauthorized {
		t.Fatal("session accepted after credentials were changed")
	}
}

func TestOIDCRateLimitDoesNotStrandAcceptedFlow(t *testing.T) {
	o, p, _ := setupOIDC(t)
	conf.Server.AuthRequestLimit = 1
	conf.Server.AuthWindowLength = time.Hour
	router := chi.NewRouter()
	o.mount(router)
	start := httptest.NewRecorder()
	router.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oidc/login", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d", start.Code)
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	q := u.Query()
	p.nonce, p.challenge, p.redirect = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")
	retry := httptest.NewRecorder()
	router.ServeHTTP(retry, httptest.NewRequest(http.MethodGet, "/oidc/login", nil))
	if retry.Code != http.StatusTooManyRequests {
		t.Fatal("authorization attempts were not rate-limited")
	}
	callback := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?code=valid-code&state="+q.Get("state"), nil)
	r.AddCookie(start.Result().Cookies()[0])
	router.ServeHTTP(callback, r)
	if !strings.HasSuffix(callback.Header().Get("Location"), "oidc=complete") {
		t.Fatal("accepted flow was blocked at callback")
	}
	session := httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/oidc/session", strings.NewReader("{}"))
	r.AddCookie(callback.Result().Cookies()[0])
	r.Header.Set("Origin", "https://music.example")
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(session, r)
	if session.Code != http.StatusOK || session.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("accepted flow was blocked at session handoff: %d", session.Code)
	}
}
