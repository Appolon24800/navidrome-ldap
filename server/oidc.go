package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"golang.org/x/oauth2"
)

const oidcCookie = "navidrome_oidc"
const oidcFlowTTL = 5 * time.Minute
const oidcHandoffTTL = time.Minute
const oidcMaxPending = 1024

type oidcTransaction struct {
	state, nonce, verifier string
	userID                 string
	epoch                  int
	expires                time.Time
	deadline               time.Time
}

// All provider credentials stay on the server. The browser holds only a random,
// short-lived transaction handle, bound to a single authorization attempt.
type oidcLogin struct {
	ds       model.DataStore
	client   *http.Client
	oauth    oauth2.Config
	issuer   string
	origin   string
	uiURL    string
	accounts map[string]string
	maxAge   time.Duration
	secure   bool

	providerMu sync.Mutex
	provider   *oidc.Provider
	mu         sync.Mutex
	pending    map[string]oidcTransaction
}

func newOIDCLogin(ds model.DataStore) *oidcLogin {
	o := conf.Server.OIDC
	redirect, _ := url.Parse(o.RedirectURL) // Validated when loading configuration.
	accounts := make(map[string]string, len(o.Accounts))
	for _, a := range o.Accounts {
		accounts[a.Subject] = a.UserID
	}
	return &oidcLogin{
		ds: ds, client: &http.Client{Timeout: 10 * time.Second},
		oauth: oauth2.Config{ClientID: o.ClientID, ClientSecret: o.ClientSecret,
			RedirectURL: o.RedirectURL, Scopes: []string{oidc.ScopeOpenID}},
		issuer: o.IssuerURL, origin: redirect.Scheme + "://" + strings.ToLower(redirect.Host), secure: redirect.Scheme == "https",
		uiURL:    path.Join(conf.Server.BasePath, consts.URLPathUI) + "/#/login",
		accounts: accounts, maxAge: o.MaxSessionDuration,
		pending: make(map[string]oidcTransaction),
	}
}

func (o *oidcLogin) mount(r chi.Router) {
	r.Route("/oidc", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Referrer-Policy", "no-referrer")
				next.ServeHTTP(w, r)
			})
		})
		if conf.Server.AuthRequestLimit > 0 {
			// Limit authorization attempts, without stranding an accepted flow at
			// its callback or cookie exchange when another login shares this IP.
			r.With(ClientIPRateLimiter(conf.Server.AuthRequestLimit, conf.Server.AuthWindowLength)).Get("/login", o.start)
		} else {
			r.Get("/login", o.start)
		}
		r.Get("/callback", o.callback)
		r.Post("/session", o.session)
	})
}

func (o *oidcLogin) discover(ctx context.Context) (*oidc.Provider, error) {
	o.providerMu.Lock()
	defer o.providerMu.Unlock()
	if o.provider == nil {
		p, err := oidc.NewProvider(context.WithValue(ctx, oauth2.HTTPClient, o.client), o.issuer)
		if err != nil {
			return nil, err
		}
		// A discovery response must not downgrade an HTTPS issuer's token exchange.
		var metadata struct {
			JWKSURL string `json:"jwks_uri"`
		}
		if err := p.Claims(&metadata); err != nil {
			return nil, err
		}
		for _, endpoint := range []string{p.Endpoint().AuthURL, p.Endpoint().TokenURL, metadata.JWKSURL} {
			u, err := url.Parse(endpoint)
			if err != nil || u.Host == "" || (strings.HasPrefix(o.issuer, "https://") && u.Scheme != "https") {
				return nil, errors.New("invalid OIDC endpoint")
			}
		}
		o.provider = p
	}
	return o.provider, nil
}

func (o *oidcLogin) cookie(w http.ResponseWriter, value string, maxAge int) {
	cookiePath := path.Join(conf.Server.BasePath, "/auth/oidc")
	if o.secure {
		// __Host- prohibits Domain cookies, including cookie injection from a
		// sibling subdomain. Browsers require Path=/ for this prefix.
		cookiePath = "/"
	}
	http.SetCookie(w, &http.Cookie{Name: o.cookieName(), Value: value,
		Path: cookiePath, HttpOnly: true,
		Secure:   o.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (o *oidcLogin) cookieName() string {
	if o.secure {
		return "__Host-" + oidcCookie
	}
	return oidcCookie
}

func (o *oidcLogin) remember(value oidcTransaction) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for key, tx := range o.pending {
		if !time.Now().Before(tx.expires) {
			delete(o.pending, key)
		}
	}
	if len(o.pending) >= oidcMaxPending {
		return "", false
	}
	key := oauth2.GenerateVerifier()
	o.pending[key] = value
	return key, true
}

func (o *oidcLogin) take(r *http.Request) (oidcTransaction, bool) {
	cookie, err := r.Cookie(o.cookieName())
	if err != nil {
		return oidcTransaction{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	tx, ok := o.pending[cookie.Value]
	delete(o.pending, cookie.Value)
	return tx, ok && time.Now().Before(tx.expires)
}

func (o *oidcLogin) fail(w http.ResponseWriter, r *http.Request) {
	o.cookie(w, "", -1)
	// Never put provider messages, codes or credentials into the UI URL.
	http.Redirect(w, r, o.uiURL+"?oidc=failed", http.StatusSeeOther)
}

func (o *oidcLogin) start(w http.ResponseWriter, r *http.Request) {
	p, err := o.discover(r.Context())
	if err != nil {
		log.Warn(r, "OIDC provider discovery unavailable")
		o.fail(w, r)
		return
	}
	tx := oidcTransaction{state: oauth2.GenerateVerifier(), nonce: oauth2.GenerateVerifier(),
		verifier: oauth2.GenerateVerifier(), expires: time.Now().Add(oidcFlowTTL)}
	key, ok := o.remember(tx)
	if !ok {
		http.Error(w, "Too many sign-in attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}
	o.cookie(w, key, int(oidcFlowTTL.Seconds()))
	cfg := o.oauth
	cfg.Endpoint = p.Endpoint()
	http.Redirect(w, r, cfg.AuthCodeURL(tx.state, oidc.Nonce(tx.nonce), oauth2.S256ChallengeOption(tx.verifier)), http.StatusFound)
}

func (o *oidcLogin) callback(w http.ResponseWriter, r *http.Request) {
	tx, ok := o.take(r)
	if !ok || tx.userID != "" || r.URL.Query().Get("error") != "" ||
		subtle.ConstantTimeCompare([]byte(tx.state), []byte(r.URL.Query().Get("state"))) != 1 || r.URL.Query().Get("code") == "" {
		o.fail(w, r)
		return
	}
	p, err := o.discover(r.Context())
	if err != nil {
		o.fail(w, r)
		return
	}
	cfg := o.oauth
	cfg.Endpoint = p.Endpoint()
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, o.client)
	token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(tx.verifier))
	if err != nil {
		log.Warn(r, "OIDC code exchange failed")
		o.fail(w, r)
		return
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil || idToken.Subject == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(tx.nonce)) != 1 {
		o.fail(w, r)
		return
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil ||
		(len(idToken.Audience) > 1 && claims.AuthorizedParty == "") ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != cfg.ClientID) {
		o.fail(w, r)
		return
	}
	userID := o.accounts[idToken.Subject]
	if userID == "" {
		log.Warn(r, "OIDC identity has no configured account link")
		o.fail(w, r)
		return
	}
	user, err := o.ds.User(r.Context()).Get(userID)
	if err != nil {
		o.fail(w, r)
		return
	}
	// Only an opaque, one-use handle crosses the redirect. The ID/access tokens
	// are discarded; existing account attributes and credentials are untouched.
	key, ok := o.remember(oidcTransaction{userID: user.ID, epoch: user.TokenEpoch,
		expires: time.Now().Add(oidcHandoffTTL), deadline: time.Now().Add(o.maxAge)})
	if !ok {
		o.fail(w, r)
		return
	}
	o.cookie(w, key, int(oidcHandoffTTL.Seconds()))
	http.Redirect(w, r, o.uiURL+"?oidc=complete", http.StatusSeeOther)
}

func (o *oidcLogin) session(w http.ResponseWriter, r *http.Request) {
	// Require same-origin JSON before touching the one-use handoff. This endpoint
	// must never be usable by a cross-origin form, including a same-site sibling.
	if r.Header.Get("Origin") != o.origin || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "Invalid sign-in request", http.StatusForbidden)
		return
	}
	tx, ok := o.take(r)
	o.cookie(w, "", -1)
	if !ok || tx.userID == "" {
		http.Error(w, "Sign-in expired. Please try again.", http.StatusUnauthorized)
		return
	}
	user, err := o.ds.User(r.Context()).Get(tx.userID)
	if err != nil || user.TokenEpoch != tx.epoch {
		http.Error(w, "Sign-in expired. Please try again.", http.StatusUnauthorized)
		return
	}
	token, err := auth.CreateTokenWithDeadline(user, tx.deadline)
	if err != nil {
		http.Error(w, "Could not create session", http.StatusInternalServerError)
		return
	}
	if err := o.ds.User(r.Context()).UpdateLastLoginAt(user.ID); err != nil {
		log.Warn(r, "Could not update OIDC last login time")
	}
	payload := buildAuthPayload(user, "")
	payload["token"] = token
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
