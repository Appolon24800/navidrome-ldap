// fakeidp is a minimal OpenID Connect provider used only to drive the Navidrome
// OIDC login end to end without a browser. The user is chosen with a "user"
// query parameter on the authorize request.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

const (
	clientID  = "navidrome"
	idpSecret = "navidrome-client-secret"
)

var (
	listen   = setting("FAKEIDP_LISTEN", "127.0.0.1:5556")
	redirect = setting("FAKEIDP_REDIRECT", "http://127.0.0.1:4535/music/auth/oidc/callback")
)

func setting(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

var (
	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes = map[string]code{}
	users = map[string]map[string]any{
		"alice":        {"sub": "subject-alice", "name": "Alice Liddell", "email": "alice@example.org"},
		"new-listener": {"sub": "subject-new-listener", "name": "New Listener", "email": "new@example.org"},
	}
)

type code struct {
	challenge, username, subject, name, email, nonce string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func issuer() string { return "http://" + listen }

func main() {
	var err error
	if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"issuer": issuer(),
			"authorization_endpoint": issuer() + "/authorize", "token_endpoint": issuer() + "/token",
			"jwks_uri": issuer() + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"},
			"code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		e := 65537
		writeJSON(w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "fake", "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64([]byte{byte(e >> 16), byte(e >> 8), byte(e)})}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		user := users[q.Get("user")]
		if user == nil || q.Get("client_id") != clientID || q.Get("redirect_uri") != redirect ||
			q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
			http.Error(w, "invalid authorization request: "+r.URL.String(), http.StatusBadRequest)
			return
		}
		c := url.Values{}
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		id := b64(buf)
		mu.Lock()
		codes[id] = code{challenge: q.Get("code_challenge"), username: q.Get("user"), subject: user["sub"].(string),
			name: user["name"].(string), email: user["email"].(string), nonce: q.Get("nonce")}
		mu.Unlock()
		c.Set("code", id)
		c.Set("state", q.Get("state"))
		http.Redirect(w, r, redirect+"?"+c.Encode(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// Public client: the secret is accepted when sent, and its absence is allowed.
		if r.Form.Get("client_id") != "" && r.Form.Get("client_id") != clientID ||
			r.Form.Get("client_secret") != "" && r.Form.Get("client_secret") != idpSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		mu.Lock()
		c, ok := codes[r.Form.Get("code")]
		delete(codes, r.Form.Get("code"))
		mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || r.Form.Get("redirect_uri") != redirect || b64(sum[:]) != c.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		now := time.Now()
		header := b64([]byte(`{"alg":"RS256","kid":"fake","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{"iss": issuer(), "aud": clientID, "sub": c.subject,
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": c.nonce, "azp": clientID,
			"preferred_username": c.username, "name": c.name, "email": c.email})
		unsigned := header + "." + b64(claims)
		digest := sha256.Sum256([]byte(unsigned))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"access_token": "fake-access-token", "token_type": "Bearer",
			"expires_in": 3600, "id_token": unsigned + "." + b64(sig)})
	})
	log.Printf("fake IdP listening on http://%s", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}
