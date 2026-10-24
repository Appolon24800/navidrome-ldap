package conf

import (
	"testing"
	"time"
)

func TestOIDCConfiguration(t *testing.T) {
	t.Cleanup(SnapshotConfig())
	Server.BaseURL = "https://music.example/music"
	valid := oidcOptions{Enabled: true, DisplayName: "PocketID", ClientID: "navidrome",
		IssuerURL: "https://id.example", RedirectURL: "https://music.example/music/auth/oidc/callback",
		MaxSessionDuration: time.Hour, Accounts: []OIDCAccount{{Subject: "CaseSensitive", UserID: "existing-user"}}}
	for _, test := range []struct {
		name   string
		change func(*oidcOptions)
		valid  bool
	}{
		{"valid", func(o *oidcOptions) {}, true},
		{"disabled", func(o *oidcOptions) { *o = oidcOptions{} }, true},
		{"automatic redirect", func(o *oidcOptions) { o.AutoRedirect = true }, true},
		{"redirect requires OIDC", func(o *oidcOptions) { o.Enabled = false; o.AutoRedirect = true }, false},
		{"loopback development", func(o *oidcOptions) { o.IssuerURL = "http://127.0.0.1:5556" }, true},
		{"insecure issuer", func(o *oidcOptions) { o.IssuerURL = "http://id.example" }, false},
		{"insecure callback", func(o *oidcOptions) { o.RedirectURL = "http://music.example/music/auth/oidc/callback" }, false},
		{"relative callback", func(o *oidcOptions) { o.RedirectURL = "/auth/oidc/callback" }, false},
		{"callback query", func(o *oidcOptions) { o.RedirectURL += "?next=evil" }, false},
		{"wrong base path", func(o *oidcOptions) { o.RedirectURL = "https://music.example/auth/oidc/callback" }, false},
		{"credentials in URL", func(o *oidcOptions) { o.IssuerURL = "https://user:password@id.example" }, false},
		{"no client", func(o *oidcOptions) { o.ClientID = "" }, false},
		{"no deadline", func(o *oidcOptions) { o.MaxSessionDuration = 0 }, false},
		{"duplicate subject", func(o *oidcOptions) { o.Accounts = append(o.Accounts, o.Accounts[0]) }, false},
		{"missing user", func(o *oidcOptions) { o.Accounts = []OIDCAccount{{Subject: "someone"}} }, false},
		{"case sensitive subjects", func(o *oidcOptions) {
			o.Accounts = []OIDCAccount{{Subject: "ABC", UserID: "a"}, {Subject: "abc", UserID: "b"}}
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			Server.OIDC = valid
			Server.OIDC.Accounts = append([]OIDCAccount(nil), valid.Accounts...)
			test.change(&Server.OIDC)
			if err := validateOIDC(); (err == nil) != test.valid {
				t.Fatalf("validation error: %v (valid=%v)", err, test.valid)
			}
		})
	}
}
