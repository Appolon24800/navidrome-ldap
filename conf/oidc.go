package conf

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
)

// Only OIDC account slices accept JSON here. Other list settings retain their
// normal comma-separated syntax, while subjects inside JSON remain exact values.
func decodeOIDCAccounts(from, to reflect.Type, value any) (any, error) {
	if from != reflect.TypeOf("") || to != reflect.TypeOf([]OIDCAccount{}) {
		return value, nil
	}
	raw := strings.TrimSpace(value.(string))
	if raw == "" {
		return []OIDCAccount{}, nil
	}
	var accounts []OIDCAccount
	if !strings.HasPrefix(raw, "[") || json.Unmarshal([]byte(raw), &accounts) != nil {
		return nil, fmt.Errorf("OIDC.Accounts must be a JSON array of objects with Subject and UserID fields")
	}
	return accounts, nil
}

// OIDC uses administrator-configured URLs, never request Host or forwarded headers.
// HTTP is permitted only on loopback addresses for local development.
func validateOIDC() error {
	o := Server.OIDC
	if !o.Enabled {
		if o.AutoRedirect {
			return fmt.Errorf("OIDC.AutoRedirect requires OIDC.Enabled=true")
		}
		return nil
	}
	if strings.TrimSpace(o.ClientID) == "" || strings.TrimSpace(o.DisplayName) == "" {
		return fmt.Errorf("OIDC.ClientID and OIDC.DisplayName are required")
	}
	for name, value := range map[string]string{"IssuerURL": o.IssuerURL, "RedirectURL": o.RedirectURL} {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return fmt.Errorf("OIDC.%s must be an absolute URL without credentials, query or fragment", name)
		}
		ip := net.ParseIP(u.Hostname())
		loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
		if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
			return fmt.Errorf("OIDC.%s requires HTTPS (HTTP is allowed only on loopback)", name)
		}
		if name == "RedirectURL" {
			base, err := url.Parse(Server.BaseURL)
			if err != nil || u.Path != strings.TrimRight(base.Path, "/")+"/auth/oidc/callback" {
				return fmt.Errorf("OIDC.RedirectURL must end with the configured base path followed by /auth/oidc/callback")
			}
		}
	}
	if o.MaxSessionDuration <= 0 {
		return fmt.Errorf("OIDC.MaxSessionDuration must be positive")
	}
	seen := map[string]bool{}
	for _, account := range o.Accounts {
		if account.Subject == "" || account.UserID == "" || seen[account.Subject] {
			return fmt.Errorf("OIDC.Accounts requires a unique, non-empty Subject and a non-empty UserID for each account")
		}
		seen[account.Subject] = true
	}
	return nil
}
