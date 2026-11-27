package conf

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type oidcOptions struct {
	Enabled            bool
	AutoRedirect       bool
	DisplayName        string
	IssuerURL          string
	ClientID           string
	ClientSecret       string
	RedirectURL        string
	MaxSessionDuration time.Duration
}

// validateOIDC only accepts administrator-configured URLs, and HTTPS unless the host is loopback.
func (s *Options) validateOIDC() error {
	o := s.OIDC
	if !o.Enabled {
		if o.AutoRedirect {
			return errors.New("OIDC.AutoRedirect requires OIDC.Enabled=true")
		}
		return nil
	}
	if strings.TrimSpace(o.ClientID) == "" || strings.TrimSpace(o.DisplayName) == "" {
		return errors.New("OIDC.ClientID and OIDC.DisplayName are required")
	}
	for name, value := range map[string]string{"IssuerURL": o.IssuerURL, "RedirectURL": o.RedirectURL} {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return fmt.Errorf("OIDC.%s must be an absolute URL without credentials, query or fragment", name)
		}
		ip := net.ParseIP(u.Hostname())
		loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
		if u.Scheme != "https" && (!loopback || u.Scheme != "http") {
			return fmt.Errorf("OIDC.%s requires HTTPS (HTTP is allowed only on loopback)", name)
		}
		if name == "RedirectURL" {
			base, err := url.Parse(s.BaseURL)
			if err != nil || u.Path != strings.TrimRight(base.Path, "/")+"/auth/oidc/callback" {
				return errors.New("OIDC.RedirectURL must end with the configured base path followed by /auth/oidc/callback")
			}
		}
	}
	if o.MaxSessionDuration <= 0 {
		return errors.New("OIDC.MaxSessionDuration must be positive")
	}
	return nil
}

// oidcDefaults is called from setViperDefaults. The OIDC options, their
// validation and their defaults live in this fork-owned file so that upstream
// edits to configuration.go merge without conflicts.
func oidcDefaults() {
	viper.SetDefault("oidc.enabled", false)
	viper.SetDefault("oidc.autoredirect", false)
	viper.SetDefault("oidc.displayname", "PocketID")
	viper.SetDefault("oidc.issuerurl", "")
	viper.SetDefault("oidc.clientid", "")
	viper.SetDefault("oidc.clientsecret", "")
	viper.SetDefault("oidc.redirecturl", "")
	viper.SetDefault("oidc.maxsessionduration", 12*time.Hour)
}
