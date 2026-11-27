package conf

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type ldapOptions struct {
	Host         string
	BindDN       string
	BindPassword string
	Base         string
	SearchFilter string
	Mail         string
	Name         string

	// LivenessSchedule, when non-empty, schedules a background sweep that
	// reconciles each LDAP-backed user against the directory and revokes
	// the app passwords of users that no longer match. Accepts any
	// scheduler spec (a duration like "5m" or a full crontab). Empty
	// disables the sweep.
	LivenessSchedule string
	// DisabledFilter is an optional LDAP filter clause that, when ANDed
	// with the per-user SearchFilter, identifies disabled directory
	// entries (e.g. AD's `(userAccountControl:1.2.840.113556.1.4.803:=2)`
	// or a custom `(loginShell=/sbin/nologin)`). When set, an entry that
	// still exists but matches this filter is treated the same as one
	// that has been removed. The filter applies to the user's own
	// attributes — it is NOT formatted with the username.
	DisabledFilter string

	// AdminGroup is the DN of an LDAP group whose members should be
	// granted Navidrome admin. When set, IsAdmin is recomputed against
	// the directory on every LDAP login and on every liveness sweep —
	// becoming the single source of truth for admin membership. The
	// search uses `(&(memberOf=<AdminGroup>)<SearchFilter for user>)`.
	// Mutually exclusive with AdminFilter (AdminGroup wins if both set).
	AdminGroup string
	// AdminFilter is an alternative to AdminGroup for directories that
	// don't expose `memberOf` or for more complex admin-membership rules.
	// The filter MUST contain `%s`, which is replaced by the escaped
	// username, mirroring SearchFilter. Example:
	// `(&(memberOf=cn=nd-admins,ou=groups,dc=example,dc=org)(uid=%s))`.
	AdminFilter string
}

func (s *Options) validateLDAPLivenessSchedule() error {
	if s.LDAP.LivenessSchedule == "0" || s.LDAP.LivenessSchedule == "" {
		s.LDAP.LivenessSchedule = ""
		return nil
	}
	var err error
	s.LDAP.LivenessSchedule, err = validateSchedule(s.LDAP.LivenessSchedule, "LDAP.LivenessSchedule")
	return err
}

// validateLDAPAdminFilter refuses to start when LDAP.AdminFilter is
// configured but missing the `%s` placeholder. Without it, fmt.Sprintf
// silently produces a malformed filter (e.g.
// `(memberOf=cn=admins,...)%!(EXTRA string=alice)`) which only surfaces
// at runtime as repeated "LDAP admin lookup failed" warnings — the kind
// of silent breakage that's better caught at startup.
func (s *Options) validateLDAPAdminFilter() error {
	if af := s.LDAP.AdminFilter; af != "" && !strings.Contains(af, "%s") {
		return fmt.Errorf("ND_LDAP_ADMINFILTER must contain %%s placeholder for the username")
	}
	return nil
}

// ldapDefaults is called from setViperDefaults. The LDAP options, their
// validation and their defaults live in this fork-owned file so that upstream
// edits to configuration.go merge without conflicts.
func ldapDefaults() {
	viper.SetDefault("ldap.host", "")
	viper.SetDefault("ldap.binddn", "")
	viper.SetDefault("ldap.bindpassword", "")
	viper.SetDefault("ldap.base", "")
	viper.SetDefault("ldap.searchfilter", "(&(objectClass=inetOrgPerson)(uid=%s))")
	viper.SetDefault("ldap.mail", "mail")
	viper.SetDefault("ldap.name", "cn")
}
