package conf_test

import (
	"github.com/navidrome/navidrome/conf"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/viper"
)

var _ = Describe("LDAP options", func() {
	BeforeEach(func() {
		viper.Reset()
		conf.SetViperDefaults()
		viper.SetDefault("datafolder", GinkgoT().TempDir())
		viper.SetDefault("loglevel", "error")
		conf.ResetConf()
		DeferCleanup(conf.PanicOnLogFatal())
	})

	Describe("validateLDAPAdminFilter", func() {
		// The validators are methods, so they run on a copy of the published options.
		setAdminFilter := func(filter string) *conf.Options {
			conf.Update(func(c *conf.Options) { c.LDAP.AdminFilter = filter })
			options := conf.Server()
			return &options
		}

		It("accepts an empty AdminFilter (feature off)", func() {
			Expect(conf.ValidateLDAPAdminFilter(setAdminFilter(""))).To(Succeed())
		})

		It("accepts an AdminFilter that contains %s", func() {
			options := setAdminFilter("(&(memberOf=cn=admins,dc=example,dc=org)(uid=%s))")
			Expect(conf.ValidateLDAPAdminFilter(options)).To(Succeed())
		})

		It("rejects a non-empty AdminFilter that is missing %s", func() {
			err := conf.ValidateLDAPAdminFilter(setAdminFilter("(memberOf=cn=admins,dc=example,dc=org)"))
			Expect(err).To(MatchError(ContainSubstring("ND_LDAP_ADMINFILTER")))
			Expect(err).To(MatchError(ContainSubstring("%s")))
		})

		It("fails Load when AdminFilter is missing %s", func() {
			viper.Set("ldap.adminfilter", "(memberOf=cn=admins,dc=example,dc=org)")
			Expect(func() {
				conf.Load(true)
			}).To(PanicWith(ContainSubstring("ND_LDAP_ADMINFILTER")))
		})
	})
})
