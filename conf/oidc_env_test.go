package conf_test

import (
	"github.com/navidrome/navidrome/conf"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/viper"
)

var _ = Describe("OIDC environment configuration", func() {
	BeforeEach(func() {
		viper.Reset()
		conf.SetViperDefaults()
		viper.SetDefault("datafolder", GinkgoT().TempDir())
		viper.SetDefault("loglevel", "error")
		conf.ResetConf()
		DeferCleanup(conf.PanicOnLogFatal())

		t := GinkgoT()
		t.Setenv("ND_CONFIGFILE", "")
		t.Setenv("ND_OIDC_ENABLED", "true")
		t.Setenv("ND_OIDC_AUTOREDIRECT", "true")
		t.Setenv("ND_OIDC_ISSUERURL", "https://id.example.com")
		t.Setenv("ND_OIDC_CLIENTID", "navidrome-client")
		t.Setenv("ND_OIDC_CLIENTSECRET", "test-client-secret")
		t.Setenv("ND_OIDC_REDIRECTURL", "https://music.example.com/auth/oidc/callback")
		conf.InitConfig("", true)
	})

	It("loads a complete setup without a configuration file or per-user mappings", func() {
		conf.Load(true)
		Expect(conf.Server().ConfigFile).To(BeEmpty())
		Expect(conf.Server().OIDC.Enabled).To(BeTrue())
		Expect(conf.Server().OIDC.AutoRedirect).To(BeTrue())
		Expect(conf.Server().OIDC.ClientID).To(Equal("navidrome-client"))
		Expect(conf.Server().OIDC.ClientSecret).To(Equal("test-client-secret"))
	})
})
