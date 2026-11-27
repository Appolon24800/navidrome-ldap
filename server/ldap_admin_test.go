package server

import (
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("LDAP admin filter construction", func() {
	// setAdminPolicy configures the admin lookup. The suite restores the configuration after each spec.
	setAdminPolicy := func(adminGroup, adminFilter string) {
		conf.Update(func(c *conf.Options) {
			c.LDAP.SearchFilter = "(uid=%s)"
			c.LDAP.AdminGroup = adminGroup
			c.LDAP.AdminFilter = adminFilter
		})
	}

	Describe("adminCheckEnabled", func() {
		It("is false when neither AdminGroup nor AdminFilter is set", func() {
			setAdminPolicy("", "")

			Expect(adminCheckEnabled()).To(BeFalse())
		})

		It("is true when AdminGroup is set", func() {
			setAdminPolicy("cn=admins,dc=example,dc=org", "")

			Expect(adminCheckEnabled()).To(BeTrue())
		})

		It("is true when AdminFilter is set", func() {
			setAdminPolicy("", "(memberOf=cn=admins,dc=example,dc=org)")

			Expect(adminCheckEnabled()).To(BeTrue())
		})
	})

	Describe("buildAdminFilter", func() {
		It("returns empty when no admin policy is configured", func() {
			setAdminPolicy("", "")

			Expect(buildAdminFilter("alice")).To(Equal(""))
		})

		It("uses memberOf=AdminGroup combined with the user's SearchFilter", func() {
			setAdminPolicy("cn=admins,dc=example,dc=org", "")

			Expect(buildAdminFilter("alice")).To(Equal(
				"(&(memberOf=cn=admins,dc=example,dc=org)(uid=alice))",
			))
		})

		It("escapes filter-special characters in the username", func() {
			setAdminPolicy("cn=admins,dc=example,dc=org", "")

			got := buildAdminFilter("a(lice)")
			Expect(got).To(ContainSubstring(`uid=a\28lice\29`))
		})

		It("escapes filter-special characters in the AdminGroup DN", func() {
			setAdminPolicy(`cn=admins(test),dc=example,dc=org`, "")

			got := buildAdminFilter("alice")
			Expect(got).To(ContainSubstring(`memberOf=cn=admins\28test\29,dc=example,dc=org`))
		})

		It("uses AdminFilter formatted with the escaped username when AdminGroup is unset", func() {
			setAdminPolicy("", "(&(memberOf=cn=ops,dc=example,dc=org)(uid=%s))")

			Expect(buildAdminFilter("bob")).To(Equal(
				"(&(memberOf=cn=ops,dc=example,dc=org)(uid=bob))",
			))
		})

		It("prefers AdminGroup over AdminFilter when both are set", func() {
			setAdminPolicy("cn=admins,dc=example,dc=org", "(uid=%s)")

			Expect(buildAdminFilter("alice")).To(ContainSubstring("memberOf=cn=admins"))
		})
	})

	Describe("applyLDAPAdminResult", func() {
		It("preserves IsAdmin when result is nil (lookup skipped or transient error)", func() {
			adminUser := &model.User{IsAdmin: true}
			applyLDAPAdminResult(adminUser, nil)
			Expect(adminUser.IsAdmin).To(BeTrue())

			regularUser := &model.User{IsAdmin: false}
			applyLDAPAdminResult(regularUser, nil)
			Expect(regularUser.IsAdmin).To(BeFalse())
		})

		It("promotes the user when result points to true", func() {
			u := &model.User{IsAdmin: false}
			result := true
			applyLDAPAdminResult(u, &result)
			Expect(u.IsAdmin).To(BeTrue())
		})

		It("demotes the user when result points to false", func() {
			u := &model.User{IsAdmin: true}
			result := false
			applyLDAPAdminResult(u, &result)
			Expect(u.IsAdmin).To(BeFalse())
		})

		It("is a no-op when the result matches the existing value", func() {
			u := &model.User{IsAdmin: true}
			result := true
			applyLDAPAdminResult(u, &result)
			Expect(u.IsAdmin).To(BeTrue())
		})
	})
})
