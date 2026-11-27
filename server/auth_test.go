package server

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/db"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/persistence"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

var _ = Describe("Auth", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = GinkgoT().Context()
	})

	Describe("User login", func() {
		var ds model.DataStore
		var req *http.Request
		var resp *httptest.ResponseRecorder

		BeforeEach(func() {
			ds = persistence.New(db.Db())
			auth.Init(ds)
		})

		Describe("createAdmin", func() {
			var createdAt time.Time
			BeforeEach(func() {
				req = httptest.NewRequest(http.MethodPost, "/createAdmin", strings.NewReader(`{"username":"johndoe", "password":"secret"}`))
				resp = httptest.NewRecorder()
				createdAt = time.Now()
				createAdmin(ds)(resp, req)
			})

			It("creates an admin user with the specified password", func() {
				usr := ds.User()
				u, err := usr.FindByUsername(ctx, "johndoe")
				Expect(err).ToNot(HaveOccurred())
				Expect(u.Password).ToNot(BeEmpty())
				Expect(u.IsAdmin).To(BeTrue())
				Expect(*u.LastLoginAt).To(BeTemporally(">=", createdAt, time.Second))
			})

			It("returns the expected payload", func() {
				Expect(resp.Code).To(Equal(http.StatusOK))
				var parsed map[string]any
				Expect(json.Unmarshal(resp.Body.Bytes(), &parsed)).To(Succeed())
				Expect(parsed["isAdmin"]).To(BeTrue())
				Expect(parsed["username"]).To(Equal("johndoe"))
				Expect(parsed["name"]).To(Equal("Johndoe"))
				Expect(parsed["id"]).ToNot(BeEmpty())
				Expect(parsed["token"]).ToNot(BeEmpty())
			})
		})

		Describe("CreateFirstAdmin", func() {
			It("returns the error when the user cannot be saved", func() {
				failing := withUserErrors(ds, userErrors{put: errors.New("db is down")})
				_, err := auth.CreateFirstAdmin(ctx, failing, "johndoe", "secret", nil)
				Expect(err).To(MatchError(ContainSubstring("db is down")))
			})
		})

		Describe("createAdmin when a user already exists", func() {
			It("responds 403", func() {
				req = httptest.NewRequest(http.MethodPost, "/createAdmin", strings.NewReader(`{"username":"another", "password":"secret"}`))
				resp = httptest.NewRecorder()
				Expect(ds.User().Put(ctx, &model.User{UserName: "johndoe", NewPassword: "secret"})).To(Succeed())

				createAdmin(ds)(resp, req)

				Expect(resp.Code).To(Equal(http.StatusForbidden))
				Expect(resp.Body.String()).To(ContainSubstring("Cannot create another first admin"))
			})
		})

		Describe("createAdmin when the user cannot be stored", func() {
			It("responds 500 rather than falling through to login", func() {
				failing := withUserErrors(ds, userErrors{put: errors.New("db is down")})
				req = httptest.NewRequest(http.MethodPost, "/createAdmin", strings.NewReader(`{"username":"johndoe", "password":"secret"}`))
				resp = httptest.NewRecorder()

				createAdmin(failing)(resp, req)

				Expect(resp.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Describe("Login from HTTP headers", func() {
			const (
				trustedIpv4   = "192.168.0.42"
				untrustedIpv4 = "8.8.8.8"
				trustedIpv6   = "2001:4860:4860:1234:5678:0000:4242:8888"
				untrustedIpv6 = "5005:0:3003"
			)

			fs := os.DirFS("tests/fixtures")

			BeforeEach(func() {
				usr := ds.User()
				Expect(usr.Put(ctx, &model.User{ID: "111", UserName: "janedoe", NewPassword: "abc123", Name: "Jane", IsAdmin: false})).To(Succeed())
				req = httptest.NewRequest(http.MethodGet, "/index.html", nil)
				req.Header.Add("Remote-User", "janedoe")
				resp = httptest.NewRecorder()
				conf.Update(func(c *conf.Options) {
					c.UILoginBackgroundURL = ""
					c.ExtAuth.TrustedSources = "192.168.0.0/16,2001:4860:4860::/48"
				})
			})

			It("sets auth data if IPv4 matches whitelist", func() {
				req = req.WithContext(request.WithReverseProxyIp(req.Context(), trustedIpv4))
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				parsed := config["auth"].(map[string]any)

				Expect(parsed["id"]).To(Equal("111"))
			})

			It("sets no auth data if IPv4 does not match whitelist", func() {
				req = req.WithContext(request.WithReverseProxyIp(req.Context(), untrustedIpv4))
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				Expect(config["auth"]).To(BeNil())
			})

			It("sets auth data if IPv6 matches whitelist", func() {
				req = req.WithContext(request.WithReverseProxyIp(req.Context(), trustedIpv6))
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				parsed := config["auth"].(map[string]any)

				Expect(parsed["id"]).To(Equal("111"))
			})

			It("sets no auth data if IPv6 does not match whitelist", func() {
				req = req.WithContext(request.WithReverseProxyIp(req.Context(), untrustedIpv6))
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				Expect(config["auth"]).To(BeNil())
			})

			It("creates user and sets auth data if user does not exist", func() {
				newUser := "NEW_USER_" + id.NewRandom()

				req = req.WithContext(request.WithReverseProxyIp(req.Context(), trustedIpv4))
				req.Header.Set("Remote-User", newUser)
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				parsed := config["auth"].(map[string]any)

				Expect(parsed["username"]).To(Equal(newUser))
			})

			It("sets auth data if user exists", func() {
				req = req.WithContext(request.WithReverseProxyIp(req.Context(), trustedIpv4))
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				parsed := config["auth"].(map[string]any)

				Expect(parsed["id"]).To(Equal("111"))
				Expect(parsed["isAdmin"]).To(BeFalse())
				Expect(parsed["name"]).To(Equal("Jane"))
				Expect(parsed["username"]).To(Equal("janedoe"))
				Expect(parsed["subsonicSalt"]).ToNot(BeEmpty())
				Expect(parsed["subsonicToken"]).ToNot(BeEmpty())
				salt := parsed["subsonicSalt"].(string)
				token := fmt.Sprintf("%x", md5.Sum([]byte("abc123"+salt)))
				Expect(parsed["subsonicToken"]).To(Equal(token))

				// Request Header authentication should not generate a JWT token
				Expect(parsed).ToNot(HaveKey("token"))
			})

			It("does not set auth data when listening on unix socket without whitelist", func() {
				conf.Update(func(c *conf.Options) {
					c.Address = "unix:/tmp/navidrome-test"
					c.ExtAuth.TrustedSources = ""
				})

				// No ReverseProxyIp in request context
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				Expect(config["auth"]).To(BeNil())
			})

			It("does not set auth data when listening on unix socket with incorrect whitelist", func() {
				conf.Update(func(c *conf.Options) { c.Address = "unix:/tmp/navidrome-test" })

				req = req.WithContext(request.WithReverseProxyIp(req.Context(), "@"))
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				Expect(config["auth"]).To(BeNil())
			})

			It("sets auth data when listening on unix socket with correct whitelist", func() {
				conf.Update(func(c *conf.Options) {
					c.Address = "unix:/tmp/navidrome-test"
					c.ExtAuth.TrustedSources = c.ExtAuth.TrustedSources + ",@"
				})

				req = req.WithContext(request.WithReverseProxyIp(req.Context(), "@"))
				serveIndex(ds, fs, nil)(resp, req)

				config := extractAppConfig(resp.Body.String())
				parsed := config["auth"].(map[string]any)

				Expect(parsed["id"]).To(Equal("111"))
			})
		})

		Describe("login", func() {
			BeforeEach(func() {
				req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"janedoe", "password":"abc123"}`))
				resp = httptest.NewRecorder()
			})

			It("fails if user does not exist", func() {
				login(ds)(resp, req)
				Expect(resp.Code).To(Equal(http.StatusUnauthorized))
			})

			It("rejects a request body larger than the limit", func() {
				body := `{"username":"janedoe", "password":"abc123", "padding":"` + strings.Repeat("x", MaxLoginBodySize) + `"}`
				req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
				LimitLoginBody(http.HandlerFunc(login(ds))).ServeHTTP(resp, req)
				Expect(resp.Code).To(Equal(http.StatusUnprocessableEntity))
			})

			It("logs in successfully if user exists", func() {
				usr := ds.User()
				Expect(usr.Put(ctx, &model.User{ID: "111", UserName: "janedoe", NewPassword: "abc123", Name: "Jane", IsAdmin: false})).To(Succeed())

				login(ds)(resp, req)
				Expect(resp.Code).To(Equal(http.StatusOK))

				var parsed map[string]any
				Expect(json.Unmarshal(resp.Body.Bytes(), &parsed)).To(Succeed())
				Expect(parsed["isAdmin"]).To(BeFalse())
				Expect(parsed["username"]).To(Equal("janedoe"))
				Expect(parsed["name"]).To(Equal("Jane"))
				Expect(parsed["id"]).ToNot(BeEmpty())
				Expect(parsed["token"]).ToNot(BeEmpty())
			})
		})
	})

	Describe("UsernameFromExtAuthHeader", func() {
		var hook *test.Hook
		var r *http.Request

		BeforeEach(func() {
			conf.Update(func(c *conf.Options) { c.ExtAuth.TrustedSources = "192.168.0.0/16" })
			prevLevel := log.CurrentLevel()
			l, h := test.NewNullLogger()
			hook = h
			prevLogger := log.SetDefaultLogger(l)
			log.SetLevel(log.LevelWarn)
			DeferCleanup(func() {
				log.SetDefaultLogger(prevLogger)
				log.SetLevel(prevLevel)
			})
			r = httptest.NewRequest(http.MethodGet, "/", nil)
		})

		warnings := func() []*logrus.Entry {
			var ws []*logrus.Entry
			for _, e := range hook.AllEntries() {
				if e.Level == logrus.WarnLevel {
					ws = append(ws, e)
				}
			}
			return ws
		}

		It("returns the username from a trusted source", func() {
			r.Header.Set("Remote-User", "janedoe")
			r = r.WithContext(request.WithReverseProxyIp(r.Context(), "192.168.0.42"))
			Expect(UsernameFromExtAuthHeader(r)).To(Equal("janedoe"))
			Expect(warnings()).To(BeEmpty())
		})

		It("does not warn when an untrusted source sends no user header", func() {
			r = r.WithContext(request.WithReverseProxyIp(r.Context(), "8.8.8.8"))
			Expect(UsernameFromExtAuthHeader(r)).To(BeEmpty())
			Expect(warnings()).To(BeEmpty())
		})

		It("warns when an untrusted source sends the user header", func() {
			r.Header.Set("Remote-User", "janedoe")
			r = r.WithContext(request.WithReverseProxyIp(r.Context(), "8.8.8.8"))
			Expect(UsernameFromExtAuthHeader(r)).To(BeEmpty())
			Expect(warnings()).To(HaveLen(1))
			Expect(warnings()[0].Message).To(Equal("IP is not whitelisted for external authentication"))
		})
	})

	Describe("tokenFromHeader", func() {
		It("returns the token when the Authorization header is set correctly", func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(consts.UIAuthorizationHeader, "Bearer testtoken")

			token := tokenFromHeader(req)
			Expect(token).To(Equal("testtoken"))
		})

		It("returns an empty string when the Authorization header is not set", func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			token := tokenFromHeader(req)
			Expect(token).To(BeEmpty())
		})

		It("returns an empty string when the Authorization header is not a Bearer token", func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(consts.UIAuthorizationHeader, "Basic testtoken")

			token := tokenFromHeader(req)
			Expect(token).To(BeEmpty())
		})

		It("returns an empty string when the Bearer token is too short", func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(consts.UIAuthorizationHeader, "Bearer")

			token := tokenFromHeader(req)
			Expect(token).To(BeEmpty())
		})
	})

	Describe("validateIPAgainstList", func() {
		Context("when provided with empty inputs", func() {
			It("should return false", func() {
				Expect(validateIPAgainstList("", "")).To(BeFalse())
				Expect(validateIPAgainstList("192.168.1.1", "")).To(BeFalse())
				Expect(validateIPAgainstList("", "192.168.0.0/16")).To(BeFalse())
			})
		})

		Context("when provided with invalid IP inputs", func() {
			It("should return false", func() {
				Expect(validateIPAgainstList("invalidIP", "192.168.0.0/16")).To(BeFalse())
			})
		})

		Context("when provided with valid inputs", func() {
			It("should return true when IP is in the list", func() {
				Expect(validateIPAgainstList("192.168.1.1", "192.168.0.0/16,10.0.0.0/8")).To(BeTrue())
				Expect(validateIPAgainstList("10.0.0.1", "192.168.0.0/16,10.0.0.0/8")).To(BeTrue())
			})

			It("should return false when IP is not in the list", func() {
				Expect(validateIPAgainstList("172.16.0.1", "192.168.0.0/16,10.0.0.0/8")).To(BeFalse())
			})
		})

		Context("when provided with invalid CIDR notation in the list", func() {
			It("should ignore invalid CIDR and return the correct result", func() {
				Expect(validateIPAgainstList("192.168.1.1", "192.168.0.0/16,invalidCIDR")).To(BeTrue())
				Expect(validateIPAgainstList("10.0.0.1", "invalidCIDR,10.0.0.0/8")).To(BeTrue())
				Expect(validateIPAgainstList("172.16.0.1", "192.168.0.0/16,invalidCIDR")).To(BeFalse())
			})
		})

		Context("when provided with IP:port format", func() {
			It("should handle IP:port format correctly", func() {
				Expect(validateIPAgainstList("192.168.1.1:8080", "192.168.0.0/16,10.0.0.0/8")).To(BeTrue())
				Expect(validateIPAgainstList("10.0.0.1:1234", "192.168.0.0/16,10.0.0.0/8")).To(BeTrue())
				Expect(validateIPAgainstList("172.16.0.1:9999", "192.168.0.0/16,10.0.0.0/8")).To(BeFalse())
			})
		})
	})

	Describe("handleLoginFromHeaders", func() {
		var ds model.DataStore
		var req *http.Request
		const trustedIP = "192.168.0.42"

		BeforeEach(func() {
			ds = persistence.New(db.Db())
			req = httptest.NewRequest(http.MethodGet, "/", nil)
			req = req.WithContext(request.WithReverseProxyIp(req.Context(), trustedIP))
			conf.Update(func(c *conf.Options) {
				c.ExtAuth.TrustedSources = "192.168.0.0/16"
				c.ExtAuth.UserHeader = "Remote-User"
			})
		})

		It("makes the first user an admin", func() {
			// No existing users
			req.Header.Set("Remote-User", "firstuser")
			result := handleLoginFromHeaders(ds, req)

			Expect(result).ToNot(BeNil())
			Expect(result["isAdmin"]).To(BeTrue())

			// Verify user was created as admin
			u, err := ds.User().FindByUsername(ctx, "firstuser")
			Expect(err).ToNot(HaveOccurred())
			Expect(u.IsAdmin).To(BeTrue())
		})

		It("does not make subsequent users admins", func() {
			// Create the first user
			Expect(ds.User().Put(ctx, &model.User{
				ID:       "existing-user-id",
				UserName: "existinguser",
				Name:     "Existing User",
				IsAdmin:  true,
			})).To(Succeed())

			// Try to create a second user via proxy header
			req.Header.Set("Remote-User", "seconduser")
			result := handleLoginFromHeaders(ds, req)

			Expect(result).ToNot(BeNil())
			Expect(result["isAdmin"]).To(BeFalse())

			// Verify user was created as non-admin
			u, err := ds.User().FindByUsername(ctx, "seconduser")
			Expect(err).ToNot(HaveOccurred())
			Expect(u.IsAdmin).To(BeFalse())
		})
	})

	Describe("LDAP Login", func() {
		var ds model.DataStore

		BeforeEach(func() {
			ds = persistence.New(db.Db())
		})

		It("validateLoginLDAP returns nil if Host is not configured", func() {
			conf.Update(func(c *conf.Options) { c.LDAP.Host = "" })
			u, err := validateLoginLDAP(ctx, ds.User(), "user", "pass")
			Expect(err).To(BeNil())
			Expect(u).To(BeNil())
		})

		It("validateLoginLDAP returns nil if connection fails", func() {
			conf.Update(func(c *conf.Options) { c.LDAP.Host = "ldap://invalid-host:389" })
			u, err := validateLoginLDAP(ctx, ds.User(), "user", "pass")
			Expect(err).To(BeNil())
			Expect(u).To(BeNil())
		})

		It("ValidateLogin proceeds to DB auth if LDAP is not configured", func() {
			conf.Update(func(c *conf.Options) { c.LDAP.Host = "" })
			userRepo := ds.User()
			_ = userRepo.Put(ctx, &model.User{ID: "1", UserName: "user", NewPassword: "password", Name: "User"})

			u, err := ValidateLogin(ctx, userRepo, "user", "password")
			Expect(err).To(BeNil())
			Expect(u).ToNot(BeNil())
			Expect(u.UserName).To(Equal("user"))
		})

		It("ValidateLogin proceeds to DB auth if LDAP fails", func() {
			conf.Update(func(c *conf.Options) { c.LDAP.Host = "ldap://invalid-host:389" })
			userRepo := ds.User()
			_ = userRepo.Put(ctx, &model.User{ID: "1", UserName: "user", NewPassword: "password", Name: "User"})

			u, err := ValidateLogin(ctx, userRepo, "user", "password")
			Expect(err).To(BeNil())
			Expect(u).ToNot(BeNil())
			Expect(u.UserName).To(Equal("user"))
		})

		// Defense-in-depth against the empty-password authentication bypass.
		// LDAP users have an empty `password` column (cleared by
		// ClearPassword on every login), so without these guards the local
		// fallback could accept an empty supplied password as a match
		// against the empty stored value during any LDAP outage.
		Context("empty-password floor", func() {
			It("rejects an empty password outright", func() {
				conf.Update(func(c *conf.Options) { c.LDAP.Host = "" })
				userRepo := ds.User()
				_ = userRepo.Put(ctx, &model.User{ID: "1", UserName: "user", NewPassword: "password", Name: "User"})

				u, err := ValidateLogin(ctx, userRepo, "user", "")
				Expect(err).To(BeNil())
				Expect(u).To(BeNil())
			})

			It("rejects an LDAP-backed user via local fallback when LDAP is down", func() {
				conf.Update(func(c *conf.Options) { c.LDAP.Host = "ldap://invalid-host:389" })
				userRepo := ds.User()
				_ = userRepo.Put(ctx, &model.User{
					ID:       "ldap-1",
					UserName: "ldapper",
					Name:     "Ldapper",
					AuthType: model.AuthTypeLDAP,
				})
				_ = userRepo.ClearPassword(ctx, "ldap-1")

				u, err := ValidateLogin(ctx, userRepo, "ldapper", "")
				Expect(err).To(BeNil())
				Expect(u).To(BeNil())

				u, err = ValidateLogin(ctx, userRepo, "ldapper", "any-non-empty-password")
				Expect(err).To(BeNil())
				Expect(u).To(BeNil())
			})

			It("rejects when the stored password is empty (mid-migration row)", func() {
				conf.Update(func(c *conf.Options) { c.LDAP.Host = "" })
				userRepo := ds.User()
				_ = userRepo.Put(ctx, &model.User{
					ID:       "stale-1",
					UserName: "staleuser",
					Name:     "Stale",
				})
				_ = userRepo.ClearPassword(ctx, "stale-1")

				u, err := ValidateLogin(ctx, userRepo, "staleuser", "anything")
				Expect(err).To(BeNil())
				Expect(u).To(BeNil())
			})
		})
	})

	Describe("App password login", func() {
		var ds model.DataStore

		BeforeEach(func() {
			ds = persistence.New(db.Db())
			auth.Init(ds)
			// App-password login must not depend on the directory; keep it
			// disabled so the happy path never tries a real LDAP bind.
			conf.Update(func(c *conf.Options) { c.LDAP.Host = "" })
		})

		It("logs in an LDAP-backed user with a valid app password", func() {
			_ = ds.User().Put(ctx, &model.User{ID: "ldap-1", UserName: "ldapper", Name: "Ldapper", AuthType: model.AuthTypeLDAP})
			_ = ds.AppPassword().Put(ctx, &model.AppPassword{UserID: "ldap-1", Name: "Feishin", NewPassword: "app-secret"})

			req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"ldapper","password":"app-secret"}`))
			resp := httptest.NewRecorder()
			login(ds)(resp, req)

			Expect(resp.Code).To(Equal(http.StatusOK))
			var parsed map[string]any
			Expect(json.Unmarshal(resp.Body.Bytes(), &parsed)).To(BeNil())
			Expect(parsed["username"]).To(Equal("ldapper"))
			tokenStr := parsed["token"].(string)
			Expect(tokenStr).ToNot(BeEmpty())

			claims, err := auth.Validate(tokenStr)
			Expect(err).To(BeNil())
			Expect(claims.AppPasswordID).ToNot(BeEmpty())
			Expect(claims.AppPasswordName).To(Equal("Feishin"))

			// The subsonic salt+token must be derived from the app password so
			// the client's subsequent /rest calls (echoing t/s back) are
			// accepted by matchAppPassword.
			Expect(parsed["subsonicSalt"]).ToNot(BeEmpty())
			Expect(parsed["subsonicToken"]).ToNot(BeEmpty())
			salt := parsed["subsonicSalt"].(string)
			expected := fmt.Sprintf("%x", md5.Sum([]byte("app-secret"+salt)))
			Expect(parsed["subsonicToken"]).To(Equal(expected))
		})

		It("fails when an LDAP user submits a wrong password", func() {
			_ = ds.User().Put(ctx, &model.User{ID: "ldap-1", UserName: "ldapper", Name: "Ldapper", AuthType: model.AuthTypeLDAP})
			_ = ds.AppPassword().Put(ctx, &model.AppPassword{UserID: "ldap-1", Name: "Feishin", NewPassword: "app-secret"})

			req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"ldapper","password":"wrong"}`))
			resp := httptest.NewRecorder()
			login(ds)(resp, req)

			// No app-password match and no reachable directory → 401.
			Expect(resp.Code).To(Equal(http.StatusUnauthorized))
		})

		It("does not let a non-LDAP user log in with an app password", func() {
			_ = ds.User().Put(ctx, &model.User{ID: "local-1", UserName: "localer", Name: "Localer", NewPassword: "real-pass"})
			_ = ds.AppPassword().Put(ctx, &model.AppPassword{UserID: "local-1", Name: "Feishin", NewPassword: "app-secret"})

			// The main password still works.
			req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"localer","password":"real-pass"}`))
			resp := httptest.NewRecorder()
			login(ds)(resp, req)
			Expect(resp.Code).To(Equal(http.StatusOK))

			// The app password must NOT grant web/JWT access to a local user.
			req = httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"localer","password":"app-secret"}`))
			resp = httptest.NewRecorder()
			login(ds)(resp, req)
			Expect(resp.Code).To(Equal(http.StatusUnauthorized))
		})
	})

	Describe("AppPasswordVerifier", func() {
		var ds model.DataStore

		BeforeEach(func() {
			ds = persistence.New(db.Db())
			auth.Init(ds)
		})

		// chain wires JWTVerifier → AppPasswordVerifier → final handler, mirroring
		// how the Native API mounts the middleware.
		chain := func(final http.Handler) http.Handler {
			return JWTVerifier(AppPasswordVerifier(ds)(final))
		}

		doRequest := func(token string) (*httptest.ResponseRecorder, *bool) {
			called := false
			h := chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest("GET", "/api/song", nil)
			if token != "" {
				req.Header.Set(consts.UIAuthorizationHeader, "Bearer "+token)
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			return resp, &called
		}

		// seedAppPassword stores an LDAP-backed user with one active app password and returns its ID.
		seedAppPassword := func() string {
			GinkgoHelper()
			Expect(ds.User().Put(ctx, &model.User{ID: "u-ldap", UserName: "ldapper", AuthType: model.AuthTypeLDAP})).To(Succeed())
			ap := &model.AppPassword{UserID: "u-ldap", Name: "Feishin", NewPassword: "secret"}
			Expect(ds.AppPassword().Put(ctx, ap)).To(Succeed())
			return ap.ID
		}

		It("passes through when there is no token", func() {
			resp, called := doRequest("")
			Expect(*called).To(BeTrue())
			Expect(resp.Code).To(Equal(http.StatusOK))
		})

		It("passes through for a regular token without an apid claim", func() {
			token, err := auth.CreateToken(&model.User{ID: "u1", UserName: "regular"})
			Expect(err).To(BeNil())

			resp, called := doRequest(token)
			Expect(*called).To(BeTrue())
			Expect(resp.Code).To(Equal(http.StatusOK))
		})

		It("passes through when the backing app password is still active", func() {
			apID := seedAppPassword()
			token, err := auth.CreateTokenWithAppPassword(&model.User{ID: "u-ldap", UserName: "ldapper", AuthType: model.AuthTypeLDAP}, apID, "Feishin")
			Expect(err).To(BeNil())

			resp, called := doRequest(token)
			Expect(*called).To(BeTrue())
			Expect(resp.Code).To(Equal(http.StatusOK))
		})

		It("rejects with 401 when the app password has been revoked", func() {
			apID := seedAppPassword()
			token, err := auth.CreateTokenWithAppPassword(&model.User{ID: "u-ldap", UserName: "ldapper", AuthType: model.AuthTypeLDAP}, apID, "Feishin")
			Expect(err).To(BeNil())

			Expect(ds.AppPassword().Revoke(ctx, apID)).To(Succeed())

			resp, called := doRequest(token)
			Expect(*called).To(BeFalse())
			Expect(resp.Code).To(Equal(http.StatusUnauthorized))
		})

		It("rejects with 401 when the app password no longer exists", func() {
			token, err := auth.CreateTokenWithAppPassword(&model.User{ID: "u-ldap", UserName: "ldapper", AuthType: model.AuthTypeLDAP}, "ap-missing", "Feishin")
			Expect(err).To(BeNil())

			resp, called := doRequest(token)
			Expect(*called).To(BeFalse())
			Expect(resp.Code).To(Equal(http.StatusUnauthorized))
		})
	})

	Describe("Authenticator token gating", func() {
		var ds model.DataStore
		var usr *model.User

		setTokenEpoch := func(epoch int) {
			GinkgoHelper()
			_, err := db.Db().Exec("UPDATE user SET token_epoch = ? WHERE id = ?", epoch, usr.ID)
			Expect(err).ToNot(HaveOccurred())
		}

		BeforeEach(func() {
			conf.Update(func(c *conf.Options) { c.SessionTimeout = time.Hour })
			ds = persistence.New(db.Db())
			auth.Init(ds)
			usr = &model.User{ID: "u1", UserName: "johndoe", NewPassword: "pw", TokenEpoch: 2}
			Expect(ds.User().Put(ctx, usr)).To(Succeed())
			setTokenEpoch(usr.TokenEpoch)
		})

		serve := func(token string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, "/api/song", nil)
			r.Header.Set(consts.UIAuthorizationHeader, "Bearer "+token)
			w := httptest.NewRecorder()
			handler := JWTVerifier(Authenticator(ds)(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
			)))
			handler.ServeHTTP(w, r)
			return w
		}

		It("accepts a current session token", func() {
			tokenStr, err := auth.CreateToken(usr)
			Expect(err).ToNot(HaveOccurred())
			Expect(serve(tokenStr).Code).To(Equal(http.StatusOK))
		})

		It("rejects a jellyfin-scoped token", func() {
			tokenStr, err := auth.CreateAPIToken(usr, auth.AudienceJellyfin)
			Expect(err).ToNot(HaveOccurred())
			Expect(serve(tokenStr).Code).To(Equal(http.StatusUnauthorized))
		})

		It("rejects a token with a stale epoch", func() {
			tokenStr, err := auth.CreateToken(usr)
			Expect(err).ToNot(HaveOccurred())
			setTokenEpoch(3)
			Expect(serve(tokenStr).Code).To(Equal(http.StatusUnauthorized))
		})

		It("ignores a stray token for someone else when config auto-login resolves the user", func() {
			conf.Update(func(c *conf.Options) { c.DevAutoLoginUsername = usr.UserName })
			tokenStr, err := auth.CreateToken(&model.User{UserName: "someone-else"})
			Expect(err).ToNot(HaveOccurred())
			Expect(serve(tokenStr).Code).To(Equal(http.StatusOK))
		})

		It("rejects a stale-epoch token whose subject differs only in case from the resolved user", func() {
			tokenStr, err := auth.CreateToken(&model.User{UserName: strings.ToUpper(usr.UserName), TokenEpoch: usr.TokenEpoch})
			Expect(err).ToNot(HaveOccurred())
			setTokenEpoch(5)
			Expect(serve(tokenStr).Code).To(Equal(http.StatusUnauthorized))
		})
	})

	Describe("JWTRefresher", func() {
		BeforeEach(func() {
			// TouchClaims reads this; left at zero every refreshed token is born expired.
			conf.Update(func(c *conf.Options) { c.SessionTimeout = time.Hour })
			auth.Init(persistence.New(db.Db()))
		})

		serveWith := func(handler http.HandlerFunc) *httptest.ResponseRecorder {
			usr := model.User{ID: "u1", UserName: "johndoe", TokenEpoch: 1}
			tokenStr, err := auth.CreateToken(&usr)
			Expect(err).ToNot(HaveOccurred())

			r := httptest.NewRequest(http.MethodGet, "/api/song", nil)
			r.Header.Set(consts.UIAuthorizationHeader, "Bearer "+tokenStr)
			w := httptest.NewRecorder()
			JWTVerifier(JWTRefresher(handler)).ServeHTTP(w, r)
			return w
		}

		It("writes a refreshed token when the handler writes a body", func() {
			w := serveWith(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})
			Expect(w.Header().Get(consts.UIAuthorizationHeader)).ToNot(BeEmpty())
		})

		It("writes a refreshed token when the handler writes no body", func() {
			w := serveWith(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			Expect(w.Header().Get(consts.UIAuthorizationHeader)).ToNot(BeEmpty())
		})

		It("picks up an epoch the handler reported", func() {
			w := serveWith(func(w http.ResponseWriter, r *http.Request) {
				request.SetTokenEpoch(r.Context(), 42)
				w.WriteHeader(http.StatusOK)
			})

			claims, err := auth.Validate(w.Header().Get(consts.UIAuthorizationHeader))
			Expect(err).ToNot(HaveOccurred())
			Expect(claims.Epoch).To(Equal(42))
		})

		It("keeps the original epoch when the handler reports nothing", func() {
			w := serveWith(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			claims, err := auth.Validate(w.Header().Get(consts.UIAuthorizationHeader))
			Expect(err).ToNot(HaveOccurred())
			Expect(claims.Epoch).To(Equal(1))
		})

		It("propagates Flush to the underlying ResponseWriter", func() {
			w := serveWith(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
			})
			Expect(w.Flushed).To(BeTrue())
		})

		It("exposes the underlying ResponseWriter via Unwrap, for http.ResponseController lookups", func() {
			var unwrapped http.ResponseWriter
			w := serveWith(func(w http.ResponseWriter, _ *http.Request) {
				u, ok := w.(interface{ Unwrap() http.ResponseWriter })
				Expect(ok).To(BeTrue())
				unwrapped = u.Unwrap()
				w.WriteHeader(http.StatusOK)
			})
			Expect(unwrapped).To(BeIdenticalTo(w))
		})
	})
})
