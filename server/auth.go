package server

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/deluan/rest"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-ldap/ldap"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/utils/gravatar"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	ErrNoUsers         = errors.New("no users created")
	ErrUnauthenticated = errors.New("request not authenticated")
)

func login(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, err := getCredentialsFromBody(r)
		if err != nil {
			log.Error(r, "Parsing request body", err)
			_ = rest.RespondWithError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		doLogin(ds, username, password, w, r)
	}
}

func doLogin(ds model.DataStore, username string, password string, w http.ResponseWriter, r *http.Request) {
	// LDAP-backed users have no persistent password and authenticate against
	// the directory on every web login. To let Navidrome-native clients
	// (e.g. Feishin, which POSTs to /auth/login) work with an LDAP account,
	// allow them to log in using a per-device app password — the same kind
	// used for the Subsonic API. This is a fallback for LDAP users only;
	// everyone else is handled solely by ValidateLogin. The comparison
	// reuses the AppPassword repository's FindActiveByUser (which performs
	// the AES-GCM decryption) and the same plaintext check as
	// server/subsonic/middlewares.go:matchAppPassword.
	user, appPassID, appPassName, appPassSecret := tryAppPasswordLogin(r.Context(), ds, username, password)
	if user == nil {
		var err error
		user, err = ValidateLogin(ds.User(r.Context()), username, password)
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authentication user. Please try again")
			return
		}
		if user == nil {
			log.Warn(r, "Unsuccessful login", "username", username, "request", r.Header)
			_ = rest.RespondWithError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
	}

	// Embed the backing app password in the JWT so AppPasswordVerifier can
	// invalidate the session the moment that credential is revoked/deleted.
	var tokenString string
	var err error
	if appPassID != "" {
		tokenString, err = auth.CreateTokenWithAppPassword(user, appPassID, appPassName)
	} else {
		tokenString, err = auth.CreateToken(user)
	}
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authenticating user. Please try again")
		return
	}
	payload := buildAuthPayload(user, appPassSecret)
	payload["token"] = tokenString
	_ = rest.RespondWithJSON(w, http.StatusOK, payload)
}

func buildAuthPayload(user *model.User, subsonicPassword string) map[string]any {
	payload := map[string]any{
		"id":       user.ID,
		"name":     user.Name,
		"username": user.UserName,
		"isAdmin":  user.IsAdmin,
	}
	if conf.Server.EnableGravatar && user.Email != "" {
		payload["avatar"] = gravatar.Url(user.Email, 50)
	}

	bytes := make([]byte, 3)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Error("Could not create subsonic salt", "user", user.UserName, err)
		return payload
	}
	subsonicSalt := hex.EncodeToString(bytes)
	payload["subsonicSalt"] = subsonicSalt

	// The Subsonic salt+token protocol needs a recoverable plaintext: the
	// client echoes back md5(secret+salt), which the Subsonic middleware's
	// matchAppPassword recomputes to validate. For an app-password login
	// (LDAP users), the secret the client will present at /rest is that app
	// password, so derive the token from it — otherwise the client would
	// resend a token the middleware can't match, getting a 40 on every
	// /rest call. Otherwise fall back to the user's main password (empty for
	// LDAP directory logins, which can't use the Subsonic API anyway).
	pwd := subsonicPassword
	if pwd == "" {
		pwd = user.Password
	}
	subsonicToken := md5.Sum([]byte(pwd + subsonicSalt))
	payload["subsonicToken"] = hex.EncodeToString(subsonicToken[:])

	return payload
}

// tryAppPasswordLogin lets an LDAP-backed user authenticate against
// /auth/login using one of their per-device app passwords — the same
// credentials used for the Subsonic API. It looks up the user and, only if
// they are LDAP-backed, compares the supplied plaintext password against
// their active app passwords. This reuses the AppPassword repository's
// FindActiveByUser (which performs the AES-GCM decryption) and the same
// plaintext comparison as server/subsonic/middlewares.go:matchAppPassword, so
// no new hashing/comparison scheme is introduced. Non-LDAP users are
// unaffected. On a match it returns (user, appPassID, appPassName,
// appPassSecret) — the plaintext secret is needed downstream so the login
// response's subsonicToken is derived from that app password (not the user's
// empty directory password), letting the client's subsequent /rest salt+token
// calls verify. Returns (nil, "", "", "") otherwise so the caller falls
// through to ValidateLogin / the LDAP bind.
func tryAppPasswordLogin(ctx context.Context, ds model.DataStore, username, password string) (*model.User, string, string, string) {
	if password == "" {
		return nil, "", "", ""
	}
	u, err := ds.User(ctx).FindByUsername(username)
	if err != nil || !u.IsLDAP() {
		return nil, "", "", ""
	}
	active, err := ds.AppPassword(ctx).FindActiveByUser(u.ID)
	if err != nil {
		log.Warn(ctx, "Error loading app passwords", "username", username, err)
		return nil, "", "", ""
	}
	for _, ap := range active {
		if password == ap.Password {
			if touchErr := ds.AppPassword(ctx).Touch(ap.ID); touchErr != nil {
				log.Warn(ctx, "Failed to bump app password last_used_at", "id", ap.ID, "username", username, touchErr)
			}
			// LDAP users carry no directory password; mirror the scrub done
			// in validateLoginLDAP so callers don't see a stale value in
			// u.Password. The app password plaintext is returned separately
			// (never stored on the user) for subsonicToken derivation.
			u.Password = ""
			if err := ds.User(ctx).UpdateLastLoginAt(u.ID); err != nil {
				log.Error(ctx, "Could not update LastLoginAt", "user", username, err)
			}
			return u, ap.ID, ap.Name, ap.Password
		}
	}
	return nil, "", "", ""
}

func getCredentialsFromBody(r *http.Request) (username string, password string, err error) {
	data := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	if err = decoder.Decode(&data); err != nil {
		log.Error(r, "parsing request body", err)
		err = errors.New("invalid request payload")
		return
	}
	username = data["username"]
	password = data["password"]
	return username, password, nil
}

func createAdmin(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, err := getCredentialsFromBody(r)
		if err != nil {
			log.Error(r, "parsing request body", err)
			_ = rest.RespondWithError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		c, err := ds.User(r.Context()).CountAll()
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if c > 0 {
			_ = rest.RespondWithError(w, http.StatusForbidden, "Cannot create another first admin")
			return
		}
		err = createAdminUser(r.Context(), ds, username, password)
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		doLogin(ds, username, password, w, r)
	}
}

func createAdminUser(ctx context.Context, ds model.DataStore, username, password string) error {
	log.Warn(ctx, "Creating initial user", "user", username)
	caser := cases.Title(language.Und)
	initialUser := model.User{
		ID:          id.NewRandom(),
		UserName:    username,
		Name:        caser.String(username),
		Email:       "",
		NewPassword: password,
		IsAdmin:     true,
		LastLoginAt: new(time.Now()),
	}
	err := ds.User(ctx).Put(&initialUser)
	if err != nil {
		log.Error(ctx, "Could not create initial user", "user", initialUser, err)
	}
	return nil
}

func ValidateLogin(userRepo model.UserRepository, userName, password string) (*model.User, error) {
	// Empty passwords never authenticate. LDAP-backed users have an empty
	// `password` column (cleared by ClearPassword on every login), so an
	// empty submitted password would otherwise match the empty stored one
	// in the local fallback below.
	if password == "" {
		return nil, nil
	}
	u, err := validateLoginLDAP(userRepo, userName, password)
	if u != nil && err == nil {
		return u, nil
	}
	u, err = userRepo.FindByUsernameWithPassword(userName)
	if errors.Is(err, model.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// LDAP-backed users have no valid local password. If we reached this
	// point for one (LDAP unreachable, directory bind failed, etc.), refuse
	// rather than fall through to the local-password compare.
	if u.IsLDAP() || u.Password == "" {
		return nil, nil
	}
	if u.Password != password {
		return nil, nil
	}
	err = userRepo.UpdateLastLoginAt(u.ID)
	if err != nil {
		log.Error("Could not update LastLoginAt", "user", userName)
	}
	return u, nil
}

func validateLoginLDAP(userRepo model.UserRepository, userName, password string) (*model.User, error) {
	if conf.Server.LDAP.Host == "" {
		return nil, nil
	}

	bindDN := conf.Server.LDAP.BindDN
	bindPassword := conf.Server.LDAP.BindPassword
	mailAttr := conf.Server.LDAP.Mail
	nameAttr := conf.Server.LDAP.Name

	l, err := ldap.DialURL(conf.Server.LDAP.Host)
	if err != nil {
		log.Error("LDAP connection failed", "host", conf.Server.LDAP.Host, err)
		return nil, nil
	}
	defer l.Close()

	// Bind with the read-only service account to search for the user
	if err := l.Bind(bindDN, bindPassword); err != nil {
		log.Error("LDAP service-account bind failed", "bindDN", bindDN, err)
		return nil, nil
	}

	searchRequest := ldap.NewSearchRequest(
		conf.Server.LDAP.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(conf.Server.LDAP.SearchFilter, ldap.EscapeFilter(userName)),
		[]string{"dn", nameAttr, mailAttr},
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Error("LDAP search failed", "user", userName, err)
		return nil, nil
	}
	if len(sr.Entries) != 1 {
		log.Warn("LDAP search returned unexpected number of entries", "user", userName, "matches", len(sr.Entries))
		return nil, nil
	}

	entry := sr.Entries[0]

	// Admin-group check (if configured). Run BEFORE the user-bind, while
	// the connection is still authenticated as the service account —
	// l.Bind below will replace that with the user's bind, which on many
	// directories cannot read group memberships. The result is only
	// applied after the user-bind succeeds.
	var adminCheckResult *bool
	if adminCheckEnabled() {
		isAdmin, adminErr := ldapAdminCheck(l, userName)
		if adminErr != nil {
			// Transient lookup failure — preserve the existing IsAdmin
			// to avoid locking the operator out from a directory hiccup.
			log.Warn("LDAP admin lookup failed; preserving existing IsAdmin", "user", userName, adminErr)
		} else {
			adminCheckResult = &isAdmin
		}
	}

	// Re-bind as the user to verify their password
	if err := l.Bind(entry.DN, password); err != nil {
		log.Warn("LDAP user authentication failed", "user", userName, err)
		return nil, nil
	}

	// User authenticated. Sync the directory-sourced attributes to the
	// local DB but DO NOT persist the directory password. LDAP-backed users
	// authenticate against the directory on every web login; for the
	// Subsonic API they must use an app password (which is independent and
	// revocable).
	u, err := userRepo.FindByUsername(userName)
	if errors.Is(err, model.ErrNotFound) {
		u = &model.User{UserName: userName}
	} else if err != nil {
		log.Error("Could not look up LDAP user in DB", "user", userName, err)
		return nil, nil
	}
	u.Name = entry.GetAttributeValue(nameAttr)
	u.Email = entry.GetAttributeValue(mailAttr)
	u.AuthType = model.AuthTypeLDAP
	applyLDAPAdminResult(u, adminCheckResult)
	if err := userRepo.Put(u); err != nil {
		log.Error("Could not save LDAP user", "user", userName, err)
		return nil, nil
	}
	// Clear any password that may have been persisted by a previous version
	// of this code (or by the user being promoted from local → LDAP). This
	// is the migration path for existing LDAP users post-upgrade: their
	// first login here scrubs the old reversibly-encrypted directory
	// password from the DB.
	if err := userRepo.ClearPassword(u.ID); err != nil {
		log.Error("Could not clear persisted password for LDAP user", "user", userName, err)
	}
	// Mirror the DB scrub in memory so callers (notably buildAuthPayload's
	// subsonicToken hash) don't compute over a stale ciphertext loaded by
	// FindByUsername above.
	u.Password = ""
	if err := userRepo.UpdateLastLoginAt(u.ID); err != nil {
		log.Error("Could not update LastLoginAt", "user", userName, err)
	}

	return u, nil
}

func JWTVerifier(next http.Handler) http.Handler {
	return jwtauth.Verify(auth.TokenAuth, tokenFromHeader, jwtauth.TokenFromCookie, jwtauth.TokenFromQuery)(next)
}

func tokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get(consts.UIAuthorizationHeader)
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

func UsernameFromToken(r *http.Request) string {
	token, _, err := jwtauth.FromContext(r.Context())
	if err != nil || token == nil {
		return ""
	}
	sub, _ := token.Subject()
	if sub == "" {
		return ""
	}
	log.Trace(r, "Found username in JWT token", "username", sub)
	return sub
}

func UsernameFromExtAuthHeader(r *http.Request) string {
	if conf.Server.ExtAuth.TrustedSources == "" {
		return ""
	}
	reverseProxyIp, ok := request.ReverseProxyIpFrom(r.Context())
	if !ok {
		log.Error("ExtAuth enabled but no proxy IP found in request context. Please report this error.")
		return ""
	}
	if !validateIPAgainstList(reverseProxyIp, conf.Server.ExtAuth.TrustedSources) {
		log.Warn(r.Context(), "IP is not whitelisted for external authentication", "proxy-ip", reverseProxyIp, "client-ip", r.RemoteAddr)
		return ""
	}
	username := r.Header.Get(conf.Server.ExtAuth.UserHeader)
	if username == "" {
		return ""
	}
	log.Trace(r, "Found username in ExtAuth.UserHeader", "username", username)
	return username
}

func InternalAuth(r *http.Request) string {
	username, ok := request.InternalAuthFrom(r.Context())
	if !ok {
		return ""
	}
	log.Trace(r, "Found username in InternalAuth", "username", username)
	return username
}

func UsernameFromConfig(*http.Request) string {
	return conf.Server.DevAutoLoginUsername
}

func contextWithUser(ctx context.Context, ds model.DataStore, username string) (context.Context, error) {
	user, err := ds.User(ctx).FindByUsername(username)
	if err == nil {
		ctx = log.NewContext(ctx, "username", username)
		ctx = request.WithUsername(ctx, user.UserName)
		return request.WithUser(ctx, *user), nil
	}
	log.Error(ctx, "Authenticated username not found in DB", "username", username)
	return ctx, err
}

func authenticateRequest(ds model.DataStore, r *http.Request, findUsernameFns ...func(r *http.Request) string) (context.Context, error) {
	var username string
	for _, fn := range findUsernameFns {
		username = fn(r)
		if username != "" {
			break
		}
	}
	if username == "" {
		return nil, ErrUnauthenticated
	}

	return contextWithUser(r.Context(), ds, username)
}

func Authenticator(ds model.DataStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := authenticateRequest(ds, r, UsernameFromConfig, UsernameFromToken, UsernameFromExtAuthHeader)
			if err != nil {
				_ = rest.RespondWithError(w, http.StatusUnauthorized, "Not authenticated")
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AppPasswordVerifier invalidates session tokens that were issued via an app
// password (carrying the "apid" claim) the moment that app password no longer
// exists or has been revoked. It only acts on token-bearing requests; tokens
// without the claim — regular local-user sessions, LDAP directory logins, dev
// auto-login, reverse-proxy auth — pass through untouched. Mount it after
// Authenticator on the Native API so JWT clients such as Feishin are cut off
// immediately when an app password is revoked.
func AppPasswordVerifier(ds model.DataStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, _, err := jwtauth.FromContext(ctx)
			if err != nil || token == nil {
				next.ServeHTTP(w, r)
				return
			}
			claims := auth.ClaimsFromToken(token)
			if claims.AppPasswordID == "" {
				next.ServeHTTP(w, r)
				return
			}
			ap, err := ds.AppPassword(ctx).Get(claims.AppPasswordID)
			// Fail closed: a missing (deleted) or revoked app password — or a
			// lookup error — rejects the request. Authenticator already did a
			// successful DB read for the user, so a transient error here is
			// unlikely; revocation must take effect immediately.
			if err != nil || !ap.IsActive() {
				log.Warn(ctx, "API: Rejecting request backed by revoked/missing app password",
					"appPasswordId", claims.AppPasswordID, "appPasswordName", claims.AppPasswordName,
					"username", claims.Subject, "remoteAddr", r.RemoteAddr, err)
				_ = rest.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// JWTRefresher updates the expiry date of the received JWT token, and add the new one to the Authorization Header
func JWTRefresher(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token, _, err := jwtauth.FromContext(ctx)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		newTokenString, err := auth.TouchToken(token)
		if err != nil {
			log.Error(r, "Could not sign new token", err)
			_ = rest.RespondWithError(w, http.StatusUnauthorized, "Not authenticated")
			return
		}

		w.Header().Set(consts.UIAuthorizationHeader, newTokenString)
		next.ServeHTTP(w, r)
	})
}

func handleLoginFromHeaders(ds model.DataStore, r *http.Request) map[string]any {
	username := UsernameFromConfig(r)
	if username == "" {
		username = UsernameFromExtAuthHeader(r)
		if username == "" {
			return nil
		}
	}

	userRepo := ds.User(r.Context())
	user, err := userRepo.FindByUsernameWithPassword(username)
	if user == nil || err != nil {
		log.Info(r, "User passed in header not found", "user", username)
		// Check if this is the first user being created
		count, _ := userRepo.CountAll()
		isFirstUser := count == 0

		newUser := model.User{
			ID:          id.NewRandom(),
			UserName:    username,
			Name:        username,
			Email:       "",
			NewPassword: consts.PasswordAutogenPrefix + id.NewRandom(),
			IsAdmin:     isFirstUser, // Make the first user an admin
		}
		err := userRepo.Put(&newUser)
		if err != nil {
			log.Error(r, "Could not create new user", "user", username, err)
			return nil
		}
		user, err = userRepo.FindByUsernameWithPassword(username)
		if user == nil || err != nil {
			log.Error(r, "Created user but failed to fetch it", "user", username)
			return nil
		}
	}

	err = userRepo.UpdateLastLoginAt(user.ID)
	if err != nil {
		log.Error(r, "Could not update LastLoginAt", "user", username, err)
		return nil
	}

	return buildAuthPayload(user, "")
}

func validateIPAgainstList(ip string, comaSeparatedList string) bool {
	if comaSeparatedList == "" || ip == "" {
		return false
	}

	cidrs := strings.Split(comaSeparatedList, ",")

	// Per https://github.com/golang/go/issues/49825, the remote address
	// on a unix socket is '@'
	if ip == "@" && strings.HasPrefix(conf.Server.Address, "unix:") {
		return slices.Contains(cidrs, "@")
	}

	if net.ParseIP(ip) == nil {
		ip, _, _ = net.SplitHostPort(ip)
	}

	if ip == "" {
		return false
	}

	testedIP, _, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		return false
	}

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(testedIP) {
			return true
		}
	}

	return false
}
