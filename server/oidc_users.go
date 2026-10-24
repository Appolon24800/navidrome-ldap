package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
)

type oidcUserClaims struct {
	AuthorizedParty   string `json:"azp"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Email             string `json:"email"`
}

func oidcUserKey(kind, issuer, value string) string {
	hash := sha256.Sum256([]byte(issuer + "\x00" + value))
	return "oidc." + kind + ":" + hex.EncodeToString(hash[:])
}

// Match the trusted provider's username automatically on first login, or create
// an ordinary user. Save the issuer/subject association internally so subsequent
// username changes cannot move an identity into a different Navidrome account.
func (o *oidcLogin) resolveUser(ctx context.Context, subject string, claims oidcUserClaims) (*model.User, error) {
	username := strings.TrimSpace(claims.PreferredUsername)
	if subject == "" || username == "" || strings.ContainsAny(username, "\x00\r\n") {
		return nil, errors.New("OIDC token requires a non-empty preferred_username")
	}
	identityKey := oidcUserKey("identity", o.issuer, subject)
	var user *model.User
	err := o.ds.WithTxImmediate(func(ds model.DataStore) error {
		users, properties := ds.User(ctx), ds.Property(ctx)
		boundID, err := properties.Get(identityKey)
		if err == nil {
			user, err = users.Get(boundID)
			if err == nil {
				return nil
			}
			if !errors.Is(err, model.ErrNotFound) {
				return err
			}
		} else if !errors.Is(err, model.ErrNotFound) {
			return err
		}

		user, err = users.FindByUsername(username)
		switch {
		case err == nil:
			// An old binding must not inherit a replacement account's data or
			// privileges after the original Navidrome account was deleted.
			if boundID != "" && boundID != user.ID {
				return errors.New("OIDC identity refers to a deleted account")
			}
		case errors.Is(err, model.ErrNotFound):
			name := strings.TrimSpace(claims.Name)
			if name == "" {
				name = username
			}
			user = &model.User{ID: id.NewRandom(), UserName: username, Name: name, Email: claims.Email,
				AuthType: model.AuthTypeLocal, IsAdmin: false,
				// Follow Navidrome's external-auth convention: a fresh random
				// placeholder, independent of all identity-provider credentials.
				NewPassword: consts.PasswordAutogenPrefix + id.NewRandom()}
			if err := users.Put(user); err != nil {
				return err
			}
		default:
			return err
		}

		ownerKey := oidcUserKey("owner", o.issuer, user.ID)
		owner, err := properties.Get(ownerKey)
		if err == nil && owner != identityKey {
			return errors.New("username is already linked to another OIDC identity")
		}
		if err != nil && !errors.Is(err, model.ErrNotFound) {
			return err
		}
		if err := properties.Put(identityKey, user.ID); err != nil {
			return err
		}
		return properties.Put(ownerKey, identityKey)
	}, "oidc_user")
	return user, err
}
