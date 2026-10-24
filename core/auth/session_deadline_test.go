package auth_test

import (
	"testing"
	"time"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/tests"
)

func TestAbsoluteSessionDeadline(t *testing.T) {
	t.Cleanup(conf.SnapshotConfig())
	conf.Server.SessionTimeout = 24 * time.Hour
	auth.Init(&tests.MockDataStore{})
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	token, err := auth.CreateTokenWithDeadline(&model.User{ID: "user", UserName: "alice"}, deadline)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		claims, err := auth.Validate(token)
		if err != nil || !claims.SessionExpiresAt.Equal(deadline) || !claims.ExpiresAt.Equal(deadline) {
			t.Fatalf("deadline was lost: %+v, %v", claims, err)
		}
		token, err = auth.TouchClaims(claims)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := auth.TouchClaims(auth.Claims{SessionExpiresAt: time.Now().Add(-time.Minute)}); err == nil {
		t.Fatal("expired session was refreshed")
	}
}
