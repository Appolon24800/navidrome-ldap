package log

import (
	"strconv"
	"strings"
	"testing"
)

func TestOIDCClientSecretRedaction(t *testing.T) {
	for _, secret := range []string{"secret-with-punctuation_123", "secret\"with\\escapes", "secret\nwith-newline"} {
		input := "OIDC:{ClientSecret:" + strconv.Quote(secret) + ", ClientID:\"public-client\"}"
		want := "OIDC:{ClientSecret:\"[REDACTED]\", ClientID:\"public-client\"}"
		if got := Redact(input); got != want || strings.Contains(got, secret) {
			t.Fatalf("client secret redaction did not preserve the surrounding configuration")
		}
	}
}
