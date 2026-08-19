package verifier

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Verifier_VerifyIDToken covers OpenID Connect Core 3.1.3.7 against a real signed token,
// rather than against a stub standing in for it.
//
// This is what ties a finished login to the person it names, so every way it can be wrong is worth
// stating: another issuer's token, another application's, an expired one, one carrying a nonce
// from some other login, and one that never says who it is about.
func Test_Verifier_VerifyIDToken(t *testing.T) {
	t.Parallel()

	const nonce = "the-nonce-of-this-login"

	cases := []struct {
		name    string
		claims  func(issuer string) map[string]any
		nonce   string
		absent  bool
		wantErr string
	}{
		{
			name: "a token minted here for this application and this login",
			claims: func(issuer string) map[string]any {
				claims := setupClaims(issuer, testAudience, testAdminSub, time.Now().Add(time.Hour))
				claims["nonce"] = nonce
				claims["sid"] = "a-session-at-the-provider"

				return claims
			},
			nonce: nonce,
		},
		{
			name: "an issuer that states no session identifier of its own",
			claims: func(issuer string) map[string]any {
				claims := setupClaims(issuer, testAudience, testAdminSub, time.Now().Add(time.Hour))
				claims["nonce"] = nonce

				return claims
			},
			nonce: nonce,
		},
		{
			name:    "no token at all",
			absent:  true,
			nonce:   nonce,
			wantErr: "no id token",
		},
		{
			name: "a token carrying another login's nonce",
			claims: func(issuer string) map[string]any {
				claims := setupClaims(issuer, testAudience, testAdminSub, time.Now().Add(time.Hour))
				claims["nonce"] = "a-nonce-from-somewhere-else"

				return claims
			},
			nonce:   nonce,
			wantErr: "does not belong to this login",
		},
		{
			name: "a token carrying no nonce where one was asked for",
			claims: func(issuer string) map[string]any {
				return setupClaims(issuer, testAudience, testAdminSub, time.Now().Add(time.Hour))
			},
			nonce:   nonce,
			wantErr: "does not belong to this login",
		},
		{
			name: "a token minted for another application",
			claims: func(issuer string) map[string]any {
				claims := setupClaims(issuer, "another-application", testAdminSub, time.Now().Add(time.Hour))
				claims["nonce"] = nonce

				return claims
			},
			nonce:   nonce,
			wantErr: "invalid id token",
		},
		{
			name: "a token minted by another issuer",
			claims: func(string) map[string]any {
				claims := setupClaims("https://evil.example.com", testAudience, testAdminSub, time.Now().Add(time.Hour))
				claims["nonce"] = nonce

				return claims
			},
			nonce:   nonce,
			wantErr: "invalid id token",
		},
		{
			name: "a token that has expired",
			claims: func(issuer string) map[string]any {
				claims := setupClaims(issuer, testAudience, testAdminSub, time.Now().Add(-time.Hour))
				claims["nonce"] = nonce

				return claims
			},
			nonce:   nonce,
			wantErr: "invalid id token",
		},
		{
			name: "a token that names nobody",
			claims: func(issuer string) map[string]any {
				claims := setupClaims(issuer, testAudience, "", time.Now().Add(time.Hour))
				claims["nonce"] = nonce

				return claims
			},
			nonce:   nonce,
			wantErr: "without a subject",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			server, key := setupIssuer(t)
			built := setupVerifier(t, server.URL)

			rawIDToken := ""
			if !c.absent {
				rawIDToken = setupSignedToken(t, key, c.claims(server.URL))
			}

			err := built.VerifyIDToken(context.Background(), rawIDToken, c.nonce)

			if c.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
