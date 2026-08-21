package verifier

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Verifier_Profile covers what a browser is told about the person it signed in as, which the
// access token says nothing about and the UserInfo endpoint does.
func Test_Verifier_Profile(t *testing.T) {
	t.Parallel()

	const subject = "some-subject"

	t.Run("the standard claims describe the user", func(t *testing.T) {
		t.Parallel()

		server, _, _ := setupCountingIssuer(t, http.StatusOK, map[string]any{
			"sub":                subject,
			"preferred_username": "amaury",
			"name":               "Amaury Valorge",
			"email":              "amaury@example.com",
			"picture":            "https://auth.example.com/avatar.png",
		})
		built := setupUserInfoVerifier(t, server.URL, userInfoTTL)

		profile, err := built.Profile(context.Background(), "raw-token", subject)

		require.NoError(t, err)
		require.NotNil(t, profile)
		assert.Equal(t, "amaury", profile.Username)
		assert.Equal(t, "Amaury Valorge", profile.Name)
		assert.Equal(t, "amaury@example.com", profile.Email)
		assert.Equal(t, "https://auth.example.com/avatar.png", profile.Picture)
	})

	t.Run("a provider stating nothing describes nobody", func(t *testing.T) {
		t.Parallel()

		server, _, _ := setupCountingIssuer(t, http.StatusOK, map[string]any{"sub": subject})
		built := setupUserInfoVerifier(t, server.URL, userInfoTTL)

		profile, err := built.Profile(context.Background(), "raw-token", subject)

		require.NoError(t, err)
		assert.Nil(t, profile)
	})

	t.Run("a claim holding something other than a string is dropped", func(t *testing.T) {
		t.Parallel()

		server, _, _ := setupCountingIssuer(t, http.StatusOK, map[string]any{
			"sub":     subject,
			"name":    42,
			"picture": map[string]any{"url": "https://auth.example.com/avatar.png"},
			"email":   "amaury@example.com",
		})
		built := setupUserInfoVerifier(t, server.URL, userInfoTTL)

		profile, err := built.Profile(context.Background(), "raw-token", subject)

		require.NoError(t, err)
		require.NotNil(t, profile)
		assert.Empty(t, profile.Name)
		assert.Empty(t, profile.Picture)
		assert.Equal(t, "amaury@example.com", profile.Email)
	})

	// OpenID Connect Core 5.3.2. A profile is shown to the visitor as their own: reading one for
	// whoever the endpoint decided to describe would show them somebody else's name and email.
	t.Run("a profile describing another subject is refused", func(t *testing.T) {
		t.Parallel()

		server, _, _ := setupCountingIssuer(t, http.StatusOK, map[string]any{
			"sub":  "somebody-else",
			"name": "Somebody Else",
		})
		built := setupUserInfoVerifier(t, server.URL, userInfoTTL)

		profile, err := built.Profile(context.Background(), "raw-token", subject)

		require.Error(t, err)
		assert.Nil(t, profile)
	})

	t.Run("an unreachable provider is an error rather than a nameless user", func(t *testing.T) {
		t.Parallel()

		server, _, _ := setupCountingIssuer(t, http.StatusServiceUnavailable, nil)
		built := setupUserInfoVerifier(t, server.URL, userInfoTTL)

		profile, err := built.Profile(context.Background(), "raw-token", subject)

		require.Error(t, err)
		assert.Nil(t, profile)
	})

	// The roles and the profile are read from the same endpoint, so a deployment reading its roles
	// there must not pay a second round trip to learn a name.
	t.Run("the roles and the profile share one lookup", func(t *testing.T) {
		t.Parallel()

		server, key, calls := setupCountingIssuer(t, http.StatusOK, map[string]any{
			"sub":    subject,
			"groups": []any{"admin"},
			"name":   "Amaury Valorge",
		})
		built := setupUserInfoVerifier(t, server.URL, userInfoTTL)

		rawToken := setupSignedToken(t, key, setupClaims(server.URL, testAudience, subject, time.Now().Add(time.Hour)))

		session, err := built.Verify(context.Background(), rawToken)
		require.NoError(t, err)
		require.True(t, session.Authorized)

		profile, err := built.Profile(context.Background(), rawToken, subject)
		require.NoError(t, err)
		require.NotNil(t, profile)
		assert.Equal(t, "Amaury Valorge", profile.Name)

		assert.Equal(t, int64(1), calls.Load())
	})
}
