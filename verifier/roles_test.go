package verifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/authorization"
	"github.com/amauryval/goauth/types"
)

func Test_roleNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
		want  []string
	}{
		{
			name:  "an array yields its names",
			value: []any{"admin", "guest"},
			want:  []string{"admin", "guest"},
		},
		{
			name:  "an object yields its keys, sorted",
			value: map[string]any{"guest": nil, "admin": nil},
			want:  []string{"admin", "guest"},
		},
		{
			name:  "non string entries are dropped",
			value: []any{"admin", 42, ""},
			want:  []string{"admin"},
		},
		{
			name:  "a scalar claim yields nothing",
			value: "admin",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, roleNames(c.value))
		})
	}
}

func Test_Verifier_Verify_ProviderRoles(t *testing.T) {
	t.Parallel()

	server, key := setupIssuer(t)

	cases := []struct {
		name           string
		rolesClaim     string
		claimed        map[string]any
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "zitadel project roles are granted",
			rolesClaim:     "urn:zitadel:iam:org:project:roles",
			claimed:        map[string]any{"urn:zitadel:iam:org:project:roles": map[string]any{"guest": map[string]any{"orgId": "example.com"}}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest},
		},
		{
			name:           "pocket id groups are granted",
			rolesClaim:     "groups",
			claimed:        map[string]any{"groups": []any{"guest"}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest},
		},
		{
			name:           "an array of role names is granted too",
			rolesClaim:     "urn:zitadel:iam:org:project:roles",
			claimed:        map[string]any{"urn:zitadel:iam:org:project:roles": []any{"admin"}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:       "the claim of another provider is ignored",
			rolesClaim: "urn:zitadel:iam:org:project:roles",
			claimed:    map[string]any{"groups": []any{"admin"}},
		},
		{
			name:       "a token carrying no roles claim authorizes nobody",
			rolesClaim: "groups",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			built, err := New(context.Background(), authorization.FromToken(types.RoleAdmin, types.RoleGuest), Config{
				IssuerURL:  server.URL,
				Audience:   testAudience,
				RolesClaim: c.rolesClaim,
			})
			require.NoError(t, err)

			claims := setupClaims(server.URL, testAudience, "some-subject", time.Now().Add(time.Hour))
			for name, value := range c.claimed {
				claims[name] = value
			}

			info, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

			require.NoError(t, err)
			assert.True(t, info.LoggedIn)
			assert.Equal(t, c.wantAuthorized, info.Authorized)
			assert.Equal(t, c.wantRoles, info.Roles)
		})
	}
}

func Test_Verifier_Verify_UserInfoRoles(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		served         map[string]any
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "the groups the endpoint serves are granted",
			served:         map[string]any{"groups": []any{"guest"}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest},
		},
		{
			name:   "an endpoint serving no groups authorizes nobody",
			served: map[string]any{"sub": "some-subject"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			server, key, userInfo := setupIssuerWithUserInfo(t)
			for name, value := range c.served {
				userInfo[name] = value
			}

			built, err := New(context.Background(), authorization.FromToken(types.RoleAdmin, types.RoleGuest), Config{
				IssuerURL:         server.URL,
				Audience:          testAudience,
				RolesClaim:        "groups",
				RolesFromUserInfo: true,
			})
			require.NoError(t, err)

			claims := setupClaims(server.URL, testAudience, "some-subject", time.Now().Add(time.Hour))
			claims["groups"] = []any{"admin"}

			info, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

			require.NoError(t, err)
			assert.True(t, info.LoggedIn)
			assert.Equal(t, c.wantAuthorized, info.Authorized)
			assert.Equal(t, c.wantRoles, info.Roles)
		})
	}
}

// setupCountingIssuer starts an issuer whose UserInfo endpoint answers with the given status and
// claims, and counts how many times it was asked. Counting is how a test tells a cached lookup
// from one that went back to the provider.
func setupCountingIssuer(t *testing.T, status int, claims map[string]any) (*httptest.Server, *rsa.PrivateKey, *atomic.Int64) {
	t.Helper()

	var calls atomic.Int64

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/keys",
			"userinfo_endpoint":                     server.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)

		if status != http.StatusOK {
			w.WriteHeader(status)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": testKeyID,
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	return server, key, &calls
}

// setupUserInfoVerifier builds a verifier reading its roles from the UserInfo endpoint.
func setupUserInfoVerifier(t *testing.T, issuerURL string, ttl time.Duration) *Verifier {
	t.Helper()

	built, err := New(context.Background(), authorization.FromToken(types.RoleAdmin, types.RoleGuest), Config{
		IssuerURL:         issuerURL,
		Audience:          testAudience,
		RolesClaim:        "groups",
		RolesFromUserInfo: true,
		UserInfoTTL:       ttl,
	})
	require.NoError(t, err)

	return built
}

// Test_Verifier_Verify_UserInfoUnavailable pins the difference between a rejected caller and an
// unreachable provider: a UserInfo outage must not silently strip the user of every role, which
// would answer an outage with a 403 and read as a permission bug.
func Test_Verifier_Verify_UserInfoUnavailable(t *testing.T) {
	t.Parallel()

	server, key, calls := setupCountingIssuer(t, http.StatusInternalServerError, nil)
	built := setupUserInfoVerifier(t, server.URL, 0)

	claims := setupClaims(server.URL, testAudience, "some-subject", time.Now().Add(time.Hour))

	info, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

	require.Error(t, err)
	assert.ErrorIs(t, err, types.ErrAuthorization)
	assert.Equal(t, types.SessionInfo{}, info)
	assert.Positive(t, calls.Load())
}

// Test_Verifier_Verify_UserInfoNotCachedOnFailure keeps a failed lookup out of the cache, so a
// recovering provider is seen at once rather than after the TTL.
func Test_Verifier_Verify_UserInfoNotCachedOnFailure(t *testing.T) {
	t.Parallel()

	server, key, calls := setupCountingIssuer(t, http.StatusInternalServerError, nil)
	built := setupUserInfoVerifier(t, server.URL, time.Hour)

	token := setupSignedToken(t, key, setupClaims(server.URL, testAudience, "some-subject", time.Now().Add(time.Hour)))

	_, first := built.Verify(context.Background(), token)
	_, second := built.Verify(context.Background(), token)

	require.Error(t, first)
	require.Error(t, second)
	assert.Equal(t, int64(2), calls.Load())
}

func Test_Verifier_Verify_UserInfoCaching(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		ttl       time.Duration
		elapsed   time.Duration
		wantCalls int64
	}{
		{
			name:      "a second request within the ttl reuses the cached roles",
			ttl:       time.Hour,
			wantCalls: 1,
		},
		{
			name:      "the endpoint is asked again once the ttl elapsed",
			ttl:       time.Minute,
			elapsed:   2 * time.Minute,
			wantCalls: 2,
		},
		{
			name:      "a negative ttl asks the endpoint on every request",
			ttl:       -time.Second,
			wantCalls: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			served := map[string]any{"sub": "some-subject", "groups": []any{"admin"}}

			server, key, calls := setupCountingIssuer(t, http.StatusOK, served)
			built := setupUserInfoVerifier(t, server.URL, c.ttl)

			now := time.Now()
			built.now = func() time.Time { return now }

			token := setupSignedToken(t, key, setupClaims(server.URL, testAudience, "some-subject", now.Add(time.Hour)))

			first, err := built.Verify(context.Background(), token)
			require.NoError(t, err)

			now = now.Add(c.elapsed)

			second, err := built.Verify(context.Background(), token)
			require.NoError(t, err)

			assert.Equal(t, c.wantCalls, calls.Load())
			assert.Equal(t, []types.Role{types.RoleAdmin}, first.Roles)
			assert.Equal(t, first.Roles, second.Roles)
		})
	}
}
