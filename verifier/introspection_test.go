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
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/types"
)

// introspecting starts an issuer that advertises an introspection endpoint and answers it with the
// given body, recording what it was asked and how often.
func introspecting(t *testing.T, status int, answer map[string]any) (*httptest.Server, *rsa.PrivateKey, *atomic.Int64, *url.Values) {
	t.Helper()

	var (
		calls atomic.Int64
		asked url.Values
	)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/keys",
			"introspection_endpoint":                server.URL + "/introspect",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)

		require.NoError(t, r.ParseForm())

		asked = r.PostForm

		w.WriteHeader(status)

		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(answer)
		}
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": testKeyID,
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	return server, key, &calls, &asked
}

func introspectingVerifier(t *testing.T, issuerURL string, adjust func(*Config)) *Verifier {
	t.Helper()

	config := Config{
		IssuerURL:  issuerURL,
		Audience:   testAudience,
		RolesClaim: testRolesClaim,
	}

	if adjust != nil {
		adjust(&config)
	}

	built, err := New(context.Background(), setupAuthorizer(), config)
	require.NoError(t, err)

	return built
}

// Test_Verifier_Verify_Introspection is the heart of it: a token the issuer no longer stands
// behind is refused, however valid its signature and however far off its expiry.
//
// This is what a disabled account, a changed password and an ended session all look like from
// here. Nothing in the token itself says any of them happened.
func Test_Verifier_Verify_Introspection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		status     int
		answer     map[string]any
		wantErr    bool
		wantOutage bool
	}{
		{
			name:   "a token the issuer stands behind is honoured",
			status: http.StatusOK,
			answer: map[string]any{"active": true, "sub": testAdminSub},
		},
		{
			name:    "a token the issuer disowns is refused",
			status:  http.StatusOK,
			answer:  map[string]any{"active": false},
			wantErr: true,
		},
		{
			name:    "an answer that states nothing is a refusal",
			status:  http.StatusOK,
			answer:  map[string]any{},
			wantErr: true,
		},
		{
			name:       "an issuer that cannot answer is an outage, not a refusal",
			status:     http.StatusInternalServerError,
			wantErr:    true,
			wantOutage: true,
		},
		{
			name:       "an issuer refusing the question is an outage too",
			status:     http.StatusUnauthorized,
			wantErr:    true,
			wantOutage: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			server, key, calls, asked := introspecting(t, c.status, c.answer)
			built := introspectingVerifier(t, server.URL, nil)

			claims := setupClaims(server.URL, testAudience, testAdminSub, time.Now().Add(time.Hour))
			claims[testRolesClaim] = []any{testAdminRole}

			info, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

			assert.Positive(t, calls.Load(), "the issuer must be asked")
			assert.Equal(t, "access_token", asked.Get("token_type_hint"))

			if !c.wantErr {
				require.NoError(t, err)
				assert.True(t, info.Authorized)

				return
			}

			require.Error(t, err)
			assert.Equal(t, types.SessionInfo{}, info)

			if c.wantOutage {
				assert.ErrorIs(t, err, types.ErrAuthorization, "not knowing is not being told no")

				return
			}

			assert.NotErrorIs(t, err, types.ErrAuthorization, "the issuer said no, which is a rejection")
		})
	}
}

// Test_Verifier_Verify_IntrospectionDefault pins that asking is the default: a deployment gets it
// from discovery alone, without having to know it should ask for it.
func Test_Verifier_Verify_IntrospectionDefault(t *testing.T) {
	t.Parallel()

	server, key, calls, _ := introspecting(t, http.StatusOK, map[string]any{"active": false})
	built := introspectingVerifier(t, server.URL, nil)

	claims := setupClaims(server.URL, testAudience, testAdminSub, time.Now().Add(time.Hour))

	_, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

	require.Error(t, err)
	assert.Equal(t, int64(1), calls.Load())
}

// Test_Verifier_Verify_NoIntrospectionEndpoint pins the one case where the issuer is not asked:
// it advertises nowhere to ask. That is the issuer's statement about itself, not a choice made
// here, and there is no setting that declines to ask an issuer that can answer.
func Test_Verifier_Verify_NoIntrospectionEndpoint(t *testing.T) {
	t.Parallel()

	server, key := setupIssuer(t)
	built := setupVerifier(t, server.URL)

	claims := setupClaims(server.URL, testAudience, testAdminSub, time.Now().Add(time.Hour))
	claims[testRolesClaim] = []any{testAdminRole}

	info, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

	require.NoError(t, err)
	assert.True(t, info.Authorized)
}

// Test_Verifier_Verify_IntrospectionCaching pins the trade a TTL makes, and that a refusal is
// never what gets cached.
func Test_Verifier_Verify_IntrospectionCaching(t *testing.T) {
	t.Parallel()

	t.Run("the default keeps the issuer off the path of nearly every request", func(t *testing.T) {
		t.Parallel()

		server, key, calls, _ := introspecting(t, http.StatusOK, map[string]any{"active": true})
		built := introspectingVerifier(t, server.URL, nil)

		now := time.Now()
		built.now = func() time.Time { return now }

		token := setupSignedToken(t, key, setupClaims(server.URL, testAudience, testAdminSub, now.Add(time.Hour)))

		_, first := built.Verify(context.Background(), token)
		_, second := built.Verify(context.Background(), token)

		require.NoError(t, first)
		require.NoError(t, second)
		assert.Equal(t, int64(1), calls.Load())

		// Past the default window the issuer is asked again, which is what bounds how long a
		// revoked token keeps working.
		now = now.Add(defaultIntrospectionTTL + time.Second)

		_, third := built.Verify(context.Background(), token)

		require.NoError(t, third)
		assert.Equal(t, int64(2), calls.Load())
	})

	t.Run("a negative ttl asks the issuer every single time", func(t *testing.T) {
		t.Parallel()

		server, key, calls, _ := introspecting(t, http.StatusOK, map[string]any{"active": true})
		built := introspectingVerifier(t, server.URL, func(c *Config) { c.IntrospectionTTL = -time.Second })

		token := setupSignedToken(t, key, setupClaims(server.URL, testAudience, testAdminSub, time.Now().Add(time.Hour)))

		_, first := built.Verify(context.Background(), token)
		_, second := built.Verify(context.Background(), token)

		require.NoError(t, first)
		require.NoError(t, second)
		assert.Equal(t, int64(2), calls.Load())
	})

	t.Run("a ttl reuses the answer for that long", func(t *testing.T) {
		t.Parallel()

		server, key, calls, _ := introspecting(t, http.StatusOK, map[string]any{"active": true})
		built := introspectingVerifier(t, server.URL, func(c *Config) { c.IntrospectionTTL = time.Minute })

		now := time.Now()
		built.now = func() time.Time { return now }

		token := setupSignedToken(t, key, setupClaims(server.URL, testAudience, testAdminSub, now.Add(time.Hour)))

		_, first := built.Verify(context.Background(), token)
		_, second := built.Verify(context.Background(), token)

		require.NoError(t, first)
		require.NoError(t, second)
		assert.Equal(t, int64(1), calls.Load())

		now = now.Add(2 * time.Minute)

		_, third := built.Verify(context.Background(), token)

		require.NoError(t, third)
		assert.Equal(t, int64(2), calls.Load(), "the answer is reused, never kept")
	})
}

// Test_New_RequireIntrospection pins the deployment-time refusal: an issuer that advertises
// nowhere to ask whether a token is still active leaves this module unable to tell a live account
// from a disabled one, and a deployment that cannot live with that says so rather than reading a
// warning in a log.
func Test_New_RequireIntrospection(t *testing.T) {
	t.Parallel()

	t.Run("an issuer advertising none is refused", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t)

		built, err := New(context.Background(), setupAuthorizer(), Config{
			IssuerURL:            server.URL,
			Audience:             testAudience,
			RolesClaim:           testRolesClaim,
			RequireIntrospection: true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no introspection endpoint")
		assert.Nil(t, built)
	})

	t.Run("an issuer advertising one is accepted", func(t *testing.T) {
		t.Parallel()

		server, _, _, _ := introspecting(t, http.StatusOK, map[string]any{"active": true})

		built, err := New(context.Background(), setupAuthorizer(), Config{
			IssuerURL:            server.URL,
			Audience:             testAudience,
			RolesClaim:           testRolesClaim,
			RequireIntrospection: true,
		})

		require.NoError(t, err)
		require.NotNil(t, built)
		assert.NotNil(t, built.introspector, "the issuer advertises one, so it must be asked")
	})

	t.Run("without the requirement an issuer advertising none still starts", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t)

		built, err := New(context.Background(), setupAuthorizer(), Config{
			IssuerURL:  server.URL,
			Audience:   testAudience,
			RolesClaim: testRolesClaim,
		})

		require.NoError(t, err)
		require.NotNil(t, built)
		assert.Nil(t, built.introspector, "there is nowhere to ask, so nothing is asked")
	})
}
