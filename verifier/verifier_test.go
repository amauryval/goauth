package verifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/authorization"
	"goauth/types"
)

const (
	testKeyID      = "test-key"
	testRolesClaim = "urn:zitadel:iam:org:project:roles"
	testAudience   = "portfolio"
	testAdminSub   = "admin-subject"
	testAdminRole  = "portfolio-admin"
	testEditorRole = "portfolio-editor"
	roleEditor     = types.Role("editor")
)

func setupIssuer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()

	server, key, _ := setupIssuerWithUserInfo(t)

	return server, key
}

// setupIssuerWithUserInfo starts an issuer whose UserInfo endpoint serves the returned claims,
// which a test fills in before presenting a token.
func setupIssuerWithUserInfo(t *testing.T) (*httptest.Server, *rsa.PrivateKey, map[string]any) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	userInfo := map[string]any{}

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/keys",
			"authorization_endpoint":                server.URL + "/auth",
			"token_endpoint":                        server.URL + "/token",
			"userinfo_endpoint":                     server.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		_ = json.NewEncoder(w).Encode(userInfo)
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

	return server, key, userInfo
}

func setupAuthorizer() types.Authorizer {
	return authorization.FromTokenNames(map[string]types.Role{
		testAdminRole:  types.RoleAdmin,
		testEditorRole: roleEditor,
	})
}

func setupSignedToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		require.NoError(t, err)

		return base64.RawURLEncoding.EncodeToString(raw)
	}

	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": testKeyID}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func setupClaims(issuer, audience, subject string, expiry time.Time) map[string]any {
	return map[string]any{
		"iss": issuer,
		"aud": audience,
		"sub": subject,
		"exp": expiry.Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
}

func setupVerifier(t *testing.T, issuerURL string) *Verifier {
	t.Helper()

	built, err := New(context.Background(), setupAuthorizer(), Config{
		IssuerURL:  issuerURL,
		Audience:   testAudience,
		RolesClaim: testRolesClaim,
	})
	require.NoError(t, err)

	return built
}

func Test_New(t *testing.T) {
	server, _ := setupIssuer(t)

	cases := []struct {
		name          string
		issuerURL     string
		audience      string
		rolesClaim    string
		noAuthorizer  bool
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:       "valid configuration",
			issuerURL:  server.URL,
			audience:   testAudience,
			rolesClaim: testRolesClaim,
		},
		{
			name:          "missing roles claim",
			issuerURL:     server.URL,
			audience:      testAudience,
			wantErr:       true,
			wantErrSubstr: "roles claim",
		},
		{
			name:          "missing authorizer",
			issuerURL:     server.URL,
			audience:      testAudience,
			rolesClaim:    testRolesClaim,
			noAuthorizer:  true,
			wantErr:       true,
			wantErrSubstr: "authorizer",
		},
		{
			name:          "missing issuer URL",
			audience:      testAudience,
			rolesClaim:    testRolesClaim,
			wantErr:       true,
			wantErrSubstr: "issuer URL",
		},
		{
			name:          "missing audience",
			issuerURL:     server.URL,
			rolesClaim:    testRolesClaim,
			wantErr:       true,
			wantErrSubstr: "audience",
		},
		{
			name:          "unreachable issuer",
			issuerURL:     "http://127.0.0.1:1",
			audience:      testAudience,
			rolesClaim:    testRolesClaim,
			wantErr:       true,
			wantErrSubstr: "oidc discovery failed",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var authorizer types.Authorizer
			if !c.noAuthorizer {
				authorizer = setupAuthorizer()
			}

			built, err := New(context.Background(), authorizer, Config{
				IssuerURL:  c.issuerURL,
				Audience:   c.audience,
				RolesClaim: c.rolesClaim,
			})

			if c.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErrSubstr)
				assert.Nil(t, built)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, built)
		})
	}
}

func Test_Verifier_Verify(t *testing.T) {
	server, key := setupIssuer(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cases := []struct {
		name           string
		audience       string
		subject        string
		roles          []any
		extraClaims    map[string]any
		expiresIn      time.Duration
		wrongIssuer    bool
		signWithOther  bool
		malformedToken bool
		wantErr        bool
		wantErrPart    string
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "a mapped provider role grants the admin role",
			audience:       testAudience,
			subject:        testAdminSub,
			roles:          []any{testAdminRole},
			expiresIn:      time.Hour,
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:           "another mapped provider role grants its own",
			audience:       testAudience,
			subject:        "other-subject",
			roles:          []any{testEditorRole},
			expiresIn:      time.Hour,
			wantAuthorized: true,
			wantRoles:      []types.Role{roleEditor},
		},
		{
			name:      "an unmapped role is authenticated but not authorized",
			audience:  testAudience,
			subject:   "unknown-subject",
			roles:     []any{"someone-else"},
			expiresIn: time.Hour,
		},
		{
			name:      "a token carrying no role is authenticated but not authorized",
			audience:  testAudience,
			subject:   "unknown-subject",
			expiresIn: time.Hour,
		},
		{
			name:      "token issued for another application is rejected",
			audience:  "another-app",
			subject:   testAdminSub,
			expiresIn: time.Hour,
			wantErr:   true,
		},
		{
			name:      "expired token is rejected",
			audience:  testAudience,
			subject:   testAdminSub,
			expiresIn: -time.Hour,
			wantErr:   true,
		},
		{
			name:          "token signed by an unknown key is rejected",
			audience:      testAudience,
			subject:       testAdminSub,
			expiresIn:     time.Hour,
			signWithOther: true,
			wantErr:       true,
		},
		{
			name:        "token from another issuer is rejected",
			audience:    testAudience,
			subject:     testAdminSub,
			expiresIn:   time.Hour,
			wrongIssuer: true,
			wantErr:     true,
		},
		{
			name:        "token without a subject is rejected",
			audience:    testAudience,
			roles:       []any{testAdminRole},
			expiresIn:   time.Hour,
			wantErr:     true,
			wantErrPart: "subject",
		},
		{
			name:        "id token carrying a nonce is rejected",
			audience:    testAudience,
			subject:     testAdminSub,
			roles:       []any{testAdminRole},
			extraClaims: map[string]any{"nonce": "browser-nonce"},
			expiresIn:   time.Hour,
			wantErr:     true,
			wantErrPart: "id token",
		},
		{
			name:        "id token carrying an access token hash is rejected",
			audience:    testAudience,
			subject:     testAdminSub,
			roles:       []any{testAdminRole},
			extraClaims: map[string]any{"at_hash": "hash"},
			expiresIn:   time.Hour,
			wantErr:     true,
			wantErrPart: "id token",
		},
		{
			name:        "id token carrying an authorization code hash is rejected",
			audience:    testAudience,
			subject:     testAdminSub,
			roles:       []any{testAdminRole},
			extraClaims: map[string]any{"c_hash": "hash"},
			expiresIn:   time.Hour,
			wantErr:     true,
			wantErrPart: "id token",
		},
		{
			name:           "malformed token is rejected",
			malformedToken: true,
			wantErr:        true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			built := setupVerifier(t, server.URL)

			rawToken := "not-a-jwt"
			if !c.malformedToken {
				issuer := server.URL
				if c.wrongIssuer {
					issuer = "https://evil.example.com"
				}

				claims := setupClaims(issuer, c.audience, c.subject, time.Now().Add(c.expiresIn))
				if c.roles != nil {
					claims[testRolesClaim] = c.roles
				}

				for name, value := range c.extraClaims {
					claims[name] = value
				}

				signingKey := key
				if c.signWithOther {
					signingKey = otherKey
				}

				rawToken = setupSignedToken(t, signingKey, claims)
			}

			info, err := built.Verify(context.Background(), rawToken)

			if c.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErrPart)
				assert.False(t, info.LoggedIn)
				assert.Nil(t, info.User)

				return
			}

			require.NoError(t, err)
			assert.True(t, info.LoggedIn)
			assert.Equal(t, c.wantAuthorized, info.Authorized)
			assert.Equal(t, c.wantRoles, info.Roles)

			require.NotNil(t, info.User)
			assert.Equal(t, c.subject, info.User.ID)
			assert.Equal(t, server.URL, info.User.Provider)
		})
	}
}
