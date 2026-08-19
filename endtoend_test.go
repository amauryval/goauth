package goauth

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
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/provider"
	"github.com/amauryval/goauth/types"
)

const (
	e2eKeyID    = "e2e-key"
	e2eAudience = "portfolio"
	e2eSubject  = "the-signed-in-user"
	e2eRole     = "portfolio-admin"
)

// e2eIssuer is a provider complete enough to walk a whole login through: it signs, it exchanges,
// and it answers introspection. What a test changes about it is what the module is being asked to
// cope with.
type e2eIssuer struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	active    bool
	idNonce   string
	idSubject string
}

func setupE2EIssuer(t *testing.T) *e2eIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := &e2eIssuer{key: key, active: true}

	mux := http.NewServeMux()
	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer.server.URL,
			"jwks_uri":                              issuer.server.URL + "/keys",
			"authorization_endpoint":                issuer.server.URL + "/authorize",
			"token_endpoint":                        issuer.server.URL + "/token",
			"introspection_endpoint":                issuer.server.URL + "/introspect",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": e2eKeyID,
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	mux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"active": issuer.active, "sub": e2eSubject})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		subject := issuer.idSubject
		if subject == "" {
			subject = e2eSubject
		}

		idClaims := issuer.claims(subject)
		idClaims["nonce"] = issuer.idNonce
		idClaims["sid"] = "a-session-at-the-provider"

		// An access token carries the roles and no nonce; an ID token carries the nonce and no
		// roles. Mixing them up is exactly what the module refuses, so the fixture keeps them apart.
		accessClaims := issuer.claims(e2eSubject)
		accessClaims[provider.Zitadel.RolesClaim()] = map[string]any{e2eRole: map[string]any{}}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  issuer.sign(t, accessClaims),
			"id_token":      issuer.sign(t, idClaims),
			"refresh_token": "a-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	return issuer
}

func (i *e2eIssuer) claims(subject string) map[string]any {
	return map[string]any{
		"iss": i.server.URL,
		"aud": e2eAudience,
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
}

func (i *e2eIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		require.NoError(t, err)

		return base64.RawURLEncoding.EncodeToString(raw)
	}

	signingInput := encode(map[string]any{"alg": "RS256", "typ": "JWT", "kid": e2eKeyID}) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// setupE2EAuth assembles the module exactly as a deployment would, against the test issuer.
//
// The issuer is asked about every request rather than every fifteen seconds: what these tests are
// about is the issuer's word governing, and the window it is reused for has its own tests.
func setupE2EAuth(t *testing.T, issuer *e2eIssuer) *Auth {
	t.Helper()

	auth, err := New(context.Background(), NewSettings(Options{
		ProviderName:     provider.Zitadel.Name(),
		IssuerURL:        issuer.server.URL,
		Audience:         e2eAudience,
		AdminRole:        e2eRole,
		IntrospectionTTL: -time.Second,
		Browser: &BrowserOptions{
			RedirectURL:     "http://app.example.com/auth/callback",
			Secret:          []byte("an-end-to-end-cookie-secret-of-enough-bytes"),
			InsecureCookies: true,
		},
	}), nil)
	require.NoError(t, err)

	return auth
}

// signIn walks a browser through the whole login and returns the session cookie it ends up with.
func signIn(t *testing.T, auth *Auth, issuer *e2eIssuer) *http.Cookie {
	t.Helper()

	started := httptest.NewRecorder()
	auth.LoginHandler()(started, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	require.Equal(t, http.StatusFound, started.Code)

	target, err := url.Parse(started.Header().Get("Location"))
	require.NoError(t, err)

	// The provider mints its ID token for the login it was actually sent through.
	issuer.idNonce = target.Query().Get("nonce")

	callback := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, CallbackPath+"?code=a-code&state="+url.QueryEscape(target.Query().Get("state")), nil)

	for _, cookie := range started.Result().Cookies() {
		request.AddCookie(cookie)
	}

	auth.CallbackHandler()(callback, request)
	require.Equal(t, http.StatusFound, callback.Code, "the login must complete: %s", callback.Body.String())

	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == "goauth_session" && cookie.MaxAge >= 0 {
			return cookie
		}
	}

	t.Fatal("the login established no session")

	return nil
}

// Test_EndToEnd_BrowserSession walks the whole thing: a login, then the session cookie used
// against a guarded route, with nothing stubbed but the provider.
//
// Every part of this was tested on its own before this test existed, and none of it had ever been
// run joined together.
func Test_EndToEnd_BrowserSession(t *testing.T) {
	t.Parallel()

	issuer := setupE2EIssuer(t)
	auth := setupE2EAuth(t, issuer)
	session := signIn(t, auth, issuer)

	require.True(t, session.HttpOnly, "the session must be out of reach of JavaScript")

	reached := false
	guarded := auth.RequireRoles(types.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, found := UserFrom(r.Context())
		require.True(t, found)
		assert.Equal(t, e2eSubject, user.ID)

		reached = true

		w.WriteHeader(http.StatusOK)
	}))

	t.Run("the session opens a guarded route", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/api/skills", nil)
		request.AddCookie(session)

		recorder := httptest.NewRecorder()
		guarded.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.True(t, reached, "the handler must run, with the user in its context")
	})

	t.Run("the session reports itself", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, SessionPath, nil)
		request.AddCookie(session)

		recorder := httptest.NewRecorder()
		auth.SessionHandler()(recorder, request)

		var reported types.SessionInfo
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &reported))

		assert.True(t, reported.LoggedIn)
		assert.True(t, reported.Authorized)
		assert.Equal(t, []types.Role{types.RoleAdmin}, reported.Roles)
	})

	t.Run("a write from another site is refused", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/skills", nil)
		request.AddCookie(session)
		request.Header.Set("Origin", "https://evil.example.com")

		recorder := httptest.NewRecorder()
		guarded.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusForbidden, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "cross_site")
	})

	t.Run("a write from this application goes through", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/skills", nil)
		request.AddCookie(session)
		request.Header.Set("Origin", "http://app.example.com")

		recorder := httptest.NewRecorder()
		guarded.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

// Test_EndToEnd_IssuerDisownsTheToken is the constraint the architecture is built on, seen from
// the outside: the provider changes its mind, and the very next request stops working.
func Test_EndToEnd_IssuerDisownsTheToken(t *testing.T) {
	t.Parallel()

	issuer := setupE2EIssuer(t)
	auth := setupE2EAuth(t, issuer)
	session := signIn(t, auth, issuer)

	guarded := auth.RequireRoles(types.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	call := func() int {
		request := httptest.NewRequest(http.MethodGet, "/api/skills", nil)
		request.AddCookie(session)

		recorder := httptest.NewRecorder()
		guarded.ServeHTTP(recorder, request)

		return recorder.Code
	}

	require.Equal(t, http.StatusOK, call())

	// The account is disabled at the provider. Nothing about the token changed: same signature,
	// same expiry, still hours away.
	issuer.active = false

	assert.Equal(t, http.StatusUnauthorized, call(), "the issuer disowned the token, so it stops working")
}

// Test_EndToEnd_ReplayedIDToken pins the one thing the ID token is verified for: that this login
// was completed by the browser that started it. A token minted for some other login carries some
// other nonce, and establishes nothing.
func Test_EndToEnd_ReplayedIDToken(t *testing.T) {
	t.Parallel()

	issuer := setupE2EIssuer(t)
	auth := setupE2EAuth(t, issuer)

	started := httptest.NewRecorder()
	auth.LoginHandler()(started, httptest.NewRequest(http.MethodGet, LoginPath, nil))

	target, err := url.Parse(started.Header().Get("Location"))
	require.NoError(t, err)

	// The provider answers with an ID token from a login this browser never started.
	issuer.idNonce = "the-nonce-of-another-login"

	callback := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, CallbackPath+"?code=a-code&state="+url.QueryEscape(target.Query().Get("state")), nil)

	for _, cookie := range started.Result().Cookies() {
		request.AddCookie(cookie)
	}

	auth.CallbackHandler()(callback, request)

	assert.Equal(t, http.StatusForbidden, callback.Code)

	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == "goauth_session" {
			assert.Negative(t, cookie.MaxAge, "no session may be established")
		}
	}
}
