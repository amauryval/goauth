package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/internal/mock"
	"github.com/amauryval/goauth/types"
)

// Test_bearerToken_Scheme pins RFC 6750: the scheme is case insensitive, and nothing else is
// accepted as a way to present a token.
func Test_bearerToken_Scheme(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header string
		query  string
		want   string
	}{
		{name: "the canonical spelling", header: "Bearer some-token", want: "some-token"},
		{name: "a lowercase scheme", header: "bearer some-token", want: "some-token"},
		{name: "an uppercase scheme", header: "BEARER some-token", want: "some-token"},
		{name: "another scheme is not a bearer token", header: "Basic some-token"},
		{name: "a bare token names no scheme", header: "some-token"},
		{name: "no header at all", header: ""},
		{name: "a token in the query string is ignored", query: "?access_token=some-token"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, "/"+c.query, nil)
			if c.header != "" {
				request.Header.Set("Authorization", c.header)
			}

			assert.Equal(t, c.want, bearerToken(request))
		})
	}
}

// Test_CachingHeaders pins that no response describing the caller may be cached, and that a shared
// cache is told the response turns on the Authorization header.
func Test_CachingHeaders(t *testing.T) {
	t.Parallel()

	authorized := types.SessionInfo{LoggedIn: true, Authorized: true, Roles: []types.Role{types.RoleAdmin}, User: mock.SetupMockUser()}

	cases := []struct {
		name     string
		info     types.SessionInfo
		handler  func(*Auth) http.Handler
		wantCode int
	}{
		{
			name:     "the session endpoint",
			info:     authorized,
			handler:  func(a *Auth) http.Handler { return a.SessionHandler() },
			wantCode: http.StatusOK,
		},
		{
			name: "a guarded route that lets the caller through",
			info: authorized,
			handler: func(a *Auth) http.Handler {
				return a.RequireRoles(types.RoleAdmin)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			},
			wantCode: http.StatusOK,
		},
		{
			name: "a guarded route that turns the caller away",
			handler: func(a *Auth) http.Handler {
				return a.RequireRoles(types.RoleAdmin)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			},
			wantCode: http.StatusForbidden,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			auth, err := NewWithVerifier(&mock.Verifier{Info: c.info}, nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			c.handler(auth).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

			assert.Equal(t, c.wantCode, recorder.Code)
			assert.Contains(t, recorder.Header().Values("Vary"), "Authorization")
			assert.Contains(t, recorder.Header().Values("Vary"), "Cookie",
				"a session arriving in a cookie is a credential a shared cache must vary on too")
		})
	}
}

func Test_SessionHandler_NoStore(t *testing.T) {
	t.Parallel()

	auth, err := NewWithVerifier(&mock.Verifier{}, nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	auth.SessionHandler()(recorder, httptest.NewRequest(http.MethodGet, SessionPath, nil))

	assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
}

// Test_respondUnauthorized_Challenge pins the challenge RFC 6750 expects on a 401.
func Test_respondUnauthorized_Challenge(t *testing.T) {
	t.Parallel()

	auth, err := NewWithVerifier(&mock.Verifier{Err: assert.AnError}, nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	guarded := auth.RequireRoles(types.RoleAdmin)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	guarded.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "Bearer", recorder.Header().Get("WWW-Authenticate"))
	assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
}

// Test_require_NilUser covers a TokenVerifier a host wrote itself reaching a decision without
// naming a user. Neither branch may take the server down, and an authorized decision without a
// user cannot be let through: the handlers behind it read UserFrom and would find nothing.
func Test_require_NilUser(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		info     types.SessionInfo
		wantCode int
	}{
		{
			name:     "an unauthorized decision naming no user",
			info:     types.SessionInfo{LoggedIn: true},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "an authorized decision naming no user",
			info:     types.SessionInfo{LoggedIn: true, Authorized: true, Roles: []types.Role{types.RoleAdmin}},
			wantCode: http.StatusUnauthorized,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			auth, err := NewWithVerifier(&mock.Verifier{Info: c.info}, nil)
			require.NoError(t, err)

			reached := false
			guarded := auth.RequireRoles(types.RoleAdmin)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				reached = true
			}))

			recorder := httptest.NewRecorder()

			assert.NotPanics(t, func() {
				guarded.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
			})

			assert.Equal(t, c.wantCode, recorder.Code)
			assert.False(t, reached)
		})
	}
}

// crossSiteSource stands in for a cookie based token source that refuses a request.
type crossSiteSource struct{ allow bool }

func (s crossSiteSource) Token(http.ResponseWriter, *http.Request) string { return "a-token" }

func (s crossSiteSource) Allow(*http.Request) bool { return s.allow }

// Test_require_RequestGuard pins that a token source refusing a request stops it before any
// verification, and that a source with no opinion changes nothing.
func Test_require_RequestGuard(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		source    TokenSource
		wantCode  int
		wantError string
	}{
		{
			name:      "a guard refusing the request",
			source:    crossSiteSource{allow: false},
			wantCode:  http.StatusForbidden,
			wantError: "cross_site",
		},
		{
			name:     "a guard allowing the request",
			source:   crossSiteSource{allow: true},
			wantCode: http.StatusOK,
		},
		{
			name:     "a source with no opinion",
			source:   bearerSource{},
			wantCode: http.StatusOK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			verifier := &mock.Verifier{Info: types.SessionInfo{
				LoggedIn:   true,
				Authorized: true,
				Roles:      []types.Role{types.RoleAdmin},
				User:       mock.SetupMockUser(),
			}}

			auth, err := NewWithVerifier(verifier, nil)
			require.NoError(t, err)

			auth.tokens = c.source

			recorder := httptest.NewRecorder()
			guarded := auth.RequireRoles(types.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			guarded.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/skills", nil))

			assert.Equal(t, c.wantCode, recorder.Code)

			if c.wantError != "" {
				assert.Contains(t, recorder.Body.String(), c.wantError)
				assert.Empty(t, verifier.ReceivedToken, "a refused request must not reach verification")
			}
		})
	}
}
