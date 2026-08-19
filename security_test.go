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
