package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/internal/mock"
	"github.com/amauryval/goauth/types"
)

func Test_Auth_SessionHandler(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		header         string
		verifyErr      bool
		authorized     bool
		grantedRoles   []types.Role
		wantLoggedIn   bool
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "authorized token reports its roles",
			header:         "Bearer valid-token",
			authorized:     true,
			grantedRoles:   []types.Role{types.RoleAdmin},
			wantLoggedIn:   true,
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:         "authenticated but unauthorized token reports no role",
			header:       "Bearer valid-token",
			wantLoggedIn: true,
		},
		{
			name:      "no token reports an anonymous session",
			verifyErr: true,
		},
		{
			name:      "rejected token reports an anonymous session",
			header:    "Bearer bad-token",
			verifyErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			verifier := &mock.Verifier{
				Info: types.SessionInfo{
					LoggedIn:   true,
					Authorized: c.authorized,
					Roles:      c.grantedRoles,
					User:       mock.SetupMockUser(),
				},
			}
			if c.verifyErr {
				verifier.Err = errors.New("token rejected")
			}

			recorder := httptest.NewRecorder()
			setupAuth(t, verifier).SessionHandler()(recorder, setupRequest(c.header))

			require.Equal(t, http.StatusOK, recorder.Code)

			var session types.SessionInfo
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &session))

			assert.Equal(t, c.wantLoggedIn, session.LoggedIn)
			assert.Equal(t, c.wantAuthorized, session.Authorized)
			assert.Equal(t, c.wantRoles, session.Roles)
		})
	}
}

func Test_Auth_ConfigHandler(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		issuerURL  string
		audience   string
		scopes     []string
		wantConfig ClientConfig
	}{
		{
			name:      "a configured provider is served with the scopes it demands",
			issuerURL: "https://issuer.example",
			audience:  "portfolio",
			scopes:    []string{"openid", "profile", "groups"},
			wantConfig: ClientConfig{
				IssuerURL: "https://issuer.example",
				ClientID:  "portfolio",
				Scopes:    "openid profile groups",
			},
		},
		{
			name: "demo mode serves nothing to sign in against",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			built := setupAuth(t, &mock.Verifier{})
			built.issuerURL = c.issuerURL
			built.audience = c.audience
			built.scopes = c.scopes

			recorder := httptest.NewRecorder()
			built.ConfigHandler()(recorder, setupRequest(""))

			require.Equal(t, http.StatusOK, recorder.Code)

			var config ClientConfig
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &config))

			assert.Equal(t, c.wantConfig, config)
		})
	}
}

func Test_Auth_SessionHandler_PolicyUnavailable(t *testing.T) {
	t.Parallel()

	verifier := &mock.Verifier{
		Err: fmt.Errorf("%w: store unreachable", types.ErrAuthorization),
	}

	recorder := httptest.NewRecorder()
	setupAuth(t, verifier).SessionHandler()(recorder, setupRequest("Bearer valid-token"))

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}

// stubRouter records the routes RegisterRoutes mounts, standing in for a chi.Router.
type stubRouter struct {
	mounted map[string]http.HandlerFunc
}

func (s *stubRouter) Get(pattern string, handler http.HandlerFunc) {
	s.mounted[pattern] = handler
}

func Test_Auth_RegisterRoutes(t *testing.T) {
	t.Parallel()

	auth, err := NewWithVerifier(&mock.Verifier{}, nil)
	require.NoError(t, err)

	router := &stubRouter{mounted: map[string]http.HandlerFunc{}}
	auth.RegisterRoutes(router)

	require.Len(t, router.mounted, 2)
	assert.Contains(t, router.mounted, ConfigPath)
	assert.Contains(t, router.mounted, SessionPath)
	assert.Equal(t, "/auth/config", ConfigPath)
	assert.Equal(t, "/auth/session", SessionPath)
}

// Test_Auth_SessionHandler_Encoding pins the wire shape of the session endpoint, which a browser
// parses: snake_case throughout, and no raw provider role name leaking out of UserInfo.
func Test_Auth_SessionHandler_Encoding(t *testing.T) {
	t.Parallel()

	verifier := &mock.Verifier{Info: types.SessionInfo{
		LoggedIn:   true,
		Authorized: true,
		Roles:      []types.Role{types.RoleAdmin},
		User:       mock.SetupMockUser(),
	}}

	auth, err := NewWithVerifier(verifier, nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	auth.SessionHandler()(recorder, httptest.NewRequest(http.MethodGet, SessionPath, nil))

	assert.JSONEq(t, `{
		"logged_in": true,
		"authorized": true,
		"roles": ["admin"],
		"user": {"provider": "https://provider.example.com", "id": "12345"}
	}`, recorder.Body.String())
	assert.NotContains(t, recorder.Body.String(), mock.MockRole)
}
