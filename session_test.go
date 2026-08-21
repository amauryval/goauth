package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/browser"
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
	methods map[string]string
}

func newStubRouter() *stubRouter {
	return &stubRouter{mounted: map[string]http.HandlerFunc{}, methods: map[string]string{}}
}

func (s *stubRouter) Get(pattern string, handler http.HandlerFunc) {
	s.mounted[pattern] = handler
	s.methods[pattern] = http.MethodGet
}

func (s *stubRouter) Post(pattern string, handler http.HandlerFunc) {
	s.mounted[pattern] = handler
	s.methods[pattern] = http.MethodPost
}

func Test_Auth_RegisterRoutes(t *testing.T) {
	t.Parallel()

	auth, err := NewWithVerifier(&mock.Verifier{}, nil)
	require.NoError(t, err)

	router := newStubRouter()
	auth.RegisterRoutes(router)

	require.Len(t, router.mounted, 2, "a deployment without the browser flow mounts no login endpoint")
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

// profileVerifier is a mock.Verifier that can also describe the user, as *verifier.Verifier does.
// It records whether it was asked, which is how a test tells a lookup that was skipped from one
// that returned nothing.
type profileVerifier struct {
	mock.Verifier

	profile *types.Profile
	err     error
	asked   bool
}

// Profile records the question and returns the canned answer.
func (m *profileVerifier) Profile(_ context.Context, _, _ string) (*types.Profile, error) {
	m.asked = true

	return m.profile, m.err
}

// Test_Auth_SessionHandler_Profile covers what a browser that never sees an ID token is told about
// itself: the claims come from the issuer, and only where this module signed the visitor in.
func Test_Auth_SessionHandler_Profile(t *testing.T) {
	t.Parallel()

	described := &types.Profile{Username: "amaury", Name: "Amaury Valorge"}

	cases := []struct {
		name        string
		serverFlow  bool
		loggedIn    bool
		profile     *types.Profile
		profileErr  error
		wantAsked   bool
		wantProfile *types.Profile
	}{
		{
			name:        "a server driven session is told who signed in",
			serverFlow:  true,
			loggedIn:    true,
			profile:     described,
			wantAsked:   true,
			wantProfile: described,
		},
		{
			// A browser holding its own tokens reads these claims from its own ID token, so
			// spending a round trip to repeat them back would buy it nothing.
			name:       "a browser driven session is told nothing this module did not decide",
			serverFlow: false,
			loggedIn:   true,
			profile:    described,
		},
		{
			name:       "an anonymous session describes nobody, and asks nobody",
			serverFlow: true,
			loggedIn:   false,
			profile:    described,
		},
		{
			// The session was established before the profile was ever asked for: losing the name
			// costs a name, and refusing the session would send the visitor back through a login.
			name:       "a failing lookup costs the name and not the session",
			serverFlow: true,
			loggedIn:   true,
			profileErr: errors.New("userinfo unavailable"),
			wantAsked:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			verifier := &profileVerifier{profile: c.profile, err: c.profileErr}
			verifier.Info = types.SessionInfo{
				LoggedIn:   true,
				Authorized: true,
				User:       mock.SetupMockUser(),
			}

			if !c.loggedIn {
				verifier.Err = errors.New("token rejected")
			}

			auth := setupAuth(t, verifier)
			if c.serverFlow {
				// Only its presence is read here: what the flow does with a login has its own tests.
				auth.flow = &browser.Flow{}
			}

			recorder := httptest.NewRecorder()
			auth.SessionHandler()(recorder, setupRequest("Bearer valid-token"))

			require.Equal(t, http.StatusOK, recorder.Code)

			var session types.SessionInfo
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &session))

			assert.Equal(t, c.wantAsked, verifier.asked)
			assert.Equal(t, c.wantProfile, session.Profile)
		})
	}
}
