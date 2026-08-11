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
			verifier := &mock.MockVerifier{
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
			built := setupAuth(t, &mock.MockVerifier{})
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
	verifier := &mock.MockVerifier{
		Err: fmt.Errorf("%w: store unreachable", types.ErrAuthorization),
	}

	recorder := httptest.NewRecorder()
	setupAuth(t, verifier).SessionHandler()(recorder, setupRequest("Bearer valid-token"))

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}
