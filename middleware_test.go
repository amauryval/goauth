package goauth

import (
	"context"
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

const roleEditor = types.Role("editor")

func setupAuth(t *testing.T, verifier types.TokenVerifier) *Auth {
	t.Helper()

	built, err := NewWithVerifier(verifier, nil)
	require.NoError(t, err)

	return built
}

func setupRequest(header string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if header != "" {
		request.Header.Set("Authorization", header)
	}

	return request
}

func Test_Auth_RequireRoles(t *testing.T) {
	cases := []struct {
		name           string
		header         string
		verifyErr      bool
		policyDown     bool
		authorized     bool
		grantedRoles   []types.Role
		requiredRoles  []types.Role
		wantStatus     int
		wantHandlerHit bool
		wantToken      string
	}{
		{
			name:           "authorized user holding the required role passes",
			header:         "Bearer valid-token",
			authorized:     true,
			grantedRoles:   []types.Role{types.RoleAdmin},
			requiredRoles:  []types.Role{types.RoleAdmin},
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
			wantToken:      "valid-token",
		},
		{
			name:           "no role required lets any authorized user through",
			header:         "Bearer valid-token",
			authorized:     true,
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
			wantToken:      "valid-token",
		},
		{
			name:           "every required role must be held",
			header:         "Bearer valid-token",
			authorized:     true,
			grantedRoles:   []types.Role{types.RoleAdmin, roleEditor},
			requiredRoles:  []types.Role{types.RoleAdmin, roleEditor},
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
			wantToken:      "valid-token",
		},
		{
			name:          "missing one of the required roles is forbidden",
			header:        "Bearer valid-token",
			authorized:    true,
			grantedRoles:  []types.Role{roleEditor},
			requiredRoles: []types.Role{types.RoleAdmin, roleEditor},
			wantStatus:    http.StatusForbidden,
			wantToken:     "valid-token",
		},
		{
			name:          "authenticated but unauthorized user is forbidden",
			header:        "Bearer valid-token",
			requiredRoles: []types.Role{types.RoleAdmin},
			wantStatus:    http.StatusForbidden,
			wantToken:     "valid-token",
		},
		{
			name:          "missing Authorization header reaches the verifier with no token",
			verifyErr:     true,
			requiredRoles: []types.Role{types.RoleAdmin},
			wantStatus:    http.StatusUnauthorized,
			wantToken:     "",
		},
		{
			name:          "non bearer scheme yields no token",
			header:        "Basic dXNlcjpwYXNz",
			verifyErr:     true,
			requiredRoles: []types.Role{types.RoleAdmin},
			wantStatus:    http.StatusUnauthorized,
			wantToken:     "",
		},
		{
			name:           "surrounding spaces are trimmed from the token",
			header:         "Bearer   valid-token  ",
			authorized:     true,
			grantedRoles:   []types.Role{types.RoleAdmin},
			requiredRoles:  []types.Role{types.RoleAdmin},
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
			wantToken:      "valid-token",
		},
		{
			name:          "an unavailable policy is a service error, not a rejection",
			header:        "Bearer valid-token",
			policyDown:    true,
			requiredRoles: []types.Role{types.RoleAdmin},
			wantStatus:    http.StatusServiceUnavailable,
			wantToken:     "valid-token",
		},
		{
			name:          "rejected token is unauthorized",
			header:        "Bearer bad-token",
			verifyErr:     true,
			requiredRoles: []types.Role{types.RoleAdmin},
			wantStatus:    http.StatusUnauthorized,
			wantToken:     "bad-token",
		},
		{
			name:           "a verifier authorizing without a token lets the request through",
			authorized:     true,
			grantedRoles:   []types.Role{types.RoleAdmin},
			requiredRoles:  []types.Role{types.RoleAdmin},
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
			wantToken:      "",
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

			if c.policyDown {
				verifier.Err = fmt.Errorf("%w: store unreachable", types.ErrAuthorization)
			}

			handlerHit := false
			handler := setupAuth(t, verifier).RequireRoles(c.requiredRoles...)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handlerHit = true

					user, found := UserFrom(r.Context())
					assert.True(t, found)
					assert.Equal(t, mock.SetupMockUser().ID, user.ID)
				}),
			)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, setupRequest(c.header))

			assert.Equal(t, c.wantStatus, recorder.Code)
			assert.Equal(t, c.wantHandlerHit, handlerHit)
			assert.Equal(t, c.wantToken, verifier.ReceivedToken)
		})
	}
}

func Test_Auth_RequireAnyRole(t *testing.T) {
	cases := []struct {
		name           string
		grantedRoles   []types.Role
		requiredRoles  []types.Role
		wantStatus     int
		wantHandlerHit bool
	}{
		{
			name:           "holding one of the required roles is enough",
			grantedRoles:   []types.Role{types.RoleGuest},
			requiredRoles:  []types.Role{types.RoleAdmin, types.RoleGuest},
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
		},
		{
			name:           "holding the other required role is enough",
			grantedRoles:   []types.Role{types.RoleAdmin},
			requiredRoles:  []types.Role{types.RoleAdmin, types.RoleGuest},
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
		},
		{
			name:          "holding none of the required roles is forbidden",
			grantedRoles:  []types.Role{roleEditor},
			requiredRoles: []types.Role{types.RoleAdmin, types.RoleGuest},
			wantStatus:    http.StatusForbidden,
		},
		{
			name:           "no role required lets any authorized user through",
			wantStatus:     http.StatusOK,
			wantHandlerHit: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verifier := &mock.MockVerifier{
				Info: types.SessionInfo{
					LoggedIn:   true,
					Authorized: true,
					Roles:      c.grantedRoles,
					User:       mock.SetupMockUser(),
				},
			}

			handlerHit := false
			handler := setupAuth(t, verifier).RequireAnyRole(c.requiredRoles...)(
				http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
					handlerHit = true
				}),
			)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, setupRequest("Bearer valid-token"))

			assert.Equal(t, c.wantStatus, recorder.Code)
			assert.Equal(t, c.wantHandlerHit, handlerHit)
		})
	}
}

func Test_UserFrom(t *testing.T) {
	cases := []struct {
		name     string
		hasUser  bool
		wantUser bool
	}{
		{
			name:     "context carrying a user",
			hasUser:  true,
			wantUser: true,
		},
		{
			name: "bare context carries nothing",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			if c.hasUser {
				ctx = context.WithValue(ctx, userContextKey{}, mock.SetupMockUser())
			}

			user, found := UserFrom(ctx)

			assert.Equal(t, c.wantUser, found)
			if c.wantUser {
				require.NotNil(t, user)
				assert.Equal(t, mock.SetupMockUser().ID, user.ID)

				return
			}

			assert.Nil(t, user)
		})
	}
}
