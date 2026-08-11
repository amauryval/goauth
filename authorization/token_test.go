package authorization_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/authorization"
	"github.com/amauryval/goauth/types"
)

func setupUser() *types.UserInfo {
	return &types.UserInfo{
		Provider: "https://provider.example.com",
		ID:       "12345",
	}
}

func Test_FromTokenNames(t *testing.T) {
	cases := []struct {
		name           string
		claimed        []string
		names          map[string]types.Role
		noUser         bool
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "a provider name grants the role it maps to",
			claimed:        []string{"portfolio_admin"},
			names:          map[string]types.Role{"portfolio_admin": types.RoleAdmin},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:           "provider names are matched regardless of case",
			claimed:        []string{"Portfolio_Admin"},
			names:          map[string]types.Role{"portfolio_admin": types.RoleAdmin},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:           "each mapped name grants its own role",
			claimed:        []string{"reader", "writer"},
			names:          map[string]types.Role{"writer": types.RoleAdmin, "reader": types.RoleGuest},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest, types.RoleAdmin},
		},
		{
			name:    "an unmapped provider name is ignored",
			claimed: []string{"admin"},
			names:   map[string]types.Role{"portfolio_admin": types.RoleAdmin},
		},
		{
			name:    "an unset name never matches",
			claimed: []string{""},
			names:   map[string]types.Role{"": types.RoleAdmin},
		},
		{
			name:    "mapping no name authorizes nobody",
			claimed: []string{"portfolio_admin"},
		},
		{
			name:   "nil user is not authorized",
			noUser: true,
			names:  map[string]types.Role{"portfolio_admin": types.RoleAdmin},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user := setupUser()
			user.Roles = c.claimed

			if c.noUser {
				user = nil
			}

			decision, err := authorization.FromTokenNames(c.names).Authorize(context.Background(), user)

			require.NoError(t, err)
			assert.Equal(t, c.wantAuthorized, decision.Authorized)
			assert.Equal(t, c.wantRoles, decision.Roles)
		})
	}
}

func Test_FromToken(t *testing.T) {
	cases := []struct {
		name           string
		claimed        []string
		declared       []types.Role
		noUser         bool
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "a declared role is granted",
			claimed:        []string{"admin"},
			declared:       []types.Role{types.RoleAdmin, types.RoleGuest},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:           "every declared role is granted",
			claimed:        []string{"guest", "admin"},
			declared:       []types.Role{types.RoleAdmin, types.RoleGuest},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest, types.RoleAdmin},
		},
		{
			name:           "role names are matched regardless of case",
			claimed:        []string{"Admin"},
			declared:       []types.Role{types.RoleAdmin},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:     "a role the application does not declare is ignored",
			claimed:  []string{"superadmin"},
			declared: []types.Role{types.RoleAdmin, types.RoleGuest},
		},
		{
			name:     "a user carrying no role is not authorized",
			declared: []types.Role{types.RoleAdmin},
		},
		{
			name:     "declaring no role authorizes nobody",
			claimed:  []string{"admin"},
			declared: nil,
		},
		{
			name:     "a duplicated role is granted once",
			claimed:  []string{"admin", "ADMIN"},
			declared: []types.Role{types.RoleAdmin},

			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:     "nil user is not authorized",
			noUser:   true,
			declared: []types.Role{types.RoleAdmin},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user := setupUser()
			user.Roles = c.claimed

			if c.noUser {
				user = nil
			}

			decision, err := authorization.FromToken(c.declared...).Authorize(context.Background(), user)

			require.NoError(t, err)
			assert.Equal(t, c.wantAuthorized, decision.Authorized)
			assert.Equal(t, c.wantRoles, decision.Roles)
		})
	}
}
