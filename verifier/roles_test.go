package verifier

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/authorization"
	"goauth/types"
)

func Test_roleNames(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  []string
	}{
		{
			name:  "an array yields its names",
			value: []any{"admin", "guest"},
			want:  []string{"admin", "guest"},
		},
		{
			name:  "an object yields its keys, sorted",
			value: map[string]any{"guest": nil, "admin": nil},
			want:  []string{"admin", "guest"},
		},
		{
			name:  "non string entries are dropped",
			value: []any{"admin", 42, ""},
			want:  []string{"admin"},
		},
		{
			name:  "a scalar claim yields nothing",
			value: "admin",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, roleNames(c.value))
		})
	}
}

func Test_Verifier_Verify_ProviderRoles(t *testing.T) {
	server, key := setupIssuer(t)

	cases := []struct {
		name           string
		rolesClaim     string
		claimed        map[string]any
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "zitadel project roles are granted",
			rolesClaim:     "urn:zitadel:iam:org:project:roles",
			claimed:        map[string]any{"urn:zitadel:iam:org:project:roles": map[string]any{"guest": map[string]any{"orgId": "example.com"}}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest},
		},
		{
			name:           "pocket id groups are granted",
			rolesClaim:     "groups",
			claimed:        map[string]any{"groups": []any{"guest"}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest},
		},
		{
			name:           "an array of role names is granted too",
			rolesClaim:     "urn:zitadel:iam:org:project:roles",
			claimed:        map[string]any{"urn:zitadel:iam:org:project:roles": []any{"admin"}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:       "the claim of another provider is ignored",
			rolesClaim: "urn:zitadel:iam:org:project:roles",
			claimed:    map[string]any{"groups": []any{"admin"}},
		},
		{
			name:       "a token carrying no roles claim authorizes nobody",
			rolesClaim: "groups",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			built, err := New(context.Background(), authorization.FromToken(types.RoleAdmin, types.RoleGuest), Config{
				IssuerURL:  server.URL,
				Audience:   testAudience,
				RolesClaim: c.rolesClaim,
			})
			require.NoError(t, err)

			claims := setupClaims(server.URL, testAudience, "some-subject", time.Now().Add(time.Hour))
			for name, value := range c.claimed {
				claims[name] = value
			}

			info, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

			require.NoError(t, err)
			assert.True(t, info.LoggedIn)
			assert.Equal(t, c.wantAuthorized, info.Authorized)
			assert.Equal(t, c.wantRoles, info.Roles)
		})
	}
}

func Test_Verifier_Verify_UserInfoRoles(t *testing.T) {
	cases := []struct {
		name           string
		served         map[string]any
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "the groups the endpoint serves are granted",
			served:         map[string]any{"groups": []any{"guest"}},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest},
		},
		{
			name:   "an endpoint serving no groups authorizes nobody",
			served: map[string]any{"sub": "some-subject"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server, key, userInfo := setupIssuerWithUserInfo(t)
			for name, value := range c.served {
				userInfo[name] = value
			}

			built, err := New(context.Background(), authorization.FromToken(types.RoleAdmin, types.RoleGuest), Config{
				IssuerURL:         server.URL,
				Audience:          testAudience,
				RolesClaim:        "groups",
				RolesFromUserInfo: true,
			})
			require.NoError(t, err)

			claims := setupClaims(server.URL, testAudience, "some-subject", time.Now().Add(time.Hour))
			claims["groups"] = []any{"admin"}

			info, err := built.Verify(context.Background(), setupSignedToken(t, key, claims))

			require.NoError(t, err)
			assert.True(t, info.LoggedIn)
			assert.Equal(t, c.wantAuthorized, info.Authorized)
			assert.Equal(t, c.wantRoles, info.Roles)
		})
	}
}
