package goauth

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/types"
)

func setupLogger() types.Logger {
	return slog.New(slog.DiscardHandler)
}

func Test_New(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		demo         bool
		providerName string
		issuerURL    string
		audience     string
		adminRole    string
		guestRole    string
		wantErr      bool
		wantErrPart  string
	}{
		{
			name:         "demo mode beside a declared provider",
			demo:         true,
			providerName: "zitadel",
			wantErr:      true,
			wantErrPart:  ProviderEnv,
		},
		{
			name:        "demo mode beside a configured issuer",
			demo:        true,
			issuerURL:   "https://issuer.example",
			wantErr:     true,
			wantErrPart: IssuerEnv,
		},
		{
			name:        "demo mode beside a configured audience",
			demo:        true,
			audience:    "portfolio",
			wantErr:     true,
			wantErrPart: AudienceEnv,
		},
		{
			name:        "no provider declared",
			issuerURL:   "https://issuer.example",
			audience:    "portfolio",
			wantErr:     true,
			wantErrPart: ProviderEnv,
		},
		{
			name:         "a provider this module knows nothing about",
			providerName: "keycloak",
			issuerURL:    "https://issuer.example",
			audience:     "portfolio",
			wantErr:      true,
			wantErrPart:  "keycloak",
		},
		{
			name:         "missing issuer",
			providerName: "zitadel",
			audience:     "portfolio",
			wantErr:      true,
			wantErrPart:  "issuer",
		},
		{
			name:         "unreachable zitadel issuer",
			providerName: "zitadel",
			issuerURL:    "http://127.0.0.1:1",
			audience:     "portfolio",
			wantErr:      true,
			wantErrPart:  "127.0.0.1:1",
		},
		{
			name:         "unreachable pocketid issuer",
			providerName: "pocketid",
			issuerURL:    "http://127.0.0.1:1",
			audience:     "portfolio",
			wantErr:      true,
			wantErrPart:  "127.0.0.1:1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			settings := NewSettings(Options{Demo: c.demo, ProviderName: c.providerName, IssuerURL: c.issuerURL, Audience: c.audience, AdminRole: c.adminRole, GuestRole: c.guestRole})

			built, err := New(context.Background(), settings, setupLogger())

			if c.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErrPart)
				assert.Nil(t, built)

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, built)
		})
	}
}

func Test_NewSettings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		demo             bool
		providerName     string
		issuerURL        string
		audience         string
		adminRole        string
		guestRole        string
		wantDemo         bool
		wantProviderName string
		wantIssuerURL    string
		wantAudience     string
		wantAdminRole    string
		wantGuestRole    string
	}{
		{
			name:             "every setting declared",
			demo:             true,
			providerName:     "pocketid",
			issuerURL:        "https://issuer.example",
			audience:         "portfolio",
			adminRole:        "portfolio_admin",
			guestRole:        "portfolio_guest",
			wantDemo:         true,
			wantProviderName: "pocketid",
			wantIssuerURL:    "https://issuer.example",
			wantAudience:     "portfolio",
			wantAdminRole:    "portfolio_admin",
			wantGuestRole:    "portfolio_guest",
		},
		{
			name:             "role names left out fall back to their default",
			providerName:     "zitadel",
			issuerURL:        "https://issuer.example",
			audience:         "portfolio",
			wantProviderName: "zitadel",
			wantIssuerURL:    "https://issuer.example",
			wantAudience:     "portfolio",
			wantAdminRole:    defaultAdminRole,
			wantGuestRole:    defaultGuestRole,
		},
		{
			name:          "nothing declared leaves the provider empty and the roles on their default",
			wantAdminRole: defaultAdminRole,
			wantGuestRole: defaultGuestRole,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			settings := NewSettings(Options{Demo: c.demo, ProviderName: c.providerName, IssuerURL: c.issuerURL, Audience: c.audience, AdminRole: c.adminRole, GuestRole: c.guestRole})

			assert.Equal(t, c.wantDemo, settings.Demo())
			assert.Equal(t, c.wantProviderName, settings.ProviderName())
			assert.Equal(t, c.wantIssuerURL, settings.IssuerURL())
			assert.Equal(t, c.wantAudience, settings.Audience())
			assert.Equal(t, c.wantAdminRole, settings.AdminRole())
			assert.Equal(t, c.wantGuestRole, settings.GuestRole())
		})
	}
}

func Test_Settings_provider(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		providerName   string
		wantErr        bool
		wantErrPart    string
		wantRolesClaim string
		wantScopes     []string
	}{
		{
			name:           "zitadel reads its namespaced project roles claim",
			providerName:   "zitadel",
			wantRolesClaim: "urn:zitadel:iam:org:project:roles",
			wantScopes:     []string{"openid", "profile", "email", "offline_access"},
		},
		{
			name:           "pocket id reads the groups claim and asks for its scope",
			providerName:   "pocketid",
			wantRolesClaim: "groups",
			wantScopes:     []string{"openid", "profile", "email", "offline_access", "groups"},
		},
		{
			name:           "the provider name is read whatever its case",
			providerName:   "PocketID",
			wantRolesClaim: "groups",
			wantScopes:     []string{"openid", "profile", "email", "offline_access", "groups"},
		},
		{
			name:        "no provider named",
			wantErr:     true,
			wantErrPart: ProviderEnv,
		},
		{
			name:         "an unsupported provider lists the supported ones",
			providerName: "keycloak",
			wantErr:      true,
			wantErrPart:  "zitadel, pocketid",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			settings := NewSettings(Options{ProviderName: c.providerName})

			selected, err := settings.provider()

			if c.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErrPart)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.wantRolesClaim, selected.RolesClaim())
			assert.Equal(t, c.wantScopes, selected.Scopes())
		})
	}
}

func Test_Settings_authorizer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		adminRole      string
		guestRole      string
		claimed        []string
		wantAuthorized bool
		wantRoles      []types.Role
	}{
		{
			name:           "the provider name of the admin role",
			adminRole:      "portfolio_admin",
			guestRole:      "portfolio_guest",
			claimed:        []string{"portfolio_admin"},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
		{
			name:           "the provider name of the guest role",
			adminRole:      "portfolio_admin",
			guestRole:      "portfolio_guest",
			claimed:        []string{"portfolio_guest"},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleGuest},
		},
		{
			name:      "a role the application does not declare",
			adminRole: "portfolio_admin",
			guestRole: "portfolio_guest",
			claimed:   []string{"portfolio_visitor"},
		},
		{
			name:      "no role at all",
			adminRole: "portfolio_admin",
			guestRole: "portfolio_guest",
		},
		{
			name:           "the default role names when none is declared",
			claimed:        []string{defaultAdminRole},
			wantAuthorized: true,
			wantRoles:      []types.Role{types.RoleAdmin},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			settings := NewSettings(Options{AdminRole: c.adminRole, GuestRole: c.guestRole})

			decision, err := settings.authorizer().Authorize(context.Background(), &types.UserInfo{Roles: c.claimed})

			require.NoError(t, err)
			assert.Equal(t, c.wantAuthorized, decision.Authorized)
			assert.Equal(t, c.wantRoles, decision.Roles)
		})
	}
}
