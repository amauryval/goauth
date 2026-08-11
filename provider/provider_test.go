package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Parse(t *testing.T) {
	cases := []struct {
		name           string
		declared       string
		wantErr        bool
		wantErrPart    string
		wantName       string
		wantRolesClaim string
		wantUserInfo   bool
		wantScopes     []string
	}{
		{
			name:           "zitadel",
			declared:       "zitadel",
			wantName:       "zitadel",
			wantRolesClaim: "urn:zitadel:iam:org:project:roles",
			wantScopes:     []string{"openid", "profile", "email", "offline_access"},
		},
		{
			name:           "pocket id",
			declared:       "pocketid",
			wantName:       "pocketid",
			wantRolesClaim: "groups",
			wantUserInfo:   true,
			wantScopes:     []string{"openid", "profile", "email", "groups"},
		},
		{
			name:           "the name is read whatever its case",
			declared:       "ZITADEL",
			wantName:       "zitadel",
			wantRolesClaim: "urn:zitadel:iam:org:project:roles",
			wantScopes:     []string{"openid", "profile", "email", "offline_access"},
		},
		{
			name:        "an unsupported provider lists the supported ones",
			declared:    "keycloak",
			wantErr:     true,
			wantErrPart: "zitadel, pocketid",
		},
		{
			name:        "no name at all",
			wantErr:     true,
			wantErrPart: "zitadel, pocketid",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parsed, err := Parse(c.declared)

			if c.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErrPart)
				assert.Empty(t, parsed.Name())

				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.wantName, parsed.Name())
			assert.Equal(t, c.wantRolesClaim, parsed.RolesClaim())
			assert.Equal(t, c.wantUserInfo, parsed.RolesFromUserInfo())
			assert.Equal(t, c.wantScopes, parsed.Scopes())
		})
	}
}

func Test_Names(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{
			name: "every supported provider, in declaration order",
			want: "zitadel, pocketid",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, Names())
		})
	}
}
