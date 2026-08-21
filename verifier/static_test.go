package verifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/types"
)

func Test_Static_Verify(t *testing.T) {
	t.Parallel()

	user := &types.UserInfo{Provider: "test", ID: "some-subject"}

	cases := []struct {
		name      string
		roles     []types.Role
		rawToken  string
		wantRoles []types.Role
	}{
		{
			name:      "the configured user and roles are returned",
			roles:     []types.Role{types.RoleAdmin},
			rawToken:  "any-token",
			wantRoles: []types.Role{types.RoleAdmin},
		},
		{
			name:     "an absent token changes nothing, since none is verified",
			rawToken: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			info, err := NewStatic(user, c.roles...).Verify(context.Background(), c.rawToken)

			require.NoError(t, err)
			assert.True(t, info.LoggedIn)
			assert.True(t, info.Authorized)
			assert.Equal(t, user, info.User)
			assert.Equal(t, c.wantRoles, info.Roles)
		})
	}
}
