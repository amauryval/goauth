//go:build authdemo

package verifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/types"
)

// Test_NewUnverified pins what demo mode grants, and that it grants it to anyone: the test only
// compiles under the authdemo tag, which is the whole point of the verifier living behind it.
func Test_NewUnverified(t *testing.T) {
	t.Parallel()

	info, err := NewUnverified().Verify(context.Background(), "")

	require.NoError(t, err)
	assert.True(t, info.LoggedIn)
	assert.True(t, info.Authorized)
	assert.Equal(t, []types.Role{types.RoleAdmin}, info.Roles)
	require.NotNil(t, info.User)
	assert.Equal(t, DemoUserID, info.User.ID)
}
