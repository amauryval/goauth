package verifier

import (
	"context"

	"github.com/amauryval/goauth/types"
)

// Static authorizes a fixed user without contacting an issuer, ignoring the token it receives.
// It exists for local development and demonstrations, and must never be enabled in production.
type Static struct {
	info types.SessionInfo
}

// NewStatic creates a verifier always returning the given user and roles.
func NewStatic(user *types.UserInfo, roles ...types.Role) *Static {
	return &Static{
		info: types.SessionInfo{
			LoggedIn:   true,
			Authorized: true,
			Roles:      roles,
			User:       user,
		},
	}
}

// Verify returns the configured user, whatever the token.
func (s *Static) Verify(_ context.Context, _ string) (types.SessionInfo, error) {
	return s.info, nil
}

// DemoUserID identifies the fixed user returned in demo mode.
const DemoUserID = "demo-user"

// NewUnverified creates a verifier accepting any request as a fixed administrator,
// without verifying a token at all. It must never be enabled in production.
func NewUnverified() *Static {
	return NewStatic(&types.UserInfo{
		Provider: "demo",
		ID:       DemoUserID,
	}, types.RoleAdmin)
}
