package verifier

import (
	"context"

	"github.com/amauryval/goauth/types"
)

// Static authorizes a fixed user without contacting an issuer, ignoring the token it receives.
// It exists for local development, demonstrations and host test suites, and must never be wired
// into a deployment facing users.
//
// Unlike the demo verifier, it grants nothing on its own: the caller states the user and the roles,
// so nothing is authorized that the host did not spell out. That is why it needs no build tag.
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
