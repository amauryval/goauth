// Package mock holds the fixtures the module's own tests share: a user, and a TokenVerifier
// returning whatever a test wants verification to have concluded.
package mock

import (
	"context"

	"github.com/amauryval/goauth/types"
)

// MockRole is the provider role name the mock user carries.
const MockRole = "portfolio-admin"

// SetupMockUser returns a mock UserInfo with typical test values.
func SetupMockUser() *types.UserInfo {
	return &types.UserInfo{
		Provider: "https://provider.example.com",
		ID:       "12345",
		Roles:    []string{MockRole},
	}
}

// Verifier is a TokenVerifier returning a canned result, for middleware tests.
// It records the token it received, so callers can assert how it was extracted.
type Verifier struct {
	Info          types.SessionInfo
	Err           error
	ReceivedToken string
}

// Verify records the token and returns the configured result.
func (m *Verifier) Verify(_ context.Context, rawToken string) (types.SessionInfo, error) {
	m.ReceivedToken = rawToken

	return m.Info, m.Err
}
