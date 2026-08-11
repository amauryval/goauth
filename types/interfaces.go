package types

import "context"

// TokenVerifier turns a bearer token into the authenticated user and the roles granted to it.
// It returns an error when the token is absent from the issuer, expired, or addressed to another app.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (SessionInfo, error)
}
