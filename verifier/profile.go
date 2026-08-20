package verifier

import (
	"context"
	"time"

	"github.com/amauryval/goauth/types"
)

// profileClaims are the standard OpenID Connect claims describing the person behind a token,
// as OpenID Connect Core 5.1 names them.
var profileClaims = struct {
	username, name, email, picture string
}{
	username: "preferred_username",
	name:     "name",
	email:    "email",
	picture:  "picture",
}

// Profile reads who the bearer of an access token is, from the UserInfo endpoint that token opens.
//
// It is for display and settles nothing: authentication and authorization are decided by Verify on
// the token itself, and a profile is only asked for once that came back. The subject is the one
// Verify returned, and is checked against the endpoint's answer, so a profile is never read for
// somebody else.
//
// It exists because an access token carries no name, no email and no avatar, and a deployment
// driving the login flow on the server keeps the ID token that does — which leaves the endpoint
// as the only place a browser can be told who it is signed in as. A browser holding its own tokens
// needs none of this: it reads its own ID token.
//
// The answer is cached for the token alongside the roles, so asking costs no round trip of its own
// on a deployment already reading its roles there. A provider stating none of the claims yields a
// nil profile rather than an error: a nameless account is not a failure.
func (v *Verifier) Profile(ctx context.Context, rawToken, subject string) (*types.Profile, error) {
	claims, err := v.userInfoClaims(ctx, rawToken, subject, time.Time{})
	if err != nil {
		return nil, err
	}

	profile := types.Profile{
		Username: claimedString(claims, profileClaims.username),
		Name:     claimedString(claims, profileClaims.name),
		Email:    claimedString(claims, profileClaims.email),
		Picture:  claimedString(claims, profileClaims.picture),
	}

	if profile.Empty() {
		return nil, nil
	}

	return &profile, nil
}

// claimedString reads a claim expected to hold a string, empty when it is absent or is anything
// else. A provider putting a number or an object where a name belongs describes nobody, and is not
// worth failing a session over.
func claimedString(claims map[string]any, name string) string {
	value, found := claims[name].(string)
	if !found {
		return ""
	}

	return value
}
