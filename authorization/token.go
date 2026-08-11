// Package authorization turns the role names an identity provider puts in a token
// into the roles an application declares.
package authorization

import (
	"context"
	"slices"
	"strings"

	"github.com/amauryval/goauth/types"
)

// tokenAuthorizer authorizes the users whose token already carries a role the application knows.
type tokenAuthorizer struct {
	known map[string]types.Role
}

// FromToken grants the roles the identity provider put in the token, restricted to the given ones.
// It is how a provider managing roles itself, such as Zitadel project roles, drives authorization.
//
// A role the application does not declare is ignored, so a misconfigured provider can never widen
// access. A user carrying none of them is not authorized, and only reaches the public routes.
func FromToken(roles ...types.Role) types.Authorizer {
	names := make(map[string]types.Role, len(roles))
	for _, role := range roles {
		names[string(role)] = role
	}

	return FromTokenNames(names)
}

// FromTokenNames grants an application role to each provider role name mapped to it.
// It frees the provider from naming its roles after the application, which nothing guarantees:
// a deployment declares the names its own provider grants.
func FromTokenNames(names map[string]types.Role) types.Authorizer {
	known := make(map[string]types.Role, len(names))
	for name, role := range names {
		if name != "" {
			known[strings.ToLower(name)] = role
		}
	}

	return &tokenAuthorizer{known: known}
}

// Authorize keeps the token roles the application declared.
func (a *tokenAuthorizer) Authorize(_ context.Context, user *types.UserInfo) (types.Decision, error) {
	if user == nil {
		return types.Decision{}, nil
	}

	var granted []types.Role
	for _, claimed := range user.Roles {
		if role, found := a.known[strings.ToLower(claimed)]; found && !slices.Contains(granted, role) {
			granted = append(granted, role)
		}
	}

	if len(granted) == 0 {
		return types.Decision{}, nil
	}

	return types.Decision{Authorized: true, Roles: granted}, nil
}
