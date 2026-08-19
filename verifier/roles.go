package verifier

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/amauryval/goauth/types"
)

// tokenRoles reads the role names the provider granted, from the token itself or from the UserInfo
// endpoint when the provider keeps them out of the access token.
func (v *Verifier) tokenRoles(ctx context.Context, token *oidc.IDToken, rawToken string) ([]string, error) {
	if v.rolesFromUserInfo {
		return v.userInfoRoles(ctx, rawToken, token.Expiry)
	}

	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		v.logger.Warn("auth: unreadable claims", "error", err)

		return nil, fmt.Errorf("unreadable claims: %w", err)
	}

	return v.claimedRoles(claims), nil
}

// userInfoRoles reads the role names from the UserInfo endpoint the access token opens,
// which is where a provider emitting no role in its access tokens states them.
//
// The lookup is cached for the token, so a busy API queries the provider once per token rather
// than once per request, and a failing lookup is an error rather than an empty role set: a user
// stripped of every role because the provider is unreachable is a service outage, and answering
// it with a 403 would read as a permission bug.
func (v *Verifier) userInfoRoles(ctx context.Context, rawToken string, tokenExpiry time.Time) ([]string, error) {
	if v.provider == nil {
		v.logger.Error("auth: no issuer to read the roles from")

		return nil, fmt.Errorf("%w: no issuer to read the roles from", types.ErrAuthorization)
	}

	now := v.now()
	if roles, cached := v.roles.get(rawToken, now); cached {
		return roles, nil
	}

	requestCtx, cancel := context.WithTimeout(ctx, v.userInfoTimeout)
	defer cancel()

	info, err := v.provider.UserInfo(requestCtx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: rawToken}))
	if err != nil {
		v.logger.Error("auth: userinfo request failed", "error", err)

		return nil, fmt.Errorf("%w: userinfo request failed: %w", types.ErrAuthorization, err)
	}

	var claims map[string]any
	if err := info.Claims(&claims); err != nil {
		v.logger.Error("auth: unreadable userinfo claims", "error", err)

		return nil, fmt.Errorf("%w: unreadable userinfo claims: %w", types.ErrAuthorization, err)
	}

	roles := v.claimedRoles(claims)
	v.roles.put(rawToken, roles, tokenExpiry, now)

	return roles, nil
}

// claimedRoles reads the role names out of the claim the provider puts them in.
// An absent claim yields nothing: a user the provider granted no role is simply not authorized.
func (v *Verifier) claimedRoles(claims map[string]any) []string {
	value, found := claims[v.rolesClaim]
	if !found {
		v.logger.Warn("auth: roles claim absent", "claim", v.rolesClaim)

		return nil
	}

	return roleNames(value)
}

// roleNames reads role names out of a claim holding either an array of names,
// or an object keyed by name as Zitadel emits.
func roleNames(value any) []string {
	switch claimed := value.(type) {
	case []any:
		names := make([]string, 0, len(claimed))
		for _, entry := range claimed {
			if name, isString := entry.(string); isString && name != "" {
				names = append(names, name)
			}
		}

		return names

	case map[string]any:
		names := make([]string, 0, len(claimed))
		for name := range claimed {
			names = append(names, name)
		}

		slices.Sort(names)

		return names

	default:
		return nil
	}
}
