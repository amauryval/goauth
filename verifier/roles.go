package verifier

import (
	"context"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// tokenRoles reads the role names the provider granted, from the token itself or from the UserInfo
// endpoint when the provider keeps them out of the access token.
func (v *Verifier) tokenRoles(ctx context.Context, token *oidc.IDToken, rawToken string) []string {
	if v.rolesFromUserInfo {
		return v.userInfoRoles(ctx, rawToken)
	}

	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		v.logger.Warn("auth: unreadable claims", "error", err)
		return nil
	}

	return v.claimedRoles(claims)
}

// userInfoRoles reads the role names from the UserInfo endpoint the access token opens,
// which is where a provider emitting no role in its access tokens states them.
func (v *Verifier) userInfoRoles(ctx context.Context, rawToken string) []string {
	if v.provider == nil {
		v.logger.Warn("auth: no issuer to read the roles from")
		return nil
	}

	info, err := v.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: rawToken}))
	if err != nil {
		v.logger.Warn("auth: userinfo request failed", "error", err)
		return nil
	}

	var claims map[string]any
	if err := info.Claims(&claims); err != nil {
		v.logger.Warn("auth: unreadable userinfo claims", "error", err)
		return nil
	}

	return v.claimedRoles(claims)
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
