package verifier

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/amauryval/goauth/types"
)

// tokenRoles reads the role names the provider granted, from the token itself or from the UserInfo
// endpoint when the provider keeps them out of the access token.
//
// The raw token goes no further than the branch that has to present it to the issuer: reading the
// roles out of claims already verified needs the parsed token, never the credential itself.
func (v *Verifier) tokenRoles(ctx context.Context, token *oidc.IDToken, rawToken, subject string) ([]string, error) {
	if v.rolesFromUserInfo {
		return v.userInfoRoles(ctx, rawToken, subject, token.Expiry)
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
func (v *Verifier) userInfoRoles(ctx context.Context, rawToken, subject string, tokenExpiry time.Time) ([]string, error) {
	claims, err := v.userInfoClaims(ctx, rawToken, subject, tokenExpiry)
	if err != nil {
		return nil, err
	}

	return v.claimedRoles(claims), nil
}

// userInfoClaims reads what the UserInfo endpoint says about the bearer of the access token.
//
// The lookup is cached for the token, so a busy API queries the provider once per token rather
// than once per request, and everything read from that endpoint — the roles a provider states
// nowhere else, the profile a browser is shown — shares the one round trip.
//
// A failing lookup is an error rather than an empty answer: a user stripped of every role because
// the provider is unreachable is a service outage, and answering it with a 403 would read as a
// permission bug.
func (v *Verifier) userInfoClaims(ctx context.Context, rawToken, subject string, tokenExpiry time.Time) (map[string]any, error) {
	if v.provider == nil {
		v.logger.Error("auth: no issuer to ask about the user")

		return nil, fmt.Errorf("%w: no issuer to ask about the user", types.ErrAuthorization)
	}

	now := v.now()
	if cached, found := v.userInfos.get(rawToken, now); found {
		return cached, nil
	}

	requestCtx, cancel := context.WithTimeout(issuerContext(ctx, v.httpClient), providerTimeout)
	defer cancel()

	info, err := v.provider.UserInfo(requestCtx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: rawToken}))
	if err != nil {
		v.logger.Error("auth: userinfo request failed", "error", err)

		return nil, fmt.Errorf("%w: userinfo request failed: %w", types.ErrAuthorization, err)
	}

	// OpenID Connect Core 5.3.2: the subject the endpoint answers with must be the one the token
	// was verified for. Without this check the roles of whoever the endpoint decides to describe
	// would be granted to the bearer, and a provider mixing two responses up would go unnoticed.
	if info.Subject != subject {
		v.logger.Error("auth: userinfo describes another subject", "token", subject, "userinfo", info.Subject)

		return nil, errors.New("userinfo describes another subject")
	}

	var claims map[string]any
	if err := info.Claims(&claims); err != nil {
		v.logger.Error("auth: unreadable userinfo claims", "error", err)

		return nil, fmt.Errorf("%w: unreadable userinfo claims: %w", types.ErrAuthorization, err)
	}

	v.userInfos.put(rawToken, claims, tokenExpiry, now)

	return claims, nil
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
