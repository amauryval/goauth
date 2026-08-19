// Package provider describes the identity providers this module knows how to read tokens from.
// Only what differs between them lives here: the rest of the module speaks plain OIDC.
package provider

import (
	"fmt"
	"strings"
)

// Provider is an identity provider, and what reading the tokens it issues demands.
// The zero value names no provider and is what demo mode runs on.
type Provider struct {
	name              string
	rolesClaim        string
	rolesFromUserInfo bool
	scopes            []string
}

// Zitadel reads project roles from the namespaced claim the Zitadel server emits by default.
var Zitadel = Provider{
	name:       "zitadel",
	rolesClaim: "urn:zitadel:iam:org:project:roles",
	scopes:     []string{"openid", "profile", "email", "offline_access"},
}

// PocketID reads roles from the group names it puts in the "groups" claim, which the browser must
// ask for through the scope of the same name. Its access tokens carry no claim beyond the OAuth2
// envelope, so the groups are read from the UserInfo endpoint.
var PocketID = Provider{
	name:              "pocketid",
	rolesClaim:        "groups",
	rolesFromUserInfo: true,
	scopes:            []string{"openid", "profile", "email", "offline_access", "groups"},
}

// supported lists the providers a deployment may choose from, in the order Names reports them.
var supported = []Provider{Zitadel, PocketID}

// Parse resolves the provider a deployment names, listing the supported ones when it is unknown.
func Parse(name string) (Provider, error) {
	for _, candidate := range supported {
		if strings.EqualFold(name, candidate.name) {
			return candidate, nil
		}
	}

	return Provider{}, fmt.Errorf("unknown identity provider %q, expected one of %s", name, Names())
}

// Names lists the supported provider names, as a deployment is expected to write them.
func Names() string {
	names := make([]string, 0, len(supported))
	for _, candidate := range supported {
		names = append(names, candidate.name)
	}

	return strings.Join(names, ", ")
}

// Name returns the provider name, empty when no provider is involved.
func (p Provider) Name() string {
	return p.name
}

// RolesClaim returns the token claim carrying the role names the provider granted.
func (p Provider) RolesClaim() string {
	return p.rolesClaim
}

// RolesFromUserInfo reports whether the roles claim must be read from the UserInfo endpoint,
// the provider leaving it out of the access token.
func (p Provider) RolesFromUserInfo() bool {
	return p.rolesFromUserInfo
}

// Scopes returns the OIDC scopes the browser must request for such a token to carry its roles.
func (p Provider) Scopes() []string {
	return p.scopes
}
