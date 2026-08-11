package auth

import (
	"fmt"
	"strings"

	"auth/authorization"
	"auth/provider"
	"auth/types"
)

const (
	// DemoBuildTag is the build tag a binary must carry for demo mode to be allowed to run.
	// Asking for it at compile time keeps a misread environment variable from disabling
	// token verification on a deployment that was never built for it.
	DemoBuildTag = "authdemo"

	// DemoEnv names the environment variable a host reads to enable demo mode.
	DemoEnv = "AUTH_DEMO"

	// ProviderEnv names the environment variable a host reads for the kind of identity provider
	// it authenticates against. It has no default: a wrong guess would read the roles of nobody.
	ProviderEnv = "AUTH_PROVIDER"

	// IssuerEnv names the environment variable a host reads for the identity provider URL.
	IssuerEnv = "AUTH_ISSUER"

	// AudienceEnv names the environment variable a host reads for this application's client Id.
	AudienceEnv = "AUTH_AUDIENCE"

	// AdminRoleEnv names the environment variable a host reads for the provider name of the admin role.
	AdminRoleEnv = "AUTH_ADMIN_ROLE"

	// GuestRoleEnv names the environment variable a host reads for the provider name of the guest role.
	GuestRoleEnv = "AUTH_GUEST_ROLE"

	// defaultAdminRole is the provider name assumed for the admin role when none is declared.
	defaultAdminRole = "admin"
	// defaultGuestRole is the provider name assumed for the guest role when none is declared.
	defaultGuestRole = "guest"
)

// Settings gathers the authentication settings of a deployment.
type Settings struct {
	demo         bool
	providerName string
	issuerURL    string
	audience     string
	adminRole    string
	guestRole    string
}

// NewSettings gathers the settings of a deployment, as the host declares them.
// Reading them from the environment is the host's business, not this module's.
func NewSettings(demo bool, providerName, issuerURL, audience, adminRole, guestRole string) Settings {
	return Settings{
		demo:         demo,
		providerName: providerName,
		issuerURL:    issuerURL,
		audience:     audience,
		adminRole:    adminRole,
		guestRole:    guestRole,
	}
}

// Demo reports whether token verification is bypassed, authorizing every visitor as an
// administrator. It is meant for local development and demonstrations, never for a deployment
// facing users.
func (s Settings) Demo() bool {
	return s.demo
}

// ProviderName returns the kind of identity provider the deployment authenticates against,
// empty when it declares none.
func (s Settings) ProviderName() string {
	return s.providerName
}

// IssuerURL returns the identity provider base URL, used for discovery and key retrieval.
func (s Settings) IssuerURL() string {
	return s.issuerURL
}

// Audience returns this application's client Id, checked against the token audience.
func (s Settings) Audience() string {
	return s.audience
}

// AdminRole returns the name the identity provider gives to the role granting administration,
// "admin" when the deployment declares none.
func (s Settings) AdminRole() string {
	if s.adminRole == "" {
		return defaultAdminRole
	}

	return s.adminRole
}

// GuestRole returns the name the identity provider gives to the read-only role,
// "guest" when the deployment declares none.
func (s Settings) GuestRole() string {
	if s.guestRole == "" {
		return defaultGuestRole
	}

	return s.guestRole
}

// provider resolves the identity provider the deployment named, and demands one:
// assuming a provider would have this module read the roles from a claim nobody fills.
func (s Settings) provider() (provider.Provider, error) {
	if s.ProviderName() == "" {
		return provider.Provider{}, fmt.Errorf("%s is required, one of %s", ProviderEnv, provider.Names())
	}

	return provider.Parse(s.ProviderName())
}

// rejectProviderSettings fails when demo mode is asked for beside a configured provider,
// a contradiction that would otherwise silently open the application to every visitor.
func (s Settings) rejectProviderSettings() error {
	var configured []string
	if s.ProviderName() != "" {
		configured = append(configured, ProviderEnv)
	}

	if s.IssuerURL() != "" {
		configured = append(configured, IssuerEnv)
	}

	if s.Audience() != "" {
		configured = append(configured, AudienceEnv)
	}

	if len(configured) == 0 {
		return nil
	}

	return fmt.Errorf("demo mode disables token verification but %s is set: drop the demo flag or unset it", strings.Join(configured, " and "))
}

// authorizer grants the application roles the provider names in its own vocabulary.
func (s Settings) authorizer() types.Authorizer {
	return authorization.FromTokenNames(map[string]types.Role{
		s.AdminRole(): types.RoleAdmin,
		s.GuestRole(): types.RoleGuest,
	})
}
