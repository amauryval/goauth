package goauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/amauryval/goauth/authorization"
	"github.com/amauryval/goauth/provider"
	"github.com/amauryval/goauth/types"
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

	// RequireIntrospectionEnv names the environment variable a host reads to demand that the issuer
	// support introspection.
	RequireIntrospectionEnv = "AUTH_REQUIRE_INTROSPECTION"

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
	demo          bool
	providerName  string
	issuerURL     string
	audience      string
	adminRole     string
	guestRole     string
	clientSecret  string
	requireIntro  bool
	introspectTTL time.Duration
	browser       *BrowserOptions
}

// Option declares one setting of a deployment. Each one names at the call site what it sets, so
// that the settings never sit side by side in a parameter list, where swapping the issuer and the
// audience still compiles and silently breaks audience isolation.
type Option func(*Settings)

// WithDemo bypasses token verification entirely. See Settings.Demo.
// It takes the flag or environment value as it is read, so a host declares it unconditionally.
func WithDemo(demo bool) Option {
	return func(s *Settings) { s.demo = demo }
}

// WithProvider names the kind of identity provider, one of provider.Names(). Required.
func WithProvider(name string) Option {
	return func(s *Settings) { s.providerName = name }
}

// WithIssuer names the identity provider base URL, used for discovery and key retrieval.
func WithIssuer(url string) Option {
	return func(s *Settings) { s.issuerURL = url }
}

// WithAudience names this application's client Id, checked against the token audience.
func WithAudience(clientID string) Option {
	return func(s *Settings) { s.audience = clientID }
}

// WithAdminRole names the role the provider grants administration with, "admin" when unset.
func WithAdminRole(name string) Option {
	return func(s *Settings) { s.adminRole = name }
}

// WithGuestRole names the role the provider grants read-only access with, "guest" when unset.
func WithGuestRole(name string) Option {
	return func(s *Settings) { s.guestRole = name }
}

// WithClientSecret authenticates this application when it asks the issuer whether a token is still
// active, as RFC 7662 requires, and when it exchanges an authorization code. A client the provider
// issued none identifies itself by its id alone.
func WithClientSecret(secret string) Option {
	return func(s *Settings) { s.clientSecret = secret }
}

// WithRequireIntrospection refuses to start against an issuer advertising no introspection
// endpoint, rather than running without one.
//
// Introspection is how this module asks the issuer whether a token is one it still stands behind.
// Without it a disabled account, a changed password and an ended session all keep working until
// the token expires on its own, which for a session held by a refresh token is never. That is
// warned about at startup either way; this makes it a deployment that does not start.
func WithRequireIntrospection(required bool) Option {
	return func(s *Settings) { s.requireIntro = required }
}

// WithIntrospectionTTL reuses the issuer's answer about a token for that long, trading how quickly
// its decisions land against a round trip per request. Unset selects 15 seconds; a negative value
// asks the issuer on every single request.
func WithIntrospectionTTL(ttl time.Duration) Option {
	return func(s *Settings) { s.introspectTTL = ttl }
}

// NewSettings gathers the settings of a deployment, as the host declares them.
// Reading them from flags or from the environment is the host's business, not this module's.
func NewSettings(options ...Option) Settings {
	var settings Settings
	for _, option := range options {
		option(&settings)
	}

	return settings
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

// ClientSecret returns the credential this application authenticates to the issuer with.
func (s Settings) ClientSecret() string {
	return s.clientSecret
}

// RequireIntrospection reports whether an issuer advertising no introspection endpoint is refused.
func (s Settings) RequireIntrospection() bool {
	return s.requireIntro
}

// IntrospectionTTL returns how long the issuer's answer is reused for.
func (s Settings) IntrospectionTTL() time.Duration {
	return s.introspectTTL
}

// Browser reports the browser flow settings, nil when the deployment asked for none.
func (s Settings) Browser() *BrowserOptions {
	return s.browser
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

	if s.RequireIntrospection() {
		configured = append(configured, RequireIntrospectionEnv)
	}

	if s.Browser() != nil {
		configured = append(configured, "the browser login flow")
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
