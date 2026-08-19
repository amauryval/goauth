// Package verifier validates OIDC bearer tokens and turns their claims into an authorization decision.
package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/amauryval/goauth/types"
)

const (
	// userInfoTTL is how long the roles read from the UserInfo endpoint are reused.
	// It trades the delay a role change takes to be seen against a round trip per request, and is
	// short enough that a revocation still lands within seconds.
	userInfoTTL = 30 * time.Second

	// defaultIntrospectionTTL is how long the issuer's answer about a token is reused.
	//
	// It is the trade this module makes between the issuer having the last word and the issuer
	// being on the path of every request. At this length a revoked token, a disabled account or a
	// closed session is refused within seconds, while a busy API leaves the provider alone for the
	// overwhelming majority of its calls. Asking on every single request would put the provider in
	// front of the whole API, which is the arrangement this module exists to avoid.
	defaultIntrospectionTTL = 15 * time.Second

	// providerTimeout bounds a single request made to the provider while answering a call, the
	// UserInfo lookup and the introspection, so an unresponsive provider fails the request rather
	// than holding a server goroutine for as long as the client waits.
	providerTimeout = 5 * time.Second

	// defaultIssuerTimeout bounds a request to the issuer when the host pins no client of its own.
	// http.DefaultClient has no timeout at all, and it is the fallback the OIDC library uses.
	defaultIssuerTimeout = 10 * time.Second

	// maxCachedUserInfo bounds the number of cached UserInfo lookups, so an attacker presenting
	// many valid tokens cannot grow the cache without end.
	maxCachedUserInfo = 4096
)

// signingAlgorithms are the signature algorithms a token may use.
// Pinning them to the asymmetric ones keeps an issuer announcing a symmetric algorithm from being
// taken at its word, whatever its discovery document claims.
var signingAlgorithms = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512,
}

// Config holds the settings of the OIDC token verifier.
type Config struct {
	// IssuerURL is the OIDC provider base URL, used for discovery and public key retrieval.
	IssuerURL string

	// Audience is this application's client ID.
	// A token issued for another application is rejected, which isolates apps sharing an issuer.
	Audience string

	// RolesClaim is the token claim the provider puts the granted role names in.
	// No standard names it, so it belongs to the provider rather than to the protocol.
	RolesClaim string

	// RolesFromUserInfo reads the roles claim from the UserInfo endpoint instead of from the token.
	// Providers emitting a bare access token state the roles there and nowhere else.
	RolesFromUserInfo bool

	// ClientSecret authenticates this application when it asks the issuer about a token, as
	// RFC 7662 requires. A client issued none identifies itself by its id alone.
	ClientSecret string

	// IntrospectionTTL reuses the issuer's answer about a token for that long, trading how quickly
	// its decisions land against a round trip per request.
	//
	// Zero selects a 15 second default, which bounds how long a revoked token keeps working while
	// keeping the issuer off the path of nearly every request. A negative value asks on every
	// single request, for a deployment that needs the issuer's word each time and can afford the
	// provider being reachable for the API to answer at all.
	IntrospectionTTL time.Duration

	// HTTPClient is the client used to reach the issuer, for discovery, for the signing keys and
	// for the UserInfo endpoint. It is where a host pins a TLS configuration, a proxy or a
	// connection budget. Defaults to a client with a bounded timeout.
	HTTPClient *http.Client

	// Logger receives verification failures. Defaults to types.DiscardLogger.
	Logger types.Logger
}

// Verifier validates OIDC bearer tokens and evaluates the authorization policy on their claims.
type Verifier struct {
	provider          *oidc.Provider
	httpClient        *http.Client
	tokens            *oidc.IDTokenVerifier
	authorizer        types.Authorizer
	rolesClaim        string
	rolesFromUserInfo bool
	roles             *roleCache
	introspector      *introspector
	introspections    *roleCache
	logger            types.Logger

	// now reads the current time, replaced by the tests to age the cache without waiting.
	now func() time.Time
}

// New builds a Verifier by discovering the issuer configuration and its public keys.
// It contacts the issuer, so it fails when the provider is unreachable.
func New(ctx context.Context, authorizer types.Authorizer, config Config) (*Verifier, error) {
	if authorizer == nil {
		return nil, errors.New("an authorizer is required")
	}

	if config.IssuerURL == "" {
		return nil, errors.New("an issuer URL is required")
	}

	if config.Audience == "" {
		return nil, errors.New("an audience is required")
	}

	if config.RolesClaim == "" {
		return nil, errors.New("a roles claim is required")
	}

	if err := requireSecureIssuer(config.IssuerURL); err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(issuerContext(ctx, config.HTTPClient), config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	tokens := provider.Verifier(&oidc.Config{
		ClientID:             config.Audience,
		SupportedSigningAlgs: signingAlgorithms,
	})

	return newVerifier(provider, tokens, authorizer, config), nil
}

// issuerContext carries the HTTP client every request to the issuer must go through.
// Leaving it to http.DefaultClient would mean no timeout and no say over TLS, on the connection
// that fetches the signing keys and carries access tokens.
func issuerContext(ctx context.Context, client *http.Client) context.Context {
	if client == nil {
		client = &http.Client{Timeout: defaultIssuerTimeout}
	}

	return oidc.ClientContext(ctx, client)
}

// newVerifier assembles a Verifier from an already built token verifier.
func newVerifier(provider *oidc.Provider, tokens *oidc.IDTokenVerifier, authorizer types.Authorizer, config Config) *Verifier {
	logger := config.Logger
	if logger == nil {
		logger = types.DiscardLogger{}
	}

	asker := buildIntrospector(provider, config, logger)

	introspectionTTL := config.IntrospectionTTL
	if introspectionTTL == 0 {
		introspectionTTL = defaultIntrospectionTTL
	}

	return &Verifier{
		provider:          provider,
		httpClient:        config.HTTPClient,
		tokens:            tokens,
		authorizer:        authorizer,
		rolesClaim:        config.RolesClaim,
		rolesFromUserInfo: config.RolesFromUserInfo,
		roles:             newRoleCache(userInfoTTL, maxCachedUserInfo),
		introspector:      asker,
		introspections:    newRoleCache(introspectionTTL, maxCachedUserInfo),
		logger:            logger,
		now:               time.Now,
	}
}

// buildIntrospector prepares the question put to the issuer about every token.
//
// There is no way to decline asking. The only deployment that does not ask is one whose issuer
// advertises nowhere to ask, and that is the issuer's statement about itself rather than a choice
// made here. It is reported loudly, because it is the one case where this module cannot tell a
// live account from a deleted one.
func buildIntrospector(provider *oidc.Provider, config Config, logger types.Logger) *introspector {
	var endpoint string

	if provider != nil {
		var claims discoveryClaims

		_ = provider.Claims(&claims)

		endpoint = claims.Introspection
	}

	if endpoint == "" {
		logger.Warn("auth: the issuer advertises no introspection endpoint, so it cannot be asked whether a token is still active: a disabled account keeps working until its token expires")

		return nil
	}

	return &introspector{
		endpoint:     endpoint,
		clientID:     config.Audience,
		clientSecret: config.ClientSecret,
		client:       config.HTTPClient,
	}
}

// tokenClaims are the access token claims an authorization policy can rule on.
// Profile claims are not among them: an access token carries none.
type tokenClaims struct {
	Subject string `json:"sub"`
	Nonce   string `json:"nonce"`
	AtHash  string `json:"at_hash"`
	CHash   string `json:"c_hash"`
}

// isIDToken reports whether the claims belong to an ID token rather than to an access token.
// Only an ID token carries them, and it is minted for the browser: it states who signed in,
// never what its bearer may call, so an API accepting one authorizes on the wrong evidence.
func (c tokenClaims) isIDToken() bool {
	return c.Nonce != "" || c.AtHash != "" || c.CHash != ""
}

// Verify validates a bearer token and evaluates the authorization policy against its claims.
// An invalid, expired or wrongly addressed token yields an error, never an unauthorized decision.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (types.SessionInfo, error) {
	if rawToken == "" {
		return types.SessionInfo{}, errors.New("no bearer token")
	}

	token, err := v.tokens.Verify(ctx, rawToken)
	if err != nil {
		v.logger.Warn("auth: token rejected", "error", err)
		return types.SessionInfo{}, fmt.Errorf("invalid token: %w", err)
	}

	var claims tokenClaims
	if err := token.Claims(&claims); err != nil {
		v.logger.Warn("auth: unreadable claims", "error", err)
		return types.SessionInfo{}, fmt.Errorf("unreadable claims: %w", err)
	}

	if claims.Subject == "" {
		v.logger.Warn("auth: token without a subject")

		return types.SessionInfo{}, errors.New("token without a subject")
	}

	if claims.isIDToken() {
		v.logger.Warn("auth: id token presented as an access token")

		return types.SessionInfo{}, errors.New("id token presented as an access token")
	}

	// The signature said the token was minted here and the expiry said it is not stale. Neither
	// can say the account still exists, so the issuer is asked.
	if err := v.stillActive(ctx, rawToken); err != nil {
		return types.SessionInfo{}, err
	}

	roles, err := v.tokenRoles(ctx, token, rawToken, claims.Subject)
	if err != nil {
		return types.SessionInfo{}, err
	}

	user := &types.UserInfo{
		Provider: token.Issuer,
		ID:       claims.Subject,
		Roles:    roles,
	}

	decision, err := v.authorizer.Authorize(ctx, user)
	if err != nil {
		v.logger.Error("auth: authorization failed", "error", err)
		return types.SessionInfo{}, fmt.Errorf("%w: %w", types.ErrAuthorization, err)
	}

	if !decision.Authorized && len(user.Roles) > 0 {
		v.logger.Warn("auth: no application role matches the token roles", "roles", user.Roles)
	}

	return types.SessionInfo{
		LoggedIn:   true,
		Authorized: decision.Authorized,
		Roles:      decision.Roles,
		User:       user,
	}, nil
}
