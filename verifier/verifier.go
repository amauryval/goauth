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
	// defaultUserInfoTTL is how long the roles read from the UserInfo endpoint are reused.
	// It trades the delay a role change takes to be seen against a round trip per request, and is
	// short enough that a revocation still lands within seconds.
	defaultUserInfoTTL = 30 * time.Second

	// defaultUserInfoTimeout bounds a UserInfo request, so an unresponsive provider fails the
	// request rather than holding a server goroutine for as long as the client waits.
	defaultUserInfoTimeout = 5 * time.Second

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

	// UserInfoTTL is how long the roles read from the UserInfo endpoint are reused for a token.
	// Zero selects a 30s default, and a negative value disables caching, querying the provider on
	// every request. Ignored unless RolesFromUserInfo is set.
	UserInfoTTL time.Duration

	// UserInfoTimeout bounds a single UserInfo request. Zero selects a 5s default.
	// Ignored unless RolesFromUserInfo is set.
	UserInfoTimeout time.Duration

	// AllowInsecureIssuer accepts an http issuer that is not on loopback, which the module
	// otherwise refuses: over cleartext an on-path attacker reads the access tokens forwarded to
	// the UserInfo endpoint and serves a signing key set of their own.
	//
	// It exists for a development stack whose provider answers on a container or LAN name rather
	// than on localhost. It is deliberately not reachable through goauth.Options, so no deployment
	// configured by environment variables can turn it on: a host wanting it assembles its verifier
	// itself, in code, where the choice is visible.
	AllowInsecureIssuer bool

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
	issuerURL         string
	tokens            *oidc.IDTokenVerifier
	authorizer        types.Authorizer
	rolesClaim        string
	rolesFromUserInfo bool
	roles             *roleCache
	userInfoTimeout   time.Duration
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

	if err := requireSecureIssuer(config.IssuerURL, config.AllowInsecureIssuer); err != nil {
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

	if config.AllowInsecureIssuer {
		logger.Warn("auth: the issuer is trusted over cleartext, access tokens and signing keys cross the network unprotected")
	}

	ttl := config.UserInfoTTL
	if ttl == 0 {
		ttl = defaultUserInfoTTL
	}

	timeout := config.UserInfoTimeout
	if timeout <= 0 {
		timeout = defaultUserInfoTimeout
	}

	return &Verifier{
		provider:          provider,
		httpClient:        config.HTTPClient,
		issuerURL:         config.IssuerURL,
		tokens:            tokens,
		authorizer:        authorizer,
		rolesClaim:        config.RolesClaim,
		rolesFromUserInfo: config.RolesFromUserInfo,
		roles:             newRoleCache(ttl, maxCachedUserInfo),
		userInfoTimeout:   timeout,
		logger:            logger,
		now:               time.Now,
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
