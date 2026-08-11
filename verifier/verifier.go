// Package verifier validates OIDC bearer tokens and turns their claims into an authorization decision.
package verifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/amauryval/goauth/types"
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

	// Logger receives verification failures. Defaults to types.DiscardLogger.
	Logger types.Logger
}

// Verifier validates OIDC bearer tokens and evaluates the authorization policy on their claims.
type Verifier struct {
	provider          *oidc.Provider
	tokens            *oidc.IDTokenVerifier
	authorizer        types.Authorizer
	rolesClaim        string
	rolesFromUserInfo bool
	logger            types.Logger
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

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	tokens := provider.Verifier(&oidc.Config{
		ClientID:             config.Audience,
		SupportedSigningAlgs: signingAlgorithms,
	})

	return newVerifier(provider, tokens, authorizer, config), nil
}

// newVerifier assembles a Verifier from an already built token verifier.
func newVerifier(provider *oidc.Provider, tokens *oidc.IDTokenVerifier, authorizer types.Authorizer, config Config) *Verifier {
	logger := config.Logger
	if logger == nil {
		logger = types.DiscardLogger{}
	}

	return &Verifier{
		provider:          provider,
		tokens:            tokens,
		authorizer:        authorizer,
		rolesClaim:        config.RolesClaim,
		rolesFromUserInfo: config.RolesFromUserInfo,
		logger:            logger,
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

	user := &types.UserInfo{
		Provider: token.Issuer,
		ID:       claims.Subject,
		Roles:    v.tokenRoles(ctx, token, rawToken),
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
