// Package goauth verifies OIDC bearer tokens and exposes role based HTTP middleware.
// Authentication happens at a central identity provider: this module only validates its tokens.
package goauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/amauryval/goauth/browser"
	"github.com/amauryval/goauth/provider"
	"github.com/amauryval/goauth/types"
	"github.com/amauryval/goauth/verifier"
)

// Auth turns verified bearer tokens into authorization decisions for HTTP handlers.
type Auth struct {
	verifier  types.TokenVerifier
	tokens    TokenSource
	flow      *browser.Flow
	logger    types.Logger
	issuerURL string
	audience  string
	scopes    []string
}

// New creates the Auth described by the settings, logging its startup decisions.
// Demo authorizes every visitor, so it demands the DemoBuildTag and refuses any provider setting.
func New(ctx context.Context, settings Settings, logger types.Logger) (*Auth, error) {
	if logger == nil {
		logger = types.DiscardLogger{}
	}

	if settings.Demo() {
		if err := settings.rejectProviderSettings(); err != nil {
			return nil, err
		}

		if !demoCompiled {
			return nil, fmt.Errorf("demo mode disables token verification and is left out of this binary: rebuild it with -tags %s to allow it", DemoBuildTag)
		}

		logger.Warn("auth: demo mode authorizes every visitor as an administrator, token verification is disabled")

		return NewWithVerifier(demoVerifier(), logger)
	}

	selected, err := settings.provider()
	if err != nil {
		return nil, err
	}

	return newVerified(ctx, settings, selected, logger)
}

// newVerified creates an Auth validating tokens issued by the configured provider.
// It contacts the issuer to discover its public keys, so it fails when the provider is unreachable.
func newVerified(ctx context.Context, settings Settings, selected provider.Provider, logger types.Logger) (*Auth, error) {
	tokenVerifier, err := verifier.New(ctx, settings.authorizer(), verifier.Config{
		IssuerURL:         settings.IssuerURL(),
		Audience:          settings.Audience(),
		RolesClaim:        selected.RolesClaim(),
		RolesFromUserInfo: selected.RolesFromUserInfo(),
		Logger:            logger,
	})
	if err != nil {
		return nil, err
	}

	built, err := newAuth(tokenVerifier, logger, settings.IssuerURL(), settings.Audience(), selected.Scopes())
	if err != nil {
		return nil, err
	}

	if settings.Browser() == nil {
		return built, nil
	}

	if err := built.driveBrowserFlow(settings, tokenVerifier, selected, logger); err != nil {
		return nil, err
	}

	return built, nil
}

// driveBrowserFlow has the module sign users in itself, rather than verifying tokens a frontend
// obtained on its own. The endpoints come off the verifier, which already discovered them, so
// asking for the flow costs no second round trip to the issuer.
func (a *Auth) driveBrowserFlow(settings Settings, tokenVerifier *verifier.Verifier, selected provider.Provider, logger types.Logger) error {
	options := settings.Browser()

	flow, err := browser.New(browser.Config{
		Endpoints:       tokenVerifier.Endpoints(),
		ClientID:        settings.Audience(),
		ClientSecret:    options.ClientSecret,
		RedirectURL:     options.RedirectURL,
		Scopes:          selected.Scopes(),
		Secret:          options.Secret,
		CookiePath:      options.CookiePath,
		CookieDomain:    options.CookieDomain,
		SameSite:        options.SameSite,
		InsecureCookies: options.InsecureCookies,
		PostLoginPath:   options.PostLoginPath,
		PostLogoutURL:   options.PostLogoutURL,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	if options.InsecureCookies {
		logger.Warn("auth: session cookies are sent without the Secure attribute, they travel in cleartext")
	}

	a.flow = flow
	a.tokens = browserSource{flow: flow}

	return nil
}

// NewWithVerifier creates an Auth from an already built verifier.
// It is how a host injects its own verification, and how New assembles the OIDC one.
//
// The Auth it returns knows no provider, so ConfigHandler serves an empty client configuration:
// a host mounting it is expected to tell the browser where to sign in by its own means.
func NewWithVerifier(tokenVerifier types.TokenVerifier, logger types.Logger) (*Auth, error) {
	return newAuth(tokenVerifier, logger, "", "", nil)
}

// newAuth assembles an Auth, the single place its fields are set: an Auth is immutable once built,
// so no caller can end up serving a client configuration that was filled in halfway.
func newAuth(tokenVerifier types.TokenVerifier, logger types.Logger, issuerURL, audience string, scopes []string) (*Auth, error) {
	if tokenVerifier == nil {
		return nil, errors.New("a token verifier is required")
	}

	if logger == nil {
		logger = types.DiscardLogger{}
	}

	return &Auth{
		verifier:  tokenVerifier,
		tokens:    bearerSource{},
		logger:    logger,
		issuerURL: issuerURL,
		audience:  audience,
		scopes:    scopes,
	}, nil
}
