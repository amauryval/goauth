// Package auth verifies OIDC bearer tokens and exposes role based HTTP middleware.
// Authentication happens at a central identity provider: this module only validates its tokens.
package goauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/amauryval/goauth/provider"
	"github.com/amauryval/goauth/types"
	"github.com/amauryval/goauth/verifier"
)

// Auth turns verified bearer tokens into authorization decisions for HTTP handlers.
type Auth struct {
	verifier  types.TokenVerifier
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

		return NewWithVerifier(verifier.NewUnverified(), logger)
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

	built, err := NewWithVerifier(tokenVerifier, logger)
	if err != nil {
		return nil, err
	}

	built.issuerURL = settings.IssuerURL()
	built.audience = settings.Audience()
	built.scopes = selected.Scopes()

	return built, nil
}

// NewWithVerifier creates an Auth from an already built verifier.
// It is how a host injects its own verification, and how New assembles the OIDC one.
func NewWithVerifier(tokenVerifier types.TokenVerifier, logger types.Logger) (*Auth, error) {
	if tokenVerifier == nil {
		return nil, errors.New("a token verifier is required")
	}

	if logger == nil {
		logger = types.DiscardLogger{}
	}

	return &Auth{verifier: tokenVerifier, logger: logger}, nil
}
