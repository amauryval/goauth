package verifier

import (
	"context"
	"errors"
	"fmt"
)

// nonceClaim reads the nonce back out of a verified ID token.
type nonceClaim struct {
	Nonce string `json:"nonce"`
}

// VerifyIDToken validates the ID token a code exchange returned, as OpenID Connect Core 3.1.3.7
// requires: its signature against the issuer's keys, its issuer, its audience and its expiry.
//
// It answers one question and returns nothing beyond it: was this login completed by the browser
// that started it. The nonce is what says so, and it is checked here rather than by the caller,
// since a nonce nobody compares is worth nothing.
//
// The claims are deliberately not handed back. Every decision this module makes is made on the
// access token, which is verified on its own terms and vouched for by the issuer on every request.
// An identity read from here would be a second, unused answer to a question already settled.
func (v *Verifier) VerifyIDToken(ctx context.Context, rawIDToken, nonce string) error {
	if rawIDToken == "" {
		return errors.New("the provider returned no id token")
	}

	token, err := v.tokens.Verify(ctx, rawIDToken)
	if err != nil {
		v.logger.Warn("auth: id token rejected", "error", err)

		return fmt.Errorf("invalid id token: %w", err)
	}

	var claims nonceClaim
	if err := token.Claims(&claims); err != nil {
		return fmt.Errorf("unreadable id token claims: %w", err)
	}

	if claims.Nonce != nonce {
		v.logger.Warn("auth: id token carries another login's nonce")

		return errors.New("the id token does not belong to this login")
	}

	if token.Subject == "" {
		return errors.New("id token without a subject")
	}

	return nil
}
