package browser

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// revoke hands a refresh token back to the provider, as RFC 7009 describes.
//
// Signing out drops the cookie, which ends the session for this browser and nothing more: the
// refresh token would otherwise stay usable at the provider for its whole life. Revocation is its
// own specification rather than part of OIDC, so a provider advertising no endpoint is not a
// failure, and neither is a refusal: the session is over either way.
func (f *Flow) revoke(ctx context.Context, refreshToken string) {
	if f.revocationURL == "" || refreshToken == "" {
		return
	}

	form := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {f.oauth2.ClientID},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.revocationURL, strings.NewReader(form.Encode()))
	if err != nil {
		f.logger.Warn("auth: the refresh token could not be revoked", "error", err)

		return
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// RFC 7009 has a confidential client authenticate as it does at the token endpoint. A public
	// client identifies itself in the form above and sends no credentials.
	if f.oauth2.ClientSecret != "" {
		request.SetBasicAuth(url.QueryEscape(f.oauth2.ClientID), url.QueryEscape(f.oauth2.ClientSecret))
	}

	response, err := (&http.Client{Timeout: providerTimeout}).Do(request)
	if err != nil {
		f.logger.Warn("auth: the refresh token could not be revoked", "error", err)

		return
	}

	defer func() {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		f.logger.Warn("auth: the provider refused to revoke the refresh token", "status", response.Status)
	}
}

// endSession builds the URL an RP initiated logout sends the browser to, empty when the issuer
// advertises none or the deployment named no destination to come back to.
//
// The ID token is passed as id_token_hint where one was kept: providers ask for it before honouring
// a post logout redirect, and several ignore the redirect entirely without it.
func (f *Flow) endSession(idToken string) string {
	if f.endSessionURL == "" || f.postLogoutURL == "" {
		return ""
	}

	target, err := url.Parse(f.endSessionURL)
	if err != nil {
		f.logger.Error("auth: the issuer logout URL is not a URL", "error", err)

		return ""
	}

	query := target.Query()
	query.Set("client_id", f.oauth2.ClientID)
	query.Set("post_logout_redirect_uri", f.postLogoutURL)

	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}

	target.RawQuery = query.Encode()

	return target.String()
}
