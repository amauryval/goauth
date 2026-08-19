package browser

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// maxSessionLifetime bounds how long a browser keeps a session cookie.
// The provider decides how long the tokens inside stay usable; this only bounds how long the
// browser bothers presenting them.
const maxSessionLifetime = 30 * 24 * time.Hour

// sameValue compares two values without letting the time taken say how far they matched.
func sameValue(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// errorsOf joins the errors that are not nil, for a single log line.
func errorsOf(errs ...error) error {
	return errors.Join(errs...)
}

// Token returns the access token of the calling browser, empty when it holds no session.
//
// It renews the token when it is about to expire and the provider granted a refresh token, sealing
// the renewed session back into the cookie, which is why it needs the response. A renewal that
// fails drops the session: the browser is signed out and starts a login again, rather than being
// left with a cookie that will never work.
//
// It is what a token source hands the rest of the module, so verification, roles and authorization
// stay exactly what they are for a bearer token.
func (f *Flow) Token(w http.ResponseWriter, r *http.Request) string {
	var current session
	if !f.read(r, f.sessionCookie, sessionPurpose, &current) {
		return ""
	}

	if !f.expiring(current) {
		return current.AccessToken
	}

	if current.RefreshToken == "" {
		f.clear(w, f.sessionCookie)

		return ""
	}

	renewed, err := f.refresh(r, current)
	if err != nil {
		f.logger.Warn("auth: the session could not be renewed", "error", err)
		f.clear(w, f.sessionCookie)

		return ""
	}

	if err := f.establish(w, renewed); err != nil {
		f.logger.Error("auth: the renewed session could not be stored", "error", err)
		f.clear(w, f.sessionCookie)

		return ""
	}

	return renewed.AccessToken
}

// expiring reports whether the access token is spent, or close enough that the call it is about to
// be read for would outlive it.
func (f *Flow) expiring(current session) bool {
	if current.Expiry.IsZero() {
		return false
	}

	return time.Now().Add(refreshWindow).After(current.Expiry)
}

// refresh spends the refresh token for a new access token.
func (f *Flow) refresh(r *http.Request, current session) (*oauth2.Token, error) {
	source := f.oauth2.TokenSource(r.Context(), &oauth2.Token{
		AccessToken:  current.AccessToken,
		RefreshToken: current.RefreshToken,
		Expiry:       current.Expiry,
	})

	renewed, err := source.Token()
	if err != nil {
		return nil, err
	}

	// A provider rotating its refresh tokens returns a new one, and one that does not returns
	// none: keeping the old one then is what makes the next renewal possible.
	if renewed.RefreshToken == "" {
		renewed.RefreshToken = current.RefreshToken
	}

	return renewed, nil
}

// Clear drops the session of the calling browser, for a host signing someone out on its own terms.
func (f *Flow) Clear(w http.ResponseWriter) {
	f.clear(w, f.sessionCookie)
}
