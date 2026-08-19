package browser

import (
	"crypto/subtle"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// sameValue compares two values without letting the time taken say how far they matched.
func sameValue(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
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
	if !f.read(r, sessionCookie, sessionPurpose, &current) {
		return ""
	}

	if !f.expiring(current) {
		return current.AccessToken
	}

	if current.RefreshToken == "" {
		f.clear(w, sessionCookie)

		return ""
	}

	renewed, err := f.refresh(r, current)
	if err != nil {
		f.logger.Warn("auth: the session could not be renewed", "error", err)
		f.clear(w, sessionCookie)

		return ""
	}

	if err := f.establish(w, renewed, current.IDToken); err != nil {
		f.logger.Error("auth: the renewed session could not be stored", "error", err)
		f.clear(w, sessionCookie)

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
	source := f.oauth2.TokenSource(f.providerContext(r.Context()), &oauth2.Token{
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

// Allow reports whether a request may proceed, and is where the session's own CSRF check lives.
//
// It only rules on requests that carry the session cookie: a caller presenting a bearer token
// chose to present it, and no other site can make that choice for them. A cookie is sent by the
// browser whether or not the visitor meant to, which is the whole of the problem.
func (f *Flow) Allow(r *http.Request) bool {
	if _, err := r.Cookie(sessionCookie); err != nil {
		// No session cookie: whatever credential this request carries, it was attached on purpose.
		return true
	}

	if f.sameOrigin(r) {
		return true
	}

	f.logger.Warn("auth: refused a cross-site request carrying the session",
		"path", r.URL.Path, "method", r.Method, "origin", r.Header.Get("Origin"))

	return false
}
