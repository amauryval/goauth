package browser

import (
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

// LoginHandler starts a sign in: it remembers a state and a PKCE verifier in a sealed cookie,
// then sends the browser to the provider.
//
// A ?return_to query names where the finished login should land, and is refused unless it is a
// path on this application: honouring an absolute URL would make the application an open redirect.
func (f *Flow) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, stateErr := randomValue(32)
		nonce, nonceErr := randomValue(32)
		codeVerifier, verifierErr := randomValue(32)

		if stateErr != nil || nonceErr != nil || verifierErr != nil {
			f.logger.Error("auth: could not start a login", "error", errorsOf(stateErr, nonceErr, verifierErr))
			http.Error(w, "login unavailable", http.StatusServiceUnavailable)

			return
		}

		returnTo := r.URL.Query().Get("return_to")
		if returnTo != "" && !isLocalPath(returnTo) {
			f.logger.Warn("auth: refused a login returning off this application", "return_to", returnTo)

			returnTo = ""
		}

		err := f.write(w, f.pendingCookie, pendingPurpose, pending{
			State:        state,
			Nonce:        nonce,
			CodeVerifier: codeVerifier,
			ReturnTo:     returnTo,
			ExpiresAt:    time.Now().Add(pendingLifetime),
		}, pendingLifetime)
		if err != nil {
			f.logger.Error("auth: could not start a login", "error", err)
			http.Error(w, "login unavailable", http.StatusServiceUnavailable)

			return
		}

		authURL := f.oauth2.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge(codeVerifier)),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("nonce", nonce),
		)

		noStore(w)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// CallbackHandler finishes a sign in: it checks the state, exchanges the code and establishes the
// session, then sends the browser where the login was started from.
func (f *Flow) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)

		var started pending
		if !f.read(r, f.pendingCookie, pendingPurpose, &started) {
			f.logger.Warn("auth: a login came back without having been started")
			http.Error(w, "no login in progress", http.StatusBadRequest)

			return
		}

		f.clear(w, f.pendingCookie)

		if time.Now().After(started.ExpiresAt) {
			f.logger.Warn("auth: a login came back too late")
			http.Error(w, "the login expired, start it again", http.StatusBadRequest)

			return
		}

		query := r.URL.Query()

		// The state ties this callback to the login this browser started. Without the check, any
		// site could walk a visitor through a sign in of its own choosing and land them here with
		// a session that is not theirs.
		if !sameValue(query.Get("state"), started.State) {
			f.logger.Warn("auth: a login came back with a state it was not sent with")
			http.Error(w, "the login could not be verified, start it again", http.StatusBadRequest)

			return
		}

		if providerErr := query.Get("error"); providerErr != "" {
			f.logger.Warn("auth: the provider refused the login", "error", providerErr)
			http.Error(w, "the provider refused the login", http.StatusForbidden)

			return
		}

		token, err := f.exchange(r.Context(), query.Get("code"), started.CodeVerifier)
		if err != nil {
			f.logger.Error("auth: the authorization code could not be exchanged", "error", err)
			http.Error(w, "the login could not be completed", http.StatusBadGateway)

			return
		}

		if err := f.establish(w, token); err != nil {
			f.logger.Error("auth: the session could not be established", "error", err)
			http.Error(w, "the login could not be completed", http.StatusInternalServerError)

			return
		}

		http.Redirect(w, r, orDefault(started.ReturnTo, f.postLoginPath), http.StatusFound)
	}
}

// LogoutHandler drops the session, and sends the browser on to the provider when the issuer
// supports it and a destination was configured.
//
// Dropping the cookie ends the session for this browser. It does not revoke the tokens at the
// provider, which is what the RP initiated logout redirect is for.
func (f *Flow) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		f.clear(w, f.sessionCookie)
		f.clear(w, f.pendingCookie)

		if f.endSessionURL == "" || f.postLogoutURL == "" {
			w.WriteHeader(http.StatusNoContent)

			return
		}

		endSession, err := url.Parse(f.endSessionURL)
		if err != nil {
			f.logger.Error("auth: the issuer logout URL is not a URL", "error", err)
			w.WriteHeader(http.StatusNoContent)

			return
		}

		query := endSession.Query()
		query.Set("client_id", f.oauth2.ClientID)
		query.Set("post_logout_redirect_uri", f.postLogoutURL)
		endSession.RawQuery = query.Encode()

		http.Redirect(w, r, endSession.String(), http.StatusFound)
	}
}

// establish seals the tokens into the session cookie.
func (f *Flow) establish(w http.ResponseWriter, token *oauth2.Token) error {
	return f.write(w, f.sessionCookie, sessionPurpose, session{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}, sessionLifetime(token))
}

// sessionLifetime is how long the browser keeps the session cookie.
// A refresh token outlives its access token by design, so the cookie follows the longer of the
// two: dropping it at the access token's expiry would end a session the provider would have
// renewed without a word.
func sessionLifetime(token *oauth2.Token) time.Duration {
	if token.RefreshToken != "" {
		return maxSessionLifetime
	}

	if token.Expiry.IsZero() {
		return maxSessionLifetime
	}

	return time.Until(token.Expiry)
}

// noStore keeps a response carrying or clearing a session out of every cache along the way.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}
