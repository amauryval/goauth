package browser

import (
	"errors"
	"net/http"
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
			f.logger.Error("auth: could not start a login", "error", errors.Join(stateErr, nonceErr, verifierErr))
			http.Error(w, "login unavailable", http.StatusServiceUnavailable)

			return
		}

		returnTo := r.URL.Query().Get("return_to")
		if returnTo != "" && !isLocalPath(returnTo) {
			f.logger.Warn("auth: refused a login returning off this application", "return_to", returnTo)

			returnTo = ""
		}

		// The cookie lives as long as the browser session: what bounds the login is the
		// authorization code the provider issued, not anything decided here.
		err := f.write(w, pendingCookie, pendingPurpose, pending{
			State:        state,
			Nonce:        nonce,
			CodeVerifier: codeVerifier,
			ReturnTo:     returnTo,
		}, 0)
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
		if !f.read(r, pendingCookie, pendingPurpose, &started) {
			f.logger.Warn("auth: a login came back without having been started")
			http.Error(w, "no login in progress", http.StatusBadRequest)

			return
		}

		f.clear(w, pendingCookie)

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

		// OpenID Connect Core 3.1.3.7. The access token says nothing about who signed in, and is
		// not meant to: the ID token is what names them, and it is worth nothing unverified.
		rawIDToken, _ := token.Extra("id_token").(string)

		err = f.idTokens.VerifyIDToken(r.Context(), rawIDToken, started.Nonce)
		if err != nil {
			f.logger.Error("auth: the id token could not be verified", "error", err)
			http.Error(w, "the login could not be verified", http.StatusForbidden)

			return
		}

		if err := f.establish(w, token, rawIDToken); err != nil {
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
//
// It makes the same origin check the rest of the module makes, rather than resting on answering to
// POST alone: POST keeps a cross-site page from signing a visitor out by linking to it, but not
// from doing so with a form it submits itself. The response clears the cookie whether or not the
// request carried one, so an unchecked logout is a sign out any site can force.
func (f *Flow) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)

		if !f.sameOrigin(r) {
			f.logger.Warn("auth: refused a sign out this application did not ask for",
				"method", r.Method, "origin", r.Header.Get("Origin"))
			http.Error(w, "this request did not come from this application", http.StatusForbidden)

			return
		}

		var current session

		hadSession := f.read(r, sessionCookie, sessionPurpose, &current)

		f.clear(w, sessionCookie)
		f.clear(w, pendingCookie)

		if hadSession {
			f.revoke(r.Context(), current.RefreshToken)
		}

		target := f.endSession(current.IDToken)
		if target == "" {
			w.WriteHeader(http.StatusNoContent)

			return
		}

		http.Redirect(w, r, target, http.StatusFound)
	}
}

// establish seals the tokens into the session cookie.
func (f *Flow) establish(w http.ResponseWriter, token *oauth2.Token, rawIDToken string) error {
	established := session{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		IDToken:      rawIDToken,
	}

	err := f.write(w, sessionCookie, sessionPurpose, established, cookieLifetime(token))
	if err == nil {
		return nil
	}

	// The ID token is the largest thing in there and the least needed: it only serves as the hint
	// of an RP initiated logout. A session that would not fit is kept without it rather than
	// refused, which costs a logout hint and saves the login.
	if established.IDToken == "" {
		return err
	}

	f.logger.Warn("auth: the session does not fit in a cookie with its id token, dropping the logout hint")

	established.IDToken = ""

	return f.write(w, sessionCookie, sessionPurpose, established, cookieLifetime(token))
}

// cookieLifetime is how long the browser keeps the session cookie.
//
// With a refresh token it is the browsing session: how long the sign in stays good is the
// provider's to decide, and this module has nothing to state a date from. Without one, the access
// token's own expiry is the whole of the session, and there is no reason to keep the cookie past
// it.
func cookieLifetime(token *oauth2.Token) time.Duration {
	if token.RefreshToken != "" || token.Expiry.IsZero() {
		return 0
	}

	return time.Until(token.Expiry)
}

// noStore keeps a response carrying or clearing a session out of every cache along the way.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}
