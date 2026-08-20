package goauth

import (
	"net/http"

	"github.com/amauryval/goauth/browser"
)

const (
	// LoginPath is where LoginHandler is meant to be mounted, relative to the API root.
	LoginPath = Root + "/login"

	// CallbackPath is where CallbackHandler is meant to be mounted, relative to the API root.
	// It must match the redirect URL registered at the provider.
	CallbackPath = Root + "/callback"

	// LogoutPath is where LogoutHandler is meant to be mounted, relative to the API root.
	// It answers to POST, so that a cross-site page cannot sign a visitor out by linking to it.
	LogoutPath = Root + "/logout"
)

// BrowserOptions asks for the login flow to be driven on the server, so that a browser never
// handles a token: it signs in by following a redirect, and calls the API with its cookie.
//
// It is what removes the OIDC client, the PKCE dance and the token storage from the frontend, and
// with them the XSS exposure a token kept in localStorage carries.
type BrowserOptions struct {
	// RedirectURL is the absolute URL the provider sends the browser back to. It must be
	// registered there, and must resolve to CallbackPath on this application.
	RedirectURL string

	// Secret seals the session cookie, at least 32 bytes.
	Secret []byte

	// PostLoginPath is where a finished login lands when it named no destination, defaulting to
	// "/". It is a path on this application, never an absolute URL.
	PostLoginPath string

	// PostLogoutURL is where the provider sends the browser after signing out. Left empty the
	// browser is not sent to the provider at all, and only the session is dropped.
	PostLogoutURL string

	// InsecureCookies drops the Secure attribute, for a local stack served over http.
	// It must never be set on a deployment: the session then travels in cleartext.
	InsecureCookies bool
}

// BrowserOption declares one setting of the browser login flow, named at the call site.
type BrowserOption func(*BrowserOptions)

// WithBrowser asks for the login flow to be driven on the server, so the frontend never handles a
// token. Left undeclared, the browser obtains its own tokens and presents them as bearer tokens.
//
// The redirect URL must be registered at the provider and resolve to CallbackPath on this
// application, and the secret sealing the session cookie must be at least 32 bytes.
func WithBrowser(redirectURL string, secret []byte, options ...BrowserOption) Option {
	return func(s *Settings) {
		browser := &BrowserOptions{RedirectURL: redirectURL, Secret: secret}
		for _, option := range options {
			option(browser)
		}

		s.browser = browser
	}
}

// WithPostLoginPath is where a finished login lands when it named no destination, defaulting to
// "/". It is a path on this application, never an absolute URL.
func WithPostLoginPath(path string) BrowserOption {
	return func(o *BrowserOptions) { o.PostLoginPath = path }
}

// WithPostLogoutURL is where the provider sends the browser after signing out. Left undeclared the
// browser is not sent to the provider at all, and only the session is dropped.
func WithPostLogoutURL(url string) BrowserOption {
	return func(o *BrowserOptions) { o.PostLogoutURL = url }
}

// WithInsecureCookies drops the Secure attribute, for a local stack served over http.
// It must never be set on a deployment: the session then travels in cleartext.
func WithInsecureCookies(insecure bool) BrowserOption {
	return func(o *BrowserOptions) { o.InsecureCookies = insecure }
}

// browserSource reads the session cookie, and falls back to the Authorization header.
//
// Keeping the header alive beside the cookie is what lets a service account or a script call the
// same API the browser does, without a second way in having to be built for them.
type browserSource struct {
	flow *browser.Flow
}

// Token returns the access token of the calling browser, or the one a client presented itself.
func (s browserSource) Token(w http.ResponseWriter, r *http.Request) string {
	if token := s.flow.Token(w, r); token != "" {
		return token
	}

	return bearerToken(r)
}

// Allow refuses a state changing request that another site made on the visitor's behalf.
func (s browserSource) Allow(r *http.Request) bool {
	return s.flow.Allow(r)
}

// LoginHandler starts a sign in, redirecting the browser to the provider.
// A ?return_to query names where to land afterwards, and must be a path on this application.
// It serves a 404 unless the deployment asked for the browser flow.
func (a *Auth) LoginHandler() http.HandlerFunc {
	if a.flow == nil {
		return notConfigured
	}

	return a.flow.LoginHandler()
}

// CallbackHandler finishes a sign in and establishes the session.
// It serves a 404 unless the deployment asked for the browser flow.
func (a *Auth) CallbackHandler() http.HandlerFunc {
	if a.flow == nil {
		return notConfigured
	}

	return a.flow.CallbackHandler()
}

// LogoutHandler drops the session, and signs out at the provider when one was configured.
// It serves a 404 unless the deployment asked for the browser flow.
func (a *Auth) LogoutHandler() http.HandlerFunc {
	if a.flow == nil {
		return notConfigured
	}

	return a.flow.LogoutHandler()
}

// notConfigured answers the browser endpoints of a deployment that never asked for them.
func notConfigured(w http.ResponseWriter, _ *http.Request) {
	respondStatus(w, http.StatusNotFound, "not_found", "this deployment does not sign users in")
}
