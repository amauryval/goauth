package browser

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// safeMethods are the methods a cross-site request may reach without an origin check.
// They are the ones a browser will issue as a top-level navigation anyway, and the ones the HTTP
// specification asks an application not to change anything with.
var safeMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace}

// sameOrigin reports whether a request that carries the session cookie may change anything.
//
// This is the CSRF check, and it is the flow's to make rather than the application's: the session
// rides in a cookie because this module put it there, so the request forgery that comes with a
// cookie is this module's to answer. It costs the frontend nothing, unlike a token it would have
// to read and echo back.
//
// A browser states where a request came from in Origin, on every request that changes something.
// Comparing it to the application's own origin is what separates a call the visitor made from one
// another site made on their behalf. Sec-Fetch-Site is honoured first where the browser sends it,
// being the same statement made directly.
func (f *Flow) sameOrigin(r *http.Request) bool {
	if slices.Contains(safeMethods, r.Method) {
		return true
	}

	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "same-site", "cross-site":
		return false
	}

	// A browser states an origin on every request that changes something. Its absence is therefore
	// not something to make room for: a request carrying our cookie and naming no origin is not a
	// request this application asked for.
	return strings.EqualFold(r.Header.Get("Origin"), f.origin)
}

// originOf reduces a URL to the scheme and host a browser would send as its Origin.
func originOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}

	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}
