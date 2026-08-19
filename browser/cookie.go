package browser

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// sessionPurpose labels the cookie holding an established session.
	sessionPurpose = "goauth.session"

	// pendingPurpose labels the cookie holding a login in flight.
	pendingPurpose = "goauth.pending"

	// maxCookieSize is the value length browsers are relied upon to keep, in bytes.
	// A session that no longer fits is refused loudly, rather than silently truncated into one
	// that never opens again.
	maxCookieSize = 4000
)

// session is what the sealed cookie holds between two requests.
//
// It carries no lifetime of its own. How long a sign in stays good is how long the provider keeps
// honouring the refresh token, and how quickly it stops is the issuer being asked on every
// request. A deadline here would be this module deciding a thing the provider decides, and
// deciding it with less to go on.
type session struct {
	AccessToken  string    `json:"a"`
	RefreshToken string    `json:"r,omitempty"`
	Expiry       time.Time `json:"e"`

	// IDToken is kept only to be handed back as the id_token_hint of an RP initiated logout, which
	// providers ask for before honouring a post logout redirect. It is dropped when the session
	// would otherwise outgrow a cookie.
	IDToken string `json:"t,omitempty"`
}

// pending is what a login in flight has to remember until the provider sends the browser back.
//
// The state ties the callback to the login this browser started, the PKCE verifier ties the code
// to it, and the nonce ties the ID token to it.
//
// It carries no expiry of its own. How long a login may take to come back is the lifetime of the
// authorization code, which the provider sets and enforces — ten minutes at most by RFC 6749, and
// single use. A deadline here would be a second opinion on a question the authority already
// answers, and the answer we would be second-guessing is the one that counts.
type pending struct {
	State        string `json:"s"`
	Nonce        string `json:"n"`
	CodeVerifier string `json:"v"`
	ReturnTo     string `json:"r,omitempty"`
}

// write seals a value into a cookie and sets it on the response.
func (f *Flow) write(w http.ResponseWriter, name, purpose string, value any, maxAge time.Duration) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cookie payload: %w", err)
	}

	sealed, err := f.sealer.seal(purpose, payload)
	if err != nil {
		return err
	}

	if len(sealed) > maxCookieSize {
		return fmt.Errorf("the %s cookie is %d bytes, past the %d a browser is relied upon to keep", name, len(sealed), maxCookieSize)
	}

	http.SetCookie(w, f.cookie(name, sealed, int(maxAge.Seconds())))

	return nil
}

// read opens the cookie of that name into value, reporting whether it was there and readable.
func (f *Flow) read(r *http.Request, name, purpose string, value any) bool {
	cookie, err := r.Cookie(name)
	if err != nil {
		return false
	}

	payload, err := f.sealer.open(purpose, cookie.Value)
	if err != nil {
		return false
	}

	return json.Unmarshal(payload, value) == nil
}

// clear expires the cookie of that name at the browser.
func (f *Flow) clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, f.cookie(name, "", -1))
}

// cookie builds a cookie carrying the module's protections, none of which are negotiable.
//
// HttpOnly is the point of the whole package: a session JavaScript cannot read is a session an XSS
// cannot steal. Secure keeps it off cleartext, and is only lifted for a local stack that has no
// TLS to offer. SameSite bounds which cross-site requests carry it at all.
func (f *Flow) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !f.insecureCookies,

		// Lax is the tightest setting the flow works under: the provider returns the browser by a
		// top-level navigation, which Strict would strip the cookie from.
		SameSite: http.SameSiteLaxMode,
	}
}
