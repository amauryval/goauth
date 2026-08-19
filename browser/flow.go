package browser

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/amauryval/goauth/types"
	"github.com/amauryval/goauth/verifier"
)

const (
	// DefaultSessionCookie is the cookie an established session is kept in.
	DefaultSessionCookie = "goauth_session"

	// DefaultPendingCookie is the cookie a login in flight is kept in.
	DefaultPendingCookie = "goauth_login"

	// refreshWindow is how long before its expiry an access token is refreshed.
	// Refreshing on the exact second would have a token expire between the check and the call it
	// was read for.
	refreshWindow = 30 * time.Second
)

// Config holds what driving the login flow on the server demands.
type Config struct {
	// Endpoints are the issuer URLs, as discovery reported them.
	Endpoints verifier.Endpoints

	// ClientID is this application's client Id at the provider.
	ClientID string

	// ClientSecret authenticates this application at the token endpoint.
	// Left empty the client is public and PKCE alone proves the exchange, which is what a provider
	// issuing no secret expects. A provider that issued one is a confidential client, and giving
	// it here is the point of running the flow on the server.
	ClientSecret string

	// RedirectURL is the absolute URL the provider sends the browser back to, which must be the
	// one registered there and must resolve to CallbackHandler.
	RedirectURL string

	// Scopes are the scopes requested at sign in.
	Scopes []string

	// Secret seals the cookies, at least 32 bytes. Losing it signs everyone out; leaking it lets
	// its holder mint sessions, so it belongs wherever the deployment keeps its other secrets.
	Secret []byte

	// SessionCookie and PendingCookie name the two cookies, defaulting to DefaultSessionCookie
	// and DefaultPendingCookie.
	SessionCookie string
	PendingCookie string

	// CookiePath and CookieDomain scope the cookies, defaulting to "/" and to the serving host.
	CookiePath   string
	CookieDomain string

	// SameSite bounds which cross-site requests carry the session, defaulting to Lax.
	// Lax is the tightest setting the flow works under: the provider sends the browser back by a
	// top-level navigation, which Strict would strip the cookie from.
	SameSite http.SameSite

	// InsecureCookies drops the Secure attribute, for a local stack served over http.
	// It must never be set on a deployment: the session then travels in cleartext.
	InsecureCookies bool

	// PostLoginPath is where a finished login lands when it was started without a destination,
	// defaulting to "/". It is a path on this application, never an absolute URL.
	PostLoginPath string

	// PostLogoutURL is where the provider sends the browser after an RP initiated logout.
	// Left empty the browser is not sent to the provider at all, and only the session is dropped.
	PostLogoutURL string

	// Logger receives the flow's failures. Defaults to types.DiscardLogger.
	Logger types.Logger
}

// Flow serves the login, callback and logout endpoints, and hands the access token of the calling
// browser to the rest of the module.
//
// About CSRF: the session rides in a cookie, so a cross-site request can carry it. SameSite=Lax
// keeps it off every cross-site request but a top-level navigation, which leaves cross-site GET.
// Guard the writes as any cookie-authenticated API must: this module's middleware protects who may
// call, never that the caller meant to. An API accepting only application/json is already beyond
// the reach of a form post.
type Flow struct {
	oauth2          oauth2.Config
	sealer          *sealer
	sessionCookie   string
	pendingCookie   string
	cookiePath      string
	cookieDomain    string
	sameSite        http.SameSite
	insecureCookies bool
	postLoginPath   string
	postLogoutURL   string
	endSessionURL   string
	logger          types.Logger
}

// New creates the Flow described by the config.
func New(config Config) (*Flow, error) {
	if config.ClientID == "" {
		return nil, errors.New("a client id is required")
	}

	if config.RedirectURL == "" {
		return nil, errors.New("a redirect URL is required")
	}

	if config.Endpoints.Authorization == "" || config.Endpoints.Token == "" {
		return nil, errors.New("the issuer endpoints are required")
	}

	sealer, err := newSealer(config.Secret)
	if err != nil {
		return nil, err
	}

	postLogin := config.PostLoginPath
	if postLogin == "" {
		postLogin = "/"
	}

	if !isLocalPath(postLogin) {
		return nil, fmt.Errorf("the post login path must be a path on this application, got %q", postLogin)
	}

	logger := config.Logger
	if logger == nil {
		logger = types.DiscardLogger{}
	}

	return &Flow{
		oauth2: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       config.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.Endpoints.Authorization,
				TokenURL: config.Endpoints.Token,
			},
		},
		sealer:          sealer,
		sessionCookie:   orDefault(config.SessionCookie, DefaultSessionCookie),
		pendingCookie:   orDefault(config.PendingCookie, DefaultPendingCookie),
		cookiePath:      orDefault(config.CookiePath, "/"),
		cookieDomain:    config.CookieDomain,
		sameSite:        orSameSite(config.SameSite),
		insecureCookies: config.InsecureCookies,
		postLoginPath:   postLogin,
		postLogoutURL:   config.PostLogoutURL,
		endSessionURL:   config.Endpoints.EndSession,
		logger:          logger,
	}, nil
}

// orDefault returns value, or fallback when it is empty.
func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

// orSameSite returns the configured policy, or Lax, the tightest the flow works under.
func orSameSite(value http.SameSite) http.SameSite {
	if value == 0 {
		return http.SameSiteLaxMode
	}

	return value
}

// isLocalPath reports whether a destination stays on this application.
//
// Anything else is an open redirect: a login link carrying ?return_to=https://evil.example.com
// would have the application itself deliver the browser there, wearing its own domain. A leading
// "//" is refused too, since a browser reads it as a protocol relative URL to another host.
//
// Backslashes are refused outright rather than inspected. Browsers disagree with url.Parse about
// them: "/\evil.example.com" parses here as a path with no host, and is followed by a browser as
// a protocol relative URL to evil.example.com. Nothing legitimate needs one in a redirect target,
// so the disagreement is settled by refusing the character.
func isLocalPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return false
	}

	if strings.Contains(path, `\`) {
		return false
	}

	parsed, err := url.Parse(path)

	return err == nil && parsed.Scheme == "" && parsed.Host == ""
}

// randomValue returns a URL safe random string of n bytes of entropy.
func randomValue(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("random value: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// codeChallenge derives the S256 PKCE challenge of a verifier.
func codeChallenge(codeVerifier string) string {
	digest := sha256.Sum256([]byte(codeVerifier))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// exchange turns an authorization code into tokens, proving the exchange with the code verifier.
func (f *Flow) exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return f.oauth2.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
}
