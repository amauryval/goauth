package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_Flow_Allow pins the CSRF check the session cookie brings with it: a request that changes
// something, carrying the session a browser attached on its own, must have come from here.
func Test_Flow_Allow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		method      string
		origin      string
		fetchSite   string
		withSession bool
		adjust      func(*Config)
		want        bool
	}{
		{
			name:        "a read carrying the session is always allowed",
			method:      http.MethodGet,
			origin:      "https://evil.example.com",
			withSession: true,
			want:        true,
		},
		{
			name:        "a write from this application is allowed",
			method:      http.MethodPost,
			origin:      "https://app.example.com",
			withSession: true,
			want:        true,
		},
		{
			name:        "a write from another site is refused",
			method:      http.MethodPost,
			origin:      "https://evil.example.com",
			withSession: true,
		},
		{
			name:        "a write stating no origin is refused",
			method:      http.MethodPost,
			withSession: true,
		},
		{
			name:        "a delete from another site is refused",
			method:      http.MethodDelete,
			origin:      "https://evil.example.com",
			withSession: true,
		},
		{
			name:   "a write carrying no session is not this check's business",
			method: http.MethodPost,
			origin: "https://evil.example.com",
			want:   true,
		},
		{
			name:        "the browser saying same-origin is enough",
			method:      http.MethodPost,
			fetchSite:   "same-origin",
			withSession: true,
			want:        true,
		},
		{
			name:        "the browser saying cross-site settles it, whatever the origin",
			method:      http.MethodPost,
			origin:      "https://app.example.com",
			fetchSite:   "cross-site",
			withSession: true,
		},
		{
			name:        "a same-site sibling is still not this origin",
			method:      http.MethodPost,
			fetchSite:   "same-site",
			withSession: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			server, _ := setupIssuer(t, nil)
			flow := setupFlow(t, server, c.adjust)

			request := httptest.NewRequest(c.method, "/api/skills", nil)

			if c.origin != "" {
				request.Header.Set("Origin", c.origin)
			}

			if c.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", c.fetchSite)
			}

			if c.withSession {
				request.AddCookie(sealedSession(t, flow, session{
					AccessToken: "an-access-token",
					Expiry:      time.Now().Add(time.Hour),
				}))
			}

			assert.Equal(t, c.want, flow.Allow(request))
		})
	}
}

func Test_originOf(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		url  string
		want string
	}{
		{name: "a redirect URL reduces to its origin", url: "https://app.example.com/auth/callback", want: "https://app.example.com"},
		{name: "a port is part of the origin", url: "http://localhost:8080/auth/callback", want: "http://localhost:8080"},
		{name: "the case is normalised", url: "HTTPS://App.Example.COM/callback", want: "https://app.example.com"},
		{name: "a path alone has no origin", url: "/auth/callback"},
		{name: "nonsense has no origin", url: "://"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, originOf(c.url))
		})
	}
}

// Test_Flow_Origin pins that the application's own origin is derived from the redirect URL, which
// a deployment already has to state and which already has to be this application. Nothing else is
// asked of it, and nothing else is trusted.
//
// A redirect URL yielding no origin never reaches here: New refuses it, since an empty origin would
// match a request stating none and turn the check below into a formality.
func Test_Flow_Origin(t *testing.T) {
	t.Parallel()

	server, _ := setupIssuer(t, nil)
	flow := setupFlow(t, server, nil)

	assert.Equal(t, "https://app.example.com", flow.origin)
}
