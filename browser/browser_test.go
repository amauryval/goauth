package browser

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/verifier"
)

const testSecret = "a-secret-of-at-least-thirty-two-bytes"

// stubIDTokens stands in for the real ID token verification, which needs an issuer to sign with.
// It records the nonce it was handed, so a test can assert the token was tied to its login.
type stubIDTokens struct {
	err           error
	seenRawToken  string
	seenNonce     string
	rejectOnNonce bool
}

func (s *stubIDTokens) VerifyIDToken(_ context.Context, rawIDToken, nonce string) error {
	s.seenRawToken = rawIDToken
	s.seenNonce = nonce

	if s.rejectOnNonce && rawIDToken == "" {
		return errors.New("the provider returned no id token")
	}

	return s.err
}

// setupIssuer starts a provider whose token endpoint mints the tokens the test asks for, and
// records the exchange it was sent.
func setupIssuer(t *testing.T, response map[string]any) (*httptest.Server, *url.Values) {
	t.Helper()

	received := &url.Values{}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		*received = r.PostForm

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})

	return server, received
}

func setupFlow(t *testing.T, server *httptest.Server, adjust func(*Config)) *Flow {
	t.Helper()

	config := Config{
		Endpoints: verifier.Endpoints{
			Authorization: server.URL + "/authorize",
			Token:         server.URL + "/token",
		},
		ClientID:    "portfolio",
		RedirectURL: "https://app.example.com/auth/callback",
		Scopes:      []string{"openid", "offline_access"},
		Secret:      []byte(testSecret),
		IDTokens:    &stubIDTokens{},
	}

	if adjust != nil {
		adjust(&config)
	}

	flow, err := New(config)
	require.NoError(t, err)

	return flow
}

// login runs LoginHandler and returns the redirect it issued with the pending cookie it set.
func login(t *testing.T, flow *Flow, query string) (*url.URL, *http.Cookie) {
	t.Helper()

	recorder := httptest.NewRecorder()
	flow.LoginHandler()(recorder, httptest.NewRequest(http.MethodGet, "/auth/login"+query, nil))

	require.Equal(t, http.StatusFound, recorder.Code)

	target, err := url.Parse(recorder.Header().Get("Location"))
	require.NoError(t, err)

	cookies := recorder.Result().Cookies()
	require.Len(t, cookies, 1)

	return target, cookies[0]
}

func Test_New(t *testing.T) {
	t.Parallel()

	server, _ := setupIssuer(t, nil)

	cases := []struct {
		name    string
		adjust  func(*Config)
		wantErr string
	}{
		{name: "a complete configuration"},
		{
			name:    "a short secret is refused",
			adjust:  func(c *Config) { c.Secret = []byte("too-short") },
			wantErr: "at least 32 bytes",
		},
		{
			name:    "no secret at all is refused",
			adjust:  func(c *Config) { c.Secret = nil },
			wantErr: "at least 32 bytes",
		},
		{
			name:    "a missing client id is refused",
			adjust:  func(c *Config) { c.ClientID = "" },
			wantErr: "client id is required",
		},
		{
			name:    "a missing redirect URL is refused",
			adjust:  func(c *Config) { c.RedirectURL = "" },
			wantErr: "redirect URL is required",
		},
		{
			name:    "a relative redirect URL is refused",
			adjust:  func(c *Config) { c.RedirectURL = "/auth/callback" },
			wantErr: "redirect URL must be absolute",
		},
		{
			name:    "a redirect URL naming no host is refused",
			adjust:  func(c *Config) { c.RedirectURL = "https:///auth/callback" },
			wantErr: "redirect URL must be absolute",
		},
		{
			name:    "no id token verification is refused",
			adjust:  func(c *Config) { c.IDTokens = nil },
			wantErr: "id token verifier is required",
		},
		{
			name:    "an absolute post login destination is refused",
			adjust:  func(c *Config) { c.PostLoginPath = "https://evil.example.com" },
			wantErr: "path on this application",
		},
		{
			name:    "a protocol relative post login destination is refused",
			adjust:  func(c *Config) { c.PostLoginPath = "//evil.example.com" },
			wantErr: "path on this application",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			config := Config{
				Endpoints:   verifier.Endpoints{Authorization: server.URL + "/authorize", Token: server.URL + "/token"},
				ClientID:    "portfolio",
				RedirectURL: "https://app.example.com/auth/callback",
				Secret:      []byte(testSecret),
				IDTokens:    &stubIDTokens{},
			}

			if c.adjust != nil {
				c.adjust(&config)
			}

			flow, err := New(config)

			if c.wantErr == "" {
				require.NoError(t, err)
				assert.NotNil(t, flow)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), c.wantErr)
			assert.Nil(t, flow)
		})
	}
}

func Test_Flow_LoginHandler(t *testing.T) {
	t.Parallel()

	server, _ := setupIssuer(t, nil)
	flow := setupFlow(t, server, nil)

	target, cookie := login(t, flow, "")
	query := target.Query()

	assert.Equal(t, "portfolio", query.Get("client_id"))
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "https://app.example.com/auth/callback", query.Get("redirect_uri"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"), "PKCE must never fall back to plain")
	assert.NotEmpty(t, query.Get("code_challenge"))
	assert.NotEmpty(t, query.Get("state"))
	assert.NotEmpty(t, query.Get("nonce"))

	assert.True(t, cookie.HttpOnly, "the login state must be out of reach of JavaScript")
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.NotContains(t, cookie.Value, query.Get("state"), "the cookie must be sealed, not readable")
}

// Test_Flow_LoginHandler_ReturnTo pins that a login can only send the browser back to this
// application: honouring an absolute URL would turn the login endpoint into an open redirect.
func Test_Flow_LoginHandler_ReturnTo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		returnTo string
		want     string
	}{
		{name: "a path on this application is honoured", returnTo: "/skills", want: "/skills"},
		{name: "an absolute URL is dropped", returnTo: "https://evil.example.com", want: "/"},
		{name: "a protocol relative URL is dropped", returnTo: "//evil.example.com", want: "/"},
		{name: "a backslash trick is dropped", returnTo: `/\evil.example.com`, want: "/"},
		{name: "no destination lands on the default", returnTo: "", want: "/"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			response := map[string]any{"access_token": "an-access-token", "token_type": "Bearer", "expires_in": 3600}

			server, _ := setupIssuer(t, response)
			flow := setupFlow(t, server, nil)

			query := ""
			if c.returnTo != "" {
				query = "?return_to=" + url.QueryEscape(c.returnTo)
			}

			target, loginCookie := login(t, flow, query)

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/auth/callback?code=a-code&state="+url.QueryEscape(target.Query().Get("state")), nil)
			request.AddCookie(loginCookie)

			flow.CallbackHandler()(recorder, request)

			require.Equal(t, http.StatusFound, recorder.Code)
			assert.Equal(t, c.want, recorder.Header().Get("Location"))
		})
	}
}

func Test_Flow_CallbackHandler(t *testing.T) {
	t.Parallel()

	response := map[string]any{
		"access_token":  "an-access-token",
		"refresh_token": "a-refresh-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
	}

	server, exchanged := setupIssuer(t, response)
	flow := setupFlow(t, server, nil)

	target, loginCookie := login(t, flow, "")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/callback?code=a-code&state="+url.QueryEscape(target.Query().Get("state")), nil)
	request.AddCookie(loginCookie)

	flow.CallbackHandler()(recorder, request)

	require.Equal(t, http.StatusFound, recorder.Code)
	assert.Equal(t, "a-code", exchanged.Get("code"))
	assert.NotEmpty(t, exchanged.Get("code_verifier"), "the exchange must prove PKCE")
	assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))

	var session, cleared *http.Cookie

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookie {
			session = cookie
		}

		if cookie.Name == pendingCookie {
			cleared = cookie
		}
	}

	require.NotNil(t, session, "a finished login must establish a session")
	assert.True(t, session.HttpOnly, "the session must be out of reach of JavaScript")
	assert.True(t, session.Secure)
	assert.NotContains(t, session.Value, "an-access-token", "the token must be sealed, not readable")
	assert.NotContains(t, session.Value, "a-refresh-token")

	require.NotNil(t, cleared, "the pending login must be dropped once spent")
	assert.Negative(t, cleared.MaxAge)
}

// Test_Flow_CallbackHandler_Rejections covers every way a callback may not be the one this browser
// started, each of which must end the flow rather than establish a session.
func Test_Flow_CallbackHandler_Rejections(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		withCookie bool
		state      string
		query      string
		wantCode   int
	}{
		{
			name:     "a callback nobody started",
			state:    "some-state",
			wantCode: http.StatusBadRequest,
		},
		{
			name:       "a state that is not the one sent",
			withCookie: true,
			state:      "another-state",
			wantCode:   http.StatusBadRequest,
		},
		{
			name:       "no state at all",
			withCookie: true,
			state:      "",
			wantCode:   http.StatusBadRequest,
		},
		{
			name:       "a provider refusing the login",
			withCookie: true,
			query:      "&error=access_denied",
			wantCode:   http.StatusForbidden,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			server, _ := setupIssuer(t, map[string]any{"access_token": "an-access-token", "token_type": "Bearer"})
			flow := setupFlow(t, server, nil)

			target, loginCookie := login(t, flow, "")

			state := c.state
			if c.query != "" {
				state = target.Query().Get("state")
			}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/auth/callback?code=a-code&state="+url.QueryEscape(state)+c.query, nil)

			if c.withCookie {
				request.AddCookie(loginCookie)
			}

			flow.CallbackHandler()(recorder, request)

			assert.Equal(t, c.wantCode, recorder.Code)

			for _, cookie := range recorder.Result().Cookies() {
				if cookie.Name == sessionCookie {
					assert.Negative(t, cookie.MaxAge, "no session may be established")
				}
			}
		})
	}
}

// Test_Flow_CallbackHandler_ForeignCookie pins that a session sealed by another server, or a
// pending cookie replayed as a session, is not accepted.
func Test_Flow_CallbackHandler_ForeignCookie(t *testing.T) {
	t.Parallel()

	server, _ := setupIssuer(t, nil)
	flow := setupFlow(t, server, nil)
	other := setupFlow(t, server, func(c *Config) { c.Secret = []byte("another-secret-of-thirty-two-plus-bytes") })

	_, loginCookie := login(t, flow, "")

	t.Run("a cookie sealed with another secret does not open", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(loginCookie)

		var started pending
		assert.False(t, other.read(request, pendingCookie, pendingPurpose, &started))
	})

	t.Run("a pending cookie cannot be replayed as a session", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: loginCookie.Value})

		assert.Empty(t, flow.Token(httptest.NewRecorder(), request))
	})
}

func Test_Flow_Token(t *testing.T) {
	t.Parallel()

	t.Run("a session hands over its access token", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		flow := setupFlow(t, server, nil)

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(sealedSession(t, flow, session{AccessToken: "an-access-token", Expiry: time.Now().Add(time.Hour)}))

		assert.Equal(t, "an-access-token", flow.Token(httptest.NewRecorder(), request))
	})

	t.Run("no cookie hands over nothing", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		flow := setupFlow(t, server, nil)

		assert.Empty(t, flow.Token(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)))
	})

	t.Run("an expired session without a refresh token is dropped", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		flow := setupFlow(t, server, nil)

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(sealedSession(t, flow, session{AccessToken: "a-spent-token", Expiry: time.Now().Add(-time.Hour)}))

		recorder := httptest.NewRecorder()

		assert.Empty(t, flow.Token(recorder, request))
		assert.Negative(t, recorder.Result().Cookies()[0].MaxAge, "the session must be cleared")
	})

	t.Run("an expiring session is renewed and resealed", func(t *testing.T) {
		t.Parallel()

		response := map[string]any{"access_token": "a-renewed-token", "token_type": "Bearer", "expires_in": 3600}

		server, spent := setupIssuer(t, response)
		flow := setupFlow(t, server, nil)

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(sealedSession(t, flow, session{
			AccessToken:  "a-spent-token",
			RefreshToken: "a-refresh-token",
			Expiry:       time.Now().Add(-time.Minute),
		}))

		recorder := httptest.NewRecorder()

		assert.Equal(t, "a-renewed-token", flow.Token(recorder, request))
		assert.Equal(t, "refresh_token", spent.Get("grant_type"))
		assert.Equal(t, "a-refresh-token", spent.Get("refresh_token"))

		renewed := recorder.Result().Cookies()[0]
		assert.Zero(t, renewed.MaxAge, "a session the provider can renew carries no expiry of ours")
		assert.NotContains(t, renewed.Value, "a-renewed-token")
	})

	t.Run("a refusal to renew drops the session", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, map[string]any{"error": "invalid_grant"})
		flow := setupFlow(t, server, nil)

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(sealedSession(t, flow, session{
			AccessToken:  "a-spent-token",
			RefreshToken: "a-revoked-refresh-token",
			Expiry:       time.Now().Add(-time.Minute),
		}))

		recorder := httptest.NewRecorder()

		assert.Empty(t, flow.Token(recorder, request))
		assert.Negative(t, recorder.Result().Cookies()[0].MaxAge)
	})
}

// logoutRequest builds the sign out a browser on this application makes, stating the origin the
// flow checks: a logout naming no origin is one the flow refuses, which Test_Flow_LogoutHandler_
// CrossSite pins.
func logoutRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	request.Header.Set("Origin", "https://app.example.com")

	return request
}

func Test_Flow_LogoutHandler(t *testing.T) {
	t.Parallel()

	t.Run("without an issuer logout the session is simply dropped", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		flow := setupFlow(t, server, nil)

		recorder := httptest.NewRecorder()
		flow.LogoutHandler()(recorder, logoutRequest())

		assert.Equal(t, http.StatusNoContent, recorder.Code)

		for _, cookie := range recorder.Result().Cookies() {
			assert.Negative(t, cookie.MaxAge)
		}
	})

	t.Run("with one the browser is sent on to sign out there too", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		flow := setupFlow(t, server, func(c *Config) {
			c.Endpoints.EndSession = server.URL + "/end-session"
			c.PostLogoutURL = "https://app.example.com/"
		})

		recorder := httptest.NewRecorder()
		flow.LogoutHandler()(recorder, logoutRequest())

		require.Equal(t, http.StatusFound, recorder.Code)

		target, err := url.Parse(recorder.Header().Get("Location"))
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(target.String(), server.URL+"/end-session"))
		assert.Equal(t, "portfolio", target.Query().Get("client_id"))
		assert.Equal(t, "https://app.example.com/", target.Query().Get("post_logout_redirect_uri"))
	})
}

// sessionCookie seals a session the way the flow itself would, for a test starting from one.
func sealedSession(t *testing.T, flow *Flow, value session) *http.Cookie {
	t.Helper()

	recorder := httptest.NewRecorder()
	require.NoError(t, flow.write(recorder, sessionCookie, sessionPurpose, value, time.Hour))

	return recorder.Result().Cookies()[0]
}

// readSession opens the session cookie a response set, as the flow itself would.
func readSession(t *testing.T, flow *Flow, recorder *httptest.ResponseRecorder) session {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/", nil)

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookie {
			request.AddCookie(cookie)
		}
	}

	var opened session
	require.True(t, flow.read(request, sessionCookie, sessionPurpose, &opened))

	return opened
}

// Test_Flow_CallbackHandler_IDToken pins OpenID Connect Core 3.1.3.7: the ID token the exchange
// returned is verified against the nonce this login was started with, and a login that fails that
// check establishes nothing.
func Test_Flow_CallbackHandler_IDToken(t *testing.T) {
	t.Parallel()

	exchange := map[string]any{
		"access_token": "an-access-token",
		"id_token":     "an-id-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	t.Run("the id token is checked against this login's nonce", func(t *testing.T) {
		t.Parallel()

		idTokens := &stubIDTokens{}

		server, _ := setupIssuer(t, exchange)
		flow := setupFlow(t, server, func(c *Config) { c.IDTokens = idTokens })

		recorder := completeLogin(t, flow)
		require.Equal(t, http.StatusFound, recorder.Code)

		assert.Equal(t, "an-id-token", idTokens.seenRawToken)
		assert.NotEmpty(t, idTokens.seenNonce, "the nonce must be carried from the login to the check")

		established := readSession(t, flow, recorder)
		assert.Equal(t, "an-id-token", established.IDToken, "kept only as the logout hint")
	})

	t.Run("a rejected id token establishes no session", func(t *testing.T) {
		t.Parallel()

		idTokens := &stubIDTokens{err: errors.New("the id token does not belong to this login")}

		server, _ := setupIssuer(t, exchange)
		flow := setupFlow(t, server, func(c *Config) { c.IDTokens = idTokens })

		recorder := completeLogin(t, flow)

		assert.Equal(t, http.StatusForbidden, recorder.Code)

		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == sessionCookie {
				assert.Negative(t, cookie.MaxAge, "no session may survive a failed id token check")
			}
		}
	})

	t.Run("a provider returning no id token is refused", func(t *testing.T) {
		t.Parallel()

		idTokens := &stubIDTokens{rejectOnNonce: true}

		server, _ := setupIssuer(t, map[string]any{"access_token": "an-access-token", "token_type": "Bearer"})
		flow := setupFlow(t, server, func(c *Config) { c.IDTokens = idTokens })

		assert.Equal(t, http.StatusForbidden, completeLogin(t, flow).Code)
	})
}

// Test_Flow_LogoutHandler_Revocation pins RFC 7009: the refresh token is handed back rather than
// left live at the provider, and an issuer advertising no endpoint is not a failure.
func Test_Flow_LogoutHandler_Revocation(t *testing.T) {
	t.Parallel()

	t.Run("the refresh token is revoked", func(t *testing.T) {
		t.Parallel()

		var revoked url.Values

		server, _ := setupIssuer(t, nil)
		revocation := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())

			revoked = r.PostForm

			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(revocation.Close)

		flow := setupFlow(t, server, func(c *Config) { c.Endpoints.Revocation = revocation.URL })

		request := logoutRequest()
		request.AddCookie(sealedSession(t, flow, session{
			AccessToken:  "an-access-token",
			RefreshToken: "a-refresh-token",
		}))

		recorder := httptest.NewRecorder()
		flow.LogoutHandler()(recorder, request)

		assert.Equal(t, http.StatusNoContent, recorder.Code)
		assert.Equal(t, "a-refresh-token", revoked.Get("token"))
		assert.Equal(t, "refresh_token", revoked.Get("token_type_hint"))
	})

	t.Run("an issuer advertising no revocation is not a failure", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		flow := setupFlow(t, server, nil)

		request := logoutRequest()
		request.AddCookie(sealedSession(t, flow, session{RefreshToken: "a-refresh-token"}))

		recorder := httptest.NewRecorder()
		flow.LogoutHandler()(recorder, request)

		assert.Equal(t, http.StatusNoContent, recorder.Code)
	})

	t.Run("a refusal to revoke still ends the session", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		revocation := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		t.Cleanup(revocation.Close)

		flow := setupFlow(t, server, func(c *Config) { c.Endpoints.Revocation = revocation.URL })

		request := logoutRequest()
		request.AddCookie(sealedSession(t, flow, session{RefreshToken: "a-refresh-token"}))

		recorder := httptest.NewRecorder()
		flow.LogoutHandler()(recorder, request)

		assert.Equal(t, http.StatusNoContent, recorder.Code)

		for _, cookie := range recorder.Result().Cookies() {
			assert.Negative(t, cookie.MaxAge)
		}
	})

	t.Run("the id token is handed back as the logout hint", func(t *testing.T) {
		t.Parallel()

		server, _ := setupIssuer(t, nil)
		flow := setupFlow(t, server, func(c *Config) {
			c.Endpoints.EndSession = server.URL + "/end-session"
			c.PostLogoutURL = "https://app.example.com/"
		})

		request := logoutRequest()
		request.AddCookie(sealedSession(t, flow, session{IDToken: "an-id-token"}))

		recorder := httptest.NewRecorder()
		flow.LogoutHandler()(recorder, request)

		require.Equal(t, http.StatusFound, recorder.Code)

		target, err := url.Parse(recorder.Header().Get("Location"))
		require.NoError(t, err)

		assert.Equal(t, "an-id-token", target.Query().Get("id_token_hint"))
	})
}

// completeLogin walks a login from start to callback and returns the callback's response.
func completeLogin(t *testing.T, flow *Flow) *httptest.ResponseRecorder {
	t.Helper()

	target, loginCookie := login(t, flow, "")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/callback?code=a-code&state="+url.QueryEscape(target.Query().Get("state")), nil)
	request.AddCookie(loginCookie)

	flow.CallbackHandler()(recorder, request)

	return recorder
}

// Test_Flow_LogoutHandler_CrossSite pins that signing out is a write like any other: answering to
// POST keeps a cross-site page from doing it with a link, not with a form it submits itself, and
// the response clears the cookie whether or not the request carried one.
func Test_Flow_LogoutHandler_CrossSite(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		origin    string
		fetchSite string
	}{
		{name: "a sign out from another site is refused", origin: "https://evil.example.com"},
		{name: "a sign out stating no origin is refused"},
		{name: "the browser saying cross-site settles it", origin: "https://app.example.com", fetchSite: "cross-site"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			server, _ := setupIssuer(t, nil)
			flow := setupFlow(t, server, nil)

			request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)

			if c.origin != "" {
				request.Header.Set("Origin", c.origin)
			}

			if c.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", c.fetchSite)
			}

			request.AddCookie(sealedSession(t, flow, session{AccessToken: "an-access-token"}))

			recorder := httptest.NewRecorder()
			flow.LogoutHandler()(recorder, request)

			assert.Equal(t, http.StatusForbidden, recorder.Code)
			assert.Empty(t, recorder.Result().Cookies(), "a refused sign out must not clear the session")
		})
	}
}

// Test_Flow_SecretRotation pins the rotation from the outside: a browser holding a session sealed
// by the previous secret keeps it, and hands over the same access token, while a deployment that
// dropped that secret signs it out. It is what makes replacing the secret an operation rather than
// an outage.
func Test_Flow_SecretRotation(t *testing.T) {
	t.Parallel()

	const retiredSecret = "a-retired-secret-of-at-least-32-bytes"

	server, _ := setupIssuer(t, nil)

	before := setupFlow(t, server, func(c *Config) { c.Secret = []byte(retiredSecret) })
	established := sealedSession(t, before, session{
		AccessToken: "an-access-token",
		Expiry:      time.Now().Add(time.Hour),
	})

	t.Run("the retired secret is still honoured", func(t *testing.T) {
		t.Parallel()

		after := setupFlow(t, server, func(c *Config) { c.RetiredSecrets = [][]byte{[]byte(retiredSecret)} })

		request := httptest.NewRequest(http.MethodGet, "/api/skills", nil)
		request.AddCookie(established)

		assert.Equal(t, "an-access-token", after.Token(httptest.NewRecorder(), request))
	})

	t.Run("dropping it signs the session out", func(t *testing.T) {
		t.Parallel()

		after := setupFlow(t, server, nil)

		request := httptest.NewRequest(http.MethodGet, "/api/skills", nil)
		request.AddCookie(established)

		assert.Empty(t, after.Token(httptest.NewRecorder(), request),
			"a secret the deployment no longer declares must open nothing")
	})
}
