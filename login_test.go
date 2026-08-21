package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/internal/mock"
	"github.com/amauryval/goauth/provider"
)

// Test_Auth_BrowserEndpoints_NotConfigured pins that a deployment which never asked for the server
// driven flow neither mounts its endpoints nor pretends to serve them.
func Test_Auth_BrowserEndpoints_NotConfigured(t *testing.T) {
	t.Parallel()

	auth, err := NewWithVerifier(&mock.Verifier{}, nil)
	require.NoError(t, err)

	handlers := map[string]http.HandlerFunc{
		LoginPath:    auth.LoginHandler(),
		CallbackPath: auth.CallbackHandler(),
		LogoutPath:   auth.LogoutHandler(),
	}

	for path, handler := range handlers {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler(recorder, httptest.NewRequest(http.MethodGet, path, nil))

			assert.Equal(t, http.StatusNotFound, recorder.Code)
		})
	}

	router := newStubRouter()
	auth.RegisterRoutes(router)

	assert.NotContains(t, router.mounted, LoginPath)
	assert.NotContains(t, router.mounted, LogoutPath)
}

// Test_ConfigHandler_BearerFlow pins what a frontend driving the flow itself is told.
func Test_ConfigHandler_BearerFlow(t *testing.T) {
	t.Parallel()

	auth, err := NewWithVerifier(&mock.Verifier{}, nil)
	require.NoError(t, err)

	auth.issuerURL = "https://auth.example.com"
	auth.audience = "portfolio"
	auth.scopes = []string{"openid", "groups"}

	recorder := httptest.NewRecorder()
	auth.ConfigHandler()(recorder, httptest.NewRequest(http.MethodGet, ConfigPath, nil))

	assert.JSONEq(t, `{
		"server_flow": false,
		"issuer_url": "https://auth.example.com",
		"client_id": "portfolio",
		"scopes": "openid groups"
	}`, recorder.Body.String())
}

func Test_Paths(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "/auth/login", LoginPath)
	assert.Equal(t, "/auth/callback", CallbackPath)
	assert.Equal(t, "/auth/logout", LogoutPath)
}

// Test_Settings_rejectProviderSettings_Browser pins that demo mode refuses the browser flow too:
// signing users in for real while authorizing everyone as an administrator is a contradiction.
func Test_Settings_rejectProviderSettings_Browser(t *testing.T) {
	t.Parallel()

	settings := NewSettings(WithDemo(true), WithBrowser("", nil))

	err := settings.rejectProviderSettings()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "browser login flow")
}

// setupIssuer starts an issuer answering discovery, so that New can build a real verifier and read
// the endpoints the login flow drives off it.
func setupIssuer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/keys",
			"authorization_endpoint":                server.URL + "/authorize",
			"token_endpoint":                        server.URL + "/token",
			"userinfo_endpoint":                     server.URL + "/userinfo",
			"end_session_endpoint":                  server.URL + "/end-session",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{}})
	})

	return server
}

// Test_New_BrowserFlow drives the whole assembly: discovery, the verifier, the endpoints read off
// it, and the flow those endpoints feed.
func Test_New_BrowserFlow(t *testing.T) {
	t.Parallel()

	server := setupIssuer(t)
	secret := []byte("a-cookie-secret-of-at-least-thirty-two-bytes")

	cases := []struct {
		name    string
		browser Option
		wantErr string
	}{
		{
			name: "a complete browser configuration",
			browser: WithBrowser("https://app.example.com/auth/callback", secret,
				WithPostLogoutURL("https://app.example.com/")),
		},
		{
			name:    "a secret too short to seal a cookie",
			browser: WithBrowser("https://app.example.com/auth/callback", []byte("too-short")),
			wantErr: "at least 32 bytes",
		},
		{
			name:    "a missing redirect URL",
			browser: WithBrowser("", secret),
			wantErr: "redirect URL is required",
		},
		{
			name: "a post login destination off this application",
			browser: WithBrowser("https://app.example.com/auth/callback", secret,
				WithPostLoginPath("https://evil.example.com")),
			wantErr: "path on this application",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			auth, err := New(context.Background(), NewSettings(
				WithProvider(provider.Zitadel.Name()),
				WithIssuer(server.URL),
				WithAudience("portfolio"),
				c.browser,
			), nil)

			if c.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErr)
				assert.Nil(t, auth)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, auth.flow, "asking for the browser flow must build one")

			router := newStubRouter()
			auth.RegisterRoutes(router)

			assert.Len(t, router.mounted, 5)
			assert.Equal(t, http.MethodGet, router.methods[LoginPath])
			assert.Equal(t, http.MethodGet, router.methods[CallbackPath])
			assert.Equal(t, http.MethodPost, router.methods[LogoutPath], "logout must not be reachable by a link")

			recorder := httptest.NewRecorder()
			auth.ConfigHandler()(recorder, httptest.NewRequest(http.MethodGet, ConfigPath, nil))

			assert.JSONEq(t, `{"server_flow": true, "login_path": "/auth/login", "logout_path": "/auth/logout"}`, recorder.Body.String())

			started := httptest.NewRecorder()
			auth.LoginHandler()(started, httptest.NewRequest(http.MethodGet, LoginPath, nil))

			assert.Equal(t, http.StatusFound, started.Code)
			assert.Contains(t, started.Header().Get("Location"), server.URL+"/authorize")
		})
	}
}
