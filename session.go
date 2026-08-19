package goauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/amauryval/goauth/types"
)

// Root is the subtree the endpoints of this module hang from, relative to the API root.
const Root = "/auth"

// SessionPath is where SessionHandler is meant to be mounted, relative to the API root.
const SessionPath = Root + "/session"

// ConfigPath is where ConfigHandler is meant to be mounted, relative to the API root.
const ConfigPath = Root + "/config"

// Router mounts GET and POST handlers, satisfied by chi.Router and any compatible mux.
// Depending on this shape rather than on a framework keeps the module usable by any application.
type Router interface {
	Get(pattern string, handler http.HandlerFunc)
	Post(pattern string, handler http.HandlerFunc)
}

// ClientConfig tells the browser how to sign in.
//
// Where the deployment drives the flow on the server, ServerFlow is true and the frontend needs
// nothing else: it sends the visitor to LoginPath and reads LogoutPath, with no client Id, no
// scopes and no token of its own to handle. The remaining fields are then empty.
//
// Where the browser drives the flow itself, they name the provider to sign in against and what to
// ask it. Every field is empty in demo mode, where no provider is involved.
type ClientConfig struct {
	ServerFlow bool   `json:"server_flow"`
	LoginPath  string `json:"login_path,omitempty"`
	LogoutPath string `json:"logout_path,omitempty"`
	IssuerURL  string `json:"issuer_url,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	Scopes     string `json:"scopes,omitempty"`
}

// RegisterRoutes mounts the endpoints of this module at their conventional paths.
// The caller decides the API root they hang from, by passing the router of that subtree.
//
// The login endpoints are only mounted where the deployment asked for the browser flow. Logout
// answers to POST, so that a cross-site page cannot sign a visitor out by linking to it; login and
// callback answer to GET, being navigations the browser is sent through.
func (a *Auth) RegisterRoutes(router Router) {
	router.Get(ConfigPath, a.ConfigHandler())
	router.Get(SessionPath, a.SessionHandler())

	if a.flow == nil {
		return
	}

	router.Get(LoginPath, a.LoginHandler())
	router.Get(CallbackPath, a.CallbackHandler())
	router.Post(LogoutPath, a.LogoutHandler())
}

// ConfigHandler serves the provider settings the browser needs to start a login.
// Serving them at runtime keeps a single build usable across every environment,
// and the scopes a provider demands out of the frontend.
func (a *Auth) ConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if a.flow != nil {
			_ = json.NewEncoder(w).Encode(ClientConfig{
				ServerFlow: true,
				LoginPath:  LoginPath,
				LogoutPath: LogoutPath,
			})

			return
		}

		_ = json.NewEncoder(w).Encode(ClientConfig{
			IssuerURL: a.issuerURL,
			ClientID:  a.audience,
			Scopes:    strings.Join(a.scopes, " "),
		})
	}
}

// SessionHandler reports the authenticated user and the roles granted to its token.
// Roles are decided by the authorization policy, never carried by the token, so the
// browser has no other way to learn them.
func (a *Auth) SessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		varyOnAuthorization(w)
		noStore(w)

		session, err := a.verifier.Verify(r.Context(), a.tokens.Token(w, r))
		if errors.Is(err, types.ErrAuthorization) {
			a.logger.Error("auth: policy unavailable", "error", err)
			respondUnavailable(w)

			return
		}

		if err != nil {
			session = types.SessionInfo{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(session)
	}
}
