package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"auth/types"
)

// Root is the subtree the endpoints of this module hang from, relative to the API root.
const Root = "/auth"

// SessionPath is where SessionHandler is meant to be mounted, relative to the API root.
const SessionPath = Root + "/session"

// ConfigPath is where ConfigHandler is meant to be mounted, relative to the API root.
const ConfigPath = Root + "/config"

// Router mounts GET handlers, satisfied by chi.Router and any compatible mux.
// Depending on this shape rather than on a framework keeps the module usable by any application.
type Router interface {
	Get(pattern string, handler http.HandlerFunc)
}

// ClientConfig tells the browser which identity provider to sign in against, and what to ask it.
// Every field is empty in demo mode, where no provider is involved.
type ClientConfig struct {
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
	Scopes    string `json:"scopes"`
}

// RegisterRoutes mounts the config and session endpoints at their conventional paths.
// The caller decides the API root they hang from, by passing the router of that subtree.
func (a *Auth) RegisterRoutes(router Router) {
	router.Get(ConfigPath, a.ConfigHandler())
	router.Get(SessionPath, a.SessionHandler())
}

// ConfigHandler serves the provider settings the browser needs to start a login.
// Serving them at runtime keeps a single build usable across every environment,
// and the scopes a provider demands out of the frontend.
func (a *Auth) ConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
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
		session, err := a.verifier.Verify(r.Context(), bearerToken(r))
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
