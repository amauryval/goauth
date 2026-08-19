package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/amauryval/goauth/types"
)

// bearerScheme is the authentication scheme expected in the Authorization header.
// RFC 6750 makes it case insensitive, and clients do spell it "bearer".
const bearerScheme = "bearer"

// userContextKey carries the authenticated user across the request context.
type userContextKey struct{}

// TokenSource hands over the access token of the calling browser or client.
//
// It takes the response because a source may renew the token it returns, and has to seal the
// renewed session back before anything is written. The default reads the Authorization header and
// ignores the response entirely.
type TokenSource interface {
	Token(w http.ResponseWriter, r *http.Request) string
}

// bearerSource reads the token a client presents in the Authorization header.
type bearerSource struct{}

// Token returns the bearer token of the request, empty when there is none.
func (bearerSource) Token(_ http.ResponseWriter, r *http.Request) string {
	return bearerToken(r)
}

// RequireRoles returns middleware requiring a valid bearer token whose user holds every role.
// With no role given, any authorized user passes.
func (a *Auth) RequireRoles(roles ...types.Role) func(http.Handler) http.Handler {
	return a.require(roles, holdsAll)
}

// RequireAnyRole returns middleware requiring a valid bearer token whose user holds one of the roles.
// It expresses a privilege reachable by several roles, without granting them all to the same user.
func (a *Auth) RequireAnyRole(roles ...types.Role) func(http.Handler) http.Handler {
	return a.require(roles, holdsAny)
}

// require builds middleware admitting the authorized users whose roles satisfy holds.
// A rejected token is not logged here: the verifier already reported it with its reason, and
// an unauthenticated caller decides how often that happens.
func (a *Auth) require(roles []types.Role, holds func(granted, required []types.Role) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			varyOnAuthorization(w)

			info, err := a.verifier.Verify(r.Context(), a.tokens.Token(w, r))
			if errors.Is(err, types.ErrAuthorization) {
				a.logger.Error("auth: policy unavailable", "path", r.URL.Path, "error", err)
				respondUnavailable(w)

				return
			}

			if err != nil {
				respondUnauthorized(w)

				return
			}

			if !info.Authorized {
				a.logger.Warn("auth: user not authorized", "path", r.URL.Path, "user", userID(info.User))
				respondForbidden(w)

				return
			}

			if info.User == nil {
				a.logger.Error("auth: the verifier authorized a request without a user", "path", r.URL.Path)
				respondUnauthorized(w)

				return
			}

			if !holds(info.Roles, roles) {
				a.logger.Warn("auth: missing role", "path", r.URL.Path, "granted", info.Roles, "required", roles)
				respondForbidden(w)

				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, info.User)))
		})
	}
}

// userID names the user a log line is about, for a SessionInfo that may carry none.
// TokenVerifier is an interface a host implements, and a decision to turn someone away is one it
// may reach without ever naming them.
func userID(user *types.UserInfo) string {
	if user == nil {
		return ""
	}

	return user.ID
}

// UserFrom returns the authenticated user carried by a request that passed RequireRoles.
func UserFrom(ctx context.Context) (*types.UserInfo, bool) {
	user, ok := ctx.Value(userContextKey{}).(*types.UserInfo)

	return user, ok
}

// bearerToken extracts the token from the Authorization header, empty when there is none.
// Deciding what an empty token means is left to the verifier, so that a development
// verifier can authorize a browser that never obtained one.
//
// The header is the only place it is read from: a token in a query string ends up in access logs,
// in proxy logs and in the Referer of every link the page carries.
func bearerToken(r *http.Request) string {
	scheme, rawToken, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return ""
	}

	return strings.TrimSpace(rawToken)
}

// varyOnAuthorization marks the response as depending on the caller's credentials.
// Without it a shared cache is free to hand one user's response to the next caller, since the
// requests differ only by a header it was never told to look at.
func varyOnAuthorization(w http.ResponseWriter) {
	w.Header().Add("Vary", "Authorization")
}

// noStore keeps a response describing the caller out of every cache along the way.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// holdsAll reports whether granted covers every required role.
func holdsAll(granted, required []types.Role) bool {
	for _, role := range required {
		if !slices.Contains(granted, role) {
			return false
		}
	}

	return true
}

// holdsAny reports whether granted covers at least one required role.
// Requiring nothing admits every authorized user, as holdsAll does.
func holdsAny(granted, required []types.Role) bool {
	if len(required) == 0 {
		return true
	}

	for _, role := range required {
		if slices.Contains(granted, role) {
			return true
		}
	}

	return false
}

// respondUnauthorized writes a generic 401 response, without leaking internal details.
// RFC 6750 has a 401 name the scheme it expects, which is how a client knows what to present.
func respondUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	respondStatus(w, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
}

// respondForbidden writes a generic 403 response for an authenticated user missing a role.
func respondForbidden(w http.ResponseWriter) {
	respondStatus(w, http.StatusForbidden, "forbidden", "this account is not allowed to perform this request")
}

// respondUnavailable writes a 503 response when the policy could not be evaluated.
func respondUnavailable(w http.ResponseWriter) {
	respondStatus(w, http.StatusServiceUnavailable, "unavailable", "authorization is temporarily unavailable, retry shortly")
}

// respondStatus writes a JSON error carrying the stable code a client branches on, and a sentence
// for whoever reads it. Neither names what actually failed: that is for the logs, not for a caller
// who may be probing.
func respondStatus(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	noStore(w)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(types.ErrorResponse{
		Error:   code,
		Message: message,
	})
}
