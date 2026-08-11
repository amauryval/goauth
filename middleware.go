package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"auth/types"
)

// bearerPrefix is the scheme expected in the Authorization header.
const bearerPrefix = "Bearer "

// userContextKey carries the authenticated user across the request context.
type userContextKey struct{}

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
			info, err := a.verifier.Verify(r.Context(), bearerToken(r))
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
				a.logger.Warn("auth: user not authorized", "path", r.URL.Path, "user", info.User.ID)
				respondForbidden(w)

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

// UserFrom returns the authenticated user carried by a request that passed RequireRoles.
func UserFrom(ctx context.Context) (*types.UserInfo, bool) {
	user, ok := ctx.Value(userContextKey{}).(*types.UserInfo)

	return user, ok
}

// bearerToken extracts the token from the Authorization header, empty when there is none.
// Deciding what an empty token means is left to the verifier, so that a development
// verifier can authorize a browser that never obtained one.
func bearerToken(r *http.Request) string {
	rawToken, found := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
	if !found {
		return ""
	}

	return strings.TrimSpace(rawToken)
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
func respondUnauthorized(w http.ResponseWriter) {
	respondStatus(w, http.StatusUnauthorized, "unauthorized")
}

// respondForbidden writes a generic 403 response for an authenticated user missing a role.
func respondForbidden(w http.ResponseWriter) {
	respondStatus(w, http.StatusForbidden, "forbidden")
}

// respondUnavailable writes a 503 response when the policy could not be evaluated.
func respondUnavailable(w http.ResponseWriter) {
	respondStatus(w, http.StatusServiceUnavailable, "unavailable")
}

// respondStatus writes a JSON error carrying the same code and message.
func respondStatus(w http.ResponseWriter, statusCode int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(types.ErrorResponse{
		Error:   code,
		Message: code,
	})
}
