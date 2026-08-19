// Package types holds the vocabulary shared by the module and by the applications embedding it:
// the roles, the user a verified token describes, and the interfaces a host implements to plug in
// its own verification or its own authorization policy.
package types

import (
	"context"
	"errors"
)

// RoleAdmin is the conventional role of a user allowed to administer the application.
const RoleAdmin Role = "admin"

// RoleGuest is the conventional role of a user allowed to read the administration, but not write.
const RoleGuest Role = "guest"

// ErrAuthorization reports that the policy could not be evaluated, as opposed to a rejected token.
// A policy reading a store fails this way when the store is unreachable, and the request deserves
// a 503 rather than a 401: nothing is wrong with the caller, and retrying may succeed.
var ErrAuthorization = errors.New("authorization unavailable")

// Role is a permission label granted to an authenticated user.
type Role string

// Decision is the outcome of an authorization check.
type Decision struct {
	Authorized bool
	Roles      []Role
}

// Authorizer decides whether an authenticated user may access the application.
// It is evaluated on every request against the session user, never against the provider.
type Authorizer interface {
	Authorize(ctx context.Context, user *UserInfo) (Decision, error)
}
