//go:build authdemo

package verifier

// This file only exists in binaries built with the authdemo tag. Leaving it out of every other
// build makes "demo mode is a compile-time opt-in" a property of the code rather than a promise:
// no import path reaches a verifier authorizing everyone as an administrator unless the binary
// was deliberately built for it.

import "github.com/amauryval/goauth/types"

// DemoUserID identifies the fixed user returned in demo mode.
const DemoUserID = "demo-user"

// NewUnverified creates a verifier accepting any request as a fixed administrator,
// without verifying a token at all. It must never be enabled in production.
func NewUnverified() *Static {
	return NewStatic(&types.UserInfo{
		Provider: "demo",
		ID:       DemoUserID,
	}, types.RoleAdmin)
}
