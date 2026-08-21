//go:build authdemo

package goauth

import (
	"github.com/amauryval/goauth/types"
	"github.com/amauryval/goauth/verifier"
)

// demoCompiled reports that this binary was built with the authdemo tag, so demo mode may run.
const demoCompiled = true

// demoVerifier returns the verifier authorizing every visitor as an administrator.
// It is the only place reaching verifier.NewUnverified, which no other build compiles at all.
func demoVerifier() types.TokenVerifier {
	return verifier.NewUnverified()
}
