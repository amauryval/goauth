//go:build !authdemo

package goauth

import "github.com/amauryval/goauth/types"

// demoCompiled reports that this binary was built without the authdemo tag, so demo mode is refused.
const demoCompiled = false

// demoVerifier returns nothing: the verifier authorizing every visitor is not part of this binary.
// New refuses demo mode before reaching it, so it never runs.
func demoVerifier() types.TokenVerifier {
	return nil
}
