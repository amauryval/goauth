package verifier

import (
	"fmt"
	"net/netip"
	"net/url"
)

// requireSecureIssuer refuses an issuer reached over cleartext, unless it is a loopback address
// or the host deliberately allowed it.
//
// The scheme is not a detail here: the module fetches the issuer's public keys over it, and
// forwards the caller's live access token to its UserInfo endpoint. Over http, an on-path attacker
// reads that credential and serves a key set of their own, which turns token verification into a
// formality. Loopback is exempt because a local provider never leaves the machine, and that is how
// the tests and a developer's own stack run.
func requireSecureIssuer(issuerURL string, allowInsecure bool) error {
	if allowInsecure {
		return nil
	}

	parsed, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("the issuer URL is not a URL: %w", err)
	}

	if parsed.Scheme == "https" {
		return nil
	}

	if parsed.Scheme != "http" {
		return fmt.Errorf("the issuer URL must be https, got %q", parsed.Scheme)
	}

	if isLoopback(parsed.Hostname()) {
		return nil
	}

	return fmt.Errorf("the issuer URL must be https: %q would fetch the signing keys and forward access tokens in cleartext", issuerURL)
}

// isLoopback reports whether the host names the local machine and nothing else.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}

	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	return address.IsLoopback()
}
