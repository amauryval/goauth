package verifier

// Endpoints are the issuer URLs a browser login flow drives, as discovery reported them.
// Reading them off an already built Verifier is what keeps the module to a single discovery call.
type Endpoints struct {
	// Authorization is where the browser is sent to sign in.
	Authorization string

	// Token is where an authorization code is exchanged, and a refresh token spent.
	Token string

	// EndSession is where the browser is sent to sign out, empty when the issuer supports none.
	EndSession string

	// Revocation is where a refresh token is handed back, empty when the issuer advertises none.
	// RFC 7009 is its own specification rather than part of OIDC, so a conforming provider may
	// well support none: what depends on it degrades rather than fails.
	Revocation string
}

// discoveryClaims reads the endpoints go-oidc does not surface, each belonging to a specification
// of its own rather than to OIDC Core.
type discoveryClaims struct {
	EndSession    string `json:"end_session_endpoint"`
	Revocation    string `json:"revocation_endpoint"`
	Introspection string `json:"introspection_endpoint"`
}

// Endpoints reports the issuer URLs a browser login flow drives.
func (v *Verifier) Endpoints() Endpoints {
	if v.provider == nil {
		return Endpoints{}
	}

	var claims discoveryClaims

	_ = v.provider.Claims(&claims)

	return Endpoints{
		Authorization: v.provider.Endpoint().AuthURL,
		Token:         v.provider.Endpoint().TokenURL,
		EndSession:    claims.EndSession,
		Revocation:    claims.Revocation,
	}
}
