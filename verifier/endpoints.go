package verifier

import "golang.org/x/oauth2"

// Endpoints are the issuer URLs a browser login flow drives, as discovery reported them.
// Reading them off an already built Verifier is what keeps the module to a single discovery call.
type Endpoints struct {
	// Issuer is the identity provider base URL, as it names itself.
	Issuer string

	// Authorization is where the browser is sent to sign in.
	Authorization string

	// Token is where an authorization code is exchanged, and a refresh token spent.
	Token string

	// EndSession is where the browser is sent to sign out, empty when the issuer supports none.
	EndSession string
}

// endSessionClaim reads the logout endpoint out of the discovery document, which go-oidc does not
// surface: RP initiated logout is its own specification rather than part of OIDC Core.
type endSessionClaim struct {
	EndSession string `json:"end_session_endpoint"`
}

// Endpoints reports the issuer URLs a browser login flow drives.
func (v *Verifier) Endpoints() Endpoints {
	if v.provider == nil {
		return Endpoints{}
	}

	var claim endSessionClaim

	_ = v.provider.Claims(&claim)

	return Endpoints{
		Issuer:        v.issuerURL,
		Authorization: v.provider.Endpoint().AuthURL,
		Token:         v.provider.Endpoint().TokenURL,
		EndSession:    claim.EndSession,
	}
}

// OAuth2Endpoint reports the authorization and token URLs in the shape the oauth2 package expects.
func (v *Verifier) OAuth2Endpoint() oauth2.Endpoint {
	if v.provider == nil {
		return oauth2.Endpoint{}
	}

	return v.provider.Endpoint()
}
