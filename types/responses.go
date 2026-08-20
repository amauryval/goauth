package types

// SessionInfo represents the outcome of verifying a bearer token.
type SessionInfo struct {
	LoggedIn   bool      `json:"logged_in"`
	Authorized bool      `json:"authorized"`
	Roles      []Role    `json:"roles,omitempty"`
	User       *UserInfo `json:"user,omitempty"`

	// Profile is who the user is to a reader, absent unless the deployment drives the login flow
	// on the server: a browser that obtained its own tokens already holds the ID token these
	// claims come from, and reads them there.
	Profile *Profile `json:"profile,omitempty"`
}

// ErrorResponse represents an error response.
// Error is a stable code a client may branch on, Message a sentence for whoever reads it.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
