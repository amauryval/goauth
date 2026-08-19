package types

// SessionInfo represents the outcome of verifying a bearer token.
type SessionInfo struct {
	LoggedIn   bool      `json:"logged_in"`
	Authorized bool      `json:"authorized"`
	Roles      []Role    `json:"roles,omitempty"`
	User       *UserInfo `json:"user,omitempty"`
}

// ErrorResponse represents an error response.
// Error is a stable code a client may branch on, Message a sentence for whoever reads it.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
