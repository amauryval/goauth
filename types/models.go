package types

// UserInfo identifies the authenticated user, as the access token describes them.
//
// Provider is the token issuer and ID its subject. The pair identifies the user, but only
// within that issuer: a different provider names the same human differently. Store the pair
// as an external identity beside your own user Id, never as the user Id itself, or changing
// provider becomes a data migration.
//
// Roles are the raw role names the provider put in the token, before any policy ruled on them.
// They are a claim like any other, so an authorization policy decides which of them it honours.
// They are deliberately left out of the JSON encoding: what a browser is told are the roles the
// policy granted, carried by SessionInfo, never the provider vocabulary behind them.
//
// Profile claims such as the name, the email or the avatar are deliberately absent: an access
// token does not carry them. They are read from the ID token, where they belong, and reach a
// browser as the Profile of a SessionInfo.
type UserInfo struct {
	Provider string   `json:"provider"`
	ID       string   `json:"id"`
	Roles    []string `json:"-"`
}

// Profile is what the ID token says about the person who signed in, for a frontend to show them
// who they are signed in as. Every field is optional: a provider fills the claims it chooses to,
// and a deployment that asked for no "profile" or "email" scope gets none of them.
//
// It settles nothing. Authentication and authorization are decided on the access token, which the
// issuer vouches for on every request; these claims only spare the browser from displaying a
// subject identifier where it means to display a name.
type Profile struct {
	// Username is the handle the provider knows the user by, from the preferred_username claim.
	Username string `json:"username,omitempty"`

	// Name is the display name, from the name claim.
	Name string `json:"name,omitempty"`

	// Email is the address the provider holds, from the email claim.
	Email string `json:"email,omitempty"`

	// Picture is the URL of the avatar, from the picture claim.
	Picture string `json:"picture,omitempty"`
}

// Empty reports whether the provider filled none of the profile claims, in which case there is
// nothing for a frontend to show and nothing worth carrying in a session cookie.
func (p Profile) Empty() bool {
	return p.Username == "" && p.Name == "" && p.Email == "" && p.Picture == ""
}
