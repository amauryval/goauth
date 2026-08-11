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
//
// Profile claims such as the name, the email or the avatar are deliberately absent: an access
// token does not carry them. The browser reads them from its own ID token, where they belong.
type UserInfo struct {
	Provider string
	ID       string
	Roles    []string
}
