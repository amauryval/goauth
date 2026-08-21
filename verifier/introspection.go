package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/amauryval/goauth/types"
)

// introspector asks the issuer whether a token is still active, as RFC 7662 describes.
//
// It exists because the issuer is the authority on whether someone is still signed in, and a
// signature and an expiry date cannot say so: a token stays cryptographically valid after the
// account behind it was disabled, its password changed or its session ended. Only the issuer knows
// that, and introspection is how it is asked.
type introspector struct {
	endpoint     string
	clientID     string
	clientSecret string
	client       *http.Client
}

// introspection is the answer RFC 7662 defines. Active is the whole of the decision: a token the
// issuer does not call active is not to be honoured, whatever else the response carries.
type introspection struct {
	Active bool           `json:"active"`
	Claims map[string]any `json:"-"`
}

// active asks the issuer about a token, and reports what it answered.
//
// An issuer that cannot be reached yields types.ErrAuthorization rather than a rejection: not
// knowing is not the same as being told no, and a network failure must not read as a revoked
// account. What the caller does with that is its own decision.
func (i *introspector) active(ctx context.Context, rawToken string) (introspection, error) {
	form := url.Values{
		"token":           {rawToken},
		"token_type_hint": {"access_token"},
	}

	if i.clientSecret == "" {
		form.Set("client_id", i.clientID)
	}

	requestCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return introspection{}, fmt.Errorf("%w: introspection request: %w", types.ErrAuthorization, err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	// RFC 7662 requires the caller to authenticate. A confidential client does so with its
	// credentials; one that was issued none identifies itself in the form above.
	if i.clientSecret != "" {
		request.SetBasicAuth(url.QueryEscape(i.clientID), url.QueryEscape(i.clientSecret))
	}

	response, err := i.httpClient().Do(request)
	if err != nil {
		return introspection{}, fmt.Errorf("%w: introspection request: %w", types.ErrAuthorization, err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return introspection{}, fmt.Errorf("%w: the issuer answered %s to introspection", types.ErrAuthorization, response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxIntrospectionBody))
	if err != nil {
		return introspection{}, fmt.Errorf("%w: introspection response: %w", types.ErrAuthorization, err)
	}

	var answer introspection
	if err := json.Unmarshal(body, &answer); err != nil {
		return introspection{}, fmt.Errorf("%w: unreadable introspection response: %w", types.ErrAuthorization, err)
	}

	// The claims are read a second time, unstructured: RFC 7662 lets an issuer state anything
	// beside "active", and the roles are among the things Zitadel states there.
	_ = json.Unmarshal(body, &answer.Claims)

	return answer, nil
}

// httpClient returns the client the issuer is reached with.
func (i *introspector) httpClient() *http.Client {
	if i.client != nil {
		return i.client
	}

	return &http.Client{Timeout: providerTimeout}
}

// maxIntrospectionBody bounds what is read from the issuer, so a misbehaving one cannot exhaust
// this process's memory on a path an unauthenticated caller reaches.
const maxIntrospectionBody = 1 << 20
