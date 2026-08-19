package verifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_requireSecureIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		issuerURL     string
		allowInsecure bool
		wantErr       string
	}{
		{name: "https is what a deployment is expected to use", issuerURL: "https://auth.example.com"},
		{name: "http on localhost is a developer's own stack", issuerURL: "http://localhost:1411"},
		{name: "http on the loopback address likewise", issuerURL: "http://127.0.0.1:1411"},
		{name: "http on the ipv6 loopback likewise", issuerURL: "http://[::1]:1411"},
		{
			name:      "http anywhere else is refused",
			issuerURL: "http://auth.example.com",
			wantErr:   "must be https",
		},
		{
			name:      "http on a container name is refused too",
			issuerURL: "http://pocketid:1411",
			wantErr:   "must be https",
		},
		{
			name:      "a scheme that is neither is refused",
			issuerURL: "ftp://auth.example.com",
			wantErr:   "must be https",
		},
		{
			name:          "a host may allow cleartext deliberately",
			issuerURL:     "http://pocketid:1411",
			allowInsecure: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			err := requireSecureIssuer(c.issuerURL, c.allowInsecure)

			if c.wantErr == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), c.wantErr)
		})
	}
}

// Test_New_RefusesCleartextIssuer pins that the check runs before any network call, so a
// misconfigured deployment fails to start rather than verifying tokens against keys it fetched
// over cleartext.
func Test_New_RefusesCleartextIssuer(t *testing.T) {
	t.Parallel()

	built, err := New(context.Background(), setupAuthorizer(), Config{
		IssuerURL:  "http://auth.example.com",
		Audience:   testAudience,
		RolesClaim: testRolesClaim,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be https")
	assert.Nil(t, built)
}
