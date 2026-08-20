package goauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amauryval/goauth/internal/mock"
	"github.com/amauryval/goauth/provider"
	"github.com/amauryval/goauth/types"
)

func Test_NewWithVerifier(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		noVerifier  bool
		withLogger  bool
		wantErr     bool
		wantDiscard bool
	}{
		{
			name:        "verifier without logger falls back to the discard logger",
			wantDiscard: true,
		},
		{
			name:       "verifier with an explicit logger",
			withLogger: true,
		},
		{
			name:       "missing verifier",
			noVerifier: true,
			wantErr:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			var verifier types.TokenVerifier
			if !c.noVerifier {
				verifier = &mock.Verifier{}
			}

			var logger types.Logger
			if c.withLogger {
				logger = types.DiscardLogger{}
			}

			built, err := NewWithVerifier(verifier, logger)

			if c.wantErr {
				require.Error(t, err)
				assert.Nil(t, built)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, built)
			assert.NotNil(t, built.logger)
			assert.NotNil(t, built.verifier)
		})
	}
}

func Test_newVerified(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		issuerURL string
		audience  string
		selected  provider.Provider
	}{
		{
			name:      "unreachable issuer",
			issuerURL: "http://127.0.0.1:1",
			audience:  "portfolio",
			selected:  provider.Zitadel,
		},
		{
			name:     "missing issuer URL",
			audience: "portfolio",
			selected: provider.PocketID,
		},
		{
			name:      "missing audience",
			issuerURL: "http://127.0.0.1:1",
			selected:  provider.Zitadel,
		},
		{
			name:      "no provider, hence no roles claim",
			issuerURL: "http://127.0.0.1:1",
			audience:  "portfolio",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			settings := NewSettings(WithProvider(c.selected.Name()), WithIssuer(c.issuerURL), WithAudience(c.audience))

			built, err := newVerified(context.Background(), settings, c.selected, setupLogger())

			require.Error(t, err)
			assert.Nil(t, built)
		})
	}
}
