//go:build !authdemo

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New_demo(t *testing.T) {
	cases := []struct {
		name         string
		providerName string
		issuerURL    string
		audience     string
		wantErrPart  string
	}{
		{
			name:        "demo mode is refused by a binary built without the tag",
			wantErrPart: DemoBuildTag,
		},
		{
			name:        "a configured issuer is reported before the missing tag",
			issuerURL:   "https://issuer.example",
			wantErrPart: IssuerEnv,
		},
		{
			name:         "a declared provider is reported before the missing tag",
			providerName: "pocketid",
			wantErrPart:  ProviderEnv,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := NewSettings(true, c.providerName, c.issuerURL, c.audience, "", "")

			built, err := New(context.Background(), settings, setupLogger())

			require.Error(t, err)
			assert.Contains(t, err.Error(), c.wantErrPart)
			assert.Nil(t, built)
		})
	}
}
