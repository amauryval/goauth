//go:build authdemo

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New_demo(t *testing.T) {
	cases := []struct {
		name string
	}{
		{
			name: "demo mode runs in a binary built with the tag",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			built, err := New(context.Background(), NewSettings(true, "", "", "", "", ""), setupLogger())

			require.NoError(t, err)
			assert.NotNil(t, built)
		})
	}
}
