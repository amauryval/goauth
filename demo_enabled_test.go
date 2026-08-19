//go:build authdemo

package goauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New_demo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
	}{
		{
			name: "demo mode runs in a binary built with the tag",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			built, err := New(context.Background(), NewSettings(Options{Demo: true}), setupLogger())

			require.NoError(t, err)
			assert.NotNil(t, built)
		})
	}
}
