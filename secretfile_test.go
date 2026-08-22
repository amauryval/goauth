package goauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_WithSecretFile pins that the secret is read from the file WithSecretFile names, with a
// trailing newline — the kind an editor or a redirected `openssl rand` leaves behind — stripped.
func Test_WithSecretFile(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		content string
		want    string
	}{
		"no trailing newline": {content: "a-secret-without-newline", want: "a-secret-without-newline"},
		"unix newline":        {content: "a-secret-with-unix-newline\n", want: "a-secret-with-unix-newline"},
		"windows newline":     {content: "a-secret-with-windows-newline\r\n", want: "a-secret-with-windows-newline"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, writeFile(path, tt.content))

			options := &BrowserOptions{}
			WithSecretFile(path)(options)

			require.NoError(t, options.resolveSecretFiles())
			assert.Equal(t, tt.want, string(options.Secret))
		})
	}
}

// Test_WithSecretFile_MissingFile pins that a misconfigured path fails rather than sealing cookies
// under an empty secret.
func Test_WithSecretFile_MissingFile(t *testing.T) {
	t.Parallel()

	options := &BrowserOptions{}
	WithSecretFile(filepath.Join(t.TempDir(), "does-not-exist"))(options)

	assert.Error(t, options.resolveSecretFiles())
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
