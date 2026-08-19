package browser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_sealer(t *testing.T) {
	t.Parallel()

	sealer, err := newSealer([]byte(testSecret))
	require.NoError(t, err)

	t.Run("what is sealed opens again", func(t *testing.T) {
		t.Parallel()

		sealed, err := sealer.seal(sessionPurpose, []byte("a-token"))
		require.NoError(t, err)

		opened, err := sealer.open(sessionPurpose, sealed)

		require.NoError(t, err)
		assert.Equal(t, []byte("a-token"), opened)
	})

	t.Run("the payload is not readable in the sealed value", func(t *testing.T) {
		t.Parallel()

		sealed, err := sealer.seal(sessionPurpose, []byte("a-token"))

		require.NoError(t, err)
		assert.NotContains(t, sealed, "a-token")
	})

	t.Run("sealing twice never yields the same value", func(t *testing.T) {
		t.Parallel()

		first, err := sealer.seal(sessionPurpose, []byte("a-token"))
		require.NoError(t, err)

		second, err := sealer.seal(sessionPurpose, []byte("a-token"))
		require.NoError(t, err)

		assert.NotEqual(t, first, second, "a repeated nonce would leak that two sessions match")
	})

	t.Run("a value sealed for another purpose does not open", func(t *testing.T) {
		t.Parallel()

		sealed, err := sealer.seal(pendingPurpose, []byte("a-token"))
		require.NoError(t, err)

		_, err = sealer.open(sessionPurpose, sealed)

		assert.ErrorIs(t, err, errCookie)
	})

	t.Run("a value sealed with another secret does not open", func(t *testing.T) {
		t.Parallel()

		other, err := newSealer([]byte("another-secret-of-thirty-two-plus-bytes"))
		require.NoError(t, err)

		sealed, err := other.seal(sessionPurpose, []byte("a-token"))
		require.NoError(t, err)

		_, err = sealer.open(sessionPurpose, sealed)

		assert.ErrorIs(t, err, errCookie)
	})

	t.Run("a tampered value does not open", func(t *testing.T) {
		t.Parallel()

		sealed, err := sealer.seal(sessionPurpose, []byte("a-token"))
		require.NoError(t, err)

		// Every position is tampered with in turn, rather than one: the last base64 character
		// carries unused bits, so changing it alone can decode to the very same bytes.
		for at := range sealed {
			tampered := sealed[:at] + string(flip(sealed[at])) + sealed[at+1:]
			if tampered == sealed {
				continue
			}

			_, err := sealer.open(sessionPurpose, tampered)

			assert.ErrorIs(t, err, errCookie, "tampering at %d must be caught", at)
		}
	})

	t.Run("nonsense does not open", func(t *testing.T) {
		t.Parallel()

		for _, value := range []string{"", "not-base64-!!", strings.Repeat("A", 8)} {
			_, err := sealer.open(sessionPurpose, value)

			assert.ErrorIs(t, err, errCookie, value)
		}
	})
}

func Test_newSealer_ShortSecret(t *testing.T) {
	t.Parallel()

	sealer, err := newSealer([]byte("too-short"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 bytes")
	assert.Nil(t, sealer)
}

// flip returns a different character of the base64url alphabet.
func flip(character byte) byte {
	if character == 'A' {
		return 'B'
	}

	return 'A'
}
