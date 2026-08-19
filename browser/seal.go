// Package browser drives the OIDC login flow on the server, so that a browser never handles a
// token at all. It signs the user in, exchanges the authorization code, keeps the tokens in a
// sealed cookie and spends the refresh token when the access token ages out.
//
// What it buys is the credential never reaching JavaScript: a token kept in localStorage is handed
// to any XSS on the page, and no amount of care in the API can take that back. What it costs is a
// cookie, and therefore the CSRF considerations a cookie brings, covered on Flow.
package browser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// minSecretLength is the shortest secret accepted, in bytes.
// It is the width of the key the secret is stretched into, so a shorter one would claim more
// entropy than it holds.
const minSecretLength = 32

// sealer encrypts the cookies this package hands the browser, so their contents are unreadable and
// unforgeable outside the server. AES-GCM authenticates as well as it encrypts, which is what makes
// a tampered cookie a decryption failure rather than a value to distrust later.
type sealer struct {
	aead cipher.AEAD
}

// newSealer stretches the host's secret into a key and prepares the cipher.
// The secret is hashed rather than used raw, so a passphrase and a random 32 bytes are both
// accepted without the caller having to know the key width.
func newSealer(secret []byte) (*sealer, error) {
	if len(secret) < minSecretLength {
		return nil, fmt.Errorf("the cookie secret must be at least %d bytes, got %d", minSecretLength, len(secret))
	}

	key := sha256.Sum256(secret)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("cookie cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cookie cipher: %w", err)
	}

	return &sealer{aead: aead}, nil
}

// seal encrypts a payload into a cookie value, binding it to a purpose.
//
// The purpose is authenticated alongside the payload, so a value sealed for one cookie cannot be
// replayed as another: a login's pending state can never be presented as an established session.
func (s *sealer) seal(purpose string, payload []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("cookie nonce: %w", err)
	}

	sealed := s.aead.Seal(nonce, nonce, payload, []byte(purpose))

	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open decrypts a cookie value sealed for the same purpose.
// Every failure reads the same, since a cookie that does not open is a cookie the caller has no
// business hearing about: tampered, stale, or sealed by a server holding another secret.
func (s *sealer) open(purpose, value string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errCookie
	}

	if len(sealed) < s.aead.NonceSize() {
		return nil, errCookie
	}

	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]

	payload, err := s.aead.Open(nil, nonce, ciphertext, []byte(purpose))
	if err != nil {
		return nil, errCookie
	}

	return payload, nil
}

// errCookie reports a cookie that did not open, whatever the reason.
var errCookie = errors.New("the cookie could not be read")
