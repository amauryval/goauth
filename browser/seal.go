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
//
// It holds one cipher per secret the deployment declared. The first seals; every one of them opens.
// That is what lets a secret be replaced without signing everyone out: the new one starts sealing
// at once, while the sessions already in the wild keep opening under the one they were sealed with,
// until they expire or are next written.
type sealer struct {
	aeads []cipher.AEAD
}

// newSealer stretches the host's secrets into keys and prepares the ciphers. The first secret is
// the one that seals; the rest are retired secrets, kept only so the cookies they sealed still open.
//
// A secret is hashed rather than used raw, so a passphrase and a random 32 bytes are both accepted
// without the caller having to know the key width.
func newSealer(secret []byte, retired ...[]byte) (*sealer, error) {
	aeads := make([]cipher.AEAD, 0, 1+len(retired))

	for position, each := range append([][]byte{secret}, retired...) {
		aead, err := newAEAD(each, position)
		if err != nil {
			return nil, err
		}

		aeads = append(aeads, aead)
	}

	return &sealer{aeads: aeads}, nil
}

// newAEAD prepares the cipher of one secret, naming which one failed when it is not usable.
func newAEAD(secret []byte, position int) (cipher.AEAD, error) {
	if len(secret) < minSecretLength {
		if position > 0 {
			return nil, fmt.Errorf("retired cookie secret %d must be at least %d bytes, got %d", position, minSecretLength, len(secret))
		}

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

	return aead, nil
}

// sealing is the cipher new cookies are sealed with, which is the one of the current secret.
func (s *sealer) sealing() cipher.AEAD {
	return s.aeads[0]
}

// seal encrypts a payload into a cookie value, binding it to a purpose.
//
// The purpose is authenticated alongside the payload, so a value sealed for one cookie cannot be
// replayed as another: a login's pending state can never be presented as an established session.
func (s *sealer) seal(purpose string, payload []byte) (string, error) {
	aead := s.sealing()

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("cookie nonce: %w", err)
	}

	sealed := aead.Seal(nonce, nonce, payload, []byte(purpose))

	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open decrypts a cookie value sealed for the same purpose, under any secret the deployment
// declared: the one sealing now, or one it has retired but still honours.
//
// Every failure reads the same, since a cookie that does not open is a cookie the caller has no
// business hearing about: tampered, stale, or sealed by a server holding another secret.
func (s *sealer) open(purpose, value string) ([]byte, error) {
	// Strict decoding refuses the non canonical spellings base64 otherwise tolerates: the trailing
	// character carries unused bits, so several strings decode to the same bytes. Nothing forges a
	// cookie that way, but it lets one be rewritten into an equivalent the server still accepts,
	// and a value that only has one spelling is one less thing to reason about.
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, errCookie
	}

	// The secrets are tried in turn. A wrong key is a failed authentication tag and nothing else:
	// it says the cookie was not sealed with it, never anything about the cookie's contents.
	for _, aead := range s.aeads {
		if len(sealed) < aead.NonceSize() {
			continue
		}

		nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]

		payload, err := aead.Open(nil, nonce, ciphertext, []byte(purpose))
		if err == nil {
			return payload, nil
		}
	}

	return nil, errCookie
}

// errCookie reports a cookie that did not open, whatever the reason.
var errCookie = errors.New("the cookie could not be read")
