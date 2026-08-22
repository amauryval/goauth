package goauth

import (
	"bytes"
	"fmt"
	"os"
)

// resolveSecretFiles reads the file WithSecretFile named, if any, and assigns its content to
// Secret. Called once the options are otherwise final, since Option cannot itself fail: a missing
// or unreadable file needs somewhere to report to, and New is that place.
func (o *BrowserOptions) resolveSecretFiles() error {
	if o.secretFile == "" {
		return nil
	}

	secret, err := readSecretFile(o.secretFile)
	if err != nil {
		return err
	}

	o.Secret = secret

	return nil
}

// readSecretFile reads the cookie secret from a file, for a deployment that mounts its secret store
// as files rather than exposing it through the environment — Docker and Kubernetes secrets both work
// this way. A trailing newline, the kind an editor or `openssl rand -base64 48 > file` leaves behind,
// is stripped; the rest of the content is returned unchanged.
func readSecretFile(path string) ([]byte, error) {
	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cookie secret file: %w", err)
	}

	return trimTrailingNewline(secret), nil
}

// trimTrailingNewline drops one trailing "\n" and, ahead of it, one trailing "\r", the line endings
// a file is saved with. It leaves everything else untouched: a secret's own bytes are not text to
// otherwise trim.
func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))

	return b
}
