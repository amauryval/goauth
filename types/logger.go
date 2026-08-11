package types

// Logger reports internal failures and rejected authentication attempts.
// HTTP responses stay opaque, so this is the only way an operator sees them.
// It is satisfied by *slog.Logger.
type Logger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// DiscardLogger drops every message. It is the default when no logger is configured.
type DiscardLogger struct{}

// Warn does nothing.
func (DiscardLogger) Warn(_ string, _ ...any) {}

// Error does nothing.
func (DiscardLogger) Error(_ string, _ ...any) {}
