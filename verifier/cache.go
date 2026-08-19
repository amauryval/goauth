package verifier

import (
	"crypto/sha256"
	"sync"
	"time"
)

// roleCache remembers the roles a UserInfo request returned, so that reading them costs one
// round trip per token rather than one per request. Entries are keyed by the digest of the token
// rather than by the token itself: a cache is long lived, and a raw credential sitting in a map
// would outlive the request that carried it.
type roleCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[[sha256.Size]byte]roleEntry
}

// roleEntry is what one cached UserInfo lookup yielded, and until when it may be reused.
type roleEntry struct {
	roles     []string
	expiresAt time.Time
}

// newRoleCache creates a cache holding at most max entries for ttl each.
// A zero ttl disables caching entirely, which is how a host asks for a fresh lookup every time.
func newRoleCache(ttl time.Duration, max int) *roleCache {
	return &roleCache{
		ttl:     ttl,
		max:     max,
		entries: make(map[[sha256.Size]byte]roleEntry),
	}
}

// get returns the roles cached for the token, and whether the entry was still fresh.
func (c *roleCache) get(rawToken string, now time.Time) ([]string, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, found := c.entries[sha256.Sum256([]byte(rawToken))]
	if !found || !now.Before(entry.expiresAt) {
		return nil, false
	}

	return entry.roles, true
}

// put caches the roles read for the token until the cache TTL elapses, or until the token itself
// expires, whichever comes first: roles read for a token are worth no more than the token.
func (c *roleCache) put(rawToken string, roles []string, tokenExpiry, now time.Time) {
	if c == nil || c.ttl <= 0 {
		return
	}

	expiresAt := now.Add(c.ttl)
	if !tokenExpiry.IsZero() && tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}

	if !now.Before(expiresAt) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.max {
		c.purge(now)
	}

	c.entries[sha256.Sum256([]byte(rawToken))] = roleEntry{roles: roles, expiresAt: expiresAt}
}

// purge drops the expired entries, and everything else once they alone do not free any room.
// Emptying the cache is a cheap bound on its size: the entries are a round trip each to rebuild,
// never a source of truth, and a cache that large is being fed more tokens than its TTL retains.
// The caller holds the lock.
func (c *roleCache) purge(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
		}
	}

	if len(c.entries) >= c.max {
		clear(c.entries)
	}
}
