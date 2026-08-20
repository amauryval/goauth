package verifier

import (
	"crypto/sha256"
	"sync"
	"time"
)

// lookupCache remembers what asking the issuer about a token yielded, so that reading it costs one
// round trip per token rather than one per request. Entries are keyed by the digest of the token
// rather than by the token itself: a cache is long lived, and a raw credential sitting in a map
// would outlive the request that carried it.
//
// It is generic over what was looked up because the answers are cached the same way whatever they
// are: the UserInfo claims a token opens, and whether the issuer still calls it active.
type lookupCache[T any] struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[[sha256.Size]byte]cacheEntry[T]
}

// cacheEntry is what one cached lookup yielded, and until when it may be reused.
type cacheEntry[T any] struct {
	value     T
	expiresAt time.Time
}

// newLookupCache creates a cache holding at most max entries for ttl each.
// A zero ttl disables caching entirely, which is how a host asks for a fresh lookup every time.
func newLookupCache[T any](ttl time.Duration, max int) *lookupCache[T] {
	return &lookupCache[T]{
		ttl:     ttl,
		max:     max,
		entries: make(map[[sha256.Size]byte]cacheEntry[T]),
	}
}

// get returns what is cached for the token, and whether the entry was still fresh.
func (c *lookupCache[T]) get(rawToken string, now time.Time) (T, bool) {
	var missing T

	if c == nil || c.ttl <= 0 {
		return missing, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, found := c.entries[sha256.Sum256([]byte(rawToken))]
	if !found || !now.Before(entry.expiresAt) {
		return missing, false
	}

	return entry.value, true
}

// put caches what was read for the token until the cache TTL elapses, or until the token itself
// expires, whichever comes first: what was read for a token is worth no more than the token.
// A zero expiry states nothing about the token, and leaves the TTL as the only bound.
func (c *lookupCache[T]) put(rawToken string, value T, tokenExpiry, now time.Time) {
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

	c.entries[sha256.Sum256([]byte(rawToken))] = cacheEntry[T]{value: value, expiresAt: expiresAt}
}

// purge drops the expired entries, and everything else once they alone do not free any room.
// Emptying the cache is a cheap bound on its size: the entries are a round trip each to rebuild,
// never a source of truth, and a cache that large is being fed more tokens than its TTL retains.
// The caller holds the lock.
func (c *lookupCache[T]) purge(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
		}
	}

	if len(c.entries) >= c.max {
		clear(c.entries)
	}
}
