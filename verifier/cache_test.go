package verifier

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_lookupCache(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	tokenExpiry := now.Add(time.Hour)

	t.Run("roles put in the cache are read back", func(t *testing.T) {
		t.Parallel()

		cache := newLookupCache[[]string](time.Minute, 8)
		cache.put("token", []string{"admin"}, tokenExpiry, now)

		roles, cached := cache.get("token", now)

		assert.True(t, cached)
		assert.Equal(t, []string{"admin"}, roles)
	})

	t.Run("an entry is forgotten once its ttl elapsed", func(t *testing.T) {
		t.Parallel()

		cache := newLookupCache[[]string](time.Minute, 8)
		cache.put("token", []string{"admin"}, tokenExpiry, now)

		roles, cached := cache.get("token", now.Add(time.Minute))

		assert.False(t, cached)
		assert.Nil(t, roles)
	})

	t.Run("an entry never outlives the token it was read for", func(t *testing.T) {
		t.Parallel()

		cache := newLookupCache[[]string](time.Hour, 8)
		cache.put("token", []string{"admin"}, now.Add(time.Minute), now)

		_, stillFresh := cache.get("token", now.Add(30*time.Second))
		_, afterToken := cache.get("token", now.Add(2*time.Minute))

		assert.True(t, stillFresh)
		assert.False(t, afterToken)
	})

	t.Run("an already expired token is not cached at all", func(t *testing.T) {
		t.Parallel()

		cache := newLookupCache[[]string](time.Hour, 8)
		cache.put("token", []string{"admin"}, now.Add(-time.Second), now)

		_, cached := cache.get("token", now)

		assert.False(t, cached)
		assert.Empty(t, cache.entries)
	})

	t.Run("a non positive ttl disables the cache", func(t *testing.T) {
		t.Parallel()

		cache := newLookupCache[[]string](-time.Second, 8)
		cache.put("token", []string{"admin"}, tokenExpiry, now)

		_, cached := cache.get("token", now)

		assert.False(t, cached)
		assert.Empty(t, cache.entries)
	})

	t.Run("a nil cache reads and writes nothing", func(t *testing.T) {
		t.Parallel()

		var cache *lookupCache[[]string]
		cache.put("token", []string{"admin"}, tokenExpiry, now)

		_, cached := cache.get("token", now)

		assert.False(t, cached)
	})

	t.Run("the cache never grows past its bound", func(t *testing.T) {
		t.Parallel()

		const max = 4

		cache := newLookupCache[[]string](time.Minute, max)
		for _, token := range []string{"a", "b", "c", "d", "e", "f", "g"} {
			cache.put(token, []string{"admin"}, tokenExpiry, now)
		}

		assert.LessOrEqual(t, len(cache.entries), max)
	})

	t.Run("expired entries are dropped before the cache is emptied", func(t *testing.T) {
		t.Parallel()

		const max = 2

		cache := newLookupCache[[]string](time.Minute, max)
		cache.put("stale", []string{"admin"}, tokenExpiry, now)
		cache.put("fresh", []string{"guest"}, tokenExpiry, now.Add(90*time.Second))
		cache.put("newest", []string{"guest"}, tokenExpiry, now.Add(91*time.Second))

		_, staleCached := cache.get("stale", now.Add(91*time.Second))
		roles, freshCached := cache.get("fresh", now.Add(91*time.Second))

		assert.False(t, staleCached)
		assert.True(t, freshCached)
		assert.Equal(t, []string{"guest"}, roles)
	})

	t.Run("the raw token is not kept as a key", func(t *testing.T) {
		t.Parallel()

		cache := newLookupCache[[]string](time.Minute, 8)
		cache.put("secret-token", []string{"admin"}, tokenExpiry, now)

		for key := range cache.entries {
			assert.NotContains(t, string(key[:]), "secret-token")
		}
	})
}
