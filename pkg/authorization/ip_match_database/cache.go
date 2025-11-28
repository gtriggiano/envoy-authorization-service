package ip_match_database

import (
	"sync"
	"time"
)

// cacheEntry represents a single cached IP lookup result
type cacheEntry struct {
	matches   bool      // Whether the IP exists in the database
	expiresAt time.Time // When this entry expires
}

// Cache provides TTL-based caching for IP lookups
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

// NewCache creates a new cache with the specified TTL
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a cached result for the IP address
// Returns (matches, found) where:
// - matches: whether the IP exists in the database (only valid if found is true)
// - found: whether a valid (non-expired) cache entry exists
func (c *Cache) Get(ipAddress string) (matches bool, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[ipAddress]
	if !exists {
		return false, false
	}

	// Check if entry has expired
	if time.Now().After(entry.expiresAt) {
		return false, false
	}

	return entry.matches, true
}

// Set stores a lookup result for the IP address with TTL expiration
func (c *Cache) Set(ipAddress string, matches bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ipAddress] = cacheEntry{
		matches:   matches,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Clear removes all entries from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]cacheEntry)
}

// Size returns the current number of entries in the cache (including expired ones)
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}
