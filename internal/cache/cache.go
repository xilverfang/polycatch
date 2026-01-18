// Package cache provides TTL-based caching for API responses to reduce
// redundant calls to external services (Polymarket CLOB API, etc.)
package cache

import (
	"sync"
	"time"
)

// Entry represents a cached value with expiration
type Entry[T any] struct {
	Value     T
	ExpiresAt time.Time
}

// IsExpired returns true if the entry has expired
func (e *Entry[T]) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Cache is a generic TTL-based cache
type Cache[T any] struct {
	data map[string]*Entry[T]
	mu   sync.RWMutex
	ttl  time.Duration
}

// New creates a new cache with the specified TTL
func New[T any](ttl time.Duration) *Cache[T] {
	c := &Cache[T]{
		data: make(map[string]*Entry[T]),
		ttl:  ttl,
	}
	// Start background cleanup goroutine
	go c.cleanup()
	return c
}

// Get retrieves a value from the cache
// Returns the value and true if found and not expired, zero value and false otherwise
func (c *Cache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists || entry.IsExpired() {
		var zero T
		return zero, false
	}
	return entry.Value, true
}

// Set stores a value in the cache with the default TTL
func (c *Cache[T]) Set(key string, value T) {
	c.SetWithTTL(key, value, c.ttl)
}

// SetWithTTL stores a value with a custom TTL
func (c *Cache[T]) SetWithTTL(key string, value T, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = &Entry[T]{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// Delete removes a value from the cache
func (c *Cache[T]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}

// Clear removes all entries from the cache
func (c *Cache[T]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]*Entry[T])
}

// Size returns the number of entries in the cache (including expired)
func (c *Cache[T]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}

// cleanup periodically removes expired entries
func (c *Cache[T]) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.data {
			if now.After(entry.ExpiresAt) {
				delete(c.data, key)
			}
		}
		c.mu.Unlock()
	}
}

// TokenMetadata holds cached token-level data
type TokenMetadata struct {
	TickSize       string
	MinOrderSize   float64
	FeeRateBps     string
	NegRisk        bool
	NegRiskFetched bool // tracks if NegRisk was actually fetched (since false is a valid value)
}

// TokenCache is a specialized cache for token metadata
// Uses longer TTL since this data rarely changes
type TokenCache struct {
	*Cache[*TokenMetadata]
}

// NewTokenCache creates a cache for token metadata (5 minute TTL)
func NewTokenCache() *TokenCache {
	return &TokenCache{
		Cache: New[*TokenMetadata](5 * time.Minute),
	}
}

// PriceCache is a specialized cache for price data
// Uses short TTL since prices change frequently
type PriceCache struct {
	*Cache[string]
}

// NewPriceCache creates a cache for prices (2 second TTL)
func NewPriceCache() *PriceCache {
	return &PriceCache{
		Cache: New[string](2 * time.Second),
	}
}

// PriceKey generates a cache key for price lookups
func PriceKey(tokenID, side string) string {
	return tokenID + ":" + side
}
