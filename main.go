package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// JwksKey represents a JSON Web Key
type JwksKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// Jwks represents a JSON Web Key Set
type Jwks struct {
	Keys []JwksKey `json:"keys"`
}

// ProviderConfig holds the configuration for a JWT provider
type ProviderConfig struct {
	Name            string        `json:"name"`
	JwksURI         string        `json:"jwks_uri"`
	CacheDuration   time.Duration `json:"cache_duration"`   // Hard expiry duration
	RefreshInterval time.Duration `json:"refresh_interval"` // Soft expiry / background refresh interval
}

// CacheEntry represents a cached JWKS entry
type CacheEntry struct {
	Jwks       *Jwks
	FetchedAt  time.Time
	HardExpiry time.Time
	SoftExpiry time.Time
}

// JwksCache manages the JWKS cache for multiple providers
type JwksCache struct {
	mu        sync.RWMutex
	providers map[string]*ProviderConfig
	cache     map[string]*CacheEntry
	client    *http.Client
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewJwksCache creates a new JwksCache
func NewJwksCache() *JwksCache {
	ctx, cancel := context.WithCancel(context.Background())
	return &JwksCache{
		providers: make(map[string]*ProviderConfig),
		cache:     make(map[string]*CacheEntry),
		client:    &http.Client{Timeout: 5 * time.Second},
		ctx:       ctx,
		cancel:    cancel,
	}
}

// RegisterProvider registers a new provider and starts its background refresh loop
func (c *JwksCache) RegisterProvider(config ProviderConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.providers[config.Name] = &config
	
	c.wg.Add(1)
	go c.backgroundRefreshLoop(config.Name)
}

// GetJwks retrieves the JWKS for a provider, fetching it synchronously if not cached or hard-expired
func (c *JwksCache) GetJwks(providerName string) (*Jwks, error) {
	c.mu.RLock()
	entry, exists := c.cache[providerName]
	config, configExists := c.providers[providerName]
	c.mu.RUnlock()

	if !configExists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	now := time.Now()
	if exists && now.Before(entry.HardExpiry) {
		return entry.Jwks, nil
	}

	// Synchronous fetch if not cached or hard-expired
	return c.fetchAndCache(config)
}

// fetchAndCache fetches the JWKS from the provider's URI and updates the cache
func (c *JwksCache) fetchAndCache(config *ProviderConfig) (*Jwks, error) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", config.JwksURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
	}

	var jwks Jwks
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	c.mu.Lock()
	now := time.Now()
	c.cache[config.Name] = &CacheEntry{
		Jwks:       &jwks,
		FetchedAt:  now,
		HardExpiry: now.Add(config.CacheDuration),
		SoftExpiry: now.Add(config.RefreshInterval),
	}
	c.mu.Unlock()

	return &jwks, nil
}

// ClearCache clears the cache for all providers or a specific provider
func (c *JwksCache) ClearCache(providerName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if providerName != "" {
		delete(c.cache, providerName)
	}
	else {
		c.cache = make(map[string]*CacheEntry)
	}
}

// backgroundRefreshLoop periodically refreshes the JWKS in the background
func (c *JwksCache) backgroundRefreshLoop(providerName string) {
	defer c.wg.Done()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			config, configExists := c.providers[providerName]
			entry, cached := c.cache[providerName]
			c.mu.RUnlock()

			if !configExists {
				return
			}

			now := time.Now()
			if !cached {
				// Proactively fetch on startup if not cached
				_, _ = c.fetchAndCache(config)
				continue
			}

			if now.After(entry.SoftExpiry) {
				_, err := c.fetchAndCache(config)
				if err != nil {
					log.Printf("Background refresh failed for provider %s: %v. Using cached keys until hard expiry.", providerName, err)
					// Delay retry to avoid spamming
					c.mu.Lock()
					if e, exists := c.cache[providerName]; exists {
						e.SoftExpiry = time.Now().Add(2 * time.Second)
					}
					c.mu.Unlock()
				}
			}
		}
	}
}

// Close stops all background routines
func (c *JwksCache) Close() {
	c.cancel()
	c.wg.Wait()
}

func main() {
	cache := NewJwksCache()
	defer cache.Close()

	// Register a default provider for demonstration/testing
	cache.RegisterProvider(ProviderConfig{
		Name:            "provider_a",
		JwksURI:         "http://localhost:8080/provider_a/jwks",
		CacheDuration:   10 * time.Second,
		RefreshInterval: 5 * time.Second,
	})

	// Admin endpoint handler to clear cache
	http.HandleFunc("/jwt_authn/clear_cache", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		provider := r.URL.Query().Get("provider")
		cache.ClearCache(provider)

		w.WriteHeader(http.StatusOK)
		if provider != "" {
			fmt.Fprintf(w, "Cleared JWKS cache for provider: %s\n", provider)
		} else {
			fmt.Fprintln(w, "Cleared JWKS cache for all providers")
		}
	})

	// Endpoint to get cache status
	http.HandleFunc("/jwt_authn/cache_status", func(w http.ResponseWriter, r *http.Request) {
		cache.mu.RLock()
		defer cache.mu.RUnlock()

		status := make(map[string]interface{})
		for name, entry := range cache.cache {
			status[name] = map[string]interface{}{
				"fetched_at":  entry.FetchedAt.Format(time.RFC3339),
				"hard_expiry": entry.HardExpiry.Format(time.RFC3339),
				"soft_expiry": entry.SoftExpiry.Format(time.RFC3339),
				"keys_count":  len(entry.Jwks.Keys),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	log.Println("Starting server on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}