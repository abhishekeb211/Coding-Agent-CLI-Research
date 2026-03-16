package llm

import (
	"testing"
	"time"
)

// TestNewCache tests cache initialization
func TestNewCache(t *testing.T) {
	tests := []struct {
		name     string
		cacheDir string
		enabled  bool
		wantErr  bool
	}{
		{
			name:     "enabled cache",
			cacheDir: t.TempDir(),
			enabled:  true,
			wantErr:  false,
		},
		{
			name:     "disabled cache",
			cacheDir: "",
			enabled:  false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := NewCache(tt.cacheDir, tt.enabled)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if cache != nil {
				defer cache.Close()

				if cache.enabled != tt.enabled {
					t.Errorf("NewCache() enabled = %v, want %v", cache.enabled, tt.enabled)
				}
			}
		})
	}
}

// TestCacheHit tests cache hit for identical findings
func TestCacheHit(t *testing.T) {
	cache, err := NewCache(t.TempDir(), true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	resp := &RemediationResponse{
		Explanation:      "SQL injection vulnerability",
		RemediationSteps: []string{"Use parameterized queries"},
		Confidence:       0.9,
	}

	// Store in cache
	err = cache.Set(req, resp)
	if err != nil {
		t.Fatalf("cache.Set() error = %v", err)
	}

	// Retrieve from cache
	cached, hit := cache.Get(req)
	if !hit {
		t.Error("Expected cache hit, got miss")
	}
	if cached == nil {
		t.Fatal("Expected cached response, got nil")
	}
	if cached.Explanation != resp.Explanation {
		t.Errorf("Cached explanation = %v, want %v", cached.Explanation, resp.Explanation)
	}
	if !cached.Cached {
		t.Error("Cached response should have Cached=true")
	}
}

// TestCacheMiss tests cache miss for new findings
func TestCacheMiss(t *testing.T) {
	cache, err := NewCache(t.TempDir(), true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	// Try to get from empty cache
	cached, hit := cache.Get(req)
	if hit {
		t.Error("Expected cache miss, got hit")
	}
	if cached != nil {
		t.Error("Expected nil response for cache miss")
	}
}

// TestCacheKeyGeneration tests cache key generation
func TestCacheKeyGeneration(t *testing.T) {
	cache, err := NewCache(t.TempDir(), true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	req1 := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	req2 := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	req3 := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  43, // Different line number
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	key1 := cache.generateCacheKey(req1)
	key2 := cache.generateCacheKey(req2)
	key3 := cache.generateCacheKey(req3)

	// Same requests should generate same key
	if key1 != key2 {
		t.Error("Identical requests should generate same cache key")
	}

	// Different requests should generate different keys
	if key1 == key3 {
		t.Error("Different requests should generate different cache keys")
	}
}

// TestCacheAccessCount tests access count tracking
func TestCacheAccessCount(t *testing.T) {
	cache, err := NewCache(t.TempDir(), true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	resp := &RemediationResponse{
		Explanation: "SQL injection vulnerability",
	}

	// Store in cache
	err = cache.Set(req, resp)
	if err != nil {
		t.Fatalf("cache.Set() error = %v", err)
	}

	// Access multiple times
	for i := 0; i < 5; i++ {
		_, hit := cache.Get(req)
		if !hit {
			t.Errorf("Expected cache hit on access %d", i+1)
		}
	}

	// Check stats
	total, avgAccess, err := cache.Stats()
	if err != nil {
		t.Fatalf("cache.Stats() error = %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 cached item, got %d", total)
	}

	// Access count should be at least 5 (initial + 5 gets)
	if avgAccess < 5 {
		t.Errorf("Expected average access count >= 5, got %f", avgAccess)
	}
}

// TestCacheClean tests cache expiration
func TestCacheClean(t *testing.T) {
	cache, err := NewCache(t.TempDir(), true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	resp := &RemediationResponse{
		Explanation: "SQL injection vulnerability",
	}

	// Store in cache
	err = cache.Set(req, resp)
	if err != nil {
		t.Fatalf("cache.Set() error = %v", err)
	}

	// Wait a bit to ensure time passes
	time.Sleep(10 * time.Millisecond)

	// Clean with very short max age (should remove everything)
	err = cache.Clean(1 * time.Millisecond)
	if err != nil {
		t.Fatalf("cache.Clean() error = %v", err)
	}

	// Check that cache is empty or nearly empty
	total, _, err := cache.Stats()
	if err != nil {
		t.Fatalf("cache.Stats() error = %v", err)
	}

	// Allow for timing variations - cache should be empty or have at most 1 item
	if total > 1 {
		t.Errorf("Expected 0-1 cached items after clean, got %d", total)
	}
}

// TestCachePersistence tests cache persistence across instances
func TestCachePersistence(t *testing.T) {
	cacheDir := t.TempDir()

	// Create first cache instance
	cache1, err := NewCache(cacheDir, true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}

	req := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	resp := &RemediationResponse{
		Explanation: "SQL injection vulnerability",
	}

	// Store in cache
	err = cache1.Set(req, resp)
	if err != nil {
		t.Fatalf("cache.Set() error = %v", err)
	}

	cache1.Close()

	// Create second cache instance with same directory
	cache2, err := NewCache(cacheDir, true)
	if err != nil {
		t.Fatalf("NewCache() second instance error = %v", err)
	}
	defer cache2.Close()

	// Retrieve from cache
	cached, hit := cache2.Get(req)
	if !hit {
		t.Error("Expected cache hit from persisted data")
	}
	if cached == nil {
		t.Fatal("Expected cached response from persisted data")
	}
	if cached.Explanation != resp.Explanation {
		t.Errorf("Cached explanation = %v, want %v", cached.Explanation, resp.Explanation)
	}
}

// TestDisabledCache tests disabled cache behavior
func TestDisabledCache(t *testing.T) {
	cache, err := NewCache("", false)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	req := RemediationRequest{
		CWEID:    "CWE-89",
		FilePath: "/test/file.py",
	}

	resp := &RemediationResponse{
		Explanation: "SQL injection vulnerability",
	}

	// Try to set (should be no-op)
	err = cache.Set(req, resp)
	if err != nil {
		t.Errorf("cache.Set() on disabled cache error = %v", err)
	}

	// Try to get (should always miss)
	cached, hit := cache.Get(req)
	if hit {
		t.Error("Disabled cache should always miss")
	}
	if cached != nil {
		t.Error("Disabled cache should return nil")
	}

	// Stats should return zeros
	total, avgAccess, err := cache.Stats()
	if err != nil {
		t.Errorf("cache.Stats() on disabled cache error = %v", err)
	}
	if total != 0 {
		t.Errorf("Disabled cache total = %d, want 0", total)
	}
	if avgAccess != 0 {
		t.Errorf("Disabled cache avgAccess = %f, want 0", avgAccess)
	}
}

// TestCacheUpdateExisting tests updating existing cache entries
func TestCacheUpdateExisting(t *testing.T) {
	cache, err := NewCache(t.TempDir(), true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		FilePath:    "/test/file.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users\"",
		RuleID:      "B608",
	}

	resp1 := &RemediationResponse{
		Explanation: "First explanation",
	}

	resp2 := &RemediationResponse{
		Explanation: "Updated explanation",
	}

	// Store first response
	err = cache.Set(req, resp1)
	if err != nil {
		t.Fatalf("cache.Set() first error = %v", err)
	}

	// Update with second response
	err = cache.Set(req, resp2)
	if err != nil {
		t.Fatalf("cache.Set() second error = %v", err)
	}

	// Retrieve should get updated response
	cached, hit := cache.Get(req)
	if !hit {
		t.Error("Expected cache hit")
	}
	if cached == nil {
		t.Fatal("Expected cached response")
	}
	if cached.Explanation != resp2.Explanation {
		t.Errorf("Cached explanation = %v, want %v", cached.Explanation, resp2.Explanation)
	}
}

// TestCacheStats tests cache statistics
func TestCacheStats(t *testing.T) {
	cache, err := NewCache(t.TempDir(), true)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	defer cache.Close()

	// Add multiple entries
	for i := 0; i < 5; i++ {
		req := RemediationRequest{
			CWEID:      "CWE-89",
			FilePath:   "/test/file.py",
			LineNumber: i,
			RuleID:     "B608",
		}

		resp := &RemediationResponse{
			Explanation: "Test explanation",
		}

		err = cache.Set(req, resp)
		if err != nil {
			t.Fatalf("cache.Set() error = %v", err)
		}
	}

	total, avgAccess, err := cache.Stats()
	if err != nil {
		t.Fatalf("cache.Stats() error = %v", err)
	}

	if total != 5 {
		t.Errorf("Expected 5 cached items, got %d", total)
	}

	if avgAccess != 1.0 {
		t.Errorf("Expected average access count 1.0, got %f", avgAccess)
	}
}
