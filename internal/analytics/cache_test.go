package analytics

import (
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	cache := NewCache(5 * time.Minute)
	if cache == nil {
		t.Fatal("Expected cache to be created")
	}

	if cache.entries == nil {
		t.Error("Expected entries map to be initialized")
	}

	if cache.ttl != 5*time.Minute {
		t.Errorf("Expected TTL to be 5 minutes, got %v", cache.ttl)
	}
}

func TestCache_SetAndGet(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	// Set a value
	cache.Set("key1", "value1")

	// Get the value
	value, ok := cache.Get("key1")
	if !ok {
		t.Error("Expected to find key1 in cache")
	}

	if value != "value1" {
		t.Errorf("Expected value1, got %v", value)
	}
}

func TestCache_GetNonExistent(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	value, ok := cache.Get("nonexistent")
	if ok {
		t.Error("Expected key to not exist")
	}

	if value != nil {
		t.Error("Expected nil value for nonexistent key")
	}
}

func TestCache_Expiration(t *testing.T) {
	cache := NewCache(100 * time.Millisecond)

	cache.Set("key1", "value1")

	// Should exist immediately
	_, ok := cache.Get("key1")
	if !ok {
		t.Error("Expected key to exist immediately after set")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, ok = cache.Get("key1")
	if ok {
		t.Error("Expected key to be expired")
	}
}

func TestCache_Delete(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")

	// Delete key1
	cache.Delete("key1")

	// key1 should not exist
	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected key1 to be deleted")
	}

	// key2 should still exist
	_, ok = cache.Get("key2")
	if !ok {
		t.Error("Expected key2 to still exist")
	}
}

func TestCache_DeletePattern(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	cache.Set("trends:2024-01-01", "data1")
	cache.Set("trends:2024-01-02", "data2")
	cache.Set("metrics:current", "data3")

	// Delete all trends
	cache.DeletePattern("trends:")

	// Trends should be deleted
	_, ok := cache.Get("trends:2024-01-01")
	if ok {
		t.Error("Expected trends:2024-01-01 to be deleted")
	}

	_, ok = cache.Get("trends:2024-01-02")
	if ok {
		t.Error("Expected trends:2024-01-02 to be deleted")
	}

	// Metrics should still exist
	_, ok = cache.Get("metrics:current")
	if !ok {
		t.Error("Expected metrics:current to still exist")
	}
}

func TestCache_Clear(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")
	cache.Set("key3", "value3")

	if cache.Size() != 3 {
		t.Errorf("Expected cache size 3, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", cache.Size())
	}

	// All keys should be gone
	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected key1 to be cleared")
	}
}

func TestCache_Size(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	if cache.Size() != 0 {
		t.Error("Expected empty cache to have size 0")
	}

	cache.Set("key1", "value1")
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	cache.Set("key2", "value2")
	if cache.Size() != 2 {
		t.Errorf("Expected cache size 2, got %d", cache.Size())
	}

	cache.Delete("key1")
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1 after delete, got %d", cache.Size())
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			cache.Set("key", n)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have a value (last write wins)
	_, ok := cache.Get("key")
	if !ok {
		t.Error("Expected key to exist after concurrent writes")
	}
}

func TestCache_StructValues(t *testing.T) {
	cache := NewCache(5 * time.Minute)

	type TestStruct struct {
		Name  string
		Count int
	}

	testData := &TestStruct{
		Name:  "test",
		Count: 42,
	}

	cache.Set("struct", testData)

	value, ok := cache.Get("struct")
	if !ok {
		t.Error("Expected to find struct in cache")
	}

	retrieved, ok := value.(*TestStruct)
	if !ok {
		t.Error("Expected value to be *TestStruct")
	}

	if retrieved.Name != "test" || retrieved.Count != 42 {
		t.Error("Expected struct values to match")
	}
}

func TestCache_CleanupExpired(t *testing.T) {
	cache := NewCache(50 * time.Millisecond)

	// Add entries
	cache.Set("key1", "value1")
	cache.Set("key2", "value2")

	if cache.Size() != 2 {
		t.Errorf("Expected cache size 2, got %d", cache.Size())
	}

	// Wait for expiration and cleanup
	time.Sleep(200 * time.Millisecond)

	// Cleanup should have removed expired entries
	// Note: cleanup runs every minute, so we can't rely on automatic cleanup in tests
	// But we can verify that Get returns false for expired entries
	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected key1 to be expired")
	}
}
