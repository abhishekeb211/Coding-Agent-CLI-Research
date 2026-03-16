package llm

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Cache handles caching of LLM responses
type Cache struct {
	db      *sql.DB
	enabled bool
}

// NewCache creates a new cache
func NewCache(cacheDir string, enabled bool) (*Cache, error) {
	if !enabled {
		return &Cache{enabled: false}, nil
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Open database
	dbPath := filepath.Join(cacheDir, "llm_cache.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	// Create table
	schema := `
	CREATE TABLE IF NOT EXISTS llm_responses (
		cache_key TEXT PRIMARY KEY,
		request_json TEXT NOT NULL,
		response_json TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		accessed_at INTEGER NOT NULL,
		access_count INTEGER DEFAULT 1
	);
	
	CREATE INDEX IF NOT EXISTS idx_accessed_at ON llm_responses(accessed_at);
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create cache schema: %w", err)
	}

	return &Cache{
		db:      db,
		enabled: true,
	}, nil
}

// generateCacheKey generates a cache key from a request
func (c *Cache) generateCacheKey(req RemediationRequest) string {
	// Create a deterministic string from the request
	key := fmt.Sprintf("%s|%s|%s|%d|%s",
		req.CWEID,
		req.FilePath,
		req.CodeSnippet,
		req.LineNumber,
		req.RuleID,
	)

	// Hash it
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// Get retrieves a cached response
func (c *Cache) Get(req RemediationRequest) (*RemediationResponse, bool) {
	if !c.enabled {
		return nil, false
	}

	cacheKey := c.generateCacheKey(req)

	var responseJSON string
	var accessCount int

	err := c.db.QueryRow(`
		SELECT response_json, access_count 
		FROM llm_responses 
		WHERE cache_key = ?
	`, cacheKey).Scan(&responseJSON, &accessCount)

	if err == sql.ErrNoRows {
		return nil, false
	}

	if err != nil {
		return nil, false
	}

	// Update access time and count
	now := time.Now().Unix()
	_, _ = c.db.Exec(`
		UPDATE llm_responses 
		SET accessed_at = ?, access_count = ? 
		WHERE cache_key = ?
	`, now, accessCount+1, cacheKey)

	// Deserialize response
	var response RemediationResponse
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		return nil, false
	}

	response.Cached = true
	return &response, true
}

// Set stores a response in the cache
func (c *Cache) Set(req RemediationRequest, resp *RemediationResponse) error {
	if !c.enabled {
		return nil
	}

	cacheKey := c.generateCacheKey(req)

	// Serialize request and response
	requestJSON, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	responseJSON, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	now := time.Now().Unix()

	_, err = c.db.Exec(`
		INSERT OR REPLACE INTO llm_responses 
		(cache_key, request_json, response_json, created_at, accessed_at, access_count)
		VALUES (?, ?, ?, ?, ?, 1)
	`, cacheKey, string(requestJSON), string(responseJSON), now, now)

	if err != nil {
		return fmt.Errorf("failed to cache response: %w", err)
	}

	return nil
}

// Clean removes old cache entries
func (c *Cache) Clean(maxAge time.Duration) error {
	if !c.enabled {
		return nil
	}

	cutoff := time.Now().Add(-maxAge).Unix()

	_, err := c.db.Exec(`
		DELETE FROM llm_responses 
		WHERE accessed_at < ?
	`, cutoff)

	return err
}

// Stats returns cache statistics
func (c *Cache) Stats() (total int, avgAccessCount float64, err error) {
	if !c.enabled {
		return 0, 0, nil
	}

	err = c.db.QueryRow(`
		SELECT COUNT(*), AVG(access_count) 
		FROM llm_responses
	`).Scan(&total, &avgAccessCount)

	return total, avgAccessCount, err
}

// Close closes the cache database
func (c *Cache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
