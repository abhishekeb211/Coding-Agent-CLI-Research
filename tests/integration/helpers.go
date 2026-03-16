// +build integration

package integration

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/coding-agent/cli/internal/storage"
)

// TestContext holds shared test resources for integration tests
type TestContext struct {
	TempDir string
	DB      *storage.Database
	DBPath  string
}

// SetupTest creates a test context with temporary directory and database
func SetupTest(t *testing.T) *TestContext {
	t.Helper()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "coding-agent-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create test database
	dbPath := filepath.Join(tempDir, "test.db")
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create test database: %v", err)
	}

	return &TestContext{
		TempDir: tempDir,
		DB:      db,
		DBPath:  dbPath,
	}
}

// Cleanup removes temporary test resources
func (ctx *TestContext) Cleanup(t *testing.T) {
	t.Helper()

	if ctx.DB != nil {
		ctx.DB.Close()
	}

	if ctx.TempDir != "" {
		os.RemoveAll(ctx.TempDir)
	}
}

// CreateTestFile creates a file with given content in the test directory
func (ctx *TestContext) CreateTestFile(t *testing.T, relativePath, content string) string {
	t.Helper()

	fullPath := filepath.Join(ctx.TempDir, relativePath)
	dir := filepath.Dir(fullPath)

	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory %s: %v", dir, err)
	}

	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write file %s: %v", fullPath, err)
	}

	return fullPath
}

// CreateTestConfig creates a test configuration file
func (ctx *TestContext) CreateTestConfig(t *testing.T, content string) string {
	t.Helper()
	return ctx.CreateTestFile(t, "config.yaml", content)
}

// CreateTestPolicy creates a test policy file
func (ctx *TestContext) CreateTestPolicy(t *testing.T, content string) string {
	t.Helper()
	return ctx.CreateTestFile(t, "policy.yaml", content)
}

// AssertFileExists checks if a file exists
func AssertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("Expected file %s to exist, but it does not", path)
	}
}

// AssertFileNotExists checks if a file does not exist
func AssertFileNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Expected file %s to not exist, but it does", path)
	}
}

// AssertDBHasFindings checks if database has expected number of findings
func AssertDBHasFindings(t *testing.T, db *storage.Database, runID string, expectedCount int) {
	t.Helper()

	query := "SELECT COUNT(*) FROM findings WHERE run_id = ?"
	var count int
	err := db.DB().QueryRow(query, runID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query findings count: %v", err)
	}

	if count != expectedCount {
		t.Errorf("Expected %d findings, got %d", expectedCount, count)
	}
}
