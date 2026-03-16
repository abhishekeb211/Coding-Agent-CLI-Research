// Package testutil provides helper functions and utilities for testing.
package testutil

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// CreateTestDB creates an in-memory SQLite database for testing.
// It automatically runs the schema migrations and returns a ready-to-use database.
func CreateTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	// Read and execute schema
	schemaPath := filepath.Join("..", "..", "internal", "storage", "schema.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read schema file: %v", err)
	}

	_, err = db.Exec(string(schema))
	if err != nil {
		t.Fatalf("failed to execute schema: %v", err)
	}

	return db
}

// InsertTestFindings inserts sample findings into the test database.
func InsertTestFindings(t *testing.T, db *sql.DB, runID string, count int) {
	t.Helper()

	for i := 0; i < count; i++ {
		_, err := db.Exec(`
			INSERT INTO findings (
				finding_id, run_id, scanner, severity, confidence,
				file_path, line_number, message, cwe_id, fingerprint
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			"test-finding-"+string(rune(i)),
			runID,
			"bandit",
			"high",
			"high",
			"/test/file.py",
			10+i,
			"Test finding message",
			"CWE-89",
			"test-fingerprint-"+string(rune(i)),
		)
		if err != nil {
			t.Fatalf("failed to insert test finding: %v", err)
		}
	}
}

// LoadFixture loads a test fixture file from the testdata directory.
func LoadFixture(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v\nEnsure testdata directory is present", path, err)
	}

	return data
}

// MockLLMProvider is a mock LLM provider for testing without external API calls.
type MockLLMProvider struct {
	Responses map[string]string
}

// GenerateRemediation returns a mock remediation response.
func (m *MockLLMProvider) GenerateRemediation(cweID, message, code string) (string, error) {
	if resp, ok := m.Responses[cweID]; ok {
		return resp, nil
	}
	return "Mock remediation guidance for " + cweID, nil
}
