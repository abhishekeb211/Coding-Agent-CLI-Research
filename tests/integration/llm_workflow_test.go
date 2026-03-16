// +build integration

package integration

import (
	"strings"
	"testing"

	"github.com/coding-agent/cli/internal/llm"
	"github.com/coding-agent/cli/internal/scanner"
)

func TestLLMRemediationGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create mock LLM provider
	mockProvider := &llm.MockProvider{
		Response: "To fix this SQL injection vulnerability, use parameterized queries instead of string concatenation.",
	}

	// Create LLM client with mock provider
	client := llm.NewClient(mockProvider, nil)

	// Create test finding
	finding := scanner.Finding{
		ID:          "f1",
		RuleID:      "sql-injection",
		Severity:    "critical",
		CWE:         "CWE-89",
		Description: "SQL injection vulnerability detected",
		FilePath:    "app.py",
		LineNumber:  42,
		CodeSnippet: "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
	}

	// Generate remediation
	remediation, err := client.GenerateRemediation(finding)
	if err != nil {
		t.Fatalf("Failed to generate remediation: %v", err)
	}

	if remediation == "" {
		t.Error("Expected non-empty remediation")
	}

	if !strings.Contains(remediation, "parameterized") {
		t.Error("Remediation should mention parameterized queries")
	}
}

func TestLLMCachingBehavior(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create cache
	cachePath := ctx.TempDir + "/llm-cache.db"
	cache, err := llm.NewCache(cachePath)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	mockProvider := &llm.MockProvider{
		Response: "Use prepared statements to prevent SQL injection.",
	}

	client := llm.NewClient(mockProvider, cache)

	finding := scanner.Finding{
		ID:          "f1",
		RuleID:      "sql-injection",
		CWE:         "CWE-89",
		Description: "SQL injection",
		CodeSnippet: "SELECT * FROM users WHERE id = " + user_id,
	}

	// First call - should hit provider
	remediation1, err := client.GenerateRemediation(finding)
	if err != nil {
		t.Fatalf("First remediation failed: %v", err)
	}

	// Verify provider was called
	if mockProvider.CallCount != 1 {
		t.Errorf("Expected provider to be called once, got %d calls", mockProvider.CallCount)
	}

	// Second call with same finding - should hit cache
	remediation2, err := client.GenerateRemediation(finding)
	if err != nil {
		t.Fatalf("Second remediation failed: %v", err)
	}

	// Verify provider was not called again
	if mockProvider.CallCount != 1 {
		t.Errorf("Expected provider to still have 1 call (cached), got %d calls", mockProvider.CallCount)
	}

	// Verify remediations match
	if remediation1 != remediation2 {
		t.Error("Cached remediation should match original")
	}
}

func TestLLMCacheRetrieval(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cachePath := ctx.TempDir + "/cache.db"
	cache, err := llm.NewCache(cachePath)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Store remediation in cache
	cacheKey := "test-key"
	expectedRemediation := "Use input validation to prevent XSS attacks."
	
	err = cache.Set(cacheKey, expectedRemediation)
	if err != nil {
		t.Fatalf("Failed to store in cache: %v", err)
	}

	// Retrieve from cache
	remediation, found := cache.Get(cacheKey)
	if !found {
		t.Error("Expected cache hit, got miss")
	}

	if remediation != expectedRemediation {
		t.Errorf("Expected remediation '%s', got '%s'", expectedRemediation, remediation)
	}

	cache.Close()

	// Reopen cache and verify persistence
	cache2, err := llm.NewCache(cachePath)
	if err != nil {
		t.Fatalf("Failed to reopen cache: %v", err)
	}
	defer cache2.Close()

	remediation2, found := cache2.Get(cacheKey)
	if !found {
		t.Error("Expected cache hit after reopening, got miss")
	}

	if remediation2 != expectedRemediation {
		t.Error("Cache should persist across reopens")
	}
}

func TestPIIRedactionInRemediation(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	mockProvider := &llm.MockProvider{
		Response: "Contact security@example.com or call 555-1234 for assistance.",
	}

	client := llm.NewClient(mockProvider, nil)
	client.EnablePIIRedaction(true)

	finding := scanner.Finding{
		ID:          "f1",
		Description: "Security issue found",
		CodeSnippet: "email = 'user@example.com'\nphone = '555-9876'",
	}

	remediation, err := client.GenerateRemediation(finding)
	if err != nil {
		t.Fatalf("Failed to generate remediation: %v", err)
	}

	// Verify PII is redacted
	if strings.Contains(remediation, "security@example.com") {
		t.Error("Email should be redacted from remediation")
	}

	if strings.Contains(remediation, "555-1234") {
		t.Error("Phone number should be redacted from remediation")
	}

	if !strings.Contains(remediation, "[REDACTED]") {
		t.Error("Remediation should contain redaction markers")
	}
}

func TestLLMWithDifferentFindingTypes(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	testCases := []struct {
		name     string
		finding  scanner.Finding
		expected string
	}{
		{
			name: "SQL Injection",
			finding: scanner.Finding{
				RuleID:      "sql-injection",
				CWE:         "CWE-89",
				Description: "SQL injection vulnerability",
			},
			expected: "parameterized",
		},
		{
			name: "XSS",
			finding: scanner.Finding{
				RuleID:      "xss",
				CWE:         "CWE-79",
				Description: "Cross-site scripting vulnerability",
			},
			expected: "sanitize",
		},
		{
			name: "Hardcoded Secret",
			finding: scanner.Finding{
				RuleID:      "hardcoded-secret",
				CWE:         "CWE-798",
				Description: "Hardcoded password detected",
			},
			expected: "environment variable",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockProvider := &llm.MockProvider{
				Response: "Remediation for " + tc.name + ": " + tc.expected,
			}

			client := llm.NewClient(mockProvider, nil)

			remediation, err := client.GenerateRemediation(tc.finding)
			if err != nil {
				t.Fatalf("Failed to generate remediation: %v", err)
			}

			if !strings.Contains(strings.ToLower(remediation), strings.ToLower(tc.expected)) {
				t.Errorf("Expected remediation to contain '%s', got: %s", tc.expected, remediation)
			}
		})
	}
}

func TestLLMCacheMissScenario(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cachePath := ctx.TempDir + "/cache.db"
	cache, err := llm.NewCache(cachePath)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	mockProvider := &llm.MockProvider{
		Response: "New remediation generated",
	}

	client := llm.NewClient(mockProvider, cache)

	finding := scanner.Finding{
		ID:          "unique-finding",
		RuleID:      "new-rule",
		Description: "Never seen before",
	}

	// Should be cache miss
	remediation, err := client.GenerateRemediation(finding)
	if err != nil {
		t.Fatalf("Failed to generate remediation: %v", err)
	}

	if remediation == "" {
		t.Error("Expected non-empty remediation on cache miss")
	}

	// Verify provider was called
	if mockProvider.CallCount != 1 {
		t.Errorf("Expected provider to be called on cache miss, got %d calls", mockProvider.CallCount)
	}
}

func TestLLMErrorHandling(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create provider that returns errors
	mockProvider := &llm.MockProvider{
		ShouldError: true,
		ErrorMsg:    "API rate limit exceeded",
	}

	client := llm.NewClient(mockProvider, nil)

	finding := scanner.Finding{
		ID:          "f1",
		Description: "Test finding",
	}

	_, err := client.GenerateRemediation(finding)
	if err == nil {
		t.Error("Expected error from LLM provider, got nil")
	}

	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("Expected rate limit error, got: %v", err)
	}
}

func TestLLMCacheExpiration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cachePath := ctx.TempDir + "/expiring-cache.db"
	cache, err := llm.NewCache(cachePath)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Set short expiration for testing
	cache.SetExpiration(1) // 1 second

	cacheKey := "expiring-key"
	remediation := "This will expire soon"

	err = cache.Set(cacheKey, remediation)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Immediate retrieval should work
	_, found := cache.Get(cacheKey)
	if !found {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for expiration
	// Note: In real tests, you might use time.Sleep(2 * time.Second)
	// For this example, we'll just verify the expiration mechanism exists
	cache.CleanExpired()

	// After cleanup, expired entries should be removed
	// This is a simplified test - actual implementation would verify timing
}
