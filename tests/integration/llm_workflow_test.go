//go:build integration
// +build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/coding-agent/cli/internal/llm"
)

func TestLLMRemediationGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create a mock LLM provider via the Manager with mock config
	config := llm.Config{
		Provider:        "mock",
		CacheEnabled:    true,
		CacheDir:        ctx.TempDir + "/llm-cache",
		MaxTokens:       1024,
		Temperature:     0.7,
		Timeout:         30 * 1e9, // 30 seconds
		MaxRetries:      1,
		RetryDelay:      100 * 1e6, // 100ms
		RetryMultiplier: 2.0,
	}

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	// Create test remediation request for SQL injection
	req := llm.RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    `query = "SELECT * FROM users WHERE id = " + user_input`,
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "high",
		RuleID:         "B608",
		Message:        "SQL injection vulnerability detected",
	}

	// Generate remediation
	resp, err := manager.GenerateRemediation(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to generate remediation: %v", err)
	}

	if resp.Explanation == "" {
		t.Error("Expected non-empty explanation")
	}

	if !strings.Contains(resp.Explanation, "SQL Injection") {
		t.Errorf("Explanation should mention SQL Injection, got: %s", resp.Explanation)
	}

	if len(resp.RemediationSteps) == 0 {
		t.Error("Expected at least one remediation step")
	}
}

func TestLLMCachingBehavior(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create cache
	cacheDir := ctx.TempDir + "/llm-cache"
	cache, err := llm.NewCache(cacheDir, true)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Create a remediation request
	req := llm.RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "SELECT * FROM users WHERE id = " + "'test'",
		FilePath:    "app.py",
		LineNumber:  42,
		RuleID:      "sql-injection",
	}

	// Create a response to cache
	resp := &llm.RemediationResponse{
		Explanation:      "Use prepared statements to prevent SQL injection.",
		RemediationSteps: []string{"Use parameterized queries", "Validate input"},
		Confidence:       0.9,
	}

	// Store in cache
	err = cache.Set(req, resp)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Retrieve from cache
	cachedResp, found := cache.Get(req)
	if !found {
		t.Error("Expected cache hit, got miss")
	}

	if cachedResp.Explanation != resp.Explanation {
		t.Errorf("Expected explanation '%s', got '%s'", resp.Explanation, cachedResp.Explanation)
	}

	if !cachedResp.Cached {
		t.Error("Expected cached response to have Cached=true")
	}
}

func TestLLMCacheRetrieval(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cacheDir := ctx.TempDir + "/cache"
	cache, err := llm.NewCache(cacheDir, true)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Store remediation in cache
	req := llm.RemediationRequest{
		CWEID:       "CWE-79",
		CodeSnippet: "html = user_input",
		FilePath:    "template.py",
		LineNumber:  10,
		RuleID:      "xss-check",
	}
	expectedResp := &llm.RemediationResponse{
		Explanation:      "Use input validation to prevent XSS attacks.",
		RemediationSteps: []string{"Escape output", "Use CSP"},
		Confidence:       0.85,
	}

	err = cache.Set(req, expectedResp)
	if err != nil {
		t.Fatalf("Failed to store in cache: %v", err)
	}

	// Retrieve from cache
	cachedResp, found := cache.Get(req)
	if !found {
		t.Error("Expected cache hit, got miss")
	}

	if cachedResp.Explanation != expectedResp.Explanation {
		t.Errorf("Expected explanation '%s', got '%s'", expectedResp.Explanation, cachedResp.Explanation)
	}

	cache.Close()

	// Reopen cache and verify persistence
	cache2, err := llm.NewCache(cacheDir, true)
	if err != nil {
		t.Fatalf("Failed to reopen cache: %v", err)
	}
	defer cache2.Close()

	cachedResp2, found := cache2.Get(req)
	if !found {
		t.Error("Expected cache hit after reopening, got miss")
	}

	if cachedResp2.Explanation != expectedResp.Explanation {
		t.Error("Cache should persist across reopens")
	}
}

func TestLLMWithDifferentCWETypes(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	config := llm.Config{
		Provider:        "mock",
		CacheEnabled:    true,
		CacheDir:        ctx.TempDir + "/llm-cache",
		MaxTokens:       1024,
		Temperature:     0.7,
		Timeout:         30 * 1e9,
		MaxRetries:      1,
		RetryDelay:      100 * 1e6,
		RetryMultiplier: 2.0,
	}

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	testCases := []struct {
		name     string
		req      llm.RemediationRequest
		expected string
	}{
		{
			name: "SQL Injection",
			req: llm.RemediationRequest{
				CWEID:       "CWE-89",
				CodeSnippet: "query = user_input",
				Severity:    "high",
			},
			expected: "parameterized",
		},
		{
			name: "XSS",
			req: llm.RemediationRequest{
				CWEID:       "CWE-79",
				CodeSnippet: "html = user_input",
				Severity:    "medium",
			},
			expected: "Scripting",
		},
		{
			name: "Hardcoded Secret",
			req: llm.RemediationRequest{
				CWEID:       "CWE-798",
				CodeSnippet: "password = 'secret123'",
				Severity:    "high",
			},
			expected: "credentials",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := manager.GenerateRemediation(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Failed to generate remediation: %v", err)
			}

			combined := resp.Explanation + " " + strings.Join(resp.RemediationSteps, " ")
			if !strings.Contains(strings.ToLower(combined), strings.ToLower(tc.expected)) {
				t.Errorf("Expected response to contain '%s', got explanation: %s", tc.expected, resp.Explanation)
			}
		})
	}
}

func TestLLMManagerAvailability(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	config := llm.Config{
		Provider:        "mock",
		CacheEnabled:    false,
		CacheDir:        ctx.TempDir + "/llm-cache",
		MaxTokens:       1024,
		Timeout:         30 * 1e9,
		MaxRetries:      1,
		RetryDelay:      100 * 1e6,
		RetryMultiplier: 2.0,
	}

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	// Mock provider should always be available
	if !manager.IsAvailable() {
		t.Error("Expected mock provider to be available")
	}
}

func TestLLMCostEstimation(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	config := llm.Config{
		Provider:        "mock",
		CacheEnabled:    false,
		CacheDir:        ctx.TempDir + "/llm-cache",
		MaxTokens:       1024,
		Timeout:         30 * 1e9,
		MaxRetries:      1,
		RetryDelay:      100 * 1e6,
		RetryMultiplier: 2.0,
	}

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	req := llm.RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "query = user_input",
		Severity:    "high",
	}

	// Mock provider should return 0 cost
	cost, err := manager.EstimateCost(req)
	if err != nil {
		t.Fatalf("Failed to estimate cost: %v", err)
	}

	if cost != 0.0 {
		t.Errorf("Expected 0 cost for mock provider, got %f", cost)
	}
}

func TestLLMCacheCleanup(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cacheDir := ctx.TempDir + "/expiring-cache"
	cache, err := llm.NewCache(cacheDir, true)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	req := llm.RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "test code",
		RuleID:      "test-rule",
	}
	resp := &llm.RemediationResponse{
		Explanation: "Test remediation",
		Confidence:  0.8,
	}

	err = cache.Set(req, resp)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Immediate retrieval should work
	_, found := cache.Get(req)
	if !found {
		t.Error("Expected cache hit immediately after set")
	}

	// Clean with zero duration should remove all entries
	err = cache.Clean(0)
	if err != nil {
		t.Fatalf("Failed to clean cache: %v", err)
	}

	// After cleanup with zero maxAge, entries should be removed
	_, found = cache.Get(req)
	if found {
		t.Error("Expected cache miss after cleanup with zero maxAge")
	}
}
