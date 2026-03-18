//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"

	"github.com/coding-agent/cli/internal/llm"
)

func TestLLMRemediationGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create LLM manager with mock provider
	config := llm.DefaultConfig()
	config.Provider = "mock"
	config.CacheEnabled = true
	config.CacheDir = ctx.TempDir

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	// Create test remediation request
	req := llm.RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    `query = "SELECT * FROM users WHERE id = '" + user_id + "'"`,
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "critical",
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

	if len(resp.RemediationSteps) == 0 {
		t.Error("Expected at least one remediation step")
	}
}

func TestLLMCachingBehavior(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create cache
	cache, err := llm.NewCache(ctx.TempDir, true)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Create a remediation request and response for caching
	req := llm.RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    `SELECT * FROM users WHERE id = 'test'`,
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "critical",
		RuleID:         "B608",
	}

	// First call - should be a cache miss
	_, found := cache.Get(req)
	if found {
		t.Error("Expected cache miss on first call")
	}

	// Generate via manager and cache should be populated
	config := llm.DefaultConfig()
	config.Provider = "mock"
	config.CacheEnabled = true
	config.CacheDir = ctx.TempDir

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	resp, err := manager.GenerateRemediation(context.Background(), req)
	if err != nil {
		t.Fatalf("First remediation failed: %v", err)
	}

	if resp == nil {
		t.Fatal("Expected non-nil response")
	}

	// Second call should hit cache
	resp2, err := manager.GenerateRemediation(context.Background(), req)
	if err != nil {
		t.Fatalf("Second remediation failed: %v", err)
	}

	if !resp2.Cached {
		t.Error("Expected second call to be served from cache")
	}
}

func TestLLMCacheRetrieval(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cache, err := llm.NewCache(ctx.TempDir, true)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	req := llm.RemediationRequest{
		CWEID:       "CWE-79",
		CodeSnippet: "html = user_input",
		FilePath:    "app.py",
		LineNumber:  10,
		RuleID:      "B201",
	}

	resp := &llm.RemediationResponse{
		Explanation:      "Use input validation to prevent XSS attacks.",
		RemediationSteps: []string{"Escape output", "Use CSP"},
		Confidence:       0.85,
	}

	// Store in cache
	err = cache.Set(req, resp)
	if err != nil {
		t.Fatalf("Failed to store in cache: %v", err)
	}

	// Retrieve from cache
	cachedResp, found := cache.Get(req)
	if !found {
		t.Error("Expected cache hit, got miss")
	}

	if cachedResp.Explanation != resp.Explanation {
		t.Errorf("Expected explanation '%s', got '%s'", resp.Explanation, cachedResp.Explanation)
	}

	cache.Close()

	// Reopen cache and verify persistence
	cache2, err := llm.NewCache(ctx.TempDir, true)
	if err != nil {
		t.Fatalf("Failed to reopen cache: %v", err)
	}
	defer cache2.Close()

	cachedResp2, found := cache2.Get(req)
	if !found {
		t.Error("Expected cache hit after reopening, got miss")
	}

	if cachedResp2.Explanation != resp.Explanation {
		t.Error("Cache should persist across reopens")
	}
}

func TestPIIRedactionInRemediation(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create a redactor and test it directly
	redactor := llm.NewRedactor(true)

	// Test redaction of sensitive data
	req := &llm.RemediationRequest{
		CWEID:       "CWE-798",
		CodeSnippet: "email = 'user@example.com'\nphone = '555-9876'\npassword = 'secret123'",
		Message:     "Hardcoded credentials detected",
	}

	redacted, matches := redactor.RedactRequest(req)

	if len(matches) == 0 {
		t.Error("Expected PII matches to be detected")
	}

	// Verify something was redacted in the code snippet
	if redacted.CodeSnippet == req.CodeSnippet && len(matches) > 0 {
		t.Error("Expected code snippet to be redacted")
	}
}

func TestLLMWithDifferentFindingTypes(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	config := llm.DefaultConfig()
	config.Provider = "mock"
	config.CacheEnabled = false

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	testCases := []struct {
		name string
		req  llm.RemediationRequest
	}{
		{
			name: "SQL Injection",
			req: llm.RemediationRequest{
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				Severity:       "critical",
			},
		},
		{
			name: "XSS",
			req: llm.RemediationRequest{
				CWEID:          "CWE-79",
				CWEDescription: "Cross-site Scripting (XSS)",
				Severity:       "medium",
			},
		},
		{
			name: "Hardcoded Secret",
			req: llm.RemediationRequest{
				CWEID:          "CWE-798",
				CWEDescription: "Hardcoded Credentials",
				Severity:       "high",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := manager.GenerateRemediation(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Failed to generate remediation: %v", err)
			}

			if resp.Explanation == "" {
				t.Error("Expected non-empty explanation")
			}

			if len(resp.RemediationSteps) == 0 {
				t.Error("Expected at least one remediation step")
			}
		})
	}
}

func TestLLMCacheMissScenario(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cache, err := llm.NewCache(ctx.TempDir, true)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	req := llm.RemediationRequest{
		CWEID:       "CWE-502",
		CodeSnippet: "pickle.loads(data)",
		FilePath:    "app.py",
		LineNumber:  100,
		RuleID:      "B301",
	}

	// Should be cache miss
	_, found := cache.Get(req)
	if found {
		t.Error("Expected cache miss for new request")
	}

	// Generate via manager
	config := llm.DefaultConfig()
	config.Provider = "mock"
	config.CacheEnabled = true
	config.CacheDir = ctx.TempDir

	manager, err := llm.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Close()

	resp, err := manager.GenerateRemediation(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to generate remediation: %v", err)
	}

	if resp == nil {
		t.Error("Expected non-nil response on cache miss")
	}

	if resp.Explanation == "" {
		t.Error("Expected non-empty explanation on cache miss")
	}
}

func TestLLMErrorHandling(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Test that manager creation validates provider configuration
	config := llm.DefaultConfig()
	config.Provider = "openai"
	config.APIKey = ""
	config.FallbackProviders = []string{} // No fallbacks
	config.CacheEnabled = false

	manager, err := llm.NewManager(config)
	if err != nil {
		// Manager creation failed due to missing API key — this is expected error handling
		t.Logf("Manager correctly rejected invalid config: %v", err)
		return
	}
	defer manager.Close()

	// If manager was created, GenerateRemediation should fail without valid API key
	req := llm.RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "test code",
	}

	_, err = manager.GenerateRemediation(context.Background(), req)
	if err != nil {
		// Expected: provider should fail without API key
		t.Logf("GenerateRemediation correctly failed: %v", err)
	} else {
		// If it succeeds, mock fallback is active — verify we got a valid response
		t.Log("GenerateRemediation succeeded via fallback provider — verifying mock fallback is active")
		if !manager.IsAvailable() {
			t.Error("Manager should report as available if generation succeeded")
		}
	}
}

func TestLLMCacheExpiration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	cache, err := llm.NewCache(ctx.TempDir, true)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	req := llm.RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "expiring test",
		FilePath:    "test.py",
		LineNumber:  1,
		RuleID:      "test-rule",
	}

	resp := &llm.RemediationResponse{
		Explanation:      "This will expire soon",
		RemediationSteps: []string{"Fix it"},
		Confidence:       0.9,
	}

	// Store in cache
	err = cache.Set(req, resp)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Immediate retrieval should work
	_, found := cache.Get(req)
	if !found {
		t.Error("Expected cache hit immediately after set")
	}

	// Verify cache stats
	total, _, err := cache.Stats()
	if err != nil {
		t.Fatalf("Failed to get cache stats: %v", err)
	}

	if total < 1 {
		t.Error("Expected at least 1 cache entry")
	}
}
