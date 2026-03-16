// +build integration

package llm

import (
	"context"
	"testing"
	"time"
)

// TestOllamaProvider_Integration tests the Ollama provider with a real Ollama instance
// This test requires Ollama to be running locally on port 11434
// Run with: go test -tags=integration -v ./internal/llm -run TestOllamaProvider_Integration
func TestOllamaProvider_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create provider with default config
	config := Config{
		Model:        "llama2",
		BaseURL:      "http://localhost:11434",
		MaxTokens:    512,
		Temperature:  0.7,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
		Timeout:      60 * time.Second, // Longer timeout for local models
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
	}
	defer provider.Close()

	// Check if Ollama is available
	if !provider.IsAvailable() {
		t.Skip("Ollama is not available, skipping integration test")
	}

	// Test remediation generation
	ctx := context.Background()
	req := RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "high",
		RuleID:         "sql-injection",
		Message:        "Potential SQL injection vulnerability",
	}

	resp, err := provider.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}

	// Verify response
	if resp == nil {
		t.Fatal("GenerateRemediation() returned nil response")
	}

	if resp.Explanation == "" {
		t.Error("Response should have an explanation")
	}

	if len(resp.RemediationSteps) == 0 {
		t.Error("Response should have remediation steps")
	}

	if resp.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be set")
	}

	if resp.Cached {
		t.Error("First response should not be cached")
	}

	t.Logf("Explanation: %s", resp.Explanation)
	t.Logf("Steps: %v", resp.RemediationSteps)
	t.Logf("Example Fix: %s", resp.ExampleFix)
	t.Logf("Confidence: %f", resp.Confidence)
}

// TestOllamaProvider_Integration_MultipleModels tests different Ollama models
func TestOllamaProvider_Integration_MultipleModels(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	models := []string{"llama2", "codellama", "mistral"}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			config := Config{
				Model:        model,
				BaseURL:      "http://localhost:11434",
				MaxTokens:    256,
				Temperature:  0.7,
				CacheEnabled: false,
				CacheDir:     t.TempDir(),
				Timeout:      60 * time.Second,
			}

			provider, err := NewOllamaProvider(config)
			if err != nil {
				t.Fatalf("NewOllamaProvider() error = %v", err)
			}
			defer provider.Close()

			if !provider.IsAvailable() {
				t.Skipf("Ollama is not available, skipping test for model %s", model)
			}

			ctx := context.Background()
			req := RemediationRequest{
				CWEID:          "CWE-79",
				CWEDescription: "Cross-site Scripting (XSS)",
				CodeSnippet:    "html = \"<div>\" + user_input + \"</div>\"",
				FilePath:       "app.py",
				LineNumber:     10,
				Severity:       "medium",
			}

			resp, err := provider.GenerateRemediation(ctx, req)
			if err != nil {
				t.Errorf("GenerateRemediation() error = %v", err)
				return
			}

			if resp == nil {
				t.Error("GenerateRemediation() returned nil response")
				return
			}

			t.Logf("Model %s - Explanation: %s", model, resp.Explanation)
		})
	}
}

// TestOllamaProvider_Integration_CostEstimate tests cost estimation
func TestOllamaProvider_Integration_CostEstimate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := Config{
		Model:        "llama2",
		BaseURL:      "http://localhost:11434",
		MaxTokens:    512,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
		Timeout:      30 * time.Second,
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
	}
	defer provider.Close()

	req := RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
		FilePath:       "app.py",
		LineNumber:     42,
	}

	cost, err := provider.EstimateCost(req)
	if err != nil {
		t.Errorf("EstimateCost() error = %v", err)
		return
	}

	// Local models should be free
	if cost != 0.0 {
		t.Errorf("EstimateCost() = %v, want 0.0 (local models are free)", cost)
	}

	t.Logf("Estimated cost for local model: $%.4f", cost)
}

// TestOllamaProvider_Integration_Caching tests caching functionality
func TestOllamaProvider_Integration_Caching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := Config{
		Model:        "llama2",
		BaseURL:      "http://localhost:11434",
		MaxTokens:    256,
		Temperature:  0.7,
		CacheEnabled: true,
		CacheDir:     t.TempDir(),
		Timeout:      60 * time.Second,
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
	}
	defer provider.Close()

	if !provider.IsAvailable() {
		t.Skip("Ollama is not available, skipping integration test")
	}

	ctx := context.Background()
	req := RemediationRequest{
		CWEID:      "CWE-89",
		FilePath:   "app.py",
		LineNumber: 42,
	}

	// First call - should hit API
	start1 := time.Now()
	resp1, err := provider.GenerateRemediation(ctx, req)
	duration1 := time.Since(start1)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if resp1.Cached {
		t.Error("First response should not be cached")
	}

	// Second call - should use cache
	start2 := time.Now()
	resp2, err := provider.GenerateRemediation(ctx, req)
	duration2 := time.Since(start2)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if !resp2.Cached {
		t.Error("Second response should be cached")
	}

	// Cached response should be much faster
	if duration2 >= duration1 {
		t.Logf("Warning: Cached response (%v) was not faster than first response (%v)", duration2, duration1)
	}

	t.Logf("First call duration: %v", duration1)
	t.Logf("Cached call duration: %v", duration2)
	t.Logf("Speedup: %.2fx", float64(duration1)/float64(duration2))
}
