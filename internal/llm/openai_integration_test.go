package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestOpenAIProviderIntegration tests OpenAI provider integration with Manager
func TestOpenAIProviderIntegration(t *testing.T) {
	// Create mock OpenAI server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request format
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header with Bearer token")
		}

		// Parse request body
		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}

		// Verify request structure
		if reqBody["model"] != "gpt-3.5-turbo" {
			t.Errorf("Expected model gpt-3.5-turbo, got %v", reqBody["model"])
		}

		// Send mock response
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": `{
							"explanation": "SQL Injection vulnerability allows attackers to execute arbitrary SQL commands.",
							"remediation_steps": [
								"Use parameterized queries or prepared statements",
								"Validate and sanitize all user inputs",
								"Apply principle of least privilege to database accounts"
							],
							"example_fix": "query = \"SELECT * FROM users WHERE id = ?\"\ncursor.execute(query, (user_input,))",
							"confidence": 0.95
						}`,
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create manager with OpenAI provider
	config := Config{
		Provider:     "openai",
		APIKey:       "test-api-key",
		Model:        "gpt-3.5-turbo",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      5 * time.Second,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	// Test remediation generation
	req := RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "high",
		RuleID:         "B608",
		Message:        "SQL injection vulnerability detected",
	}

	ctx := context.Background()
	resp, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}

	// Verify response
	if resp == nil {
		t.Fatal("GenerateRemediation() returned nil response")
	}

	if resp.Explanation == "" {
		t.Error("Explanation should not be empty")
	}

	if len(resp.RemediationSteps) == 0 {
		t.Error("RemediationSteps should not be empty")
	}

	if resp.Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95", resp.Confidence)
	}

	if resp.Cached {
		t.Error("First response should not be cached")
	}

	if resp.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be set")
	}
}

// TestOpenAIProviderFallback tests fallback from OpenAI to mock provider
func TestOpenAIProviderFallback(t *testing.T) {
	// Create mock OpenAI server that always fails
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{
				"message": "Invalid API key",
				"type":    "invalid_request_error",
			},
		})
	}))
	defer failingServer.Close()

	// Create manager with OpenAI as primary and mock as fallback
	config := Config{
		Provider:          "openai",
		FallbackProviders: []string{"mock"},
		APIKey:            "invalid-key",
		Model:             "gpt-3.5-turbo",
		BaseURL:           failingServer.URL,
		MaxTokens:         1024,
		Temperature:       0.7,
		Timeout:           5 * time.Second,
		MaxRetries:        1,
		RetryDelay:        10 * time.Millisecond,
		CacheEnabled:      false,
		CacheDir:          t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	// Verify we have 2 providers
	if len(manager.providers) != 2 {
		t.Fatalf("Expected 2 providers, got %d", len(manager.providers))
	}

	// Test remediation generation - should fall back to mock
	req := RemediationRequest{
		CWEID:    "CWE-89",
		Severity: "high",
	}

	ctx := context.Background()
	resp, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v (should have fallen back to mock)", err)
	}

	if resp == nil {
		t.Fatal("GenerateRemediation() returned nil response")
	}

	// Response should come from mock provider
	if resp.Explanation == "" {
		t.Error("Explanation should not be empty")
	}
}

// TestOpenAIProviderCostEstimation tests cost estimation
func TestOpenAIProviderCostEstimation(t *testing.T) {
	config := Config{
		Provider:     "openai",
		APIKey:       "test-key",
		Model:        "gpt-3.5-turbo",
		MaxTokens:    1024,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
		Timeout:      5 * time.Second,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	req := RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "high",
	}

	cost, err := manager.EstimateCost(req)
	if err != nil {
		t.Fatalf("EstimateCost() error = %v", err)
	}

	// Cost should be greater than 0 for OpenAI
	if cost <= 0 {
		t.Errorf("EstimateCost() = %v, want > 0", cost)
	}

	// Cost should be reasonable (less than $0.10 for a simple request)
	if cost > 0.10 {
		t.Errorf("EstimateCost() = %v, seems too high", cost)
	}
}

// TestOpenAIProviderCostLimit tests cost limit enforcement
func TestOpenAIProviderCostLimit(t *testing.T) {
	// Create mock OpenAI server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": `{"explanation":"test","remediation_steps":["step1"],"confidence":0.8}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := Config{
		Provider:     "openai",
		APIKey:       "test-key",
		Model:        "gpt-3.5-turbo",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
		Timeout:      5 * time.Second,
		CostLimit:    0.00001, // Very low limit
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "query = \"SELECT * FROM users WHERE id = \" + user_input",
		Severity:    "high",
	}

	ctx := context.Background()
	_, err = manager.GenerateRemediation(ctx, req)

	// Should fail due to cost limit
	if err == nil {
		t.Error("GenerateRemediation() should fail due to cost limit")
	}
}

// TestOpenAIProviderRateLimiting tests rate limiting
func TestOpenAIProviderRateLimiting(t *testing.T) {
	requestTimes := []time.Time{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": `{"explanation":"test","remediation_steps":["step1"],"confidence":0.8}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := Config{
		Provider:     "openai",
		APIKey:       "test-key",
		Model:        "gpt-3.5-turbo",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
		Timeout:      5 * time.Second,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	// Make multiple requests
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		req := RemediationRequest{
			CWEID:      "CWE-89",
			Severity:   "high",
			LineNumber: i, // Make each request unique to avoid caching
		}
		_, err := manager.GenerateRemediation(ctx, req)
		if err != nil {
			t.Errorf("GenerateRemediation() request %d error = %v", i, err)
		}
	}

	// Verify rate limiting (should have at least 100ms between requests)
	if len(requestTimes) >= 2 {
		for i := 1; i < len(requestTimes); i++ {
			interval := requestTimes[i].Sub(requestTimes[i-1])
			if interval < 90*time.Millisecond { // Allow some tolerance
				t.Errorf("Request interval %v is less than expected 100ms", interval)
			}
		}
	}
}

// TestOpenAIProviderWithCache tests caching with OpenAI provider
func TestOpenAIProviderWithCache(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": `{"explanation":"SQL Injection test","remediation_steps":["Use parameterized queries"],"confidence":0.9}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := Config{
		Provider:     "openai",
		APIKey:       "test-key",
		Model:        "gpt-3.5-turbo",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		CacheEnabled: true,
		CacheDir:     t.TempDir(),
		Timeout:      5 * time.Second,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	req := RemediationRequest{
		CWEID:      "CWE-89",
		FilePath:   "app.py",
		LineNumber: 42,
		Severity:   "high",
	}

	ctx := context.Background()

	// First request - should hit API
	resp1, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("First GenerateRemediation() error = %v", err)
	}
	if resp1.Cached {
		t.Error("First response should not be cached")
	}

	// Second request - should use cache
	resp2, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("Second GenerateRemediation() error = %v", err)
	}
	if !resp2.Cached {
		t.Error("Second response should be cached")
	}

	// Verify API was only called once
	if callCount != 1 {
		t.Errorf("API call count = %v, want 1 (second call should use cache)", callCount)
	}
}

// TestOpenAIProviderErrorHandling tests various error scenarios
func TestOpenAIProviderErrorHandling(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		responseBody    string
		wantErrContains string
	}{
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			responseBody: `{
				"error": {
					"message": "Invalid API key",
					"type": "invalid_request_error"
				}
			}`,
			wantErrContains: "Invalid API key",
		},
		{
			name:       "rate limit",
			statusCode: http.StatusTooManyRequests,
			responseBody: `{
				"error": {
					"message": "Rate limit exceeded",
					"type": "rate_limit_error"
				}
			}`,
			wantErrContains: "Rate limit exceeded",
		},
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			responseBody: `{
				"error": {
					"message": "Internal server error",
					"type": "server_error"
				}
			}`,
			wantErrContains: "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			config := Config{
				Provider:     "openai",
				APIKey:       "test-key",
				Model:        "gpt-3.5-turbo",
				BaseURL:      server.URL,
				MaxTokens:    1024,
				CacheEnabled: false,
				CacheDir:     t.TempDir(),
				Timeout:      5 * time.Second,
				MaxRetries:   1,
				RetryDelay:   10 * time.Millisecond,
			}

			manager, err := NewManager(config)
			if err != nil {
				t.Fatalf("NewManager() error = %v", err)
			}
			defer manager.Close()

			req := RemediationRequest{
				CWEID:    "CWE-89",
				Severity: "high",
			}

			ctx := context.Background()
			_, err = manager.GenerateRemediation(ctx, req)

			if err == nil {
				t.Error("GenerateRemediation() should return error")
				return
			}

			if tt.wantErrContains != "" && !contains(err.Error(), tt.wantErrContains) {
				t.Errorf("Error should contain %q, got %v", tt.wantErrContains, err)
			}
		})
	}
}
