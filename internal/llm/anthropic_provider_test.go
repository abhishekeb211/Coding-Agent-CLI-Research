package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewAnthropicProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with default model",
			config: Config{
				APIKey:       "test-api-key",
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config with opus model",
			config: Config{
				APIKey:       "test-api-key",
				Model:        "claude-3-opus-20240229",
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config with sonnet model",
			config: Config{
				APIKey:       "test-api-key",
				Model:        "claude-3-sonnet-20240229",
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config with haiku model",
			config: Config{
				APIKey:       "test-api-key",
				Model:        "claude-3-haiku-20240307",
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "missing API key",
			config: Config{
				CacheEnabled: false,
			},
			wantErr: true,
			errMsg:  "API key is required",
		},
		{
			name: "unsupported model",
			config: Config{
				APIKey:       "test-api-key",
				Model:        "claude-2",
				CacheEnabled: false,
			},
			wantErr: true,
			errMsg:  "unsupported Anthropic model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set default timeout
			if tt.config.Timeout == 0 {
				tt.config.Timeout = 30 * time.Second
			}

			provider, err := NewAnthropicProvider(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewAnthropicProvider() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("NewAnthropicProvider() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("NewAnthropicProvider() unexpected error = %v", err)
				return
			}

			if provider == nil {
				t.Error("NewAnthropicProvider() returned nil provider")
				return
			}

			// Verify default model
			if tt.config.Model == "" && provider.model != "claude-3-sonnet-20240229" {
				t.Errorf("NewAnthropicProvider() default model = %v, want claude-3-sonnet-20240229", provider.model)
			}

			// Verify default base URL
			if provider.baseURL != "https://api.anthropic.com/v1" {
				t.Errorf("NewAnthropicProvider() baseURL = %v, want https://api.anthropic.com/v1", provider.baseURL)
			}

			// Verify provider is available
			if !provider.IsAvailable() {
				t.Error("NewAnthropicProvider() provider should be available with API key")
			}

			// Verify provider name
			expectedName := "anthropic-" + provider.model
			if provider.Name() != expectedName {
				t.Errorf("NewAnthropicProvider() name = %v, want %v", provider.Name(), expectedName)
			}

			// Clean up
			if err := provider.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestAnthropicProvider_GenerateRemediation(t *testing.T) {
	tests := []struct {
		name           string
		request        RemediationRequest
		mockResponse   string
		mockStatusCode int
		wantErr        bool
		errMsg         string
	}{
		{
			name: "successful text response",
			request: RemediationRequest{
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_id",
				FilePath:       "app.py",
				LineNumber:     42,
				Severity:       "high",
				RuleID:         "sql-injection",
				Message:        "Potential SQL injection",
			},
			mockResponse: `{
				"content": [
					{
						"type": "text",
						"text": "This code is vulnerable to SQL injection.\n\nRemediation steps:\n- Use parameterized queries\n- Validate input\n- Use an ORM\n\nExample fix:\n` + "```python\nquery = \"SELECT * FROM users WHERE id = ?\"\ncursor.execute(query, (user_id,))\n```" + `"
					}
				]
			}`,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "API error response",
			request: RemediationRequest{
				CWEID:       "CWE-89",
				CodeSnippet: "test",
			},
			mockResponse: `{
				"error": {
					"type": "invalid_request_error",
					"message": "Invalid API key"
				}
			}`,
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			errMsg:         "Invalid API key",
		},
		{
			name: "empty response",
			request: RemediationRequest{
				CWEID:       "CWE-89",
				CodeSnippet: "test",
			},
			mockResponse: `{
				"content": []
			}`,
			mockStatusCode: http.StatusOK,
			wantErr:        true,
			errMsg:         "no response from Anthropic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify headers
				if r.Header.Get("x-api-key") != "test-api-key" {
					t.Errorf("Expected x-api-key header, got %v", r.Header.Get("x-api-key"))
				}
				if r.Header.Get("anthropic-version") != "2023-06-01" {
					t.Errorf("Expected anthropic-version header, got %v", r.Header.Get("anthropic-version"))
				}

				w.WriteHeader(tt.mockStatusCode)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			config := Config{
				APIKey:       "test-api-key",
				Model:        "claude-3-sonnet-20240229",
				BaseURL:      server.URL,
				MaxTokens:    1024,
				Temperature:  0.7,
				Timeout:      30 * time.Second,
				CacheEnabled: false,
			}

			provider, err := NewAnthropicProvider(config)
			if err != nil {
				t.Fatalf("NewAnthropicProvider() error = %v", err)
			}
			defer provider.Close()

			ctx := context.Background()
			response, err := provider.GenerateRemediation(ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateRemediation() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("GenerateRemediation() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateRemediation() unexpected error = %v", err)
				return
			}

			if response == nil {
				t.Error("GenerateRemediation() returned nil response")
				return
			}

			// Verify response structure
			if response.Explanation == "" {
				t.Error("GenerateRemediation() response missing explanation")
			}
			if len(response.RemediationSteps) == 0 {
				t.Error("GenerateRemediation() response missing remediation steps")
			}
			if response.Cached {
				t.Error("GenerateRemediation() response should not be cached on first call")
			}
		})
	}
}

func TestAnthropicProvider_EstimateCost(t *testing.T) {
	config := Config{
		APIKey:       "test-api-key",
		Model:        "claude-3-sonnet-20240229",
		MaxTokens:    1024,
		CacheEnabled: false,
		Timeout:      30 * time.Second,
	}

	provider, err := NewAnthropicProvider(config)
	if err != nil {
		t.Fatalf("NewAnthropicProvider() error = %v", err)
	}
	defer provider.Close()

	req := RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection vulnerability",
		CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_id",
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "high",
		RuleID:         "sql-injection",
		Message:        "Potential SQL injection detected",
	}

	cost, err := provider.EstimateCost(req)
	if err != nil {
		t.Errorf("EstimateCost() error = %v", err)
		return
	}

	if cost <= 0 {
		t.Errorf("EstimateCost() cost = %v, want > 0", cost)
	}

	// Verify cost is reasonable (should be small for this request)
	if cost > 0.01 {
		t.Errorf("EstimateCost() cost = %v, seems too high", cost)
	}
}

func TestAnthropicProvider_RateLimit(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"content": [
				{
					"type": "text",
					"text": "Test response"
				}
			]
		}`))
	}))
	defer server.Close()

	config := Config{
		APIKey:       "test-api-key",
		Model:        "claude-3-sonnet-20240229",
		BaseURL:      server.URL,
		MaxTokens:    100,
		Temperature:  0.7,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
	}

	provider, err := NewAnthropicProvider(config)
	if err != nil {
		t.Fatalf("NewAnthropicProvider() error = %v", err)
	}
	defer provider.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "test",
	}

	ctx := context.Background()
	start := time.Now()

	// Make 3 requests
	for i := 0; i < 3; i++ {
		_, err := provider.GenerateRemediation(ctx, req)
		if err != nil {
			t.Errorf("GenerateRemediation() error = %v", err)
		}
	}

	elapsed := time.Since(start)

	// With rate limiting of 100ms between requests, 3 requests should take at least 200ms
	minExpected := 200 * time.Millisecond
	if elapsed < minExpected {
		t.Errorf("Rate limiting not working: 3 requests took %v, expected at least %v", elapsed, minExpected)
	}

	if requestCount != 3 {
		t.Errorf("Expected 3 requests, got %d", requestCount)
	}
}

func TestAnthropicProvider_Caching(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"content": [
				{
					"type": "text",
					"text": "Cached response"
				}
			]
		}`))
	}))
	defer server.Close()

	config := Config{
		APIKey:       "test-api-key",
		Model:        "claude-3-sonnet-20240229",
		BaseURL:      server.URL,
		MaxTokens:    100,
		Temperature:  0.7,
		Timeout:      30 * time.Second,
		CacheEnabled: true,
		CacheDir:     t.TempDir(),
	}

	provider, err := NewAnthropicProvider(config)
	if err != nil {
		t.Fatalf("NewAnthropicProvider() error = %v", err)
	}
	defer provider.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "test code",
		FilePath:    "test.py",
		LineNumber:  10,
	}

	ctx := context.Background()

	// First request - should hit API
	resp1, err := provider.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if resp1.Cached {
		t.Error("First request should not be cached")
	}

	// Second request - should hit cache
	resp2, err := provider.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if !resp2.Cached {
		t.Error("Second request should be cached")
	}

	// Should only have made 1 API request
	if requestCount != 1 {
		t.Errorf("Expected 1 API request, got %d", requestCount)
	}
}

func TestAnthropicProvider_ParseTextResponse(t *testing.T) {
	config := Config{
		APIKey:       "test-api-key",
		CacheEnabled: false,
		Timeout:      30 * time.Second,
	}

	provider, err := NewAnthropicProvider(config)
	if err != nil {
		t.Fatalf("NewAnthropicProvider() error = %v", err)
	}
	defer provider.Close()

	tests := []struct {
		name          string
		content       string
		wantSteps     int
		wantExplanation bool
	}{
		{
			name: "structured response with sections",
			content: `This is a SQL injection vulnerability.

Remediation steps:
- Use parameterized queries
- Validate input
- Use an ORM

Example fix:
` + "```python\nquery = \"SELECT * FROM users WHERE id = ?\"\n```",
			wantSteps:       3,
			wantExplanation: true,
		},
		{
			name: "numbered list",
			content: `SQL injection detected.

Steps:
1. Use prepared statements
2. Validate input
3. Escape special characters`,
			wantSteps:       3,
			wantExplanation: true,
		},
		{
			name:            "plain text without structure",
			content:         "This is a simple explanation without sections.",
			wantSteps:       1, // Should create a generic step
			wantExplanation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := provider.parseTextResponse(tt.content)
			if err != nil {
				t.Errorf("parseTextResponse() error = %v", err)
				return
			}

			if tt.wantExplanation && response.Explanation == "" {
				t.Error("parseTextResponse() missing explanation")
			}

			if len(response.RemediationSteps) != tt.wantSteps {
				t.Errorf("parseTextResponse() steps = %d, want %d", len(response.RemediationSteps), tt.wantSteps)
			}
		})
	}
}

func TestAnthropicProvider_ModelPricing(t *testing.T) {
	models := []string{
		"claude-3-opus-20240229",
		"claude-3-sonnet-20240229",
		"claude-3-haiku-20240307",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			pricing, ok := anthropicPricing[model]
			if !ok {
				t.Errorf("Model %s not found in pricing table", model)
				return
			}

			if pricing.inputCost <= 0 {
				t.Errorf("Model %s has invalid input cost: %v", model, pricing.inputCost)
			}

			if pricing.outputCost <= 0 {
				t.Errorf("Model %s has invalid output cost: %v", model, pricing.outputCost)
			}

			// Verify output cost is higher than input cost (typical for LLMs)
			if pricing.outputCost <= pricing.inputCost {
				t.Errorf("Model %s output cost (%v) should be higher than input cost (%v)",
					model, pricing.outputCost, pricing.inputCost)
			}
		})
	}
}

func TestAnthropicProvider_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content": [{"type": "text", "text": "Response"}]}`))
	}))
	defer server.Close()

	config := Config{
		APIKey:       "test-api-key",
		BaseURL:      server.URL,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
	}

	provider, err := NewAnthropicProvider(config)
	if err != nil {
		t.Fatalf("NewAnthropicProvider() error = %v", err)
	}
	defer provider.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "test",
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = provider.GenerateRemediation(ctx, req)
	if err == nil {
		t.Error("GenerateRemediation() expected timeout error, got nil")
	}
}

func TestAnthropicProvider_JSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a response with JSON content
		response := map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": `{
						"explanation": "This is a SQL injection vulnerability",
						"remediation_steps": ["Use parameterized queries", "Validate input"],
						"example_fix": "query = \"SELECT * FROM users WHERE id = ?\"",
						"confidence": 0.95
					}`,
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := Config{
		APIKey:       "test-api-key",
		BaseURL:      server.URL,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
	}

	provider, err := NewAnthropicProvider(config)
	if err != nil {
		t.Fatalf("NewAnthropicProvider() error = %v", err)
	}
	defer provider.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "test",
	}

	ctx := context.Background()
	response, err := provider.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}

	if response.Explanation != "This is a SQL injection vulnerability" {
		t.Errorf("Unexpected explanation: %v", response.Explanation)
	}

	if len(response.RemediationSteps) != 2 {
		t.Errorf("Expected 2 remediation steps, got %d", len(response.RemediationSteps))
	}

	if response.Confidence != 0.95 {
		t.Errorf("Expected confidence 0.95, got %v", response.Confidence)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
