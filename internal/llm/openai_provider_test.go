package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewOpenAIProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with gpt-3.5-turbo",
			config: Config{
				APIKey:       "test-key",
				Model:        "gpt-3.5-turbo",
				MaxTokens:    1024,
				Temperature:  0.7,
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config with gpt-4",
			config: Config{
				APIKey:       "test-key",
				Model:        "gpt-4",
				MaxTokens:    1024,
				Temperature:  0.7,
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "missing API key",
			config: Config{
				Model:        "gpt-3.5-turbo",
				MaxTokens:    1024,
				CacheEnabled: false,
			},
			wantErr: true,
			errMsg:  "API key is required",
		},
		{
			name: "unsupported model",
			config: Config{
				APIKey:       "test-key",
				Model:        "gpt-5",
				MaxTokens:    1024,
				CacheEnabled: false,
			},
			wantErr: true,
			errMsg:  "unsupported OpenAI model",
		},
		{
			name: "default model when not specified",
			config: Config{
				APIKey:       "test-key",
				MaxTokens:    1024,
				CacheEnabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp cache dir
			tempDir := t.TempDir()
			tt.config.CacheDir = tempDir
			tt.config.Timeout = 30 * time.Second

			provider, err := NewOpenAIProvider(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewOpenAIProvider() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("NewOpenAIProvider() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("NewOpenAIProvider() unexpected error = %v", err)
				return
			}

			if provider == nil {
				t.Error("NewOpenAIProvider() returned nil provider")
				return
			}

			// Verify default model
			if tt.config.Model == "" && provider.model != "gpt-3.5-turbo" {
				t.Errorf("NewOpenAIProvider() default model = %v, want gpt-3.5-turbo", provider.model)
			}

			// Verify default base URL
			if provider.baseURL != "https://api.openai.com/v1" {
				t.Errorf("NewOpenAIProvider() baseURL = %v, want https://api.openai.com/v1", provider.baseURL)
			}

			// Clean up
			provider.Close()
		})
	}
}

func TestOpenAIProvider_GenerateRemediation(t *testing.T) {
	tests := []struct {
		name           string
		request        RemediationRequest
		mockResponse   string
		mockStatusCode int
		wantErr        bool
		checkResponse  func(*testing.T, *RemediationResponse)
	}{
		{
			name: "successful JSON response",
			request: RemediationRequest{
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
				FilePath:       "app.py",
				LineNumber:     42,
				Severity:       "high",
			},
			mockResponse: `{
				"choices": [{
					"message": {
						"content": "{\"explanation\":\"SQL Injection vulnerability\",\"remediation_steps\":[\"Use parameterized queries\",\"Validate input\"],\"example_fix\":\"query = \\\"SELECT * FROM users WHERE id = ?\\\"\",\"confidence\":0.9}"
					}
				}]
			}`,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			checkResponse: func(t *testing.T, resp *RemediationResponse) {
				if resp.Explanation != "SQL Injection vulnerability" {
					t.Errorf("Explanation = %v, want SQL Injection vulnerability", resp.Explanation)
				}
				if len(resp.RemediationSteps) != 2 {
					t.Errorf("RemediationSteps length = %v, want 2", len(resp.RemediationSteps))
				}
				if resp.Confidence != 0.9 {
					t.Errorf("Confidence = %v, want 0.9", resp.Confidence)
				}
			},
		},
		{
			name: "successful text response",
			request: RemediationRequest{
				CWEID:          "CWE-79",
				CWEDescription: "XSS",
				CodeSnippet:    "html = \"<div>\" + user_input + \"</div>\"",
				FilePath:       "app.py",
				LineNumber:     10,
				Severity:       "medium",
			},
			mockResponse:   "{\"choices\": [{\"message\": {\"content\": \"This is a Cross-Site Scripting vulnerability.\\n\\nRemediation Steps:\\n- Escape user input\\n- Use Content Security Policy\\n\\nExample Fix:\\nfrom html import escape\\nhtml = escape(user_input)\"}}]}",
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			checkResponse: func(t *testing.T, resp *RemediationResponse) {
				if !contains(resp.Explanation, "Cross-Site Scripting") {
					t.Errorf("Explanation should contain 'Cross-Site Scripting', got %v", resp.Explanation)
				}
				if len(resp.RemediationSteps) < 1 {
					t.Errorf("RemediationSteps should have at least 1 step, got %v", len(resp.RemediationSteps))
				}
			},
		},
		{
			name: "API error response",
			request: RemediationRequest{
				CWEID:      "CWE-89",
				FilePath:   "app.py",
				LineNumber: 42,
			},
			mockResponse: `{
				"error": {
					"message": "Invalid API key",
					"type": "invalid_request_error"
				}
			}`,
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
		},
		{
			name: "empty response",
			request: RemediationRequest{
				CWEID:      "CWE-89",
				FilePath:   "app.py",
				LineNumber: 42,
			},
			mockResponse:   `{"choices": []}`,
			mockStatusCode: http.StatusOK,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				if r.Method != "POST" {
					t.Errorf("Expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Authorization") != "Bearer test-key" {
					t.Errorf("Expected Authorization header with Bearer token")
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected Content-Type application/json")
				}

				// Send mock response
				w.WriteHeader(tt.mockStatusCode)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			// Create provider with mock server URL
			tempDir := t.TempDir()
			config := Config{
				APIKey:       "test-key",
				Model:        "gpt-3.5-turbo",
				BaseURL:      server.URL,
				MaxTokens:    1024,
				Temperature:  0.7,
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOpenAIProvider(config)
			if err != nil {
				t.Fatalf("NewOpenAIProvider() error = %v", err)
			}
			defer provider.Close()

			// Call GenerateRemediation
			ctx := context.Background()
			resp, err := provider.GenerateRemediation(ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateRemediation() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateRemediation() unexpected error = %v", err)
				return
			}

			if resp == nil {
				t.Error("GenerateRemediation() returned nil response")
				return
			}

			// Run custom checks
			if tt.checkResponse != nil {
				tt.checkResponse(t, resp)
			}

			// Verify common fields
			if resp.GeneratedAt.IsZero() {
				t.Error("GeneratedAt should be set")
			}
			if resp.Cached {
				t.Error("First response should not be cached")
			}
		})
	}
}

func TestOpenAIProvider_EstimateCost(t *testing.T) {
	tests := []struct {
		name    string
		model   string
		request RemediationRequest
		wantMin float64
		wantMax float64
	}{
		{
			name:  "gpt-3.5-turbo cost",
			model: "gpt-3.5-turbo",
			request: RemediationRequest{
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
				FilePath:       "app.py",
				LineNumber:     42,
			},
			wantMin: 0.0001,
			wantMax: 0.01,
		},
		{
			name:  "gpt-4 cost",
			model: "gpt-4",
			request: RemediationRequest{
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
				FilePath:       "app.py",
				LineNumber:     42,
			},
			wantMin: 0.001,
			wantMax: 0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			config := Config{
				APIKey:       "test-key",
				Model:        tt.model,
				MaxTokens:    1024,
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOpenAIProvider(config)
			if err != nil {
				t.Fatalf("NewOpenAIProvider() error = %v", err)
			}
			defer provider.Close()

			cost, err := provider.EstimateCost(tt.request)
			if err != nil {
				t.Errorf("EstimateCost() error = %v", err)
				return
			}

			if cost < tt.wantMin || cost > tt.wantMax {
				t.Errorf("EstimateCost() = %v, want between %v and %v", cost, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestOpenAIProvider_RateLimit(t *testing.T) {
	// Create mock server that tracks request times
	var requestTimes []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices": [{"message": {"content": "test"}}]}`))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	config := Config{
		APIKey:       "test-key",
		Model:        "gpt-3.5-turbo",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		CacheEnabled: false,
		CacheDir:     tempDir,
		Timeout:      5 * time.Second,
	}

	provider, err := NewOpenAIProvider(config)
	if err != nil {
		t.Fatalf("NewOpenAIProvider() error = %v", err)
	}
	defer provider.Close()

	// Make multiple requests
	ctx := context.Background()
	req := RemediationRequest{
		CWEID:      "CWE-89",
		FilePath:   "app.py",
		LineNumber: 42,
	}

	for i := 0; i < 3; i++ {
		_, err := provider.GenerateRemediation(ctx, req)
		if err != nil {
			t.Errorf("GenerateRemediation() error = %v", err)
		}
	}

	// Verify rate limiting
	if len(requestTimes) < 2 {
		t.Fatal("Not enough requests to test rate limiting")
	}

	for i := 1; i < len(requestTimes); i++ {
		interval := requestTimes[i].Sub(requestTimes[i-1])
		if interval < provider.minInterval {
			t.Errorf("Request interval %v is less than minimum %v", interval, provider.minInterval)
		}
	}
}

func TestOpenAIProvider_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices": [{"message": {"content": "{\"explanation\":\"test\",\"remediation_steps\":[\"step1\"],\"confidence\":0.8}"}}]}`))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	config := Config{
		APIKey:       "test-key",
		Model:        "gpt-3.5-turbo",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		CacheEnabled: true,
		CacheDir:     tempDir,
		Timeout:      5 * time.Second,
	}

	provider, err := NewOpenAIProvider(config)
	if err != nil {
		t.Fatalf("NewOpenAIProvider() error = %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := RemediationRequest{
		CWEID:      "CWE-89",
		FilePath:   "app.py",
		LineNumber: 42,
	}

	// First call - should hit API
	resp1, err := provider.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if resp1.Cached {
		t.Error("First response should not be cached")
	}

	// Second call - should use cache
	resp2, err := provider.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if !resp2.Cached {
		t.Error("Second response should be cached")
	}

	// Verify API was only called once
	if callCount != 1 {
		t.Errorf("API call count = %v, want 1", callCount)
	}
}

func TestOpenAIProvider_Name(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"gpt-3.5-turbo", "openai-gpt-3.5-turbo"},
		{"gpt-4", "openai-gpt-4"},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			tempDir := t.TempDir()
			config := Config{
				APIKey:       "test-key",
				Model:        tt.model,
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOpenAIProvider(config)
			if err != nil {
				t.Fatalf("NewOpenAIProvider() error = %v", err)
			}
			defer provider.Close()

			if got := provider.Name(); got != tt.want {
				t.Errorf("Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenAIProvider_IsAvailable(t *testing.T) {
	tests := []struct {
		name   string
		apiKey string
		want   bool
	}{
		{"with API key", "test-key", true},
		{"without API key", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			config := Config{
				APIKey:       tt.apiKey,
				Model:        "gpt-3.5-turbo",
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			// Skip provider creation if no API key
			if tt.apiKey == "" {
				provider := &OpenAIProvider{apiKey: tt.apiKey}
				if got := provider.IsAvailable(); got != tt.want {
					t.Errorf("IsAvailable() = %v, want %v", got, tt.want)
				}
				return
			}

			provider, err := NewOpenAIProvider(config)
			if err != nil {
				t.Fatalf("NewOpenAIProvider() error = %v", err)
			}
			defer provider.Close()

			if got := provider.IsAvailable(); got != tt.want {
				t.Errorf("IsAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenAIProvider_parseTextResponse(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantSteps int
		checkResp func(*testing.T, *RemediationResponse)
	}{
		{
			name: "structured response with sections",
			content: `This is a SQL Injection vulnerability.

Remediation Steps:
- Use parameterized queries
- Validate all user inputs
- Apply least privilege

Example Fix:
` + "```python\nquery = \"SELECT * FROM users WHERE id = ?\"\n```",
			wantSteps: 3,
			checkResp: func(t *testing.T, resp *RemediationResponse) {
				if !contains(resp.Explanation, "SQL Injection") {
					t.Errorf("Explanation should contain 'SQL Injection'")
				}
				if !contains(resp.ExampleFix, "query") {
					t.Errorf("ExampleFix should contain code")
				}
			},
		},
		{
			name: "numbered list",
			content: `Explanation here.

Steps:
1. First step
2. Second step
3. Third step`,
			wantSteps: 3,
		},
		{
			name:      "no explicit steps",
			content:   `Just some explanation without clear steps.`,
			wantSteps: 1, // Should create a generic step
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			config := Config{
				APIKey:       "test-key",
				Model:        "gpt-3.5-turbo",
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOpenAIProvider(config)
			if err != nil {
				t.Fatalf("NewOpenAIProvider() error = %v", err)
			}
			defer provider.Close()

			resp, err := provider.parseTextResponse(tt.content)
			if err != nil {
				t.Errorf("parseTextResponse() error = %v", err)
				return
			}

			if len(resp.RemediationSteps) != tt.wantSteps {
				t.Errorf("RemediationSteps length = %v, want %v", len(resp.RemediationSteps), tt.wantSteps)
			}

			if tt.checkResp != nil {
				tt.checkResp(t, resp)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
