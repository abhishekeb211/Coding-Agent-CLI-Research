package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewOllamaProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with default model",
			config: Config{
				MaxTokens:    1024,
				Temperature:  0.7,
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config with custom model",
			config: Config{
				Model:        "codellama",
				MaxTokens:    1024,
				Temperature:  0.7,
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config with custom base URL",
			config: Config{
				BaseURL:      "http://custom-host:11434",
				Model:        "llama2",
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

			provider, err := NewOllamaProvider(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewOllamaProvider() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("NewOllamaProvider() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("NewOllamaProvider() unexpected error = %v", err)
				return
			}

			if provider == nil {
				t.Error("NewOllamaProvider() returned nil provider")
				return
			}

			// Verify default model
			if tt.config.Model == "" && provider.model != "llama2" {
				t.Errorf("NewOllamaProvider() default model = %v, want llama2", provider.model)
			}

			// Verify default base URL
			expectedBaseURL := tt.config.BaseURL
			if expectedBaseURL == "" {
				expectedBaseURL = "http://localhost:11434"
			}
			if provider.baseURL != expectedBaseURL {
				t.Errorf("NewOllamaProvider() baseURL = %v, want %v", provider.baseURL, expectedBaseURL)
			}

			// Clean up
			provider.Close()
		})
	}
}

func TestOllamaProvider_GenerateRemediation(t *testing.T) {
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
				"response": "{\"explanation\":\"SQL Injection vulnerability\",\"remediation_steps\":[\"Use parameterized queries\",\"Validate input\"],\"example_fix\":\"query = \\\"SELECT * FROM users WHERE id = ?\\\"\",\"confidence\":0.9}"
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
			mockResponse: `{
				"response": "This is a Cross-Site Scripting vulnerability.\n\nRemediation Steps:\n- Escape user input\n- Use Content Security Policy\n\nExample Fix:\n` + "```python\nfrom html import escape\nhtml = \"<div>\" + escape(user_input) + \"</div>\"\n```" + `"
			}`,
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
				"error": "model not found"
			}`,
			mockStatusCode: http.StatusNotFound,
			wantErr:        true,
		},
		{
			name: "empty response",
			request: RemediationRequest{
				CWEID:      "CWE-89",
				FilePath:   "app.py",
				LineNumber: 42,
			},
			mockResponse:   `{"response": ""}`,
			mockStatusCode: http.StatusOK,
			wantErr:        true,
		},
		{
			name: "connection error simulation",
			request: RemediationRequest{
				CWEID:      "CWE-89",
				FilePath:   "app.py",
				LineNumber: 42,
			},
			mockResponse:   ``,
			mockStatusCode: http.StatusServiceUnavailable,
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
				Model:        "llama2",
				BaseURL:      server.URL,
				MaxTokens:    1024,
				Temperature:  0.7,
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOllamaProvider(config)
			if err != nil {
				t.Fatalf("NewOllamaProvider() error = %v", err)
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

func TestOllamaProvider_EstimateCost(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		Model:        "llama2",
		MaxTokens:    1024,
		CacheEnabled: false,
		CacheDir:     tempDir,
		Timeout:      5 * time.Second,
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
	}
	defer provider.Close()

	request := RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
		FilePath:       "app.py",
		LineNumber:     42,
	}

	cost, err := provider.EstimateCost(request)
	if err != nil {
		t.Errorf("EstimateCost() error = %v", err)
		return
	}

	// Local models should be free
	if cost != 0.0 {
		t.Errorf("EstimateCost() = %v, want 0.0 (local models are free)", cost)
	}
}

func TestOllamaProvider_RateLimit(t *testing.T) {
	// Create mock server that tracks request times
	var requestTimes []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"response": "test"}`))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	config := Config{
		Model:        "llama2",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		CacheEnabled: false,
		CacheDir:     tempDir,
		Timeout:      5 * time.Second,
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
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

func TestOllamaProvider_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"response": "{\"explanation\":\"test\",\"remediation_steps\":[\"step1\"],\"confidence\":0.7}"}`))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	config := Config{
		Model:        "llama2",
		BaseURL:      server.URL,
		MaxTokens:    1024,
		CacheEnabled: true,
		CacheDir:     tempDir,
		Timeout:      5 * time.Second,
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
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

func TestOllamaProvider_Name(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"llama2", "ollama-llama2"},
		{"codellama", "ollama-codellama"},
		{"mistral", "ollama-mistral"},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			tempDir := t.TempDir()
			config := Config{
				Model:        tt.model,
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOllamaProvider(config)
			if err != nil {
				t.Fatalf("NewOllamaProvider() error = %v", err)
			}
			defer provider.Close()

			if got := provider.Name(); got != tt.want {
				t.Errorf("Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOllamaProvider_IsAvailable(t *testing.T) {
	tests := []struct {
		name           string
		mockStatusCode int
		want           bool
	}{
		{"server available", http.StatusOK, true},
		{"server not found", http.StatusNotFound, false},
		{"server error", http.StatusInternalServerError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server for /api/tags endpoint
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/tags" {
					w.WriteHeader(tt.mockStatusCode)
					w.Write([]byte(`{"models": []}`))
				}
			}))
			defer server.Close()

			tempDir := t.TempDir()
			config := Config{
				Model:        "llama2",
				BaseURL:      server.URL,
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOllamaProvider(config)
			if err != nil {
				t.Fatalf("NewOllamaProvider() error = %v", err)
			}
			defer provider.Close()

			if got := provider.IsAvailable(); got != tt.want {
				t.Errorf("IsAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOllamaProvider_IsAvailable_NoServer(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		Model:        "llama2",
		BaseURL:      "http://localhost:99999", // Invalid port
		CacheEnabled: false,
		CacheDir:     tempDir,
		Timeout:      5 * time.Second,
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
	}
	defer provider.Close()

	// Should return false when server is not reachable
	if got := provider.IsAvailable(); got != false {
		t.Errorf("IsAvailable() = %v, want false when server is not reachable", got)
	}
}

func TestOllamaProvider_parseTextResponse(t *testing.T) {
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
				Model:        "llama2",
				CacheEnabled: false,
				CacheDir:     tempDir,
				Timeout:      5 * time.Second,
			}

			provider, err := NewOllamaProvider(config)
			if err != nil {
				t.Fatalf("NewOllamaProvider() error = %v", err)
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

func TestOllamaProvider_ConnectionError(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		Model:        "llama2",
		BaseURL:      "http://localhost:99999", // Invalid port
		MaxTokens:    1024,
		CacheEnabled: false,
		CacheDir:     tempDir,
		Timeout:      1 * time.Second, // Short timeout
	}

	provider, err := NewOllamaProvider(config)
	if err != nil {
		t.Fatalf("NewOllamaProvider() error = %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := RemediationRequest{
		CWEID:      "CWE-89",
		FilePath:   "app.py",
		LineNumber: 42,
	}

	_, err = provider.GenerateRemediation(ctx, req)
	if err == nil {
		t.Error("GenerateRemediation() expected error when server is not reachable, got nil")
	}

	// Error message should indicate connection issue
	if !contains(err.Error(), "Ollama") {
		t.Errorf("Error message should mention Ollama, got: %v", err)
	}
}
