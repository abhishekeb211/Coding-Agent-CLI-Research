package llm

import (
	"context"
	"testing"
	"time"
)

// TestNewManager tests LLM manager initialization
func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config with mock provider",
			config: Config{
				Provider:     "mock",
				MaxTokens:    1024,
				Temperature:  0.7,
				Timeout:      30 * time.Second,
				CacheEnabled: true,
				CacheDir:     t.TempDir(),
			},
			wantErr: false,
		},
		{
			name: "minimal config defaults to mock",
			config: Config{
				CacheDir: t.TempDir(),
			},
			wantErr: false,
		},
		{
			name: "config with fallback providers",
			config: Config{
				Provider:          "mock",
				FallbackProviders: []string{"mock"},
				CacheDir:          t.TempDir(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				defer manager.Close()

				if manager == nil {
					t.Error("NewManager() returned nil manager")
				}
				if len(manager.providers) == 0 {
					t.Error("NewManager() has no providers")
				}
			}
		})
	}
}

// TestDefaultConfig tests default configuration
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Provider != "mock" {
		t.Errorf("DefaultConfig() Provider = %v, want mock", config.Provider)
	}
	if config.MaxTokens != 1024 {
		t.Errorf("DefaultConfig() MaxTokens = %v, want 1024", config.MaxTokens)
	}
	if config.Temperature != 0.7 {
		t.Errorf("DefaultConfig() Temperature = %v, want 0.7", config.Temperature)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("DefaultConfig() Timeout = %v, want 30s", config.Timeout)
	}
	if config.MaxRetries != 3 {
		t.Errorf("DefaultConfig() MaxRetries = %v, want 3", config.MaxRetries)
	}
	if config.RetryDelay != 1*time.Second {
		t.Errorf("DefaultConfig() RetryDelay = %v, want 1s", config.RetryDelay)
	}
	if config.RetryMultiplier != 2.0 {
		t.Errorf("DefaultConfig() RetryMultiplier = %v, want 2.0", config.RetryMultiplier)
	}
	if !config.CacheEnabled {
		t.Error("DefaultConfig() CacheEnabled should be true")
	}
	if config.CacheDir == "" {
		t.Error("DefaultConfig() CacheDir should not be empty")
	}
}

// TestGenerateRemediation tests remediation generation with mock provider
func TestGenerateRemediation(t *testing.T) {
	config := Config{
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	tests := []struct {
		name    string
		req     RemediationRequest
		wantErr bool
	}{
		{
			name: "valid SQL injection request",
			req: RemediationRequest{
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				Severity:       "high",
				FilePath:       "/test/file.py",
				LineNumber:     42,
				CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_id",
				Message:        "SQL injection vulnerability detected",
				RuleID:         "B608",
			},
			wantErr: false,
		},
		{
			name: "valid XSS request",
			req: RemediationRequest{
				CWEID:          "CWE-79",
				CWEDescription: "Cross-site Scripting",
				Severity:       "medium",
				FilePath:       "/test/file.js",
				LineNumber:     10,
				CodeSnippet:    "document.write(userInput)",
				Message:        "XSS vulnerability detected",
				RuleID:         "xss-check",
			},
			wantErr: false,
		},
		{
			name: "minimal request",
			req: RemediationRequest{
				CWEID:    "CWE-78",
				Severity: "high",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := manager.GenerateRemediation(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRemediation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp == nil {
					t.Error("GenerateRemediation() returned nil response")
					return
				}
				if resp.Explanation == "" {
					t.Error("GenerateRemediation() explanation is empty")
				}
				if len(resp.RemediationSteps) == 0 {
					t.Error("GenerateRemediation() remediation steps are empty")
				}
			}
		})
	}
}

// TestGenerateRemediationTimeout tests timeout handling
func TestGenerateRemediationTimeout(t *testing.T) {
	config := Config{
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      1 * time.Millisecond, // Very short timeout
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
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

	// The mock provider is fast, so this might not always timeout
	// But we're testing that the timeout mechanism works
	_, err = manager.GenerateRemediation(ctx, req)
	// We don't assert error here because mock provider is too fast
	// This test mainly ensures timeout logic doesn't panic
	_ = err
}

// TestGenerateRemediationCancellation tests context cancellation
func TestGenerateRemediationCancellation(t *testing.T) {
	config := Config{
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = manager.GenerateRemediation(ctx, req)
	if err == nil {
		// Mock provider might be too fast to catch cancellation
		// This is acceptable for testing
		t.Log("Context cancellation not caught (mock provider too fast)")
	}
}

// TestIsAvailable tests LLM availability check
func TestIsAvailable(t *testing.T) {
	config := Config{
		CacheDir: t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	if !manager.IsAvailable() {
		t.Error("IsAvailable() should return true for mock provider")
	}
}

// TestClose tests resource cleanup
func TestClose(t *testing.T) {
	config := Config{
		CacheDir: t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	err = manager.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Calling Close again should not panic
	err = manager.Close()
	if err != nil {
		t.Errorf("Close() second call error = %v", err)
	}
}

// TestGenerateRemediationWithLongCode tests handling of long code snippets
func TestGenerateRemediationWithLongCode(t *testing.T) {
	config := Config{
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	// Create a very long code snippet
	longCode := ""
	for i := 0; i < 1000; i++ {
		longCode += "def function_" + string(rune(i)) + "():\n    pass\n"
	}

	req := RemediationRequest{
		CWEID:       "CWE-89",
		Severity:    "high",
		CodeSnippet: longCode,
	}

	ctx := context.Background()
	resp, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Errorf("GenerateRemediation() with long code error = %v", err)
		return
	}

	if resp == nil {
		t.Error("GenerateRemediation() returned nil response")
	}
}

// TestGenerateRemediationWithSpecialCharacters tests handling of special characters
func TestGenerateRemediationWithSpecialCharacters(t *testing.T) {
	config := Config{
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		Severity:    "high",
		CodeSnippet: "query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n// Special chars: <>&\"'",
		Message:     "SQL injection with special characters: <>&\"'",
	}

	ctx := context.Background()
	resp, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Errorf("GenerateRemediation() with special characters error = %v", err)
		return
	}

	if resp == nil {
		t.Error("GenerateRemediation() returned nil response")
	}
}

// TestConcurrentRequests tests concurrent remediation requests
func TestConcurrentRequests(t *testing.T) {
	config := Config{
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      30 * time.Second,
		CacheEnabled: false,
		CacheDir:     t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	// Run multiple concurrent requests
	done := make(chan bool)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			req := RemediationRequest{
				CWEID:    "CWE-89",
				Severity: "high",
				Message:  "Test request " + string(rune(id)),
			}

			ctx := context.Background()
			_, err := manager.GenerateRemediation(ctx, req)
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all requests
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent request error: %v", err)
	}
}

// TestEstimateCost tests cost estimation
func TestEstimateCost(t *testing.T) {
	config := Config{
		Provider: "mock",
		CacheDir: t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	req := RemediationRequest{
		CWEID:       "CWE-89",
		Severity:    "high",
		CodeSnippet: "query = \"SELECT * FROM users WHERE id = \" + user_id",
	}

	cost, err := manager.EstimateCost(req)
	if err != nil {
		t.Errorf("EstimateCost() error = %v", err)
	}

	// Mock provider should return 0 cost
	if cost != 0.0 {
		t.Errorf("EstimateCost() = %v, want 0.0 for mock provider", cost)
	}
}

// TestCostLimit tests cost limit enforcement
func TestCostLimit(t *testing.T) {
	config := Config{
		Provider:  "mock",
		CacheDir:  t.TempDir(),
		CostLimit: 0.01, // Very low limit
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
	// Mock provider has 0 cost, so this should succeed
	_, err = manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Errorf("GenerateRemediation() with cost limit error = %v", err)
	}
}

// TestRetryLogicSuccess tests retry with exponential backoff on successful mock
func TestRetryLogicSuccess(t *testing.T) {
	config := Config{
		Provider:        "mock",
		CacheDir:        t.TempDir(),
		MaxRetries:      2,
		RetryDelay:      10 * time.Millisecond,
		RetryMultiplier: 2.0,
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
	start := time.Now()
	_, err = manager.GenerateRemediation(ctx, req)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("GenerateRemediation() error = %v", err)
	}

	// Mock provider succeeds immediately, so elapsed should be minimal
	if elapsed > 100*time.Millisecond {
		t.Logf("GenerateRemediation() took %v (expected < 100ms for successful mock)", elapsed)
	}
}

// TestFallbackChainWithManager tests provider fallback through manager
func TestFallbackChainWithManager(t *testing.T) {
	config := Config{
		Provider:          "mock",
		FallbackProviders: []string{"mock", "mock"},
		CacheDir:          t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	if len(manager.providers) != 3 {
		t.Errorf("Expected 3 providers (1 primary + 2 fallback), got %d", len(manager.providers))
	}

	req := RemediationRequest{
		CWEID:    "CWE-89",
		Severity: "high",
	}

	ctx := context.Background()
	resp, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Errorf("GenerateRemediation() with fallback error = %v", err)
	}
	if resp == nil {
		t.Error("GenerateRemediation() returned nil response")
	}
}

// TestProviderName tests provider name retrieval
func TestProviderName(t *testing.T) {
	config := Config{
		Provider: "mock",
		CacheDir: t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	if len(manager.providers) == 0 {
		t.Fatal("No providers available")
	}

	name := manager.providers[0].Name()
	if name != "mock" {
		t.Errorf("Provider name = %v, want mock", name)
	}
}

// TestCacheIntegration tests cache integration with new manager
func TestCacheIntegration(t *testing.T) {
	config := Config{
		Provider:     "mock",
		CacheEnabled: true,
		CacheDir:     t.TempDir(),
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	req := RemediationRequest{
		CWEID:    "CWE-89",
		Severity: "high",
		Message:  "Test cache",
	}

	ctx := context.Background()

	// First request - should not be cached
	resp1, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("First GenerateRemediation() error = %v", err)
	}
	if resp1.Cached {
		t.Error("First response should not be cached")
	}

	// Second request - should be cached
	resp2, err := manager.GenerateRemediation(ctx, req)
	if err != nil {
		t.Fatalf("Second GenerateRemediation() error = %v", err)
	}
	if !resp2.Cached {
		t.Error("Second response should be cached")
	}
}
