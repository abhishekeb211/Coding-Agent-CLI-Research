package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// mockFailingProvider is a mock provider that always fails
type mockFailingProvider struct {
	name      string
	err       error
	available bool
}

func (m *mockFailingProvider) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
	return nil, m.err
}

func (m *mockFailingProvider) EstimateCost(req RemediationRequest) (float64, error) {
	return 0.01, nil
}

func (m *mockFailingProvider) Name() string {
	return m.name
}

func (m *mockFailingProvider) IsAvailable() bool {
	return m.available
}

func (m *mockFailingProvider) Close() error {
	return nil
}

// mockSuccessProvider is a mock provider that always succeeds
type mockSuccessProvider struct {
	name      string
	available bool
}

func (m *mockSuccessProvider) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
	return &RemediationResponse{
		Explanation:      "Test explanation",
		RemediationSteps: []string{"Step 1", "Step 2"},
		ExampleFix:       "fix code",
		Confidence:       0.9,
		GeneratedAt:      time.Now(),
		Cached:           false,
	}, nil
}

func (m *mockSuccessProvider) EstimateCost(req RemediationRequest) (float64, error) {
	return 0.01, nil
}

func (m *mockSuccessProvider) Name() string {
	return m.name
}

func (m *mockSuccessProvider) IsAvailable() bool {
	return m.available
}

func (m *mockSuccessProvider) Close() error {
	return nil
}

func TestFallbackChain(t *testing.T) {
	tests := []struct {
		name        string
		providers   []LLMProvider
		wantSuccess bool
		wantErr     error
	}{
		{
			name: "first provider succeeds",
			providers: []LLMProvider{
				&mockSuccessProvider{name: "provider1", available: true},
				&mockFailingProvider{name: "provider2", err: errors.New("should not be called"), available: true},
			},
			wantSuccess: true,
		},
		{
			name: "first fails, second succeeds",
			providers: []LLMProvider{
				&mockFailingProvider{name: "provider1", err: NewProviderError("provider1", ErrProviderUnavailable, "unavailable", true), available: true},
				&mockSuccessProvider{name: "provider2", available: true},
			},
			wantSuccess: true,
		},
		{
			name: "first unavailable, second succeeds",
			providers: []LLMProvider{
				&mockFailingProvider{name: "provider1", err: errors.New("should not be called"), available: false},
				&mockSuccessProvider{name: "provider2", available: true},
			},
			wantSuccess: true,
		},
		{
			name: "all providers fail",
			providers: []LLMProvider{
				&mockFailingProvider{name: "provider1", err: NewProviderError("provider1", ErrInvalidAPIKey, "invalid key", false), available: true},
				&mockFailingProvider{name: "provider2", err: NewProviderError("provider2", ErrProviderUnavailable, "unavailable", true), available: true},
			},
			wantSuccess: false,
		},
		{
			name: "all providers unavailable",
			providers: []LLMProvider{
				&mockFailingProvider{name: "provider1", err: errors.New("should not be called"), available: false},
				&mockFailingProvider{name: "provider2", err: errors.New("should not be called"), available: false},
			},
			wantSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.CacheEnabled = false // Disable cache for testing
			config.MaxRetries = 0       // No retries for faster tests
			
			manager := &Manager{
				providers: tt.providers,
				config:    config,
			}

			req := RemediationRequest{
				CWEID:       "CWE-89",
				CodeSnippet: "test code",
			}

			resp, err := manager.GenerateRemediation(context.Background(), req)

			if tt.wantSuccess {
				if err != nil {
					t.Errorf("Expected success, got error: %v", err)
				}
				if resp == nil {
					t.Error("Expected response, got nil")
				}
			} else {
				if err == nil {
					t.Error("Expected error, got success")
				}
			}
		})
	}
}

func TestRetryLogic(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		maxRetries  int
		wantAttempts int
	}{
		{
			name:        "retryable error with retries",
			err:         NewProviderError("test", ErrRateLimitExceeded, "rate limit", true),
			maxRetries:  2,
			wantAttempts: 3, // initial + 2 retries
		},
		{
			name:        "non-retryable error",
			err:         NewProviderError("test", ErrInvalidAPIKey, "invalid key", false),
			maxRetries:  2,
			wantAttempts: 1, // should fail immediately
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			provider := &mockFailingProvider{
				name:      "test",
				available: true,
				err:       tt.err,
			}
			
			// Wrap provider to count attempts
			countingProvider := &struct {
				*mockFailingProvider
			}{provider}
			
			originalGenerate := provider.GenerateRemediation
			countingProvider.GenerateRemediation = func(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
				attempts++
				return originalGenerate(ctx, req)
			}

			config := DefaultConfig()
			config.CacheEnabled = false
			config.MaxRetries = tt.maxRetries
			config.RetryDelay = 1 * time.Millisecond // Fast retries for testing
			
			manager := &Manager{
				providers: []LLMProvider{countingProvider},
				config:    config,
			}

			req := RemediationRequest{
				CWEID:       "CWE-89",
				CodeSnippet: "test code",
			}

			_, err := manager.GenerateRemediation(context.Background(), req)
			
			if err == nil {
				t.Error("Expected error, got success")
			}
			
			if attempts != tt.wantAttempts {
				t.Errorf("Expected %d attempts, got %d", tt.wantAttempts, attempts)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name         string
		providers    []LLMProvider
		wantContains []string
	}{
		{
			name: "invalid API key error",
			providers: []LLMProvider{
				&mockFailingProvider{
					name:      "openai",
					err:       NewProviderError("openai", ErrInvalidAPIKey, "Invalid API key", false),
					available: true,
				},
			},
			wantContains: []string{"openai", "Invalid API key", "All LLM providers failed"},
		},
		{
			name: "provider unavailable error",
			providers: []LLMProvider{
				&mockFailingProvider{
					name:      "ollama",
					err:       NewProviderError("ollama", ErrProviderUnavailable, "Cannot connect", true),
					available: true,
				},
			},
			wantContains: []string{"ollama", "Cannot connect", "All LLM providers failed"},
		},
		{
			name: "multiple provider errors",
			providers: []LLMProvider{
				&mockFailingProvider{
					name:      "openai",
					err:       NewProviderError("openai", ErrInvalidAPIKey, "Invalid key", false),
					available: true,
				},
				&mockFailingProvider{
					name:      "anthropic",
					err:       NewProviderError("anthropic", ErrProviderUnavailable, "Service down", true),
					available: true,
				},
			},
			wantContains: []string{"openai", "anthropic", "Invalid key", "Service down", "All LLM providers failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.CacheEnabled = false
			config.MaxRetries = 0
			
			manager := &Manager{
				providers: tt.providers,
				config:    config,
			}

			req := RemediationRequest{
				CWEID:       "CWE-89",
				CodeSnippet: "test code",
			}

			_, err := manager.GenerateRemediation(context.Background(), req)
			
			if err == nil {
				t.Fatal("Expected error, got success")
			}

			errMsg := err.Error()
			for _, want := range tt.wantContains {
				if !strings.Contains(errMsg, want) {
					t.Errorf("Error message should contain %q, got: %s", want, errMsg)
				}
			}
		})
	}
}

func TestCostLimitEnforcement(t *testing.T) {
	config := DefaultConfig()
	config.CacheEnabled = false
	config.CostLimit = 0.005 // Very low limit
	
	provider := &mockSuccessProvider{
		name:      "expensive-provider",
		available: true,
	}
	
	manager := &Manager{
		providers: []LLMProvider{provider},
		config:    config,
	}

	req := RemediationRequest{
		CWEID:       "CWE-89",
		CodeSnippet: "test code",
	}

	_, err := manager.GenerateRemediation(context.Background(), req)
	
	if err == nil {
		t.Error("Expected cost limit error, got success")
	}
	
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("Expected cost limit error, got: %v", err)
	}
}
