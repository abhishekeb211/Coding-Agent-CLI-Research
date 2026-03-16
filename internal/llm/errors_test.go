package llm

import (
	"errors"
	"strings"
	"testing"
)

func TestProviderError(t *testing.T) {
	tests := []struct {
		name      string
		provider  string
		err       error
		message   string
		retryable bool
		wantErr   string
	}{
		{
			name:      "basic error",
			provider:  "openai",
			err:       errors.New("connection failed"),
			message:   "Failed to connect",
			retryable: true,
			wantErr:   "openai provider error: Failed to connect: connection failed",
		},
		{
			name:      "error without message",
			provider:  "anthropic",
			err:       ErrInvalidAPIKey,
			message:   "",
			retryable: false,
			wantErr:   "anthropic provider error: invalid or missing API key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewProviderError(tt.provider, tt.err, tt.message, tt.retryable)
			
			if err.Error() != tt.wantErr {
				t.Errorf("Error() = %v, want %v", err.Error(), tt.wantErr)
			}
			
			if err.IsRetryable() != tt.retryable {
				t.Errorf("IsRetryable() = %v, want %v", err.IsRetryable(), tt.retryable)
			}
			
			if !errors.Is(err, tt.err) {
				t.Errorf("errors.Is() failed, want error to wrap %v", tt.err)
			}
		})
	}
}

func TestClassifyHTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		provider   string
		wantErr    error
		wantMsg    string
		retryable  bool
	}{
		{
			name:       "401 with API key error",
			statusCode: 401,
			body:       `{"error": {"message": "Invalid API key"}}`,
			provider:   "openai",
			wantErr:    ErrInvalidAPIKey,
			wantMsg:    "Invalid API key",
			retryable:  false,
		},
		{
			name:       "401 unauthorized",
			statusCode: 401,
			body:       "Unauthorized",
			provider:   "anthropic",
			wantErr:    ErrInvalidAPIKey,
			wantMsg:    "Authentication failed",
			retryable:  false,
		},
		{
			name:       "403 forbidden",
			statusCode: 403,
			body:       "Forbidden",
			provider:   "openai",
			wantErr:    ErrInvalidAPIKey,
			wantMsg:    "Access forbidden",
			retryable:  false,
		},
		{
			name:       "429 rate limit",
			statusCode: 429,
			body:       "Rate limit exceeded",
			provider:   "openai",
			wantErr:    ErrRateLimitExceeded,
			wantMsg:    "Rate limit exceeded",
			retryable:  true,
		},
		{
			name:       "500 server error",
			statusCode: 500,
			body:       "Internal server error",
			provider:   "anthropic",
			wantErr:    ErrProviderUnavailable,
			wantMsg:    "Provider server error",
			retryable:  true,
		},
		{
			name:       "503 service unavailable",
			statusCode: 503,
			body:       "Service unavailable",
			provider:   "ollama",
			wantErr:    ErrProviderUnavailable,
			wantMsg:    "Provider server error",
			retryable:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ClassifyHTTPError(tt.statusCode, tt.body, tt.provider)
			
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) {
				t.Fatalf("Expected ProviderError, got %T", err)
			}
			
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Expected error type %v, got %v", tt.wantErr, providerErr.Err)
			}
			
			if !strings.Contains(providerErr.Message, tt.wantMsg) {
				t.Errorf("Expected message to contain %q, got %q", tt.wantMsg, providerErr.Message)
			}
			
			if providerErr.IsRetryable() != tt.retryable {
				t.Errorf("IsRetryable() = %v, want %v", providerErr.IsRetryable(), tt.retryable)
			}
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "rate limit error",
			err:       ErrRateLimitExceeded,
			retryable: true,
		},
		{
			name:      "provider unavailable",
			err:       ErrProviderUnavailable,
			retryable: true,
		},
		{
			name:      "timeout error",
			err:       ErrTimeout,
			retryable: true,
		},
		{
			name:      "invalid API key",
			err:       ErrInvalidAPIKey,
			retryable: false,
		},
		{
			name:      "retryable provider error",
			err:       NewProviderError("test", errors.New("temp error"), "temporary", true),
			retryable: true,
		},
		{
			name:      "non-retryable provider error",
			err:       NewProviderError("test", errors.New("perm error"), "permanent", false),
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryableError(tt.err); got != tt.retryable {
				t.Errorf("IsRetryableError() = %v, want %v", got, tt.retryable)
			}
		})
	}
}

func TestFormatUserError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantText string
	}{
		{
			name:     "nil error",
			err:      nil,
			wantText: "",
		},
		{
			name:     "invalid API key provider error",
			err:      NewProviderError("openai", ErrInvalidAPIKey, "Invalid key", false),
			wantText: "❌ openai: Invalid key",
		},
		{
			name:     "provider unavailable",
			err:      NewProviderError("anthropic", ErrProviderUnavailable, "Service down", true),
			wantText: "⚠️  anthropic: Service down",
		},
		{
			name:     "rate limit exceeded",
			err:      NewProviderError("openai", ErrRateLimitExceeded, "Too many requests", true),
			wantText: "⏱️  openai: Too many requests",
		},
		{
			name:     "no providers available",
			err:      ErrNoProvidersAvailable,
			wantText: "❌ No LLM providers are available",
		},
		{
			name:     "standard invalid API key",
			err:      ErrInvalidAPIKey,
			wantText: "❌ Invalid API key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatUserError(tt.err)
			
			if !strings.Contains(got, tt.wantText) {
				t.Errorf("FormatUserError() = %q, want to contain %q", got, tt.wantText)
			}
		})
	}
}
