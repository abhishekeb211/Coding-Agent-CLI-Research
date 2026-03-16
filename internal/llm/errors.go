package llm

import (
	"errors"
	"fmt"
	"strings"
)

// Error types for LLM operations
var (
	// ErrInvalidAPIKey indicates the API key is invalid or missing
	ErrInvalidAPIKey = errors.New("invalid or missing API key")
	
	// ErrProviderUnavailable indicates the provider is not available
	ErrProviderUnavailable = errors.New("provider is unavailable")
	
	// ErrRateLimitExceeded indicates rate limit has been exceeded
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	
	// ErrCostLimitExceeded indicates cost limit has been exceeded
	ErrCostLimitExceeded = errors.New("cost limit exceeded")
	
	// ErrTimeout indicates the request timed out
	ErrTimeout = errors.New("request timed out")
	
	// ErrInvalidModel indicates the model is not supported
	ErrInvalidModel = errors.New("invalid or unsupported model")
	
	// ErrNoProvidersAvailable indicates no providers are available
	ErrNoProvidersAvailable = errors.New("no providers available")
)

// ProviderError wraps provider-specific errors with context
type ProviderError struct {
	Provider string
	Err      error
	Message  string
	Retryable bool
}

func (e *ProviderError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s provider error: %s: %v", e.Provider, e.Message, e.Err)
	}
	return fmt.Sprintf("%s provider error: %v", e.Provider, e.Err)
}

func (e *ProviderError) Unwrap() error {
	return e.Err
}

// IsRetryable returns true if the error is retryable
func (e *ProviderError) IsRetryable() bool {
	return e.Retryable
}

// NewProviderError creates a new provider error
func NewProviderError(provider string, err error, message string, retryable bool) *ProviderError {
	return &ProviderError{
		Provider:  provider,
		Err:       err,
		Message:   message,
		Retryable: retryable,
	}
}

// ClassifyHTTPError classifies HTTP errors and returns appropriate error types
func ClassifyHTTPError(statusCode int, body string, provider string) error {
	bodyLower := strings.ToLower(body)
	
	switch statusCode {
	case 401:
		// Unauthorized - likely invalid API key
		if strings.Contains(bodyLower, "api key") || strings.Contains(bodyLower, "unauthorized") {
			return NewProviderError(provider, ErrInvalidAPIKey, 
				"Invalid API key. Please check your API key configuration.", false)
		}
		return NewProviderError(provider, ErrInvalidAPIKey, 
			fmt.Sprintf("Authentication failed (status %d)", statusCode), false)
		
	case 403:
		// Forbidden - could be invalid key or insufficient permissions
		return NewProviderError(provider, ErrInvalidAPIKey, 
			"Access forbidden. Check your API key permissions.", false)
		
	case 429:
		// Rate limit exceeded
		return NewProviderError(provider, ErrRateLimitExceeded, 
			"Rate limit exceeded. Please wait before retrying.", true)
		
	case 500, 502, 503, 504:
		// Server errors - retryable
		return NewProviderError(provider, ErrProviderUnavailable, 
			fmt.Sprintf("Provider server error (status %d). Will retry with fallback.", statusCode), true)
		
	default:
		// Other errors
		return NewProviderError(provider, fmt.Errorf("HTTP error %d", statusCode), 
			fmt.Sprintf("Request failed with status %d", statusCode), false)
	}
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check if it's a ProviderError
	var providerErr *ProviderError
	if errors.As(err, &providerErr) {
		return providerErr.IsRetryable()
	}
	
	// Check for specific error types
	if errors.Is(err, ErrRateLimitExceeded) || 
	   errors.Is(err, ErrProviderUnavailable) ||
	   errors.Is(err, ErrTimeout) {
		return true
	}
	
	return false
}

// FormatUserError formats an error message for end users
func FormatUserError(err error) string {
	if err == nil {
		return ""
	}
	
	var providerErr *ProviderError
	if errors.As(err, &providerErr) {
		switch {
		case errors.Is(providerErr.Err, ErrInvalidAPIKey):
			return fmt.Sprintf("❌ %s: %s\n\nTo fix this:\n  1. Check your API key in the configuration\n  2. Verify the key has not expired\n  3. Ensure the key has proper permissions\n\nConfiguration file: ~/.coding-agent-cli/config.yaml", 
				providerErr.Provider, providerErr.Message)
				
		case errors.Is(providerErr.Err, ErrProviderUnavailable):
			return fmt.Sprintf("⚠️  %s: %s\n\nThe system will automatically try fallback providers.", 
				providerErr.Provider, providerErr.Message)
				
		case errors.Is(providerErr.Err, ErrRateLimitExceeded):
			return fmt.Sprintf("⏱️  %s: %s\n\nThe system will automatically retry with exponential backoff.", 
				providerErr.Provider, providerErr.Message)
				
		default:
			return fmt.Sprintf("❌ %s: %s", providerErr.Provider, providerErr.Message)
		}
	}
	
	// Handle standard errors
	switch {
	case errors.Is(err, ErrNoProvidersAvailable):
		return "❌ No LLM providers are available.\n\nTo fix this:\n  1. Configure at least one provider (OpenAI, Anthropic, or Ollama)\n  2. Ensure API keys are set correctly\n  3. Check network connectivity\n\nSee documentation: https://docs.coding-agent-cli.dev/llm-providers"
		
	case errors.Is(err, ErrInvalidAPIKey):
		return "❌ Invalid API key.\n\nPlease check your API key configuration in ~/.coding-agent-cli/config.yaml"
		
	default:
		return fmt.Sprintf("❌ Error: %v", err)
	}
}
