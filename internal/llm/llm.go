package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manager manages LLM providers and remediation generation
type Manager struct {
	providers []LLMProvider
	config    Config
	cache     *Cache
	redactor  *Redactor
}

// NewManager creates a new LLM manager with provider fallback chain
func NewManager(config Config) (*Manager, error) {
	// Create cache
	cache, err := NewCache(config.CacheDir, config.CacheEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	// Create redactor
	redactor := NewRedactor(true)

	// Create providers based on configuration
	providers := make([]LLMProvider, 0)
	
	// Add primary provider
	if config.Provider != "" {
		provider, err := createProvider(config.Provider, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create primary provider %s: %w", config.Provider, err)
		}
		providers = append(providers, provider)
	}
	
	// Add fallback providers
	for _, providerName := range config.FallbackProviders {
		provider, err := createProvider(providerName, config)
		if err != nil {
			// Log warning but continue with other providers
			continue
		}
		providers = append(providers, provider)
	}
	
	// If no providers configured, use mock provider
	if len(providers) == 0 {
		provider, err := NewMockProvider(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create mock provider: %w", err)
		}
		providers = append(providers, provider)
	}

	return &Manager{
		providers: providers,
		config:    config,
		cache:     cache,
		redactor:  redactor,
	}, nil
}

// createProvider creates a provider instance based on name
func createProvider(name string, config Config) (LLMProvider, error) {
	switch name {
	case "mock":
		return NewMockProvider(config)
	case "openai":
		return NewOpenAIProvider(config)
	case "anthropic":
		return NewAnthropicProvider(config)
	case "ollama":
		return NewOllamaProvider(config)
	default:
		return nil, fmt.Errorf("unknown provider: %s", name)
	}
}

// DefaultConfig returns the default LLM configuration
func DefaultConfig() Config {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".coding-agent-cli", "llm-cache")

	return Config{
		Provider:         "mock",
		FallbackProviders: []string{},
		APIKey:           "",
		ModelPath:        "",
		Model:            "",
		BaseURL:          "",
		MaxTokens:        1024,
		Temperature:      0.7,
		Timeout:          30 * time.Second,
		MaxRetries:       3,
		RetryDelay:       1 * time.Second,
		RetryMultiplier:  2.0,
		CacheEnabled:     true,
		CacheDir:         cacheDir,
		CostLimit:        0.0, // No limit by default
	}
}

// GenerateRemediation generates remediation guidance for a finding with fallback and retry
func (m *Manager) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()

	// Check cache first
	if m.cache != nil && m.config.CacheEnabled {
		if cached, found := m.cache.Get(req); found {
			return cached, nil
		}
	}

	// Redact secrets from request
	redactedReq := &req
	if m.redactor != nil {
		redactedReq, _ = m.redactor.RedactRequest(&req)
	}

	// Try each provider in the fallback chain
	var lastErr error
	var providerErrors []string
	
	for i, provider := range m.providers {
		providerName := provider.Name()
		
		// Check if provider is available
		if !provider.IsAvailable() {
			errMsg := fmt.Sprintf("%s is not available", providerName)
			providerErrors = append(providerErrors, errMsg)
			lastErr = NewProviderError(providerName, ErrProviderUnavailable, errMsg, false)
			continue
		}

		// Estimate cost if limit is set
		if m.config.CostLimit > 0 {
			cost, err := provider.EstimateCost(*redactedReq)
			if err != nil {
				errMsg := fmt.Sprintf("failed to estimate cost: %v", err)
				providerErrors = append(providerErrors, fmt.Sprintf("%s: %s", providerName, errMsg))
				lastErr = NewProviderError(providerName, err, errMsg, false)
				continue
			}
			if cost > m.config.CostLimit {
				errMsg := fmt.Sprintf("estimated cost $%.4f exceeds limit $%.4f", cost, m.config.CostLimit)
				providerErrors = append(providerErrors, fmt.Sprintf("%s: %s", providerName, errMsg))
				lastErr = NewProviderError(providerName, ErrCostLimitExceeded, errMsg, false)
				continue
			}
		}

		// Try to generate remediation with retry
		response, err := m.generateWithRetry(ctx, provider, *redactedReq)
		if err != nil {
			// Extract error message
			var providerErr *ProviderError
			if errors.As(err, &providerErr) {
				providerErrors = append(providerErrors, fmt.Sprintf("%s: %s", providerName, providerErr.Message))
			} else {
				providerErrors = append(providerErrors, fmt.Sprintf("%s: %v", providerName, err))
			}
			lastErr = err
			
			// If this is not the last provider, try the next one
			if i < len(m.providers)-1 {
				continue
			}
			// Last provider failed, return comprehensive error
			return nil, m.formatFallbackError(providerErrors, lastErr)
		}

		// Success! Cache the response
		if m.cache != nil && m.config.CacheEnabled {
			if err := m.cache.Set(req, response); err != nil {
				// Log error but don't fail
				_ = err
			}
		}

		return response, nil
	}

	// All providers failed
	if lastErr != nil {
		return nil, m.formatFallbackError(providerErrors, lastErr)
	}
	return nil, NewProviderError("manager", ErrNoProvidersAvailable, 
		"No LLM providers are configured or available", false)
}

// formatFallbackError creates a comprehensive error message when all providers fail
func (m *Manager) formatFallbackError(providerErrors []string, lastErr error) error {
	var msg strings.Builder
	msg.WriteString("All LLM providers failed:\n")
	for _, errMsg := range providerErrors {
		msg.WriteString(fmt.Sprintf("  • %s\n", errMsg))
	}
	
	// Add helpful suggestions
	msg.WriteString("\nTroubleshooting:\n")
	msg.WriteString("  1. Check your API keys are configured correctly\n")
	msg.WriteString("  2. Verify network connectivity\n")
	msg.WriteString("  3. Ensure at least one provider is available\n")
	msg.WriteString("  4. Check the documentation: https://docs.coding-agent-cli.dev/llm-providers\n")
	
	return fmt.Errorf("%s\nLast error: %w", msg.String(), lastErr)
}

// generateWithRetry attempts to generate remediation with exponential backoff retry
func (m *Manager) generateWithRetry(ctx context.Context, provider LLMProvider, req RemediationRequest) (*RemediationResponse, error) {
	var lastErr error
	delay := m.config.RetryDelay

	for attempt := 0; attempt <= m.config.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Try to generate
		response, err := provider.GenerateRemediation(ctx, req)
		if err == nil {
			return response, nil
		}

		lastErr = err
		
		// Check if error is retryable
		if !IsRetryableError(err) {
			// Non-retryable error, fail immediately
			return nil, err
		}

		// If this is the last attempt, don't wait
		if attempt == m.config.MaxRetries {
			break
		}

		// Wait before retry with exponential backoff
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
			delay = time.Duration(float64(delay) * m.config.RetryMultiplier)
		}
	}

	return nil, fmt.Errorf("failed after %d retries: %w", m.config.MaxRetries, lastErr)
}

// EstimateCost estimates the cost of generating remediation using the primary provider
func (m *Manager) EstimateCost(req RemediationRequest) (float64, error) {
	if len(m.providers) == 0 {
		return 0, fmt.Errorf("no providers available")
	}

	// Redact secrets from request
	redactedReq := &req
	if m.redactor != nil {
		redactedReq, _ = m.redactor.RedactRequest(&req)
	}

	return m.providers[0].EstimateCost(*redactedReq)
}

// IsAvailable checks if any LLM provider is available
func (m *Manager) IsAvailable() bool {
	for _, provider := range m.providers {
		if provider.IsAvailable() {
			return true
		}
	}
	return false
}

// Close cleans up resources
func (m *Manager) Close() error {
	var errs []error
	
	// Close cache
	if m.cache != nil {
		if err := m.cache.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	
	// Close all providers
	for _, provider := range m.providers {
		if err := provider.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("errors closing manager: %v", errs)
	}
	return nil
}
