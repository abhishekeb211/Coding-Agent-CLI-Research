package llm

import (
	"context"
	"time"
)

// RemediationRequest represents a request for remediation guidance
type RemediationRequest struct {
	CWEID          string
	CWEDescription string
	CodeSnippet    string
	FilePath       string
	LineNumber     int
	Severity       string
	RuleID         string
	Message        string
}

// RemediationResponse represents the LLM's remediation guidance
type RemediationResponse struct {
	Explanation    string   `json:"explanation"`
	RemediationSteps []string `json:"remediation_steps"`
	ExampleFix     string   `json:"example_fix,omitempty"`
	Confidence     float64  `json:"confidence"`
	GeneratedAt    time.Time `json:"generated_at"`
	Cached         bool     `json:"cached"`
}

// LLMProvider defines the interface for LLM implementations
type LLMProvider interface {
	// GenerateRemediation generates remediation guidance for a finding
	GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error)
	
	// EstimateCost estimates the cost of generating remediation for a request
	EstimateCost(req RemediationRequest) (float64, error)
	
	// Name returns the provider name
	Name() string
	
	// IsAvailable checks if the LLM is available
	IsAvailable() bool
	
	// Close cleans up resources
	Close() error
}

// Config holds LLM configuration
type Config struct {
	// Provider selection
	Provider         string   // "openai", "anthropic", "ollama", "mock"
	FallbackProviders []string // Fallback chain
	
	// Provider-specific settings
	APIKey       string
	ModelPath    string
	Model        string
	BaseURL      string
	
	// Generation settings
	MaxTokens    int
	Temperature  float32
	Timeout      time.Duration
	
	// Retry settings
	MaxRetries      int
	RetryDelay      time.Duration
	RetryMultiplier float64
	
	// Cache settings
	CacheEnabled bool
	CacheDir     string
	
	// Cost settings
	CostLimit float64 // Maximum cost per request
}

// ProviderConfig holds provider-specific configuration
type ProviderConfig struct {
	Name    string
	APIKey  string
	Model   string
	BaseURL string
}
