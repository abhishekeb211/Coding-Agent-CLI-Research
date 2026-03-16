package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnthropicProvider implements the LLMProvider interface for Anthropic Claude
type AnthropicProvider struct {
	apiKey      string
	model       string
	baseURL     string
	maxTokens   int
	temperature float32
	cache       *Cache
	redactor    *Redactor
	template    *PromptTemplate
	config      Config
	
	// Rate limiting
	lastRequest time.Time
	minInterval time.Duration
}

// Anthropic model pricing (per 1M tokens) as of 2024
var anthropicPricing = map[string]struct {
	inputCost  float64
	outputCost float64
}{
	"claude-3-opus-20240229": {
		inputCost:  15.00,
		outputCost: 75.00,
	},
	"claude-3-sonnet-20240229": {
		inputCost:  3.00,
		outputCost: 15.00,
	},
	"claude-3-haiku-20240307": {
		inputCost:  0.25,
		outputCost: 1.25,
	},
}

// NewAnthropicProvider creates a new Anthropic provider
func NewAnthropicProvider(config Config) (*AnthropicProvider, error) {
	if config.APIKey == "" {
		return nil, NewProviderError("anthropic", ErrInvalidAPIKey, 
			"Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable or configure in config file.", false)
	}

	// Set default model if not specified
	model := config.Model
	if model == "" {
		model = "claude-3-sonnet-20240229"
	}

	// Validate model
	if _, ok := anthropicPricing[model]; !ok {
		return nil, NewProviderError("anthropic", ErrInvalidModel, 
			fmt.Sprintf("Unsupported model: %s. Supported models: claude-3-opus-20240229, claude-3-sonnet-20240229, claude-3-haiku-20240307", model), false)
	}

	// Set default base URL if not specified
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.anthropic.com/v1"
	}

	cache, err := NewCache(config.CacheDir, config.CacheEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	return &AnthropicProvider{
		apiKey:      config.APIKey,
		model:       model,
		baseURL:     baseURL,
		maxTokens:   config.MaxTokens,
		temperature: config.Temperature,
		cache:       cache,
		redactor:    NewRedactor(true),
		template:    NewPromptTemplate(config.MaxTokens),
		config:      config,
		minInterval: 100 * time.Millisecond, // Rate limit: max 10 requests/second
	}, nil
}

// GenerateRemediation generates remediation guidance using Anthropic Claude
func (p *AnthropicProvider) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
	// Check cache first
	if cached, found := p.cache.Get(req); found {
		return cached, nil
	}

	// Redact secrets
	redactedReq, matches := p.redactor.RedactRequest(&req)
	if len(matches) > 0 {
		// Secrets were redacted
		_ = matches
	}

	// Apply rate limiting
	p.applyRateLimit()

	// Generate prompt
	prompt := p.template.GeneratePrompt(*redactedReq)

	// Call Anthropic API
	response, err := p.callAnthropic(ctx, prompt)
	if err != nil {
		// Wrap error with provider context if not already wrapped
		var providerErr *ProviderError
		if !errors.As(err, &providerErr) {
			return nil, NewProviderError("anthropic", err, "Failed to generate remediation", IsRetryableError(err))
		}
		return nil, err
	}

	// Parse response
	remediationResp, err := p.parseResponse(response)
	if err != nil {
		return nil, NewProviderError("anthropic", err, "Failed to parse response", false)
	}

	remediationResp.GeneratedAt = time.Now()
	remediationResp.Cached = false

	// Cache the response
	if err := p.cache.Set(req, remediationResp); err != nil {
		// Log error but don't fail
		_ = err
	}

	return remediationResp, nil
}

// applyRateLimit enforces rate limiting between requests
func (p *AnthropicProvider) applyRateLimit() {
	if !p.lastRequest.IsZero() {
		elapsed := time.Since(p.lastRequest)
		if elapsed < p.minInterval {
			time.Sleep(p.minInterval - elapsed)
		}
	}
	p.lastRequest = time.Now()
}

// callAnthropic makes the actual API call to Anthropic
func (p *AnthropicProvider) callAnthropic(ctx context.Context, prompt string) (string, error) {
	// Prepare request payload
	payload := map[string]interface{}{
		"model": p.model,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":  p.maxTokens,
		"temperature": p.temperature,
		"system":      "You are a security expert helping developers fix vulnerabilities. Provide clear, actionable remediation guidance.",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP request
	url := fmt.Sprintf("%s/messages", p.baseURL)
	respBody, err := p.makeHTTPRequest(ctx, url, payloadBytes)
	if err != nil {
		return "", err
	}

	// Parse response
	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API errors
	if apiResp.Error != nil {
		return "", fmt.Errorf("Anthropic API error (%s): %s", apiResp.Error.Type, apiResp.Error.Message)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("no response from Anthropic")
	}

	// Extract text from content blocks
	var responseText strings.Builder
	for _, content := range apiResp.Content {
		if content.Type == "text" {
			responseText.WriteString(content.Text)
		}
	}

	return responseText.String(), nil
}

// makeHTTPRequest makes an HTTP request to the Anthropic API
func (p *AnthropicProvider) makeHTTPRequest(ctx context.Context, url string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers (Anthropic requires specific headers)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: p.config.Timeout,
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		// Try to parse error message
		var errResp struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		
		errorMsg := string(body)
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			errorMsg = errResp.Error.Message
			
			// Check for specific error types
			if errResp.Error.Type == "authentication_error" || 
			   strings.Contains(strings.ToLower(errorMsg), "api key") {
				return nil, NewProviderError("anthropic", ErrInvalidAPIKey, 
					"Invalid API key. Please check your Anthropic API key configuration.", false)
			}
		}
		
		// Classify the HTTP error
		return nil, ClassifyHTTPError(resp.StatusCode, errorMsg, "anthropic")
	}

	return body, nil
}

// parseResponse parses the Anthropic response into a RemediationResponse
func (p *AnthropicProvider) parseResponse(content string) (*RemediationResponse, error) {
	// Try to parse as JSON first
	var jsonResp struct {
		Explanation      string   `json:"explanation"`
		RemediationSteps []string `json:"remediation_steps"`
		ExampleFix       string   `json:"example_fix"`
		Confidence       float64  `json:"confidence"`
	}

	if err := json.Unmarshal([]byte(content), &jsonResp); err == nil {
		// Successfully parsed as JSON
		return &RemediationResponse{
			Explanation:      jsonResp.Explanation,
			RemediationSteps: jsonResp.RemediationSteps,
			ExampleFix:       jsonResp.ExampleFix,
			Confidence:       jsonResp.Confidence,
		}, nil
	}

	// Fall back to text parsing
	return p.parseTextResponse(content)
}

// parseTextResponse parses a text response into structured format
func (p *AnthropicProvider) parseTextResponse(content string) (*RemediationResponse, error) {
	lines := strings.Split(content, "\n")
	
	var explanation strings.Builder
	var steps []string
	var exampleFix strings.Builder
	
	section := "explanation"
	inCodeBlock := false
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Detect section headers
		if strings.Contains(strings.ToLower(trimmed), "remediation") || 
		   strings.Contains(strings.ToLower(trimmed), "steps") {
			section = "steps"
			continue
		}
		if strings.Contains(strings.ToLower(trimmed), "example") || 
		   strings.Contains(strings.ToLower(trimmed), "fix") {
			section = "example"
			continue
		}
		
		// Handle code blocks
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			if section == "example" {
				exampleFix.WriteString(line + "\n")
			}
			continue
		}
		
		// Add content to appropriate section
		switch section {
		case "explanation":
			if trimmed != "" {
				explanation.WriteString(line + "\n")
			}
		case "steps":
			if strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "*") || 
			   (len(trimmed) > 2 && trimmed[0] >= '0' && trimmed[0] <= '9' && trimmed[1] == '.') {
				// This is a list item
				step := strings.TrimLeft(trimmed, "-*0123456789. ")
				if step != "" {
					steps = append(steps, step)
				}
			}
		case "example":
			exampleFix.WriteString(line + "\n")
		}
	}
	
	// If no steps were found, create a generic one
	if len(steps) == 0 {
		steps = []string{"Review and apply the suggested fixes"}
	}
	
	return &RemediationResponse{
		Explanation:      strings.TrimSpace(explanation.String()),
		RemediationSteps: steps,
		ExampleFix:       strings.TrimSpace(exampleFix.String()),
		Confidence:       0.8,
	}, nil
}

// EstimateCost estimates the cost of generating remediation
func (p *AnthropicProvider) EstimateCost(req RemediationRequest) (float64, error) {
	pricing, ok := anthropicPricing[p.model]
	if !ok {
		return 0, fmt.Errorf("unknown model: %s", p.model)
	}

	// Generate prompt to estimate token count
	prompt := p.template.GeneratePrompt(req)
	
	// Rough estimation: 1 token ≈ 4 characters
	inputTokens := len(prompt) / 4
	outputTokens := p.maxTokens
	
	// Calculate cost (pricing is per 1M tokens)
	inputCost := float64(inputTokens) / 1000000.0 * pricing.inputCost
	outputCost := float64(outputTokens) / 1000000.0 * pricing.outputCost
	
	return inputCost + outputCost, nil
}

// Name returns the provider name
func (p *AnthropicProvider) Name() string {
	return fmt.Sprintf("anthropic-%s", p.model)
}

// IsAvailable checks if the Anthropic provider is available
func (p *AnthropicProvider) IsAvailable() bool {
	return p.apiKey != ""
}

// Close cleans up resources
func (p *AnthropicProvider) Close() error {
	if p.cache != nil {
		return p.cache.Close()
	}
	return nil
}
