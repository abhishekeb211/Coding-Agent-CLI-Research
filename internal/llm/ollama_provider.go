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

// OllamaProvider implements the LLMProvider interface for Ollama (local LLMs)
type OllamaProvider struct {
	baseURL     string
	model       string
	maxTokens   int
	temperature float32
	cache       *Cache
	redactor    *Redactor
	template    *PromptTemplate
	config      Config
	
	// Rate limiting (less strict for local models)
	lastRequest time.Time
	minInterval time.Duration
}

// NewOllamaProvider creates a new Ollama provider for local LLMs
func NewOllamaProvider(config Config) (*OllamaProvider, error) {
	// Set default model if not specified
	model := config.Model
	if model == "" {
		model = "llama2" // Default to llama2
	}

	// Set default base URL if not specified
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:11434" // Default Ollama port
	}

	cache, err := NewCache(config.CacheDir, config.CacheEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	return &OllamaProvider{
		baseURL:     baseURL,
		model:       model,
		maxTokens:   config.MaxTokens,
		temperature: config.Temperature,
		cache:       cache,
		redactor:    NewRedactor(true),
		template:    NewPromptTemplate(config.MaxTokens),
		config:      config,
		minInterval: 10 * time.Millisecond, // Less strict for local models
	}, nil
}

// GenerateRemediation generates remediation guidance using Ollama
func (p *OllamaProvider) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
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

	// Call Ollama API
	response, err := p.callOllama(ctx, prompt)
	if err != nil {
		// Wrap error with provider context if not already wrapped
		var providerErr *ProviderError
		if !errors.As(err, &providerErr) {
			// Check if it's a connection error
			if strings.Contains(err.Error(), "connection refused") || 
			   strings.Contains(err.Error(), "is Ollama running") {
				return nil, NewProviderError("ollama", ErrProviderUnavailable, 
					"Cannot connect to Ollama. Please ensure Ollama is running (ollama serve).", true)
			}
			return nil, NewProviderError("ollama", err, "Failed to generate remediation", IsRetryableError(err))
		}
		return nil, err
	}

	// Parse response
	remediationResp, err := p.parseResponse(response)
	if err != nil {
		return nil, NewProviderError("ollama", err, "Failed to parse response", false)
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
func (p *OllamaProvider) applyRateLimit() {
	if !p.lastRequest.IsZero() {
		elapsed := time.Since(p.lastRequest)
		if elapsed < p.minInterval {
			time.Sleep(p.minInterval - elapsed)
		}
	}
	p.lastRequest = time.Now()
}

// callOllama makes the actual API call to Ollama
func (p *OllamaProvider) callOllama(ctx context.Context, prompt string) (string, error) {
	// Prepare request payload for Ollama's generate endpoint
	payload := map[string]interface{}{
		"model":  p.model,
		"prompt": fmt.Sprintf("You are a security expert helping developers fix vulnerabilities. Provide clear, actionable remediation guidance.\n\n%s", prompt),
		"stream": false,
		"options": map[string]interface{}{
			"temperature": p.temperature,
			"num_predict": p.maxTokens,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP request
	url := fmt.Sprintf("%s/api/generate", p.baseURL)
	respBody, err := p.makeHTTPRequest(ctx, url, payloadBytes)
	if err != nil {
		return "", err
	}

	// Parse response
	var apiResp struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API errors
	if apiResp.Error != "" {
		return "", fmt.Errorf("Ollama API error: %s", apiResp.Error)
	}

	if apiResp.Response == "" {
		return "", fmt.Errorf("no response from Ollama")
	}

	return apiResp.Response, nil
}

// makeHTTPRequest makes an HTTP request to the Ollama API
func (p *OllamaProvider) makeHTTPRequest(ctx context.Context, url string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: p.config.Timeout,
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed (is Ollama running?): %w", err)
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
			Error string `json:"error"`
		}
		
		errorMsg := string(body)
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			errorMsg = errResp.Error
		}
		
		// Check for connection errors
		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusBadGateway {
			return nil, NewProviderError("ollama", ErrProviderUnavailable, 
				"Ollama server is not available. Please ensure Ollama is running (ollama serve).", true)
		}
		
		// Classify the HTTP error
		return nil, ClassifyHTTPError(resp.StatusCode, errorMsg, "ollama")
	}

	return body, nil
}

// parseResponse parses the Ollama response into a RemediationResponse
func (p *OllamaProvider) parseResponse(content string) (*RemediationResponse, error) {
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
func (p *OllamaProvider) parseTextResponse(content string) (*RemediationResponse, error) {
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
		Confidence:       0.7, // Lower confidence for local models
	}, nil
}

// EstimateCost estimates the cost of generating remediation (free for local models)
func (p *OllamaProvider) EstimateCost(req RemediationRequest) (float64, error) {
	// Local models are free
	return 0.0, nil
}

// Name returns the provider name
func (p *OllamaProvider) Name() string {
	return fmt.Sprintf("ollama-%s", p.model)
}

// IsAvailable checks if the Ollama provider is available
func (p *OllamaProvider) IsAvailable() bool {
	// Try to ping Ollama server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/tags", p.baseURL), nil)
	if err != nil {
		return false
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// Close cleans up resources
func (p *OllamaProvider) Close() error {
	if p.cache != nil {
		return p.cache.Close()
	}
	return nil
}
