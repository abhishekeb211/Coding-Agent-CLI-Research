package llm

import (
	"context"
	"fmt"
	"time"
)

// MockProvider is a mock LLM provider for testing and development
type MockProvider struct {
	cache    *Cache
	redactor *Redactor
	template *PromptTemplate
	config   Config
}

// NewMockProvider creates a new mock provider
func NewMockProvider(config Config) (*MockProvider, error) {
	cache, err := NewCache(config.CacheDir, config.CacheEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	return &MockProvider{
		cache:    cache,
		redactor: NewRedactor(true),
		template: NewPromptTemplate(config.MaxTokens),
		config:   config,
	}, nil
}

// GenerateRemediation generates mock remediation guidance
func (m *MockProvider) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
	// Check cache first
	if cached, found := m.cache.Get(req); found {
		return cached, nil
	}

	// Redact secrets
	redactedReq, matches := m.redactor.RedactRequest(&req)
	if len(matches) > 0 {
		// Log redaction (in real implementation)
		_ = matches
	}

	// Generate mock response based on CWE
	response := m.generateMockResponse(*redactedReq)
	response.GeneratedAt = time.Now()
	response.Cached = false

	// Cache the response
	if err := m.cache.Set(req, response); err != nil {
		// Log error but don't fail
		_ = err
	}

	return response, nil
}

// generateMockResponse creates a mock response based on the CWE
func (m *MockProvider) generateMockResponse(req RemediationRequest) *RemediationResponse {
	// Generate CWE-specific guidance
	explanation, steps, example := m.getCWEGuidance(req.CWEID)

	return &RemediationResponse{
		Explanation:      explanation,
		RemediationSteps: steps,
		ExampleFix:       example,
		Confidence:       0.85,
	}
}

// getCWEGuidance returns mock guidance for common CWEs
func (m *MockProvider) getCWEGuidance(cweID string) (string, []string, string) {
	switch cweID {
	case "CWE-89":
		return "SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query. This allows attackers to execute arbitrary SQL commands.",
			[]string{
				"Use parameterized queries or prepared statements",
				"Validate and sanitize all user inputs",
				"Apply principle of least privilege to database accounts",
				"Use ORM frameworks that handle escaping automatically",
			},
			"# Instead of:\nquery = \"SELECT * FROM users WHERE id = \" + user_input\n\n# Use:\nquery = \"SELECT * FROM users WHERE id = ?\"\ncursor.execute(query, (user_input,))"

	case "CWE-78":
		return "OS Command Injection allows attackers to execute arbitrary commands on the host operating system via a vulnerable application.",
			[]string{
				"Avoid calling OS commands with user input",
				"Use language-specific APIs instead of shell commands",
				"If shell commands are necessary, use allowlists for validation",
				"Escape special characters properly",
			},
			"# Instead of:\nos.system(\"ping \" + user_input)\n\n# Use:\nimport subprocess\nsubprocess.run([\"ping\", \"-c\", \"1\", user_input], check=True)"

	case "CWE-79":
		return "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.",
			[]string{
				"Encode all user-supplied data before rendering",
				"Use Content Security Policy (CSP) headers",
				"Validate input on both client and server side",
				"Use modern frameworks with automatic escaping",
			},
			"# Instead of:\nhtml = \"<div>\" + user_input + \"</div>\"\n\n# Use:\nfrom html import escape\nhtml = \"<div>\" + escape(user_input) + \"</div>\""

	case "CWE-798":
		return "Hard-coded credentials in source code can be easily discovered by attackers who gain access to the codebase.",
			[]string{
				"Store credentials in environment variables",
				"Use secure credential management systems (e.g., AWS Secrets Manager, HashiCorp Vault)",
				"Never commit credentials to version control",
				"Rotate credentials regularly",
			},
			"# Instead of:\npassword = \"hardcoded_password\"\n\n# Use:\nimport os\npassword = os.environ.get(\"DB_PASSWORD\")"

	case "CWE-327":
		return "Use of broken or weak cryptographic algorithms can allow attackers to compromise encrypted data.",
			[]string{
				"Use strong, modern encryption algorithms (AES-256, RSA-2048+)",
				"Avoid deprecated algorithms (MD5, SHA1, DES)",
				"Use established cryptographic libraries",
				"Keep cryptographic libraries up to date",
			},
			"# Instead of:\nimport md5\nhash = md5.new(data).hexdigest()\n\n# Use:\nimport hashlib\nhash = hashlib.sha256(data).hexdigest()"

	case "CWE-22":
		return "Path Traversal allows attackers to access files and directories outside the intended directory structure.",
			[]string{
				"Validate and sanitize file paths",
				"Use allowlists for permitted files/directories",
				"Avoid constructing file paths from user input",
				"Use secure path manipulation functions",
			},
			"# Instead of:\nfile_path = base_dir + user_input\n\n# Use:\nimport os\nfile_path = os.path.join(base_dir, os.path.basename(user_input))\nif not os.path.realpath(file_path).startswith(base_dir):\n    raise ValueError(\"Invalid path\")"

	case "CWE-502":
		return "Deserialization of untrusted data can lead to remote code execution and other attacks.",
			[]string{
				"Avoid deserializing untrusted data",
				"Use safe serialization formats (JSON instead of pickle)",
				"Implement integrity checks (HMAC signatures)",
				"Validate deserialized objects",
			},
			"# Instead of:\nimport pickle\ndata = pickle.loads(user_input)\n\n# Use:\nimport json\ndata = json.loads(user_input)"

	default:
		return fmt.Sprintf("This vulnerability (%s) represents a security weakness that should be addressed.", cweID),
			[]string{
				"Review the code for security best practices",
				"Validate and sanitize all inputs",
				"Apply the principle of least privilege",
				"Keep dependencies up to date",
			},
			"# Review the specific vulnerability and apply appropriate fixes"
	}
}

// EstimateCost estimates the cost of generating remediation (mock provider is free)
func (m *MockProvider) EstimateCost(req RemediationRequest) (float64, error) {
	return 0.0, nil
}

// Name returns the provider name
func (m *MockProvider) Name() string {
	return "mock"
}

// IsAvailable checks if the mock provider is available
func (m *MockProvider) IsAvailable() bool {
	return true
}

// Close cleans up resources
func (m *MockProvider) Close() error {
	if m.cache != nil {
		return m.cache.Close()
	}
	return nil
}
