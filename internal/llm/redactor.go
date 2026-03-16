package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// SecretPattern represents a pattern for detecting secrets
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

var secretPatterns = []SecretPattern{
	{
		Name:    "AWS Access Key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		Name:    "AWS Secret Key",
		Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]`),
	},
	{
		Name:    "API Token",
		Pattern: regexp.MustCompile(`[a-zA-Z0-9_-]{32,}`),
	},
	{
		Name:    "Email Address",
		Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	},
	{
		Name:    "Private Key",
		Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
	},
	{
		Name:    "Password in Code",
		Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]`),
	},
	{
		Name:    "Generic Secret",
		Pattern: regexp.MustCompile(`(?i)(secret|token|key)\s*=\s*['\"][^'\"]+['\"]`),
	},
	{
		Name:    "Standalone Password Value",
		Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token):\s*[a-zA-Z0-9@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]+`),
	},
}

// Redactor handles secret redaction
type Redactor struct {
	patterns []SecretPattern
	enabled  bool
}

// NewRedactor creates a new redactor
func NewRedactor(enabled bool) *Redactor {
	return &Redactor{
		patterns: secretPatterns,
		enabled:  enabled,
	}
}

// RedactedMatch represents a redacted secret
type RedactedMatch struct {
	Original string
	Redacted string
	Pattern  string
	Hash     string
}

// Redact redacts secrets from the input text
func (r *Redactor) Redact(text string) (string, []RedactedMatch) {
	if !r.enabled {
		return text, nil
	}

	matches := []RedactedMatch{}
	result := text

	for _, pattern := range r.patterns {
		found := pattern.Pattern.FindAllString(result, -1)
		for _, match := range found {
			// Skip very short matches for API tokens to reduce false positives
			if pattern.Name == "API Token" && len(match) < 40 {
				continue
			}

			// Create hash of the secret
			hash := sha256.Sum256([]byte(match))
			hashStr := hex.EncodeToString(hash[:])[:16]

			// Create redacted version
			redacted := "[REDACTED:" + hashStr + "]"

			matches = append(matches, RedactedMatch{
				Original: match,
				Redacted: redacted,
				Pattern:  pattern.Name,
				Hash:     hashStr,
			})

			// Replace in result
			result = strings.ReplaceAll(result, match, redacted)
		}
	}

	return result, matches
}

// RedactRequest redacts secrets from a remediation request
func (r *Redactor) RedactRequest(req *RemediationRequest) (*RemediationRequest, []RedactedMatch) {
	if !r.enabled {
		return req, nil
	}

	allMatches := []RedactedMatch{}

	// Redact code snippet
	redactedCode, matches := r.Redact(req.CodeSnippet)
	req.CodeSnippet = redactedCode
	allMatches = append(allMatches, matches...)

	// Redact message
	redactedMsg, matches := r.Redact(req.Message)
	req.Message = redactedMsg
	allMatches = append(allMatches, matches...)

	// Redact CWE description (less likely but possible)
	redactedDesc, matches := r.Redact(req.CWEDescription)
	req.CWEDescription = redactedDesc
	allMatches = append(allMatches, matches...)

	return req, allMatches
}
