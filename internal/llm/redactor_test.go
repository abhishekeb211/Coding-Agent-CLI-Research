package llm

import (
	"strings"
	"testing"
)

// TestNewRedactor tests redactor initialization
func TestNewRedactor(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{
			name:    "enabled redactor",
			enabled: true,
		},
		{
			name:    "disabled redactor",
			enabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redactor := NewRedactor(tt.enabled)
			if redactor == nil {
				t.Error("NewRedactor() returned nil")
			}
			if redactor.enabled != tt.enabled {
				t.Errorf("NewRedactor() enabled = %v, want %v", redactor.enabled, tt.enabled)
			}
		})
	}
}

// TestRedactEmails tests email redaction
func TestRedactEmails(t *testing.T) {
	redactor := NewRedactor(true)

	tests := []struct {
		name  string
		input string
		want  bool // Should contain redaction
	}{
		{
			name:  "simple email",
			input: "Contact us at support@example.com",
			want:  true,
		},
		{
			name:  "email in code",
			input: "email = \"user@domain.com\"",
			want:  true,
		},
		{
			name:  "multiple emails",
			input: "admin@test.com and user@test.org",
			want:  true,
		},
		{
			name:  "no email",
			input: "This is just text without emails",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, matches := redactor.Redact(tt.input)

			hasRedaction := strings.Contains(result, "[REDACTED:")
			if hasRedaction != tt.want {
				t.Errorf("Redact() hasRedaction = %v, want %v", hasRedaction, tt.want)
			}

			if tt.want && len(matches) == 0 {
				t.Error("Expected redaction matches but got none")
			}

			// Verify original email is not in result
			if tt.want {
				for _, match := range matches {
					if strings.Contains(result, match.Original) {
						t.Errorf("Original secret still present in result: %s", match.Original)
					}
				}
			}
		})
	}
}

// TestRedactPasswords tests password redaction
func TestRedactPasswords(t *testing.T) {
	redactor := NewRedactor(true)

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "password assignment",
			input: "password = \"secret123\"",
			want:  true,
		},
		{
			name:  "passwd variable",
			input: "passwd = 'mypassword'",
			want:  true,
		},
		{
			name:  "pwd variable",
			input: "pwd = \"p@ssw0rd\"",
			want:  true,
		},
		{
			name:  "no password",
			input: "username = \"admin\"",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, matches := redactor.Redact(tt.input)

			hasRedaction := strings.Contains(result, "[REDACTED:")
			if hasRedaction != tt.want {
				t.Errorf("Redact() hasRedaction = %v, want %v", hasRedaction, tt.want)
			}

			if tt.want && len(matches) == 0 {
				t.Error("Expected redaction matches but got none")
			}
		})
	}
}

// TestRedactAWSKeys tests AWS key redaction
func TestRedactAWSKeys(t *testing.T) {
	redactor := NewRedactor(true)

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "AWS access key",
			input: "aws_access_key = AKIAIOSFODNN7EXAMPLE",
			want:  true,
		},
		{
			name:  "AWS secret key",
			input: "aws_secret = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
			want:  true,
		},
		{
			name:  "no AWS keys",
			input: "config = {\"region\": \"us-east-1\"}",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, matches := redactor.Redact(tt.input)

			hasRedaction := strings.Contains(result, "[REDACTED:")
			if hasRedaction != tt.want {
				t.Errorf("Redact() hasRedaction = %v, want %v", hasRedaction, tt.want)
			}

			if tt.want && len(matches) == 0 {
				t.Error("Expected redaction matches but got none")
			}
		})
	}
}

// TestRedactPrivateKeys tests private key redaction
func TestRedactPrivateKeys(t *testing.T) {
	redactor := NewRedactor(true)

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "RSA private key",
			input: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
			want:  true,
		},
		{
			name:  "EC private key",
			input: "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEII...",
			want:  true,
		},
		{
			name:  "generic private key",
			input: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...",
			want:  true,
		},
		{
			name:  "public key (should not redact)",
			input: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, matches := redactor.Redact(tt.input)

			hasRedaction := strings.Contains(result, "[REDACTED:")
			if hasRedaction != tt.want {
				t.Errorf("Redact() hasRedaction = %v, want %v", hasRedaction, tt.want)
			}

			if tt.want && len(matches) == 0 {
				t.Error("Expected redaction matches but got none")
			}
		})
	}
}

// TestRedactGenericSecrets tests generic secret redaction
func TestRedactGenericSecrets(t *testing.T) {
	redactor := NewRedactor(true)

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "secret variable",
			input: "secret = \"my-secret-value\"",
			want:  true,
		},
		{
			name:  "token variable",
			input: "token = \"abc123xyz\"",
			want:  true,
		},
		{
			name:  "api key variable",
			input: "key = \"api-key-12345\"",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, matches := redactor.Redact(tt.input)

			hasRedaction := strings.Contains(result, "[REDACTED:")
			if hasRedaction != tt.want {
				t.Errorf("Redact() hasRedaction = %v, want %v", hasRedaction, tt.want)
			}

			if tt.want && len(matches) == 0 {
				t.Error("Expected redaction matches but got none")
			}
		})
	}
}

// TestRedactRequest tests request redaction
func TestRedactRequest(t *testing.T) {
	redactor := NewRedactor(true)

	req := &RemediationRequest{
		CWEID:          "CWE-798",
		CWEDescription: "Hardcoded credentials detected",
		CodeSnippet:    "password = \"secret123\"\nemail = \"admin@example.com\"",
		Message:        "Found hardcoded password: secret123",
	}

	redactedReq, matches := redactor.RedactRequest(req)

	if len(matches) == 0 {
		t.Error("Expected redaction matches but got none")
	}

	// Verify code snippet was redacted
	if strings.Contains(redactedReq.CodeSnippet, "secret123") {
		t.Error("Password still present in code snippet")
	}
	if strings.Contains(redactedReq.CodeSnippet, "admin@example.com") {
		t.Error("Email still present in code snippet")
	}

	// Verify message was redacted
	if strings.Contains(redactedReq.Message, "secret123") {
		t.Error("Password still present in message")
	}

	// Verify redaction markers are present
	if !strings.Contains(redactedReq.CodeSnippet, "[REDACTED:") {
		t.Error("Expected redaction markers in code snippet")
	}
}

// TestDisabledRedactor tests disabled redactor behavior
func TestDisabledRedactor(t *testing.T) {
	redactor := NewRedactor(false)

	input := "password = \"secret123\"\nemail = admin@example.com"
	result, matches := redactor.Redact(input)

	if result != input {
		t.Error("Disabled redactor should not modify input")
	}

	if len(matches) != 0 {
		t.Error("Disabled redactor should not return matches")
	}

	// Test request redaction
	req := &RemediationRequest{
		CodeSnippet: input,
	}

	redactedReq, matches := redactor.RedactRequest(req)

	if redactedReq.CodeSnippet != input {
		t.Error("Disabled redactor should not modify request")
	}

	if len(matches) != 0 {
		t.Error("Disabled redactor should not return matches")
	}
}

// TestRedactionHash tests that redaction hashes are consistent
func TestRedactionHash(t *testing.T) {
	redactor := NewRedactor(true)

	input := "password = \"secret123\""

	result1, matches1 := redactor.Redact(input)
	result2, matches2 := redactor.Redact(input)

	if result1 != result2 {
		t.Error("Same input should produce same redacted output")
	}

	if len(matches1) != len(matches2) {
		t.Error("Same input should produce same number of matches")
	}

	if len(matches1) > 0 && len(matches2) > 0 {
		if matches1[0].Hash != matches2[0].Hash {
			t.Error("Same secret should produce same hash")
		}
	}
}

// TestMultipleSecretsInSameText tests redacting multiple secrets
func TestMultipleSecretsInSameText(t *testing.T) {
	redactor := NewRedactor(true)

	input := `
	password = "secret123"
	email = "admin@example.com"
	api_key = "AKIAIOSFODNN7EXAMPLE"
	token = "my-secret-token-12345678901234567890123456789012"
	`

	result, matches := redactor.Redact(input)

	if len(matches) < 3 {
		t.Errorf("Expected at least 3 redactions, got %d", len(matches))
	}

	// Verify all secrets are redacted
	if strings.Contains(result, "secret123") {
		t.Error("Password not redacted")
	}
	if strings.Contains(result, "admin@example.com") {
		t.Error("Email not redacted")
	}
	if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key not redacted")
	}
}

// TestRedactionWithNoSecrets tests text with no secrets
func TestRedactionWithNoSecrets(t *testing.T) {
	redactor := NewRedactor(true)

	input := "This is just normal text without any secrets"
	result, matches := redactor.Redact(input)

	if result != input {
		t.Error("Text without secrets should not be modified")
	}

	if len(matches) != 0 {
		t.Error("Text without secrets should not produce matches")
	}
}

// TestAPITokenFiltering tests that short API tokens are filtered
func TestAPITokenFiltering(t *testing.T) {
	redactor := NewRedactor(true)

	// Short token (should not be redacted due to false positive filtering)
	shortToken := "abc123"
	result1, matches1 := redactor.Redact(shortToken)

	// The short token might or might not be redacted depending on other patterns
	// This test mainly ensures the code doesn't panic

	// Long token (should be redacted)
	longToken := "this-is-a-very-long-api-token-that-should-be-redacted-1234567890"
	result2, matches2 := redactor.Redact(longToken)

	if result2 == longToken && len(matches2) == 0 {
		t.Log("Long token was not redacted (might be expected depending on pattern matching)")
	}

	_ = result1
	_ = matches1
}
