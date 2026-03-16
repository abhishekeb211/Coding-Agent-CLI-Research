package llm

import (
	"strings"
	"testing"
)

// TestNewPromptTemplate tests prompt template initialization
func TestNewPromptTemplate(t *testing.T) {
	tests := []struct {
		name      string
		maxTokens int
	}{
		{
			name:      "standard max tokens",
			maxTokens: 1024,
		},
		{
			name:      "large max tokens",
			maxTokens: 4096,
		},
		{
			name:      "small max tokens",
			maxTokens: 256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := NewPromptTemplate(tt.maxTokens)
			if pt == nil {
				t.Error("NewPromptTemplate() returned nil")
			}
			if pt.maxTokens != tt.maxTokens {
				t.Errorf("NewPromptTemplate() maxTokens = %v, want %v", pt.maxTokens, tt.maxTokens)
			}
		})
	}
}

// TestGeneratePrompt tests prompt generation for different finding types
func TestGeneratePrompt(t *testing.T) {
	pt := NewPromptTemplate(1024)

	tests := []struct {
		name string
		req  RemediationRequest
	}{
		{
			name: "SQL injection",
			req: RemediationRequest{
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				Severity:       "high",
				FilePath:       "/test/file.py",
				LineNumber:     42,
				CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_id",
				Message:        "SQL injection vulnerability detected",
				RuleID:         "B608",
			},
		},
		{
			name: "XSS vulnerability",
			req: RemediationRequest{
				CWEID:          "CWE-79",
				CWEDescription: "Cross-site Scripting",
				Severity:       "medium",
				FilePath:       "/test/file.js",
				LineNumber:     10,
				CodeSnippet:    "document.write(userInput)",
				Message:        "XSS vulnerability detected",
				RuleID:         "xss-check",
			},
		},
		{
			name: "hardcoded credentials",
			req: RemediationRequest{
				CWEID:          "CWE-798",
				CWEDescription: "Use of Hard-coded Credentials",
				Severity:       "high",
				FilePath:       "/test/config.py",
				LineNumber:     5,
				CodeSnippet:    "password = \"admin123\"",
				Message:        "Hardcoded password detected",
				RuleID:         "B105",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt := pt.GeneratePrompt(tt.req)

			if prompt == "" {
				t.Error("GeneratePrompt() returned empty prompt")
			}

			// Verify prompt contains key information
			if !strings.Contains(prompt, tt.req.CWEID) {
				t.Error("Prompt should contain CWE ID")
			}
			if !strings.Contains(prompt, tt.req.FilePath) {
				t.Error("Prompt should contain file path")
			}
			if !strings.Contains(prompt, tt.req.Severity) {
				t.Error("Prompt should contain severity")
			}
		})
	}
}

// TestTruncateCode tests code truncation
func TestTruncateCode(t *testing.T) {
	pt := NewPromptTemplate(1024)

	tests := []struct {
		name     string
		code     string
		maxChars int
		wantLen  int // Approximate expected length
	}{
		{
			name:     "short code",
			code:     "def hello():\n    print('hello')",
			maxChars: 100,
			wantLen:  35,
		},
		{
			name:     "long code",
			code:     strings.Repeat("def function():\n    pass\n", 100),
			maxChars: 100,
			wantLen:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pt.truncateCode(tt.code, tt.maxChars)

			if len(result) > tt.maxChars+20 { // Allow some margin for truncation marker
				t.Errorf("truncateCode() length = %v, want <= %v", len(result), tt.maxChars+20)
			}

			// Long code should have truncation marker
			if len(tt.code) > tt.maxChars {
				if !strings.Contains(result, "[truncated]") {
					t.Error("Long code should have truncation marker")
				}
			}
		})
	}
}

// TestTruncateText tests text truncation
func TestTruncateText(t *testing.T) {
	pt := NewPromptTemplate(1024)

	tests := []struct {
		name     string
		text     string
		maxChars int
	}{
		{
			name:     "short text",
			text:     "This is a short message",
			maxChars: 100,
		},
		{
			name:     "long text",
			text:     strings.Repeat("This is a very long message that needs truncation. ", 20),
			maxChars: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pt.truncateText(tt.text, tt.maxChars)

			if len(result) > tt.maxChars+5 { // Allow margin for "..."
				t.Errorf("truncateText() length = %v, want <= %v", len(result), tt.maxChars+5)
			}

			// Long text should have ellipsis
			if len(tt.text) > tt.maxChars {
				if !strings.HasSuffix(result, "...") {
					t.Error("Long text should have ellipsis")
				}
			}
		})
	}
}

// TestParseResponse tests response parsing
func TestParseResponse(t *testing.T) {
	pt := NewPromptTemplate(1024)

	tests := []struct {
		name     string
		response string
		wantExp  bool // Should have explanation
		wantSteps bool // Should have steps
		wantFix  bool // Should have example fix
	}{
		{
			name: "complete response",
			response: `Explanation:
This is a SQL injection vulnerability where user input is directly concatenated into SQL queries.

Remediation Steps:
1. Use parameterized queries
2. Validate and sanitize input
3. Use an ORM framework

Example Fix:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))`,
			wantExp:   true,
			wantSteps: true,
			wantFix:   true,
		},
		{
			name: "explanation only",
			response: `This is a SQL injection vulnerability where user input is directly concatenated into SQL queries.`,
			wantExp:   true,
			wantSteps: false,
			wantFix:   false,
		},
		{
			name: "with steps",
			response: `Explanation:
SQL injection vulnerability detected.

Steps to fix:
- Use parameterized queries
- Validate input
- Use prepared statements`,
			wantExp:   true,
			wantSteps: true,
			wantFix:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pt.ParseResponse(tt.response)

			if result == nil {
				t.Fatal("ParseResponse() returned nil")
			}

			if tt.wantExp && result.Explanation == "" {
				t.Error("Expected explanation but got empty")
			}

			if tt.wantSteps && len(result.RemediationSteps) == 0 {
				t.Error("Expected remediation steps but got none")
			}

			if tt.wantFix && result.ExampleFix == "" {
				t.Error("Expected example fix but got empty")
			}

			// Confidence should be set
			if result.Confidence == 0 {
				t.Error("Confidence should be set")
			}
		})
	}
}

// TestPromptLength tests that prompts don't exceed reasonable length
func TestPromptLength(t *testing.T) {
	pt := NewPromptTemplate(1024)

	// Create request with very long code
	longCode := strings.Repeat("def function():\n    pass\n", 1000)

	req := RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		Severity:       "high",
		FilePath:       "/test/file.py",
		LineNumber:     42,
		CodeSnippet:    longCode,
		Message:        "SQL injection vulnerability detected",
		RuleID:         "B608",
	}

	prompt := pt.GeneratePrompt(req)

	// Prompt should be reasonable length (not thousands of lines)
	if len(prompt) > 2000 {
		t.Errorf("Prompt too long: %d characters", len(prompt))
	}
}

// TestParseResponseWithBulletPoints tests parsing different bullet point styles
func TestParseResponseWithBulletPoints(t *testing.T) {
	pt := NewPromptTemplate(1024)

	tests := []struct {
		name     string
		response string
		wantSteps int
	}{
		{
			name: "dash bullets",
			response: `Steps:
- Step one
- Step two
- Step three`,
			wantSteps: 3,
		},
		{
			name: "asterisk bullets",
			response: `Steps:
* Step one
* Step two`,
			wantSteps: 2,
		},
		{
			name: "numbered list",
			response: `Steps:
1. Step one
2. Step two
3. Step three`,
			wantSteps: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pt.ParseResponse(tt.response)

			if len(result.RemediationSteps) != tt.wantSteps {
				t.Errorf("ParseResponse() steps = %v, want %v", len(result.RemediationSteps), tt.wantSteps)
			}

			// Verify steps don't contain bullet points or numbers
			for _, step := range result.RemediationSteps {
				if strings.HasPrefix(step, "-") || strings.HasPrefix(step, "*") {
					t.Errorf("Step should not start with bullet point: %s", step)
				}
				if len(step) > 2 && step[1] == '.' {
					t.Errorf("Step should not start with number: %s", step)
				}
			}
		})
	}
}

// TestGeneratePromptWithEmptyFields tests prompt generation with missing fields
func TestGeneratePromptWithEmptyFields(t *testing.T) {
	pt := NewPromptTemplate(1024)

	req := RemediationRequest{
		CWEID:    "CWE-89",
		Severity: "high",
		// Other fields empty
	}

	prompt := pt.GeneratePrompt(req)

	if prompt == "" {
		t.Error("GeneratePrompt() should not return empty prompt even with minimal fields")
	}

	// Should still contain CWE ID
	if !strings.Contains(prompt, "CWE-89") {
		t.Error("Prompt should contain CWE ID")
	}
}

// TestTruncateCodeAtNewline tests that code truncation prefers newlines
func TestTruncateCodeAtNewline(t *testing.T) {
	pt := NewPromptTemplate(1024)

	code := "line1\nline2\nline3\nline4\nline5"
	maxChars := 15 // Should fit "line1\nline2\n"

	result := pt.truncateCode(code, maxChars)

	// Should truncate at newline if possible
	if !strings.Contains(result, "line1") {
		t.Error("Should contain first line")
	}

	// Should have truncation marker
	if !strings.Contains(result, "[truncated]") {
		t.Error("Should have truncation marker")
	}
}

// TestTruncateTextAtWordBoundary tests that text truncation prefers word boundaries
func TestTruncateTextAtWordBoundary(t *testing.T) {
	pt := NewPromptTemplate(1024)

	text := "This is a very long message that needs to be truncated at a word boundary"
	maxChars := 30

	result := pt.truncateText(text, maxChars)

	// Should not cut in middle of word
	words := strings.Split(result, " ")
	lastWord := words[len(words)-1]

	// Last word should not be "..." alone and should be complete
	if lastWord != "..." && !strings.HasSuffix(lastWord, "...") {
		t.Error("Truncation should preserve word boundaries")
	}
}

// TestParseEmptyResponse tests parsing empty response
func TestParseEmptyResponse(t *testing.T) {
	pt := NewPromptTemplate(1024)

	result := pt.ParseResponse("")

	if result == nil {
		t.Fatal("ParseResponse() should not return nil for empty response")
	}

	if result.Explanation != "" {
		t.Error("Empty response should have empty explanation")
	}

	if len(result.RemediationSteps) != 0 {
		t.Error("Empty response should have no steps")
	}
}
