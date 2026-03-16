package llm

import (
	"fmt"
	"strings"
)

// PromptTemplate handles prompt generation
type PromptTemplate struct {
	maxTokens int
}

// NewPromptTemplate creates a new prompt template
func NewPromptTemplate(maxTokens int) *PromptTemplate {
	return &PromptTemplate{
		maxTokens: maxTokens,
	}
}

// GeneratePrompt creates a prompt for remediation guidance
func (pt *PromptTemplate) GeneratePrompt(req RemediationRequest) string {
	// Truncate code snippet if too long
	codeSnippet := pt.truncateCode(req.CodeSnippet, 500)

	prompt := fmt.Sprintf(`You are a security analyst. Analyze this vulnerability and provide remediation guidance.

CWE: %s
Description: %s
Severity: %s
File: %s:%d
Rule: %s

Code:
%s

Message: %s

Provide:
1. Brief explanation (2-3 sentences)
2. Remediation steps (3-5 bullet points)
3. Example fix (code snippet if applicable)

Keep your response concise and actionable.`,
		req.CWEID,
		pt.truncateText(req.CWEDescription, 200),
		req.Severity,
		req.FilePath,
		req.LineNumber,
		req.RuleID,
		codeSnippet,
		pt.truncateText(req.Message, 150),
	)

	return prompt
}

// truncateCode truncates code to a maximum length
func (pt *PromptTemplate) truncateCode(code string, maxChars int) string {
	if len(code) <= maxChars {
		return code
	}

	// Try to truncate at a newline
	truncated := code[:maxChars]
	lastNewline := strings.LastIndex(truncated, "\n")
	if lastNewline > maxChars/2 {
		truncated = code[:lastNewline]
	}

	return truncated + "\n... [truncated]"
}

// truncateText truncates text to a maximum length
func (pt *PromptTemplate) truncateText(text string, maxChars int) string {
	if len(text) <= maxChars {
		return text
	}

	// Try to truncate at a word boundary
	truncated := text[:maxChars]
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > maxChars/2 {
		truncated = text[:lastSpace]
	}

	return truncated + "..."
}

// ParseResponse parses the LLM response into structured format
func (pt *PromptTemplate) ParseResponse(response string) *RemediationResponse {
	result := &RemediationResponse{
		RemediationSteps: []string{},
		Confidence:       0.8, // Default confidence
	}

	lines := strings.Split(response, "\n")
	var currentSection string
	var explanationLines []string
	var steps []string
	var exampleLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)
		
		// Detect section headers
		if strings.Contains(lower, "explanation:") {
			currentSection = "explanation"
			continue
		} else if strings.Contains(lower, "remediation") || strings.Contains(lower, "steps") {
			currentSection = "steps"
			continue
		} else if strings.Contains(lower, "example") && strings.Contains(lower, "fix") {
			currentSection = "example"
			continue
		}

		// Add content to current section
		switch currentSection {
		case "explanation":
			explanationLines = append(explanationLines, line)
		case "steps":
			// Extract bullet points
			if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "•") {
				line = strings.TrimPrefix(line, "-")
				line = strings.TrimPrefix(line, "*")
				line = strings.TrimPrefix(line, "•")
				line = strings.TrimSpace(line)
				if line != "" {
					steps = append(steps, line)
				}
			} else if len(line) > 2 && line[0] >= '0' && line[0] <= '9' && line[1] == '.' {
				// Numbered list like "1. Step one"
				line = line[2:]
				line = strings.TrimSpace(line)
				if line != "" {
					steps = append(steps, line)
				}
			} else if line != "" {
				// Plain text step
				steps = append(steps, line)
			}
		case "example":
			exampleLines = append(exampleLines, line)
		default:
			// No section detected yet, treat as explanation
			explanationLines = append(explanationLines, line)
		}
	}

	result.Explanation = strings.TrimSpace(strings.Join(explanationLines, " "))
	result.RemediationSteps = steps
	result.ExampleFix = strings.TrimSpace(strings.Join(exampleLines, "\n"))

	// If parsing failed, use the whole response as explanation
	if result.Explanation == "" && len(steps) == 0 && result.ExampleFix == "" {
		result.Explanation = strings.TrimSpace(response)
	}

	return result
}
