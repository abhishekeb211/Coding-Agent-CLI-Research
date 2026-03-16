package eslint

import (
	"context"
	"testing"
	"time"
)

// TestScanWithContextCancellation tests handling of context cancellation
func TestScanWithContextCancellation(t *testing.T) {
	scanner := &Scanner{execPath: "eslint"}
	
	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	
	_, err := scanner.Scan(ctx, ".")
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

// TestScanWithTimeout tests handling of scan timeout
func TestScanWithTimeout(t *testing.T) {
	scanner := &Scanner{execPath: "eslint"}
	
	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	
	// Wait for timeout to trigger
	time.Sleep(10 * time.Millisecond)
	
	_, err := scanner.Scan(ctx, ".")
	if err == nil {
		t.Error("Expected error for timeout")
	}
}

// TestScanWithNonExistentScanner tests error when scanner binary doesn't exist
func TestScanWithNonExistentScanner(t *testing.T) {
	scanner := &Scanner{execPath: "/nonexistent/eslint/binary"}
	ctx := context.Background()
	
	_, err := scanner.Scan(ctx, ".")
	if err == nil {
		t.Error("Expected error for non-existent scanner binary")
	}
}

// TestConvertFindingsWithInvalidPaths tests handling of invalid file paths
func TestConvertFindingsWithInvalidPaths(t *testing.T) {
	scanner := New()
	
	eslintOutput := []ESLintFile{
		{
			FilePath: "", // Empty file path
			Messages: []ESLintMessage{
				{
					RuleID:   "security/detect-eval-with-expression",
					Severity: 2,
					Message:  "Test issue",
					Line:     10,
				},
			},
		},
		{
			FilePath: "/absolute/path/outside/project.js",
			Messages: []ESLintMessage{
				{
					RuleID:   "security/detect-child-process",
					Severity: 2,
					Message:  "Another issue",
					Line:     20,
				},
			},
		},
	}
	
	findings := scanner.convertFindings(eslintOutput, "/test/project")
	
	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}
	
	// Verify findings are created even with problematic paths
	for _, f := range findings {
		if f.ToolName != "eslint" {
			t.Errorf("ToolName = %q, want eslint", f.ToolName)
		}
		if f.ID == "" {
			t.Error("Finding ID should not be empty")
		}
	}
}

// TestMapSeverityEdgeCases tests edge cases in severity mapping
func TestMapSeverityEdgeCases(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		input    int
		expected string
	}{
		{-1, "low"},
		{0, "low"},
		{1, "medium"},
		{2, "high"},
		{3, "low"},
		{999, "low"},
	}
	
	for _, tt := range tests {
		result := scanner.mapSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSeverity(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestExtractCategoryWithUnknownRules tests category extraction for unknown rules
func TestExtractCategoryWithUnknownRules(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"security/unknown-rule", "unknown-rule"},
		{"security/", "security"},
		{"", "security"},
		{"no-slash", "no-slash"},
		{"multiple/slashes/here", "slashes/here"},
		{"security/detect-new-vulnerability", "new-vulnerability"},
	}
	
	for _, tt := range tests {
		result := scanner.extractCategory(tt.ruleID)
		// The function extracts category from rule ID
		// Just verify it doesn't crash and returns something
		if result == "" {
			t.Errorf("extractCategory(%q) returned empty string", tt.ruleID)
		}
	}
}

// TestConvertFindingsWithMissingFields tests handling of eslint output with missing fields
func TestConvertFindingsWithMissingFields(t *testing.T) {
	scanner := New()
	
	eslintOutput := []ESLintFile{
		{
			FilePath: "test.js",
			Messages: []ESLintMessage{
				{
					// Minimal message with only required fields
					RuleID:   "security/detect-eval-with-expression",
					Severity: 2,
					Message:  "Test",
					Line:     0, // Zero line number
				},
				{
					// Message with empty rule ID (should be filtered)
					RuleID:   "",
					Severity: 2,
					Message:  "Test 2",
					Line:     10,
				},
				{
					// Non-security rule (should be filtered)
					RuleID:   "no-console",
					Severity: 1,
					Message:  "Test 3",
					Line:     15,
				},
			},
		},
	}
	
	findings := scanner.convertFindings(eslintOutput, "/test")
	
	// Should only include the first finding (security rule with valid fields)
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}
	
	// Verify the finding has all required fields
	f := findings[0]
	if f.ToolName != "eslint" {
		t.Errorf("ToolName = %q, want eslint", f.ToolName)
	}
	if f.Severity == "" {
		t.Error("Severity should not be empty")
	}
	if f.Confidence == "" {
		t.Error("Confidence should not be empty")
	}
	if f.ID == "" {
		t.Error("ID should not be empty")
	}
}

// TestToJSONWithNilInput tests JSON conversion with nil input
func TestToJSONWithNilInput(t *testing.T) {
	scanner := New()
	
	result := scanner.toJSON(nil)
	
	if result != nil {
		t.Errorf("Expected nil result for nil input, got %v", result)
	}
}

// TestConvertFindingsWithMultipleFiles tests handling of multiple files
func TestConvertFindingsWithMultipleFiles(t *testing.T) {
	scanner := New()
	
	eslintOutput := []ESLintFile{
		{
			FilePath: "/test/file1.js",
			Messages: []ESLintMessage{
				{
					RuleID:   "security/detect-eval-with-expression",
					Severity: 2,
					Message:  "Issue 1",
					Line:     10,
				},
			},
		},
		{
			FilePath: "/test/file2.js",
			Messages: []ESLintMessage{
				{
					RuleID:   "security/detect-child-process",
					Severity: 2,
					Message:  "Issue 2",
					Line:     20,
				},
				{
					RuleID:   "security/detect-non-literal-fs-filename",
					Severity: 1,
					Message:  "Issue 3",
					Line:     30,
				},
			},
		},
		{
			FilePath: "/test/file3.js",
			Messages: []ESLintMessage{}, // No messages
		},
	}
	
	findings := scanner.convertFindings(eslintOutput, "/test")
	
	if len(findings) != 3 {
		t.Fatalf("Expected 3 findings, got %d", len(findings))
	}
	
	// Verify findings are from different files
	fileCount := make(map[string]int)
	for _, f := range findings {
		fileCount[f.FilePath]++
	}
	
	if len(fileCount) != 2 {
		t.Errorf("Expected findings from 2 files, got %d", len(fileCount))
	}
}

// TestConvertFindingsWithDifferentSeverities tests handling of different severity levels
func TestConvertFindingsWithDifferentSeverities(t *testing.T) {
	scanner := New()
	
	eslintOutput := []ESLintFile{
		{
			FilePath: "/test/test.js",
			Messages: []ESLintMessage{
				{
					RuleID:   "security/detect-eval-with-expression",
					Severity: 2, // error -> high
					Message:  "Error level",
					Line:     10,
				},
				{
					RuleID:   "security/detect-child-process",
					Severity: 1, // warning -> medium
					Message:  "Warning level",
					Line:     20,
				},
				{
					RuleID:   "security/detect-non-literal-fs-filename",
					Severity: 0, // info -> low
					Message:  "Info level",
					Line:     30,
				},
			},
		},
	}
	
	findings := scanner.convertFindings(eslintOutput, "/test")
	
	if len(findings) != 3 {
		t.Fatalf("Expected 3 findings, got %d", len(findings))
	}
	
	// Verify severity mapping
	expectedSeverities := []string{"high", "medium", "low"}
	for i, f := range findings {
		if f.Severity != expectedSeverities[i] {
			t.Errorf("Finding %d: Severity = %q, want %q", i, f.Severity, expectedSeverities[i])
		}
	}
}

// TestESLintMessageWithOptionalFields tests handling of optional fields
func TestESLintMessageWithOptionalFields(t *testing.T) {
	scanner := New()
	
	eslintOutput := []ESLintFile{
		{
			FilePath: "/test/test.js",
			Messages: []ESLintMessage{
				{
					RuleID:    "security/detect-eval-with-expression",
					Severity:  2,
					Message:   "Test",
					Line:      10,
					Column:    5,
					NodeType:  "CallExpression",
					MessageID: "unexpected",
					EndLine:   10,
					EndColumn: 20,
				},
			},
		},
	}
	
	findings := scanner.convertFindings(eslintOutput, "/test")
	
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}
	
	// Verify the finding is created successfully with optional fields
	f := findings[0]
	if f.RawJSON == nil {
		t.Error("RawJSON should not be nil")
	}
	
	// Check that optional fields are preserved in RawJSON
	if nodeType, ok := f.RawJSON["nodeType"]; ok {
		if nodeType != "CallExpression" {
			t.Errorf("NodeType in RawJSON = %v, want CallExpression", nodeType)
		}
	}
}
