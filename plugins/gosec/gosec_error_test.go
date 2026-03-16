package gosec

import (
	"context"
	"testing"
	"time"
)

// TestScanWithContextCancellation tests handling of context cancellation
func TestScanWithContextCancellation(t *testing.T) {
	scanner := &Scanner{execPath: "gosec"}
	
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
	scanner := &Scanner{execPath: "gosec"}
	
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

// TestScanWithMalformedJSON tests handling of malformed JSON output
func TestScanWithMalformedJSON(t *testing.T) {
	scanner := New()
	
	// This test documents expected behavior when gosec returns invalid JSON
	// In practice, this would require mocking exec.Command
	// The actual implementation handles this in the json.Unmarshal error check
	
	// Test that empty/invalid JSON is handled
	gosecOutput := GosecOutput{}
	findings := scanner.convertFindings(gosecOutput, "/test")
	
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty output, got %d", len(findings))
	}
}

// TestScanWithNonExistentScanner tests error when scanner binary doesn't exist
func TestScanWithNonExistentScanner(t *testing.T) {
	scanner := &Scanner{execPath: "/nonexistent/gosec/binary"}
	ctx := context.Background()
	
	_, err := scanner.Scan(ctx, ".")
	if err == nil {
		t.Error("Expected error for non-existent scanner binary")
	}
}

// TestConvertFindingsWithInvalidPaths tests handling of invalid file paths
func TestConvertFindingsWithInvalidPaths(t *testing.T) {
	scanner := New()
	
	gosecOutput := GosecOutput{
		Issues: []GosecIssue{
			{
				Severity:   "HIGH",
				Confidence: "HIGH",
				RuleID:     "G101",
				Details:    "Test issue",
				File:       "", // Empty file path
				Line:       "10",
			},
			{
				Severity:   "MEDIUM",
				Confidence: "MEDIUM",
				RuleID:     "G204",
				Details:    "Another issue",
				File:       "/absolute/path/outside/project.go",
				Line:       "20",
			},
		},
	}
	
	findings := scanner.convertFindings(gosecOutput, "/test/project")
	
	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}
	
	// Verify findings are created even with problematic paths
	for _, f := range findings {
		if f.ToolName != "gosec" {
			t.Errorf("ToolName = %q, want gosec", f.ToolName)
		}
		if f.ID == "" {
			t.Error("Finding ID should not be empty")
		}
	}
}

// TestParseLineNumberEdgeCases tests edge cases in line number parsing
func TestParseLineNumberEdgeCases(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		input    string
		expected int
	}{
		{"0", 0},
		{"1", 1},
		{"999999", 999999},
		{"10-", 10},
		{"-20", 0},
		{"abc-def", 0},
		{"  15  ", 15},
		{"10-20-30", 10}, // Multiple dashes
	}
	
	for _, tt := range tests {
		result := scanner.parseLineNumber(tt.input)
		if result != tt.expected {
			t.Errorf("parseLineNumber(%q) = %d, want %d", tt.input, result, tt.expected)
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
		{"G999", "security"},
		{"UNKNOWN", "security"},
		{"", "security"},
		{"G", "security"},
		{"123", "security"},
		{"NewRule", "security"},
	}
	
	for _, tt := range tests {
		result := scanner.extractCategory(tt.ruleID)
		if result != tt.expected {
			t.Errorf("extractCategory(%q) = %q, want %q", tt.ruleID, result, tt.expected)
		}
	}
}

// TestConvertFindingsWithMissingFields tests handling of gosec output with missing fields
func TestConvertFindingsWithMissingFields(t *testing.T) {
	scanner := New()
	
	gosecOutput := GosecOutput{
		Issues: []GosecIssue{
			{
				// Minimal issue with only required fields
				RuleID:  "G101",
				Details: "Test",
				File:    "test.go",
			},
			{
				// Issue with empty severity/confidence
				Severity:   "",
				Confidence: "",
				RuleID:     "G102",
				Details:    "Test 2",
				File:       "test2.go",
				Line:       "",
			},
		},
	}
	
	findings := scanner.convertFindings(gosecOutput, "/test")
	
	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}
	
	// Verify defaults are applied
	for _, f := range findings {
		if f.Severity == "" {
			t.Error("Severity should have default value")
		}
		if f.Confidence == "" {
			t.Error("Confidence should have default value")
		}
		if f.LineNumber < 0 {
			t.Error("LineNumber should not be negative")
		}
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

// TestMapSeverityWithMixedCase tests severity mapping with various case combinations
func TestMapSeverityWithMixedCase(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		input    string
		expected string
	}{
		{"High", "high"},
		{"HiGh", "high"},
		{"MEDIUM", "medium"},
		{"Medium", "medium"},
		{"MeDiUm", "medium"},
		{"Low", "low"},
		{"LOW", "low"},
		{"LoW", "low"},
	}
	
	for _, tt := range tests {
		result := scanner.mapSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
