package gosec

import (
	"context"
	"encoding/json"
	"testing"
)

// TestName tests plugin name
func TestName(t *testing.T) {
	scanner := New()
	if scanner.Name() != "gosec" {
		t.Errorf("Name() = %v, want gosec", scanner.Name())
	}
}

// TestIsAvailable tests availability check
func TestIsAvailable(t *testing.T) {
	scanner := New()
	// Just ensure it doesn't panic
	_ = scanner.IsAvailable()
}

// TestScanWithInvalidPath tests error handling for invalid paths
func TestScanWithInvalidPath(t *testing.T) {
	scanner := &Scanner{execPath: "gosec"}
	ctx := context.Background()

	_, err := scanner.Scan(ctx, "/non/existent/path")
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
}

// TestMapSeverity tests severity mapping
func TestMapSeverity(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		input    string
		expected string
	}{
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"UNKNOWN", "medium"}, // default
		{"", "medium"},        // default
	}

	for _, tt := range tests {
		result := scanner.mapSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestMapConfidence tests confidence mapping
func TestMapConfidence(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		input    string
		expected string
	}{
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"UNKNOWN", "medium"}, // default
		{"", "medium"},        // default
	}

	for _, tt := range tests {
		result := scanner.mapConfidence(tt.input)
		if result != tt.expected {
			t.Errorf("mapConfidence(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestParseLineNumber tests line number parsing
func TestParseLineNumber(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		input    string
		expected int
	}{
		{"10", 10},
		{"42", 42},
		{"10-15", 10}, // range, should return start
		{"100-200", 100},
		{"", 0},       // empty
		{"invalid", 0}, // invalid
	}

	for _, tt := range tests {
		result := scanner.parseLineNumber(tt.input)
		if result != tt.expected {
			t.Errorf("parseLineNumber(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

// TestExtractCategory tests category extraction from rule IDs
func TestExtractCategory(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"G101", "credentials"},
		{"G102", "network"},
		{"G103", "unsafe"},
		{"G104", "errors"},
		{"G201", "sql-injection"},
		{"G204", "command-injection"},
		{"G304", "path-traversal"},
		{"G401", "weak-crypto"},
		{"G404", "weak-random"},
		{"G601", "implicit-aliasing"},
		{"G999", "security"}, // unknown rule
		{"", "security"},     // empty
	}

	for _, tt := range tests {
		result := scanner.extractCategory(tt.ruleID)
		if result != tt.expected {
			t.Errorf("extractCategory(%q) = %q, want %q", tt.ruleID, result, tt.expected)
		}
	}
}

// TestConvertFindings tests conversion of gosec output to RawFinding format
func TestConvertFindings(t *testing.T) {
	scanner := New()
	
	gosecOutput := GosecOutput{
		Issues: []GosecIssue{
			{
				Severity:   "HIGH",
				Confidence: "HIGH",
				RuleID:     "G101",
				Details:    "Potential hardcoded credentials",
				File:       "/test/path/main.go",
				Code:       "password := \"secret\"",
				Line:       "10",
				Column:     "5",
			},
			{
				Severity:   "MEDIUM",
				Confidence: "MEDIUM",
				RuleID:     "G204",
				Details:    "Subprocess launched with variable",
				File:       "/test/path/cmd.go",
				Code:       "exec.Command(userInput)",
				Line:       "25-30",
				Column:     "10",
			},
		},
		Stats: GosecStats{
			Files: 2,
			Lines: 100,
			Found: 2,
		},
	}

	findings := scanner.convertFindings(gosecOutput, "/test/path")

	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}

	// Check first finding
	f1 := findings[0]
	if f1.ToolName != "gosec" {
		t.Errorf("Finding 1: ToolName = %q, want gosec", f1.ToolName)
	}
	if f1.RuleID != "G101" {
		t.Errorf("Finding 1: RuleID = %q, want G101", f1.RuleID)
	}
	if f1.Severity != "high" {
		t.Errorf("Finding 1: Severity = %q, want high", f1.Severity)
	}
	if f1.Confidence != "high" {
		t.Errorf("Finding 1: Confidence = %q, want high", f1.Confidence)
	}
	if f1.LineNumber != 10 {
		t.Errorf("Finding 1: LineNumber = %d, want 10", f1.LineNumber)
	}
	if f1.Category != "credentials" {
		t.Errorf("Finding 1: Category = %q, want credentials", f1.Category)
	}

	// Check second finding
	f2 := findings[1]
	if f2.RuleID != "G204" {
		t.Errorf("Finding 2: RuleID = %q, want G204", f2.RuleID)
	}
	if f2.Severity != "medium" {
		t.Errorf("Finding 2: Severity = %q, want medium", f2.Severity)
	}
	if f2.LineNumber != 25 {
		t.Errorf("Finding 2: LineNumber = %d, want 25", f2.LineNumber)
	}
	if f2.Category != "command-injection" {
		t.Errorf("Finding 2: Category = %q, want command-injection", f2.Category)
	}
}

// TestToJSON tests JSON conversion
func TestToJSON(t *testing.T) {
	scanner := New()
	
	issue := GosecIssue{
		Severity:   "HIGH",
		Confidence: "HIGH",
		RuleID:     "G101",
		Details:    "Test issue",
		File:       "test.go",
		Line:       "10",
	}

	result := scanner.toJSON(issue)
	
	if result == nil {
		t.Fatal("toJSON returned nil")
	}

	// Verify some fields are present
	if result["severity"] != "HIGH" {
		t.Errorf("JSON severity = %v, want HIGH", result["severity"])
	}
	if result["rule_id"] != "G101" {
		t.Errorf("JSON rule_id = %v, want G101", result["rule_id"])
	}
}

// TestGosecOutputParsing tests parsing of gosec JSON output
func TestGosecOutputParsing(t *testing.T) {
	jsonOutput := `{
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "HIGH",
				"rule_id": "G101",
				"details": "Potential hardcoded credentials",
				"file": "/test/main.go",
				"code": "password := \"secret\"",
				"line": "10",
				"column": "5"
			}
		],
		"Stats": {
			"files": 1,
			"lines": 50,
			"found": 1
		}
	}`

	var output GosecOutput
	err := json.Unmarshal([]byte(jsonOutput), &output)
	if err != nil {
		t.Fatalf("Failed to parse gosec JSON: %v", err)
	}

	if len(output.Issues) != 1 {
		t.Errorf("Expected 1 issue, got %d", len(output.Issues))
	}

	issue := output.Issues[0]
	if issue.RuleID != "G101" {
		t.Errorf("RuleID = %q, want G101", issue.RuleID)
	}
	if issue.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", issue.Severity)
	}

	if output.Stats.Files != 1 {
		t.Errorf("Stats.Files = %d, want 1", output.Stats.Files)
	}
}

// TestEmptyGosecOutput tests handling of empty gosec output
func TestEmptyGosecOutput(t *testing.T) {
	scanner := New()
	
	gosecOutput := GosecOutput{
		Issues: []GosecIssue{},
		Stats: GosecStats{
			Files: 0,
			Lines: 0,
			Found: 0,
		},
	}

	findings := scanner.convertFindings(gosecOutput, "/test/path")

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty output, got %d", len(findings))
	}
}
