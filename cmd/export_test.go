package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestDetectFormatFromFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected string
	}{
		{
			name:     "JSON extension",
			filename: "findings.json",
			expected: "json",
		},
		{
			name:     "CSV extension",
			filename: "findings.csv",
			expected: "csv",
		},
		{
			name:     "Excel extension",
			filename: "findings.xlsx",
			expected: "excel",
		},
		{
			name:     "SARIF extension",
			filename: "results.sarif",
			expected: "sarif",
		},
		{
			name:     "YAML extension",
			filename: "policies.yaml",
			expected: "yaml",
		},
		{
			name:     "YML extension",
			filename: "policies.yml",
			expected: "yaml",
		},
		{
			name:     "Unknown extension defaults to JSON",
			filename: "data.txt",
			expected: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFormatFromFile(tt.filename)
			if result != tt.expected {
				t.Errorf("detectFormatFromFile(%s) = %s, want %s", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestParseSeverityFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "Single severity",
			input:    "critical",
			expected: []string{"critical"},
		},
		{
			name:     "Multiple severities",
			input:    "critical,high,medium",
			expected: []string{"critical", "high", "medium"},
		},
		{
			name:     "Severities with spaces",
			input:    "critical, high, medium",
			expected: []string{"critical", "high", "medium"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSeverityFilter(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseSeverityFilter(%s) length = %d, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("parseSeverityFilter(%s)[%d] = %s, want %s", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestExportCommand_ValidateFlags(t *testing.T) {
	// Test that export command has expected flags
	if exportCmd == nil {
		t.Fatal("exportCmd is nil")
	}
	if exportCmd.Use != "export" {
		t.Errorf("Expected 'export', got '%s'", exportCmd.Use)
	}

	// Check flags exist
	formatFlag := exportCmd.Flags().Lookup("format")
	if formatFlag == nil {
		t.Error("format flag not found")
	}

	outputFlag := exportCmd.Flags().Lookup("output")
	if outputFlag == nil {
		t.Error("output flag not found")
	}

	runIDFlag := exportCmd.Flags().Lookup("run-id")
	if runIDFlag == nil {
		t.Error("run-id flag not found")
	}

	severityFlag := exportCmd.Flags().Lookup("severity")
	if severityFlag == nil {
		t.Error("severity flag not found")
	}

	startDateFlag := exportCmd.Flags().Lookup("start-date")
	if startDateFlag == nil {
		t.Error("start-date flag not found")
	}

	endDateFlag := exportCmd.Flags().Lookup("end-date")
	if endDateFlag == nil {
		t.Error("end-date flag not found")
	}

	policyIDFlag := exportCmd.Flags().Lookup("policy-id")
	if policyIDFlag == nil {
		t.Error("policy-id flag not found")
	}
}

func TestExportCommand_Help(t *testing.T) {
	// Verify help text mentions key features
	if !containsSubstring(exportCmd.Long, "findings") {
		t.Error("Help text should mention findings")
	}
	if !containsSubstring(exportCmd.Long, "policies") {
		t.Error("Help text should mention policies")
	}
	if !containsSubstring(exportCmd.Long, "JSON") {
		t.Error("Help text should mention JSON format")
	}
	if !containsSubstring(exportCmd.Long, "CSV") {
		t.Error("Help text should mention CSV format")
	}
	if !containsSubstring(exportCmd.Long, "SARIF") {
		t.Error("Help text should mention SARIF format")
	}
	if !containsSubstring(exportCmd.Long, "YAML") {
		t.Error("Help text should mention YAML format")
	}
}

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{
			name:     "Bytes",
			bytes:    512,
			expected: "512 B",
		},
		{
			name:     "Kilobytes",
			bytes:    1024,
			expected: "1.0 KB",
		},
		{
			name:     "Megabytes",
			bytes:    1048576,
			expected: "1.0 MB",
		},
		{
			name:     "Gigabytes",
			bytes:    1073741824,
			expected: "1.0 GB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatFileSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatFileSize(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{
			name:     "Item exists",
			slice:    []string{"json", "csv", "excel"},
			item:     "csv",
			expected: true,
		},
		{
			name:     "Item does not exist",
			slice:    []string{"json", "csv", "excel"},
			item:     "yaml",
			expected: false,
		},
		{
			name:     "Empty slice",
			slice:    []string{},
			item:     "json",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			if result != tt.expected {
				t.Errorf("contains(%v, %s) = %v, want %v", tt.slice, tt.item, result, tt.expected)
			}
		})
	}
}

// Helper function for substring checking
func containsSubstring(s, substr string) bool {
	if len(s) == 0 || len(substr) == 0 {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestExportCommand_Subcommands(t *testing.T) {
	// Verify export command has subcommands
	if exportCmd == nil {
		t.Fatal("exportCmd is nil")
	}

	// Check for findings subcommand
	findingsCmd := findCommand(exportCmd, "findings")
	if findingsCmd == nil {
		t.Error("findings subcommand not found")
	}

	// Check for policies subcommand
	policiesCmd := findCommand(exportCmd, "policies")
	if policiesCmd == nil {
		t.Error("policies subcommand not found")
	}
}

func TestParseSeverityFilter_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Trailing comma",
			input:    "critical,high,",
			expected: []string{"critical", "high", ""},
		},
		{
			name:     "Multiple spaces",
			input:    "critical,  high,  medium",
			expected: []string{"critical", "high", "medium"},
		},
		{
			name:     "Single item with spaces",
			input:    "  critical  ",
			expected: []string{"critical"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSeverityFilter(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseSeverityFilter(%s) length = %d, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("parseSeverityFilter(%s)[%d] = %s, want %s", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestDetectFormatFromFile_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected string
	}{
		{
			name:     "Uppercase extension",
			filename: "findings.JSON",
			expected: "json",
		},
		{
			name:     "Mixed case extension",
			filename: "findings.CsV",
			expected: "csv",
		},
		{
			name:     "No extension",
			filename: "findings",
			expected: "json",
		},
		{
			name:     "Multiple dots",
			filename: "findings.backup.json",
			expected: "json",
		},
		{
			name:     "Hidden file",
			filename: ".findings.json",
			expected: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFormatFromFile(tt.filename)
			if result != tt.expected {
				t.Errorf("detectFormatFromFile(%s) = %s, want %s", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestFormatFileSize_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{
			name:     "Zero bytes",
			bytes:    0,
			expected: "0 B",
		},
		{
			name:     "Fractional KB",
			bytes:    1536,
			expected: "1.5 KB",
		},
		{
			name:     "Fractional MB",
			bytes:    1572864,
			expected: "1.5 MB",
		},
		{
			name:     "Large GB",
			bytes:    10737418240,
			expected: "10.0 GB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatFileSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatFileSize(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestContains_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{
			name:     "Nil slice",
			slice:    nil,
			item:     "json",
			expected: false,
		},
		{
			name:     "Empty item",
			slice:    []string{"json", "csv"},
			item:     "",
			expected: false,
		},
		{
			name:     "Case sensitive",
			slice:    []string{"json", "csv"},
			item:     "JSON",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			if result != tt.expected {
				t.Errorf("contains(%v, %s) = %v, want %v", tt.slice, tt.item, result, tt.expected)
			}
		})
	}
}

// Helper function to find a command by name
func findCommand(parent *cobra.Command, name string) *cobra.Command {
	for _, cmd := range parent.Commands() {
		if cmd.Name() == name {
			return cmd
		}
	}
	return nil
}
