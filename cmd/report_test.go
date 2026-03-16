package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

// TestReportCommandExists tests that report command is registered
func TestReportCommandExists(t *testing.T) {
	if reportCmd == nil {
		t.Error("reportCmd should not be nil")
	}
	if reportCmd.Use != "report" {
		t.Errorf("reportCmd.Use = %v, want 'report'", reportCmd.Use)
	}
}

// TestReportGenerateCommand tests report generate subcommand
func TestReportGenerateCommand(t *testing.T) {
	if len(reportCmd.Commands()) < 1 {
		t.Fatal("reportCmd should have subcommands")
	}
	
	// Find generate command
	var generateCmd *cobra.Command
	for _, cmd := range reportCmd.Commands() {
		if cmd.Use == "generate" {
			generateCmd = cmd
			break
		}
	}
	
	if generateCmd == nil {
		t.Fatal("Expected 'generate' subcommand not found")
	}
	
	if generateCmd.Use != "generate" {
		t.Errorf("Expected 'generate' subcommand, got %v", generateCmd.Use)
	}
}

// TestReportCommandFlags tests report command flags
func TestReportCommandFlags(t *testing.T) {
	// Check that reportGenerateCmd has the flags (not reportCmd)
	flags := []string{"format", "output", "run-id"}
	for _, flagName := range flags {
		flag := reportGenerateCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag %s to exist in reportGenerateCmd", flagName)
		}
	}
}

// TestReportGenerateFlagDefaults tests default flag values
func TestReportGenerateFlagDefaults(t *testing.T) {
	tests := []struct {
		name         string
		flagName     string
		expectedType string
		defaultValue string
	}{
		{"format flag", "format", "string", "markdown"},
		{"output flag", "output", "string", ""},
		{"run-id flag", "run-id", "string", ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := reportGenerateCmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Fatalf("Flag %s not found", tt.flagName)
			}
			if flag.Value.Type() != tt.expectedType {
				t.Errorf("Flag %s type = %v, want %v", tt.flagName, flag.Value.Type(), tt.expectedType)
			}
			if flag.DefValue != tt.defaultValue {
				t.Errorf("Flag %s default = %v, want %v", tt.flagName, flag.DefValue, tt.defaultValue)
			}
		})
	}
}

// TestReportFormatFlag tests different report format flags
func TestReportFormatFlag(t *testing.T) {
	formats := []string{"markdown", "html", "json", "csv"}
	
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			// Reset flags
			reportGenerateCmd.ResetFlags()
			initConfig() // Re-initialize config/flags
			
			if err := reportGenerateCmd.Flags().Set("format", format); err != nil {
				t.Errorf("Failed to set format flag to %s: %v", format, err)
			}
			
			actualFormat, err := reportGenerateCmd.Flags().GetString("format")
			if err != nil {
				t.Errorf("Failed to get format flag: %v", err)
			}
			if actualFormat != format {
				t.Errorf("Format flag = %v, want %v", actualFormat, format)
			}
		})
	}
}

// TestReportOutputFlag tests output flag
func TestReportOutputFlag(t *testing.T) {
	// Reset flags
	reportGenerateCmd.ResetFlags()
	initConfig() // Re-initialize config/flags
	
	outputPath := "./report.html"
	if err := reportGenerateCmd.Flags().Set("output", outputPath); err != nil {
		t.Errorf("Failed to set output flag: %v", err)
	}
	
	actualOutput, err := reportGenerateCmd.Flags().GetString("output")
	if err != nil {
		t.Errorf("Failed to get output flag: %v", err)
	}
	if actualOutput != outputPath {
		t.Errorf("Output flag = %v, want %v", actualOutput, outputPath)
	}
}

// TestReportRunIDFlag tests run-id flag
func TestReportRunIDFlag(t *testing.T) {
	// Reset flags
	reportGenerateCmd.ResetFlags()
	initConfig() // Re-initialize config/flags
	
	runID := "test-run-123"
	if err := reportGenerateCmd.Flags().Set("run-id", runID); err != nil {
		t.Errorf("Failed to set run-id flag: %v", err)
	}
	
	actualRunID, err := reportGenerateCmd.Flags().GetString("run-id")
	if err != nil {
		t.Errorf("Failed to get run-id flag: %v", err)
	}
	if actualRunID != runID {
		t.Errorf("Run-id flag = %v, want %v", actualRunID, runID)
	}
}

// TestReportFormatShorthand tests format flag shorthand
func TestReportFormatShorthand(t *testing.T) {
	flag := reportGenerateCmd.Flags().Lookup("format")
	if flag == nil {
		t.Fatal("format flag not found")
	}
	
	if flag.Shorthand != "f" {
		t.Errorf("format flag shorthand = %v, want 'f'", flag.Shorthand)
	}
}

// TestReportOutputShorthand tests output flag shorthand
func TestReportOutputShorthand(t *testing.T) {
	flag := reportGenerateCmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("output flag not found")
	}
	
	if flag.Shorthand != "o" {
		t.Errorf("output flag shorthand = %v, want 'o'", flag.Shorthand)
	}
}

// TestPercentageFunction tests the percentage helper function
func TestPercentageFunction(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		total    int
		expected float64
	}{
		{"zero total", 5, 0, 0.0},
		{"zero count", 0, 100, 0.0},
		{"50 percent", 50, 100, 50.0},
		{"33.33 percent", 1, 3, 33.333333333333336},
		{"100 percent", 100, 100, 100.0},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := percentage(tt.count, tt.total)
			if result != tt.expected {
				t.Errorf("percentage(%d, %d) = %v, want %v", tt.count, tt.total, result, tt.expected)
			}
		})
	}
}

// TestGenerateMarkdownReport tests markdown report generation
func TestGenerateMarkdownReport(t *testing.T) {
	runID := "test-run-123"
	targetPath := "/test/path"
	total := 100
	critical := 10
	high := 20
	medium := 30
	low := 40
	
	report := generateMarkdownReport(runID, targetPath, total, critical, high, medium, low)
	
	if len(report) == 0 {
		t.Error("Expected markdown report, got empty string")
	}
	
	// Check for expected content
	expectedStrings := []string{
		"Security Scan Report",
		runID,
		targetPath,
		"Critical",
		"High",
		"Medium",
		"Low",
		"Recommendations",
	}
	
	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(report), []byte(expected)) {
			t.Errorf("Markdown report should contain '%s'", expected)
		}
	}
}

// TestGenerateHTMLReport tests HTML report generation
func TestGenerateHTMLReport(t *testing.T) {
	runID := "test-run-123"
	targetPath := "/test/path"
	total := 100
	critical := 10
	high := 20
	medium := 30
	low := 40
	
	report := generateHTMLReport(runID, targetPath, total, critical, high, medium, low)
	
	if len(report) == 0 {
		t.Error("Expected HTML report, got empty string")
	}
	
	// Check for expected HTML elements
	expectedStrings := []string{
		"<!DOCTYPE html>",
		"<html>",
		"<head>",
		"<body>",
		"Security Scan Report",
		runID,
		targetPath,
		"Critical",
		"High",
		"Medium",
		"Low",
	}
	
	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(report), []byte(expected)) {
			t.Errorf("HTML report should contain '%s'", expected)
		}
	}
}

// TestGenerateJSONReport tests JSON report generation
func TestGenerateJSONReport(t *testing.T) {
	runID := "test-run-123"
	targetPath := "/test/path"
	total := 100
	critical := 10
	high := 20
	medium := 30
	low := 40
	
	report := generateJSONReport(runID, targetPath, total, critical, high, medium, low)
	
	if len(report) == 0 {
		t.Error("Expected JSON report, got empty string")
	}
	
	// Check for expected JSON fields
	expectedStrings := []string{
		`"run_id"`,
		`"target_path"`,
		`"summary"`,
		`"total_findings"`,
		`"critical"`,
		`"high"`,
		`"medium"`,
		`"low"`,
		`"distribution"`,
		runID,
		targetPath,
	}
	
	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(report), []byte(expected)) {
			t.Errorf("JSON report should contain '%s'", expected)
		}
	}
}

// TestReportGenerateCommandHelp tests help output
func TestReportGenerateCommandHelp(t *testing.T) {
	// Reset command
	reportGenerateCmd.SetArgs([]string{"--help"})
	
	// Capture output
	buf := new(bytes.Buffer)
	reportGenerateCmd.SetOut(buf)
	reportGenerateCmd.SetErr(buf)
	
	err := reportGenerateCmd.Execute()
	if err != nil {
		t.Errorf("Execute() with --help failed: %v", err)
	}
	
	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected help output, got empty string")
	}
}
