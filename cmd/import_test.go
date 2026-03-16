package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		expected string
	}{
		{
			name:     "SARIF extension",
			filename: "results.sarif",
			content:  `{}`,
			expected: "sarif",
		},
		{
			name:     "JSON extension with SARIF content",
			filename: "results.json",
			content:  `{"$schema": "https://sarif.example.com/schema.json", "version": "2.1.0"}`,
			expected: "sarif",
		},
		{
			name:     "JSON extension with regular content",
			filename: "findings.json",
			content:  `{"findings": []}`,
			expected: "json",
		},
		{
			name:     "Unknown extension",
			filename: "data.txt",
			content:  `{}`,
			expected: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, tt.filename)
			err := os.WriteFile(path, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write file: %v", err)
			}

			result := detectFormat(path)
			if result != tt.expected {
				t.Errorf("detectFormat() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestImportCommand_ValidateFlags(t *testing.T) {
	// Test that import command has expected flags
	if importCmd == nil {
		t.Fatal("importCmd is nil")
	}
	if importCmd.Use != "import [file]" {
		t.Errorf("Expected 'import [file]', got '%s'", importCmd.Use)
	}

	// Check flags exist
	formatFlag := importCmd.Flags().Lookup("format")
	if formatFlag == nil {
		t.Error("format flag not found")
	}

	modeFlag := importCmd.Flags().Lookup("mode")
	if modeFlag == nil {
		t.Error("mode flag not found")
	}
	if modeFlag.DefValue != "replace" {
		t.Errorf("Expected default mode 'replace', got '%s'", modeFlag.DefValue)
	}

	runIDFlag := importCmd.Flags().Lookup("run-id")
	if runIDFlag == nil {
		t.Error("run-id flag not found")
	}

	validateFlag := importCmd.Flags().Lookup("validate-only")
	if validateFlag == nil {
		t.Error("validate-only flag not found")
	}
}

func TestImportCommand_PolicyFlags(t *testing.T) {
	// Check policy-specific flags exist
	typeFlag := importCmd.Flags().Lookup("type")
	if typeFlag == nil {
		t.Error("type flag not found")
	}
	if typeFlag.DefValue != "findings" {
		t.Errorf("Expected default type 'findings', got '%s'", typeFlag.DefValue)
	}

	overwriteFlag := importCmd.Flags().Lookup("overwrite")
	if overwriteFlag == nil {
		t.Error("overwrite flag not found")
	}

	templateDirFlag := importCmd.Flags().Lookup("template-dir")
	if templateDirFlag == nil {
		t.Error("template-dir flag not found")
	}

	listTemplatesFlag := importCmd.Flags().Lookup("list-templates")
	if listTemplatesFlag == nil {
		t.Error("list-templates flag not found")
	}
}

func TestImportCommand_UpdatedHelp(t *testing.T) {
	// Verify help text mentions policies
	if !containsSubstr(importCmd.Long, "policies") {
		t.Error("Help text should mention policies")
	}
	if !containsSubstr(importCmd.Long, "template") {
		t.Error("Help text should mention templates")
	}
}

func containsSubstr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDetectFormat_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		expected string
	}{
		{
			name:     "YAML extension",
			filename: "policies.yaml",
			content:  `policies: []`,
			expected: "yaml",
		},
		{
			name:     "YML extension",
			filename: "policies.yml",
			content:  `policies: []`,
			expected: "yaml",
		},
		{
			name:     "JSON with schema but not SARIF",
			filename: "data.json",
			content:  `{"$schema": "https://example.com/schema.json"}`,
			expected: "json",
		},
		{
			name:     "Empty file",
			filename: "empty.json",
			content:  ``,
			expected: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, tt.filename)
			err := os.WriteFile(path, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write file: %v", err)
			}

			result := detectFormat(path)
			if result != tt.expected {
				t.Errorf("detectFormat() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestImportCommand_RequiredArgs(t *testing.T) {
	// Test that import command requires file argument
	if importCmd == nil {
		t.Fatal("importCmd is nil")
	}

	// Check Args validation
	if importCmd.Args == nil {
		t.Error("importCmd should have Args validation")
	}
}

func TestImportCommand_ModeValidation(t *testing.T) {
	// Verify mode flag has valid default
	modeFlag := importCmd.Flags().Lookup("mode")
	if modeFlag == nil {
		t.Fatal("mode flag not found")
	}

	validModes := []string{"replace", "merge", "skip"}
	isValid := false
	for _, mode := range validModes {
		if modeFlag.DefValue == mode {
			isValid = true
			break
		}
	}

	if !isValid {
		t.Errorf("Default mode '%s' is not valid. Valid modes: %v", modeFlag.DefValue, validModes)
	}
}

func TestImportCommand_TypeValidation(t *testing.T) {
	// Verify type flag has valid default
	typeFlag := importCmd.Flags().Lookup("type")
	if typeFlag == nil {
		t.Fatal("type flag not found")
	}

	validTypes := []string{"findings", "policies"}
	isValid := false
	for _, typ := range validTypes {
		if typeFlag.DefValue == typ {
			isValid = true
			break
		}
	}

	if !isValid {
		t.Errorf("Default type '%s' is not valid. Valid types: %v", typeFlag.DefValue, validTypes)
	}
}

func TestImportCommand_FlagCombinations(t *testing.T) {
	// Test that certain flags are mutually exclusive or have dependencies
	// For example, template-dir should only be used with policies type

	// Verify all expected flags exist
	expectedFlags := []string{
		"format",
		"mode",
		"run-id",
		"validate-only",
		"type",
		"overwrite",
		"template-dir",
		"list-templates",
	}

	for _, flagName := range expectedFlags {
		flag := importCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag '%s' not found", flagName)
		}
	}
}

func TestDetectFormat_FileNotFound(t *testing.T) {
	// Test behavior when file doesn't exist
	result := detectFormat("/nonexistent/file.json")
	// Should default to json even if file doesn't exist
	if result != "json" {
		t.Errorf("detectFormat() for nonexistent file = %s, want json", result)
	}
}

func TestContains_Performance(t *testing.T) {
	// Test with large slice
	largeSlice := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		largeSlice[i] = fmt.Sprintf("item-%d", i)
	}

	// Test finding item at beginning
	if !contains(largeSlice, "item-0") {
		t.Error("Should find item at beginning")
	}

	// Test finding item at end
	if !contains(largeSlice, "item-999") {
		t.Error("Should find item at end")
	}

	// Test not finding item
	if contains(largeSlice, "nonexistent") {
		t.Error("Should not find nonexistent item")
	}
}
