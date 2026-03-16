package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestScanCommandExists tests that scan command is registered
func TestScanCommandExists(t *testing.T) {
	if scanCmd == nil {
		t.Error("scanCmd should not be nil")
	}
	if scanCmd.Use != "scan [path]" {
		t.Errorf("scanCmd.Use = %v, want 'scan [path]'", scanCmd.Use)
	}
}

// TestScanCommandFlags tests scan command flags
func TestScanCommandFlags(t *testing.T) {
	// Check actual flags defined in scan.go: output, format, scanners, db, llm, policies, waivers
	flags := []string{"output", "format", "scanners", "db", "llm", "policies", "waivers"}
	for _, flagName := range flags {
		flag := scanCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag %s to exist", flagName)
		}
	}
}

// TestScanCommandFlagDefaults tests default flag values
func TestScanCommandFlagDefaults(t *testing.T) {
	tests := []struct {
		name         string
		flagName     string
		expectedType string
		defaultValue string
	}{
		{"output flag", "output", "string", ""},
		{"format flag", "format", "string", "json"},
		{"db flag", "db", "string", "./data/findings.db"},
		{"llm flag", "llm", "bool", "false"},
		{"policies flag", "policies", "string", ""},
		{"waivers flag", "waivers", "string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := scanCmd.Flags().Lookup(tt.flagName)
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

// TestScanCommandRequiresPath tests that scan command requires a path argument
func TestScanCommandRequiresPath(t *testing.T) {
	// Reset command for testing
	scanCmd.SetArgs([]string{})
	
	// Capture output
	buf := new(bytes.Buffer)
	scanCmd.SetOut(buf)
	scanCmd.SetErr(buf)
	
	err := scanCmd.Execute()
	if err == nil {
		t.Error("Expected error when no path provided, got nil")
	}
}

// TestScanCommandInvalidPath tests scan with non-existent path
func TestScanCommandInvalidPath(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "nonexistent")
	
	// Reset command
	scanCmd.SetArgs([]string{nonExistentPath})
	
	err := scanCmd.RunE(scanCmd, []string{nonExistentPath})
	if err == nil {
		t.Error("Expected error for non-existent path, got nil")
	}
}

// TestScanCommandValidPath tests scan with valid path
func TestScanCommandValidPath(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()
	
	// Create a test file
	testFile := filepath.Join(tmpDir, "test.py")
	if err := os.WriteFile(testFile, []byte("print('hello')"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	// Create a temporary database path
	dbPath := filepath.Join(tmpDir, "test.db")
	
	// Reset command and set flags
	scanCmd.SetArgs([]string{tmpDir, "--db", dbPath, "--scanners", "bandit"})
	
	// Note: This will fail if scanners aren't installed, but we're testing the command setup
	// The actual scan execution is tested in integration tests
	err := scanCmd.ValidateArgs([]string{tmpDir})
	if err != nil {
		t.Errorf("ValidateArgs failed for valid path: %v", err)
	}
}

// TestScanCommandOutputFormats tests different output format flags
func TestScanCommandOutputFormats(t *testing.T) {
	formats := []string{"json", "sarif", "markdown"}
	
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			// Reset command
			scanCmd.ResetFlags()
			initConfig() // Re-initialize config/flags
			
			// Set format flag
			if err := scanCmd.Flags().Set("format", format); err != nil {
				t.Errorf("Failed to set format flag to %s: %v", format, err)
			}
			
			// Verify flag was set
			actualFormat, err := scanCmd.Flags().GetString("format")
			if err != nil {
				t.Errorf("Failed to get format flag: %v", err)
			}
			if actualFormat != format {
				t.Errorf("Format flag = %v, want %v", actualFormat, format)
			}
		})
	}
}

// TestScanCommandScannersFlag tests scanners flag parsing
func TestScanCommandScannersFlag(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"single scanner", []string{"bandit"}, []string{"bandit"}},
		{"multiple scanners", []string{"bandit", "semgrep"}, []string{"bandit", "semgrep"}},
		{"empty", []string{}, []string{}},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset command
			scanCmd.ResetFlags()
			initConfig() // Re-initialize config/flags
			
			// Set scanners flag
			for _, scanner := range tt.input {
				if err := scanCmd.Flags().Set("scanners", scanner); err != nil {
					t.Errorf("Failed to set scanners flag: %v", err)
				}
			}
			
			// Verify flag was set
			actualScanners, err := scanCmd.Flags().GetStringSlice("scanners")
			if err != nil {
				t.Errorf("Failed to get scanners flag: %v", err)
			}
			
			if len(actualScanners) != len(tt.expected) {
				t.Errorf("Scanners length = %v, want %v", len(actualScanners), len(tt.expected))
			}
		})
	}
}

// TestScanCommandLLMFlag tests LLM flag
func TestScanCommandLLMFlag(t *testing.T) {
	// Reset command
	scanCmd.ResetFlags()
	initConfig() // Re-initialize config/flags
	
	// Default should be false
	llmEnabled, err := scanCmd.Flags().GetBool("llm")
	if err != nil {
		t.Errorf("Failed to get llm flag: %v", err)
	}
	if llmEnabled {
		t.Error("LLM flag should default to false")
	}
	
	// Set to true
	if err := scanCmd.Flags().Set("llm", "true"); err != nil {
		t.Errorf("Failed to set llm flag: %v", err)
	}
	
	llmEnabled, err = scanCmd.Flags().GetBool("llm")
	if err != nil {
		t.Errorf("Failed to get llm flag: %v", err)
	}
	if !llmEnabled {
		t.Error("LLM flag should be true after setting")
	}
}

// TestScanCommandPolicyFlags tests policy and waiver flags
func TestScanCommandPolicyFlags(t *testing.T) {
	// Reset command
	scanCmd.ResetFlags()
	initConfig() // Re-initialize config/flags
	
	// Test policy flag
	policyPath := "./policies/test.yaml"
	if err := scanCmd.Flags().Set("policies", policyPath); err != nil {
		t.Errorf("Failed to set policies flag: %v", err)
	}
	
	actualPolicy, err := scanCmd.Flags().GetString("policies")
	if err != nil {
		t.Errorf("Failed to get policies flag: %v", err)
	}
	if actualPolicy != policyPath {
		t.Errorf("Policy path = %v, want %v", actualPolicy, policyPath)
	}
	
	// Test waiver flag
	waiverPath := "./waivers/test.yaml"
	if err := scanCmd.Flags().Set("waivers", waiverPath); err != nil {
		t.Errorf("Failed to set waivers flag: %v", err)
	}
	
	actualWaiver, err := scanCmd.Flags().GetString("waivers")
	if err != nil {
		t.Errorf("Failed to get waivers flag: %v", err)
	}
	if actualWaiver != waiverPath {
		t.Errorf("Waiver path = %v, want %v", actualWaiver, waiverPath)
	}
}
