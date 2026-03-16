package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestPolicyCommandExists tests that policy command is registered
func TestPolicyCommandExists(t *testing.T) {
	if policyCmd == nil {
		t.Error("policyCmd should not be nil")
	}
	if policyCmd.Use != "policy" {
		t.Errorf("policyCmd.Use = %v, want 'policy'", policyCmd.Use)
	}
}

// TestPolicyValidateCommand tests policy validate subcommand
func TestPolicyValidateCommand(t *testing.T) {
	if len(policyCmd.Commands()) < 1 {
		t.Fatal("policyCmd should have subcommands")
	}
	
	// Find validate command
	var validateCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "validate [policy-file]" {
			validateCmd = cmd
			break
		}
	}
	
	if validateCmd == nil {
		t.Fatal("Expected 'validate' subcommand not found")
	}
	
	if validateCmd.Use != "validate [policy-file]" {
		t.Errorf("Expected 'validate [policy-file]' subcommand, got %v", validateCmd.Use)
	}
}

// TestPolicyListCommand tests policy list subcommand
func TestPolicyListCommand(t *testing.T) {
	if len(policyCmd.Commands()) < 2 {
		t.Fatal("policyCmd should have at least 2 subcommands")
	}
	
	// Find list command
	var listCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "list [policy-dir]" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("Expected 'list' subcommand not found")
	}
	
	if listCmd.Use != "list [policy-dir]" {
		t.Errorf("Expected 'list [policy-dir]' subcommand, got %v", listCmd.Use)
	}
}

// TestPolicyValidateRequiresFile tests that validate requires a file argument
func TestPolicyValidateRequiresFile(t *testing.T) {
	var validateCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "validate [policy-file]" {
			validateCmd = cmd
			break
		}
	}
	
	if validateCmd == nil {
		t.Fatal("validate command not found")
	}
	
	// Reset command for testing
	validateCmd.SetArgs([]string{})
	
	// Capture output
	buf := new(bytes.Buffer)
	validateCmd.SetOut(buf)
	validateCmd.SetErr(buf)
	
	err := validateCmd.Execute()
	if err == nil {
		t.Error("Expected error when no policy file provided, got nil")
	}
}

// TestPolicyValidateNonExistentFile tests validate with non-existent file
func TestPolicyValidateNonExistentFile(t *testing.T) {
	var validateCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "validate [policy-file]" {
			validateCmd = cmd
			break
		}
	}
	
	if validateCmd == nil {
		t.Fatal("validate command not found")
	}
	
	tmpDir := t.TempDir()
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.yaml")
	
	err := validateCmd.RunE(validateCmd, []string{nonExistentFile})
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

// TestPolicyValidateValidFile tests validate with a valid policy file
func TestPolicyValidateValidFile(t *testing.T) {
	var validateCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "validate [policy-file]" {
			validateCmd = cmd
			break
		}
	}
	
	if validateCmd == nil {
		t.Fatal("validate command not found")
	}
	
	// Create a temporary policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-policy.yaml")
	
	policyContent := `---
name: test-policy
version: 1.0
rules:
  - name: block-critical
    severity: critical
    action: deny
`
	
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}
	
	// Capture output
	buf := new(bytes.Buffer)
	validateCmd.SetOut(buf)
	validateCmd.SetErr(buf)
	
	err := validateCmd.RunE(validateCmd, []string{policyFile})
	if err != nil {
		t.Errorf("Unexpected error for valid policy file: %v", err)
	}
}

// TestPolicyValidateEmptyFile tests validate with empty file
func TestPolicyValidateEmptyFile(t *testing.T) {
	var validateCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "validate [policy-file]" {
			validateCmd = cmd
			break
		}
	}
	
	if validateCmd == nil {
		t.Fatal("validate command not found")
	}
	
	// Create an empty policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "empty-policy.yaml")
	
	if err := os.WriteFile(policyFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty policy file: %v", err)
	}
	
	err := validateCmd.RunE(validateCmd, []string{policyFile})
	if err == nil {
		t.Error("Expected error for empty policy file, got nil")
	}
}

// TestPolicyListDefaultDirectory tests list with default directory
func TestPolicyListDefaultDirectory(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "list [policy-dir]" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	// Create a temporary directory structure
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatalf("Failed to create policy directory: %v", err)
	}
	
	// Create some test policy files
	policies := []string{"policy1.yaml", "policy2.yml", "readme.txt"}
	for _, policy := range policies {
		policyPath := filepath.Join(policyDir, policy)
		if err := os.WriteFile(policyPath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create policy file %s: %v", policy, err)
		}
	}
	
	// Capture output
	buf := new(bytes.Buffer)
	listCmd.SetOut(buf)
	listCmd.SetErr(buf)
	
	// Run with the test directory
	err := listCmd.RunE(listCmd, []string{policyDir})
	if err != nil {
		t.Errorf("Unexpected error listing policies: %v", err)
	}
	
	output := buf.String()
	// Should list .yaml and .yml files but not .txt
	if len(output) == 0 {
		t.Error("Expected output from policy list, got empty string")
	}
}

// TestPolicyListNonExistentDirectory tests list with non-existent directory
func TestPolicyListNonExistentDirectory(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "list [policy-dir]" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	tmpDir := t.TempDir()
	nonExistentDir := filepath.Join(tmpDir, "nonexistent")
	
	err := listCmd.RunE(listCmd, []string{nonExistentDir})
	if err == nil {
		t.Error("Expected error for non-existent directory, got nil")
	}
}

// TestPolicyListEmptyDirectory tests list with empty directory
func TestPolicyListEmptyDirectory(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if cmd.Use == "list [policy-dir]" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	// Create an empty directory
	tmpDir := t.TempDir()
	emptyDir := filepath.Join(tmpDir, "empty")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatalf("Failed to create empty directory: %v", err)
	}
	
	// Capture output
	buf := new(bytes.Buffer)
	listCmd.SetOut(buf)
	listCmd.SetErr(buf)
	
	err := listCmd.RunE(listCmd, []string{emptyDir})
	if err != nil {
		t.Errorf("Unexpected error for empty directory: %v", err)
	}
	
	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected output from policy list, got empty string")
	}
}

// TestPolicyTestPatternsCommand tests policy test-patterns subcommand
func TestPolicyTestPatternsCommand(t *testing.T) {
	// Find test-patterns command
	var testPatternsCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if strings.HasPrefix(cmd.Use, "test-patterns") {
			testPatternsCmd = cmd
			break
		}
	}
	
	if testPatternsCmd == nil {
		t.Fatal("Expected 'test-patterns' subcommand not found")
	}
	
	if !strings.HasPrefix(testPatternsCmd.Use, "test-patterns") {
		t.Errorf("Expected 'test-patterns' subcommand, got %v", testPatternsCmd.Use)
	}
}

// TestPolicyTestPatternsRequiresArgs tests that test-patterns requires arguments
func TestPolicyTestPatternsRequiresArgs(t *testing.T) {
	var testPatternsCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if strings.HasPrefix(cmd.Use, "test-patterns") {
			testPatternsCmd = cmd
			break
		}
	}
	
	if testPatternsCmd == nil {
		t.Fatal("test-patterns command not found")
	}
	
	// Test with no arguments
	err := testPatternsCmd.RunE(testPatternsCmd, []string{})
	if err == nil {
		t.Error("Expected error when no arguments provided, got nil")
	}
	
	// Test with only one argument
	err = testPatternsCmd.RunE(testPatternsCmd, []string{"policy.yaml"})
	if err == nil {
		t.Error("Expected error when only one argument provided, got nil")
	}
}

// TestPolicyTestPatternsNonExistentFile tests test-patterns with non-existent files
func TestPolicyTestPatternsNonExistentFile(t *testing.T) {
	var testPatternsCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if strings.HasPrefix(cmd.Use, "test-patterns") {
			testPatternsCmd = cmd
			break
		}
	}
	
	if testPatternsCmd == nil {
		t.Fatal("test-patterns command not found")
	}
	
	tmpDir := t.TempDir()
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.yaml")
	
	err := testPatternsCmd.RunE(testPatternsCmd, []string{nonExistentFile, tmpDir})
	if err == nil {
		t.Error("Expected error for non-existent policy file, got nil")
	}
	
	// Test with non-existent target path
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	policyContent := `policies:
  - id: "test-policy"
    name: "Test Policy"
    description: "Test"
    cwe: ["CWE-89"]
    severity: "high"
    action: "deny"
    enabled: true
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}
	
	nonExistentPath := filepath.Join(tmpDir, "nonexistent")
	err = testPatternsCmd.RunE(testPatternsCmd, []string{policyFile, nonExistentPath})
	if err == nil {
		t.Error("Expected error for non-existent target path, got nil")
	}
}

// TestPolicyTestPatternsValidInput tests test-patterns with valid input
func TestPolicyTestPatternsValidInput(t *testing.T) {
	var testPatternsCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if strings.HasPrefix(cmd.Use, "test-patterns") {
			testPatternsCmd = cmd
			break
		}
	}
	
	if testPatternsCmd == nil {
		t.Fatal("test-patterns command not found")
	}
	
	// Create test directory structure
	tmpDir := t.TempDir()
	
	// Create policy file with patterns
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	policyContent := `policies:
  - id: "test-go-files"
    name: "Test Go Files"
    description: "Match Go files"
    cwe: ["CWE-89"]
    severity: "high"
    action: "deny"
    enabled: true
    patterns:
      include:
        - "**/*.go"
      exclude:
        - "**/*_test.go"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}
	
	// Create test files
	testDir := filepath.Join(tmpDir, "testcode")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	
	testFiles := []string{
		"main.go",
		"main_test.go",
		"utils.go",
		"readme.txt",
	}
	
	for _, file := range testFiles {
		filePath := filepath.Join(testDir, file)
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}
	
	// Capture output
	buf := new(bytes.Buffer)
	testPatternsCmd.SetOut(buf)
	testPatternsCmd.SetErr(buf)
	
	err := testPatternsCmd.RunE(testPatternsCmd, []string{policyFile, testDir})
	if err != nil {
		t.Errorf("Unexpected error testing patterns: %v", err)
	}
	
	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected output from test-patterns, got empty string")
	}
	
	// Check that output contains expected information
	if !bytes.Contains([]byte(output), []byte("Pattern Matching Test")) {
		t.Error("Expected output to contain 'Pattern Matching Test'")
	}
	
	if !bytes.Contains([]byte(output), []byte("Test Go Files")) {
		t.Error("Expected output to contain policy name 'Test Go Files'")
	}
}

// TestPolicyTestPatternsInvalidYAML tests test-patterns with invalid YAML
func TestPolicyTestPatternsInvalidYAML(t *testing.T) {
	var testPatternsCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if strings.HasPrefix(cmd.Use, "test-patterns") {
			testPatternsCmd = cmd
			break
		}
	}
	
	if testPatternsCmd == nil {
		t.Fatal("test-patterns command not found")
	}
	
	tmpDir := t.TempDir()
	
	// Create invalid policy file
	policyFile := filepath.Join(tmpDir, "invalid.yaml")
	invalidContent := `policies:
  - id: "test"
    name: "Test"
    invalid yaml here [[[
`
	if err := os.WriteFile(policyFile, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to create invalid policy file: %v", err)
	}
	
	testDir := filepath.Join(tmpDir, "testcode")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	
	err := testPatternsCmd.RunE(testPatternsCmd, []string{policyFile, testDir})
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

// TestPolicyTestPatternsWithVerboseFlag tests test-patterns with verbose flag
func TestPolicyTestPatternsWithVerboseFlag(t *testing.T) {
	var testPatternsCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if strings.HasPrefix(cmd.Use, "test-patterns") {
			testPatternsCmd = cmd
			break
		}
	}
	
	if testPatternsCmd == nil {
		t.Fatal("test-patterns command not found")
	}
	
	// Check that verbose flag exists
	verboseFlag := testPatternsCmd.Flags().Lookup("verbose")
	if verboseFlag == nil {
		t.Error("Expected 'verbose' flag to exist")
	}
	
	// Check that limit flag exists
	limitFlag := testPatternsCmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Error("Expected 'limit' flag to exist")
	}
}

// TestPolicyTestPatternsMultiplePolicies tests test-patterns with multiple policies
func TestPolicyTestPatternsMultiplePolicies(t *testing.T) {
	var testPatternsCmd *cobra.Command
	for _, cmd := range policyCmd.Commands() {
		if strings.HasPrefix(cmd.Use, "test-patterns") {
			testPatternsCmd = cmd
			break
		}
	}
	
	if testPatternsCmd == nil {
		t.Fatal("test-patterns command not found")
	}
	
	tmpDir := t.TempDir()
	
	// Create policy file with multiple policies
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	policyContent := `policies:
  - id: "go-files"
    name: "Go Files"
    description: "Match Go files"
    cwe: ["CWE-89"]
    severity: "high"
    action: "deny"
    enabled: true
    patterns:
      include:
        - "**/*.go"
  - id: "python-files"
    name: "Python Files"
    description: "Match Python files"
    cwe: ["CWE-79"]
    severity: "medium"
    action: "warn"
    enabled: true
    patterns:
      include:
        - "**/*.py"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}
	
	// Create test files
	testDir := filepath.Join(tmpDir, "testcode")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	
	testFiles := []string{
		"main.go",
		"script.py",
		"readme.txt",
	}
	
	for _, file := range testFiles {
		filePath := filepath.Join(testDir, file)
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}
	
	// Capture output
	buf := new(bytes.Buffer)
	testPatternsCmd.SetOut(buf)
	testPatternsCmd.SetErr(buf)
	
	err := testPatternsCmd.RunE(testPatternsCmd, []string{policyFile, testDir})
	if err != nil {
		t.Errorf("Unexpected error testing patterns: %v", err)
	}
	
	output := buf.String()
	
	// Check that both policies are shown
	if !bytes.Contains([]byte(output), []byte("Go Files")) {
		t.Error("Expected output to contain 'Go Files' policy")
	}
	
	if !bytes.Contains([]byte(output), []byte("Python Files")) {
		t.Error("Expected output to contain 'Python Files' policy")
	}
}
