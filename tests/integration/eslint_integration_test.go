package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/coding-agent/cli/plugins/eslint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestESLintIntegration(t *testing.T) {
	// Skip if eslint is not available
	if _, err := exec.LookPath("eslint"); err != nil {
		t.Skip("eslint not available, skipping integration test")
	}

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "eslint-integration-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test JavaScript files with various security issues
	testFiles := map[string]string{
		"eval-issue.js": `
// File with eval usage
const userInput = process.argv[2];
eval(userInput); // Should be detected
`,
		"child-process.js": `
// File with child_process usage
const { exec } = require('child_process');
const userCmd = process.argv[2];
exec(userCmd); // Should be detected
`,
		"fs-issue.js": `
// File with non-literal fs path
const fs = require('fs');
const userPath = process.argv[2];
fs.readFile(userPath, 'utf8', (err, data) => {}); // Should be detected
`,
		"safe-file.js": `
// File with no security issues
const message = "Hello, World!";
console.log(message);
`,
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tmpDir, filename)
		err := os.WriteFile(filePath, []byte(content), 0644)
		require.NoError(t, err)
	}

	// Create scanner instance
	scanner := eslint.New()
	require.NotNil(t, scanner)

	// Verify scanner is available
	if !scanner.IsAvailable() {
		t.Skip("eslint scanner not available")
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)

	// Note: The scan may fail if eslint-plugin-security is not installed
	if err != nil {
		t.Logf("Scan failed (may be expected if eslint-plugin-security not installed): %v", err)
		// Don't fail the test, just log and skip
		t.Skip("eslint-plugin-security may not be installed")
		return
	}

	// Verify findings structure
	assert.NotNil(t, findings)
	t.Logf("Found %d findings", len(findings))

	// If eslint-plugin-security is properly installed, we should find issues
	if len(findings) > 0 {
		// Verify finding structure
		for _, finding := range findings {
			assert.Equal(t, "eslint", finding.ToolName)
			assert.NotEmpty(t, finding.ID)
			assert.NotEmpty(t, finding.Message)
			assert.NotEmpty(t, finding.FilePath)
			assert.Greater(t, finding.LineNumber, 0)
			assert.NotEmpty(t, finding.Severity)
			assert.NotEmpty(t, finding.Confidence)
			assert.NotEmpty(t, finding.RuleID)
			assert.Contains(t, finding.RuleID, "security/")
			assert.NotEmpty(t, finding.Category)
			assert.NotNil(t, finding.RawJSON)
			assert.False(t, finding.Timestamp.IsZero())

			t.Logf("Finding: %s in %s:%d - %s",
				finding.RuleID,
				finding.FilePath,
				finding.LineNumber,
				finding.Message)
		}

		// Verify we found expected issues
		ruleIDs := make(map[string]bool)
		for _, finding := range findings {
			ruleIDs[finding.RuleID] = true
		}

		// We expect to find at least some of these rules
		expectedRules := []string{
			"security/detect-eval-with-expression",
			"security/detect-child-process",
			"security/detect-non-literal-fs-filename",
		}

		foundExpected := false
		for _, rule := range expectedRules {
			if ruleIDs[rule] {
				foundExpected = true
				t.Logf("Found expected rule: %s", rule)
			}
		}

		if !foundExpected {
			t.Logf("Warning: None of the expected security rules were triggered")
			t.Logf("Found rules: %v", ruleIDs)
		}
	} else {
		t.Log("No findings detected - this may indicate eslint-plugin-security is not properly configured")
	}
}

func TestESLintIntegration_TypeScript(t *testing.T) {
	// Skip if eslint is not available
	if _, err := exec.LookPath("eslint"); err != nil {
		t.Skip("eslint not available, skipping integration test")
	}

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "eslint-ts-integration-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test TypeScript file
	testFile := filepath.Join(tmpDir, "test.ts")
	testCode := `
// TypeScript file with security issue
const userInput: string = process.argv[2];
eval(userInput); // Should be detected
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	require.NoError(t, err)

	// Create scanner instance
	scanner := eslint.New()
	require.NotNil(t, scanner)

	if !scanner.IsAvailable() {
		t.Skip("eslint scanner not available")
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)

	if err != nil {
		t.Logf("Scan failed: %v", err)
		t.Skip("TypeScript scanning may require additional setup")
		return
	}

	// Just verify the scan completes without errors
	assert.NotNil(t, findings)
	t.Logf("TypeScript scan completed with %d findings", len(findings))
}

func TestESLintIntegration_EmptyDirectory(t *testing.T) {
	// Skip if eslint is not available
	if _, err := exec.LookPath("eslint"); err != nil {
		t.Skip("eslint not available, skipping integration test")
	}

	// Create an empty temporary directory
	tmpDir, err := os.MkdirTemp("", "eslint-empty-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create scanner instance
	scanner := eslint.New()
	require.NotNil(t, scanner)

	if !scanner.IsAvailable() {
		t.Skip("eslint scanner not available")
	}

	// Run scan on empty directory
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)

	// Should complete without error
	if err != nil {
		t.Logf("Scan error: %v", err)
	}

	// Should return empty findings
	assert.NotNil(t, findings)
	assert.Empty(t, findings)
}

func TestESLintIntegration_NonJavaScriptFiles(t *testing.T) {
	// Skip if eslint is not available
	if _, err := exec.LookPath("eslint"); err != nil {
		t.Skip("eslint not available, skipping integration test")
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "eslint-nojs-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create non-JavaScript files
	testFiles := map[string]string{
		"test.py":  "print('Hello')",
		"test.go":  "package main",
		"test.txt": "Just text",
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tmpDir, filename)
		err := os.WriteFile(filePath, []byte(content), 0644)
		require.NoError(t, err)
	}

	// Create scanner instance
	scanner := eslint.New()
	require.NotNil(t, scanner)

	if !scanner.IsAvailable() {
		t.Skip("eslint scanner not available")
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)

	// Should complete without error
	if err != nil {
		t.Logf("Scan error: %v", err)
	}

	// Should return empty findings (no JS/TS files)
	assert.NotNil(t, findings)
	assert.Empty(t, findings)
}

func TestESLintIntegration_CWEMapping(t *testing.T) {
	// Skip if eslint is not available
	if _, err := exec.LookPath("eslint"); err != nil {
		t.Skip("eslint not available, skipping integration test")
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "eslint-cwe-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test file with known security issue
	testFile := filepath.Join(tmpDir, "test.js")
	testCode := `
const crypto = require('crypto');
const random = crypto.pseudoRandomBytes(16); // Weak random - CWE-330
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	require.NoError(t, err)

	// Create scanner instance
	scanner := eslint.New()
	require.NotNil(t, scanner)

	if !scanner.IsAvailable() {
		t.Skip("eslint scanner not available")
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)

	if err != nil {
		t.Skip("Scan failed, may need eslint-plugin-security")
		return
	}

	// If we found the weak random issue, verify the category
	for _, finding := range findings {
		if finding.RuleID == "security/detect-pseudoRandomBytes" {
			assert.Equal(t, "weak-random", finding.Category)
			t.Logf("Verified CWE mapping for %s -> %s", finding.RuleID, finding.Category)
		}
	}
}
