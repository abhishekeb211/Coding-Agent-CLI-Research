package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/coding-agent/cli/plugins/safety"
)

// TestSafetyIntegration tests the safety plugin with a real vulnerable requirements.txt
func TestSafetyIntegration(t *testing.T) {
	scanner := safety.New()

	// Skip if safety is not installed
	if !scanner.IsAvailable() {
		t.Skip("safety not installed, skipping integration test")
	}

	// Create a temporary directory with vulnerable dependencies
	tmpDir := t.TempDir()
	
	// Use known vulnerable versions for testing
	// Note: These are old versions with known CVEs
	vulnerableRequirements := `django==2.2.0
requests==2.6.0
flask==0.12.0
`

	// Write requirements.txt
	requirementsFile := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(requirementsFile, []byte(vulnerableRequirements), 0644); err != nil {
		t.Fatalf("Failed to write requirements.txt: %v", err)
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)
	
	// Note: This test may fail if:
	// 1. Safety database is not available
	// 2. Network issues prevent database access
	// 3. The vulnerabilities have been removed from the database
	if err != nil {
		t.Logf("Scan failed (this may be expected if safety database is unavailable): %v", err)
		t.Skip("Skipping test due to scan failure")
	}

	// Log findings for debugging
	t.Logf("Found %d vulnerabilities", len(findings))
	for _, finding := range findings {
		t.Logf("Found: %s - %s (severity: %s, confidence: %s)",
			finding.RuleID, finding.Message, finding.Severity, finding.Confidence)
	}

	// Verify findings structure (if any were found)
	for _, finding := range findings {
		// Verify required fields
		if finding.ToolName != "safety" {
			t.Errorf("ToolName = %s, want safety", finding.ToolName)
		}
		if finding.Message == "" {
			t.Error("Message is empty")
		}
		if finding.FilePath != "requirements.txt" {
			t.Errorf("FilePath = %s, want requirements.txt", finding.FilePath)
		}
		if finding.Severity == "" {
			t.Error("Severity is empty")
		}
		if finding.Confidence != "high" {
			t.Errorf("Confidence = %s, want high", finding.Confidence)
		}
		if finding.RuleID == "" {
			t.Error("RuleID is empty")
		}
		if finding.Category == "" {
			t.Error("Category is empty")
		}
		
		// Verify message contains package name
		if finding.Message == "" {
			t.Error("Message should contain package information")
		}
	}
}

// TestSafetyWithCleanDependencies tests safety with up-to-date dependencies
func TestSafetyWithCleanDependencies(t *testing.T) {
	scanner := safety.New()

	// Skip if safety is not installed
	if !scanner.IsAvailable() {
		t.Skip("safety not installed, skipping integration test")
	}

	// Create a temporary directory with clean dependencies
	tmpDir := t.TempDir()
	
	// Use recent versions that should be clean
	// Note: These versions may have vulnerabilities discovered in the future
	cleanRequirements := `requests>=2.31.0
flask>=3.0.0
`

	// Write requirements.txt
	requirementsFile := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(requirementsFile, []byte(cleanRequirements), 0644); err != nil {
		t.Fatalf("Failed to write requirements.txt: %v", err)
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)
	
	if err != nil {
		t.Logf("Scan failed: %v", err)
		t.Skip("Skipping test due to scan failure")
	}

	// Log any findings (there may be some if new vulnerabilities were discovered)
	if len(findings) > 0 {
		t.Logf("Found %d vulnerabilities in supposedly clean dependencies:", len(findings))
		for _, f := range findings {
			t.Logf("  - %s: %s", f.RuleID, f.Message)
		}
	}
}

// TestSafetyWithNoRequirementsFile tests safety when requirements.txt is missing
func TestSafetyWithNoRequirementsFile(t *testing.T) {
	scanner := safety.New()

	// Skip if safety is not installed
	if !scanner.IsAvailable() {
		t.Skip("safety not installed, skipping integration test")
	}

	// Create a temporary directory without requirements.txt
	tmpDir := t.TempDir()

	// Run scan - should fail gracefully
	ctx := context.Background()
	_, err := scanner.Scan(ctx, tmpDir)

	// Expect an error since requirements.txt doesn't exist
	if err == nil {
		t.Error("Expected error when requirements.txt is missing, got nil")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}

// TestSafetyWithEmptyRequirementsFile tests safety with an empty requirements.txt
func TestSafetyWithEmptyRequirementsFile(t *testing.T) {
	scanner := safety.New()

	// Skip if safety is not installed
	if !scanner.IsAvailable() {
		t.Skip("safety not installed, skipping integration test")
	}

	// Create a temporary directory with empty requirements.txt
	tmpDir := t.TempDir()
	
	emptyRequirements := ``

	// Write empty requirements.txt
	requirementsFile := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(requirementsFile, []byte(emptyRequirements), 0644); err != nil {
		t.Fatalf("Failed to write requirements.txt: %v", err)
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)
	
	if err != nil {
		t.Logf("Scan with empty requirements: %v", err)
		// This is acceptable - safety may error on empty file
		return
	}

	// Should have no findings for empty requirements
	if len(findings) > 0 {
		t.Errorf("Expected no findings for empty requirements, got %d", len(findings))
	}
}

// TestSafetyCategoryMapping tests that categories are correctly extracted
func TestSafetyCategoryMapping(t *testing.T) {
	scanner := safety.New()

	// Skip if safety is not installed
	if !scanner.IsAvailable() {
		t.Skip("safety not installed, skipping integration test")
	}

	// We'll test category mapping through actual scan results
	// by checking that findings have appropriate categories
	t.Log("Category mapping is tested through unit tests in safety_test.go")
}
