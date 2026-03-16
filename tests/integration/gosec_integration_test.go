package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/coding-agent/cli/plugins/gosec"
)

// TestGosecIntegration tests the gosec plugin with a real vulnerable Go file
func TestGosecIntegration(t *testing.T) {
	scanner := gosec.New()

	// Skip if gosec is not installed
	if !scanner.IsAvailable() {
		t.Skip("gosec not installed, skipping integration test")
	}

	// Create a temporary directory with vulnerable Go code
	tmpDir := t.TempDir()
	
	vulnerableCode := `package main

import (
	"crypto/md5"
	"fmt"
)

const apiKey = "secret123"  // G101: Hardcoded credential

func main() {
	// G401: Weak crypto
	hash := md5.New()
	hash.Write([]byte("data"))
	fmt.Printf("%x\n", hash.Sum(nil))
}
`

	// Write vulnerable code to file
	mainFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainFile, []byte(vulnerableCode), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create go.mod file (required for gosec to work)
	goModContent := `module testapp

go 1.21
`
	goModFile := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goModFile, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify findings
	if len(findings) == 0 {
		t.Error("Expected findings, got none")
	}

	// Check for expected vulnerability types
	foundG101 := false
	foundG401 := false

	for _, finding := range findings {
		t.Logf("Found: %s - %s (severity: %s, confidence: %s)",
			finding.RuleID, finding.Message, finding.Severity, finding.Confidence)

		if finding.RuleID == "G101" {
			foundG101 = true
			if finding.Category != "credentials" {
				t.Errorf("G101 category = %s, want credentials", finding.Category)
			}
		}

		if finding.RuleID == "G401" {
			foundG401 = true
			if finding.Category != "weak-crypto" {
				t.Errorf("G401 category = %s, want weak-crypto", finding.Category)
			}
		}

		// Verify required fields
		if finding.ToolName != "gosec" {
			t.Errorf("ToolName = %s, want gosec", finding.ToolName)
		}
		if finding.Message == "" {
			t.Error("Message is empty")
		}
		if finding.FilePath == "" {
			t.Error("FilePath is empty")
		}
		if finding.Severity == "" {
			t.Error("Severity is empty")
		}
	}

	if !foundG101 {
		t.Error("Expected to find G101 (hardcoded credentials)")
	}
	if !foundG401 {
		t.Error("Expected to find G401 (weak crypto)")
	}
}

// TestGosecWithNoVulnerabilities tests gosec with clean code
func TestGosecWithNoVulnerabilities(t *testing.T) {
	scanner := gosec.New()

	// Skip if gosec is not installed
	if !scanner.IsAvailable() {
		t.Skip("gosec not installed, skipping integration test")
	}

	// Create a temporary directory with clean Go code
	tmpDir := t.TempDir()
	
	cleanCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
`

	// Write clean code to file
	mainFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainFile, []byte(cleanCode), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create go.mod file
	goModContent := `module testapp

go 1.21
`
	goModFile := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goModFile, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should have no findings for clean code
	if len(findings) > 0 {
		t.Logf("Unexpected findings in clean code:")
		for _, f := range findings {
			t.Logf("  - %s: %s", f.RuleID, f.Message)
		}
	}
}
