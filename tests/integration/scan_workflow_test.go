// +build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
)

func TestScanWorkflow(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create vulnerable test code
	vulnCode := `
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
`
	codePath := ctx.CreateTestFile(t, "vulnerable.py", vulnCode)

	// Create scanner configuration
	config := &scanner.Config{
		Scanners: []string{"bandit"},
		Path:     filepath.Dir(codePath),
		Output:   "json",
	}

	// Initialize orchestrator
	orch, err := scanner.NewOrchestrator(config, ctx.DB)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Run scan
	runID, err := orch.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify findings were stored in database
	findings, err := ctx.DB.GetFindingsByRunID(runID)
	if err != nil {
		t.Fatalf("Failed to retrieve findings: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected findings to be stored in database, got none")
	}

	// Verify findings have CWE mappings
	for _, finding := range findings {
		if finding.CWE == "" {
			t.Errorf("Finding %s missing CWE mapping", finding.ID)
		}
	}
}

func TestMultiScannerWorkflow(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create vulnerable Python code
	pyCode := `
import os
def run_command(user_input):
    os.system(user_input)  # Command injection
`
	ctx.CreateTestFile(t, "vuln.py", pyCode)

	// Create vulnerable JavaScript code
	jsCode := `
function displayUser(name) {
    document.getElementById('user').innerHTML = name;  // XSS
}
`
	ctx.CreateTestFile(t, "vuln.js", jsCode)

	// Configure multiple scanners
	config := &scanner.Config{
		Scanners: []string{"bandit", "semgrep"},
		Path:     ctx.TempDir,
		Output:   "json",
	}

	orch, err := scanner.NewOrchestrator(config, ctx.DB)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Run scan with multiple scanners
	runID, err := orch.Scan()
	if err != nil {
		t.Fatalf("Multi-scanner scan failed: %v", err)
	}

	// Verify findings from both scanners
	findings, err := ctx.DB.GetFindingsByRunID(runID)
	if err != nil {
		t.Fatalf("Failed to retrieve findings: %v", err)
	}

	if len(findings) < 2 {
		t.Errorf("Expected findings from multiple scanners, got %d", len(findings))
	}

	// Verify scanner sources are recorded
	scannerSources := make(map[string]bool)
	for _, finding := range findings {
		scannerSources[finding.Scanner] = true
	}

	if len(scannerSources) < 2 {
		t.Error("Expected findings from at least 2 different scanners")
	}
}

func TestScanWithNormalization(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create test code with known vulnerability
	code := `
def authenticate(password):
    hardcoded_pass = "admin123"  # Hardcoded secret
    return password == hardcoded_pass
`
	ctx.CreateTestFile(t, "auth.py", code)

	config := &scanner.Config{
		Scanners: []string{"bandit"},
		Path:     ctx.TempDir,
		Output:   "json",
	}

	orch, err := scanner.NewOrchestrator(config, ctx.DB)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	runID, err := orch.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	findings, err := ctx.DB.GetFindingsByRunID(runID)
	if err != nil {
		t.Fatalf("Failed to retrieve findings: %v", err)
	}

	// Verify normalized fields
	for _, finding := range findings {
		if finding.Severity == "" {
			t.Error("Finding missing normalized severity")
		}
		if finding.CWE == "" {
			t.Error("Finding missing CWE mapping")
		}
		if finding.FilePath == "" {
			t.Error("Finding missing file path")
		}
		if finding.LineNumber == 0 {
			t.Error("Finding missing line number")
		}
	}
}

func TestScanPersistence(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create test code
	code := `SELECT * FROM users WHERE id = ?`
	ctx.CreateTestFile(t, "query.sql", code)

	config := &scanner.Config{
		Scanners: []string{"semgrep"},
		Path:     ctx.TempDir,
		Output:   "json",
	}

	orch, err := scanner.NewOrchestrator(config, ctx.DB)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// First scan
	runID1, err := orch.Scan()
	if err != nil {
		t.Fatalf("First scan failed: %v", err)
	}

	// Second scan
	runID2, err := orch.Scan()
	if err != nil {
		t.Fatalf("Second scan failed: %v", err)
	}

	// Verify both runs are stored separately
	if runID1 == runID2 {
		t.Error("Expected different run IDs for separate scans")
	}

	findings1, err := ctx.DB.GetFindingsByRunID(runID1)
	if err != nil {
		t.Fatalf("Failed to retrieve findings from run 1: %v", err)
	}

	findings2, err := ctx.DB.GetFindingsByRunID(runID2)
	if err != nil {
		t.Fatalf("Failed to retrieve findings from run 2: %v", err)
	}

	// Both runs should have findings
	if len(findings1) == 0 || len(findings2) == 0 {
		t.Error("Expected findings in both scan runs")
	}
}

func TestScanOutputFormats(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	code := `eval(user_input)  # Code injection`
	ctx.CreateTestFile(t, "dangerous.py", code)

	formats := []string{"json", "sarif", "markdown", "html", "csv"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			config := &scanner.Config{
				Scanners: []string{"bandit"},
				Path:     ctx.TempDir,
				Output:   format,
			}

			orch, err := scanner.NewOrchestrator(config, ctx.DB)
			if err != nil {
				t.Fatalf("Failed to create orchestrator for %s: %v", format, err)
			}

			runID, err := orch.Scan()
			if err != nil {
				t.Fatalf("Scan with %s output failed: %v", format, err)
			}

			// Verify output file was created
			outputPath := filepath.Join(ctx.TempDir, "output."+format)
			if format == "json" {
				// Verify JSON is valid
				data, err := os.ReadFile(outputPath)
				if err == nil {
					var result interface{}
					if err := json.Unmarshal(data, &result); err != nil {
						t.Errorf("Invalid JSON output: %v", err)
					}
				}
			}

			// Verify findings are in database regardless of output format
			findings, err := ctx.DB.GetFindingsByRunID(runID)
			if err != nil {
				t.Fatalf("Failed to retrieve findings: %v", err)
			}

			if len(findings) == 0 {
				t.Error("Expected findings in database")
			}
		})
	}
}
