// +build integration

package integration

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coding-agent/cli/internal/policy"
	"github.com/coding-agent/cli/internal/sarif"
	"github.com/coding-agent/cli/internal/scanner"
)

func TestJSONReportGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create test findings
	findings := []scanner.Finding{
		{
			ID:          "f1",
			RuleID:      "sql-injection",
			Severity:    "critical",
			CWE:         "CWE-89",
			Description: "SQL injection vulnerability",
			FilePath:    "app.py",
			LineNumber:  42,
		},
		{
			ID:          "f2",
			RuleID:      "xss",
			Severity:    "high",
			CWE:         "CWE-79",
			Description: "XSS vulnerability",
			FilePath:    "web.js",
			LineNumber:  15,
		},
	}

	// Generate JSON report
	reportPath := filepath.Join(ctx.TempDir, "report.json")
	err := policy.GenerateJSONReport(findings, reportPath)
	if err != nil {
		t.Fatalf("Failed to generate JSON report: %v", err)
	}

	// Verify file exists
	AssertFileExists(t, reportPath)

	// Verify JSON is valid
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Invalid JSON report: %v", err)
	}

	// Verify report structure
	if _, ok := report["findings"]; !ok {
		t.Error("Report missing 'findings' field")
	}

	if _, ok := report["summary"]; !ok {
		t.Error("Report missing 'summary' field")
	}
}

func TestSARIFReportGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	findings := []scanner.Finding{
		{
			ID:          "f1",
			RuleID:      "hardcoded-secret",
			Severity:    "high",
			CWE:         "CWE-798",
			Description: "Hardcoded password detected",
			FilePath:    "config.py",
			LineNumber:  10,
			Scanner:     "bandit",
		},
	}

	// Generate SARIF report
	reportPath := filepath.Join(ctx.TempDir, "report.sarif")
	err := sarif.GenerateReport(findings, reportPath)
	if err != nil {
		t.Fatalf("Failed to generate SARIF report: %v", err)
	}

	AssertFileExists(t, reportPath)

	// Verify SARIF format
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("Failed to read SARIF report: %v", err)
	}

	var sarifDoc map[string]interface{}
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		t.Fatalf("Invalid SARIF JSON: %v", err)
	}

	// Verify SARIF 2.1.0 structure
	if version, ok := sarifDoc["version"].(string); !ok || version != "2.1.0" {
		t.Error("SARIF report missing or incorrect version")
	}

	if _, ok := sarifDoc["runs"]; !ok {
		t.Error("SARIF report missing 'runs' field")
	}
}

func TestMarkdownReportGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	findings := []scanner.Finding{
		{
			ID:          "f1",
			RuleID:      "command-injection",
			Severity:    "critical",
			CWE:         "CWE-78",
			Description: "Command injection vulnerability",
			FilePath:    "exec.py",
			LineNumber:  25,
		},
	}

	reportPath := filepath.Join(ctx.TempDir, "report.md")
	err := policy.GenerateMarkdownReport(findings, reportPath)
	if err != nil {
		t.Fatalf("Failed to generate Markdown report: %v", err)
	}

	AssertFileExists(t, reportPath)

	// Verify Markdown content
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("Failed to read Markdown report: %v", err)
	}

	content := string(data)

	// Check for expected sections
	if !strings.Contains(content, "# Security Scan Report") {
		t.Error("Markdown report missing title")
	}

	if !strings.Contains(content, "## Summary") {
		t.Error("Markdown report missing summary section")
	}

	if !strings.Contains(content, "## Findings") {
		t.Error("Markdown report missing findings section")
	}

	if !strings.Contains(content, "CWE-78") {
		t.Error("Markdown report missing CWE information")
	}
}

func TestHTMLReportGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	findings := []scanner.Finding{
		{
			ID:          "f1",
			RuleID:      "path-traversal",
			Severity:    "high",
			CWE:         "CWE-22",
			Description: "Path traversal vulnerability",
			FilePath:    "file_handler.py",
			LineNumber:  33,
		},
	}

	reportPath := filepath.Join(ctx.TempDir, "report.html")
	err := policy.GenerateHTMLReport(findings, reportPath)
	if err != nil {
		t.Fatalf("Failed to generate HTML report: %v", err)
	}

	AssertFileExists(t, reportPath)

	// Verify HTML content
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("Failed to read HTML report: %v", err)
	}

	content := string(data)

	// Check for HTML structure
	if !strings.Contains(content, "<html") {
		t.Error("HTML report missing html tag")
	}

	if !strings.Contains(content, "<head>") {
		t.Error("HTML report missing head section")
	}

	if !strings.Contains(content, "<body>") {
		t.Error("HTML report missing body section")
	}

	if !strings.Contains(content, "CWE-22") {
		t.Error("HTML report missing finding details")
	}
}

func TestCSVReportGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	findings := []scanner.Finding{
		{
			ID:          "f1",
			RuleID:      "xxe",
			Severity:    "high",
			CWE:         "CWE-611",
			Description: "XML external entity vulnerability",
			FilePath:    "parser.py",
			LineNumber:  18,
		},
		{
			ID:          "f2",
			RuleID:      "csrf",
			Severity:    "medium",
			CWE:         "CWE-352",
			Description: "CSRF vulnerability",
			FilePath:    "views.py",
			LineNumber:  55,
		},
	}

	reportPath := filepath.Join(ctx.TempDir, "report.csv")
	err := policy.GenerateCSVReport(findings, reportPath)
	if err != nil {
		t.Fatalf("Failed to generate CSV report: %v", err)
	}

	AssertFileExists(t, reportPath)

	// Verify CSV content
	file, err := os.Open(reportPath)
	if err != nil {
		t.Fatalf("Failed to open CSV report: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Verify header row
	if len(records) < 1 {
		t.Fatal("CSV report is empty")
	}

	header := records[0]
	expectedHeaders := []string{"ID", "Rule ID", "Severity", "CWE", "Description", "File", "Line"}
	for i, expected := range expectedHeaders {
		if i >= len(header) || header[i] != expected {
			t.Errorf("Expected header %s at position %d, got %s", expected, i, header[i])
		}
	}

	// Verify data rows
	if len(records) != 3 { // header + 2 findings
		t.Errorf("Expected 3 rows (header + 2 findings), got %d", len(records))
	}
}

func TestReportWithEmptyFindings(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	findings := []scanner.Finding{}

	// Test all formats with empty findings
	formats := map[string]func([]scanner.Finding, string) error{
		"json":     policy.GenerateJSONReport,
		"markdown": policy.GenerateMarkdownReport,
		"html":     policy.GenerateHTMLReport,
		"csv":      policy.GenerateCSVReport,
	}

	for format, generator := range formats {
		t.Run(format, func(t *testing.T) {
			reportPath := filepath.Join(ctx.TempDir, "empty."+format)
			err := generator(findings, reportPath)
			if err != nil {
				t.Fatalf("Failed to generate %s report with empty findings: %v", format, err)
			}

			AssertFileExists(t, reportPath)

			// Verify file is not empty
			info, err := os.Stat(reportPath)
			if err != nil {
				t.Fatalf("Failed to stat report file: %v", err)
			}

			if info.Size() == 0 {
				t.Errorf("Report file for %s is empty", format)
			}
		})
	}
}

func TestReportContentAccuracy(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	findings := []scanner.Finding{
		{
			ID:          "test-finding-1",
			RuleID:      "test-rule",
			Severity:    "critical",
			CWE:         "CWE-89",
			Description: "Test SQL injection",
			FilePath:    "test.py",
			LineNumber:  100,
			Scanner:     "bandit",
		},
	}

	// Generate JSON report
	reportPath := filepath.Join(ctx.TempDir, "accuracy.json")
	err := policy.GenerateJSONReport(findings, reportPath)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Read and parse report
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}

	var report struct {
		Findings []scanner.Finding `json:"findings"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Failed to parse report: %v", err)
	}

	// Verify finding details match
	if len(report.Findings) != 1 {
		t.Fatalf("Expected 1 finding in report, got %d", len(report.Findings))
	}

	finding := report.Findings[0]

	if finding.ID != "test-finding-1" {
		t.Errorf("Expected ID 'test-finding-1', got '%s'", finding.ID)
	}

	if finding.Severity != "critical" {
		t.Errorf("Expected severity 'critical', got '%s'", finding.Severity)
	}

	if finding.CWE != "CWE-89" {
		t.Errorf("Expected CWE 'CWE-89', got '%s'", finding.CWE)
	}

	if finding.LineNumber != 100 {
		t.Errorf("Expected line number 100, got %d", finding.LineNumber)
	}
}
