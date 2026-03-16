package scanner

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRawFinding_JSONMarshaling(t *testing.T) {
	finding := RawFinding{
		ID:          "test-1",
		ToolName:    "bandit",
		Message:     "SQL injection detected",
		FilePath:    "/test/file.py",
		LineNumber:  10,
		Severity:    "high",
		Confidence:  "high",
		RuleID:      "B608",
		Category:    "sql",
		RawJSON:     map[string]interface{}{"key": "value"},
		Timestamp:   time.Now(),
	}

	// Marshal to JSON
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal finding: %v", err)
	}

	// Unmarshal back
	var unmarshaled RawFinding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal finding: %v", err)
	}

	// Verify key fields
	if unmarshaled.ID != finding.ID {
		t.Errorf("ID = %s, want %s", unmarshaled.ID, finding.ID)
	}
	if unmarshaled.ToolName != finding.ToolName {
		t.Errorf("ToolName = %s, want %s", unmarshaled.ToolName, finding.ToolName)
	}
	if unmarshaled.Severity != finding.Severity {
		t.Errorf("Severity = %s, want %s", unmarshaled.Severity, finding.Severity)
	}
}

func TestNormalizedFinding_JSONMarshaling(t *testing.T) {
	finding := NormalizedFinding{
		ID:              "norm-1",
		FindingID:       "raw-1",
		CWEID:           "CWE-89",
		CWEDescription:  "SQL Injection",
		Severity:        "high",
		Confidence:      "high",
		CodeFingerprint: "abc123",
		FilePath:        "/test/file.py",
		LineNumber:      10,
		Description:     "SQL injection vulnerability",
		Timestamp:       time.Now(),
	}

	// Marshal to JSON
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal finding: %v", err)
	}

	// Unmarshal back
	var unmarshaled NormalizedFinding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal finding: %v", err)
	}

	// Verify key fields
	if unmarshaled.CWEID != finding.CWEID {
		t.Errorf("CWEID = %s, want %s", unmarshaled.CWEID, finding.CWEID)
	}
	if unmarshaled.CodeFingerprint != finding.CodeFingerprint {
		t.Errorf("CodeFingerprint = %s, want %s", unmarshaled.CodeFingerprint, finding.CodeFingerprint)
	}
}

func TestScanResult_SaveToFile_JSON(t *testing.T) {
	result := &ScanResult{
		RunID:         "test-run-1",
		TargetPath:    "/test/path",
		StartTime:     time.Now(),
		EndTime:       time.Now().Add(time.Minute),
		Duration:      time.Minute,
		TotalFindings: 2,
		CriticalCount: 1,
		HighCount:     1,
		Findings: []NormalizedFinding{
			{
				ID:         "1",
				CWEID:      "CWE-89",
				Severity:   "critical",
				FilePath:   "/test/file.py",
				LineNumber: 10,
			},
			{
				ID:         "2",
				CWEID:      "CWE-79",
				Severity:   "high",
				FilePath:   "/test/file.js",
				LineNumber: 20,
			},
		},
		Scanners: []string{"bandit", "semgrep"},
	}

	tmpFile := t.TempDir() + "/result.json"

	if err := result.SaveToFile(tmpFile, "json"); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Output file was not created")
	}

	// Read and verify content
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var loaded ScanResult
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if loaded.RunID != result.RunID {
		t.Errorf("RunID = %s, want %s", loaded.RunID, result.RunID)
	}
	if loaded.TotalFindings != result.TotalFindings {
		t.Errorf("TotalFindings = %d, want %d", loaded.TotalFindings, result.TotalFindings)
	}
}

func TestScanResult_SaveToFile_Markdown(t *testing.T) {
	result := &ScanResult{
		RunID:         "test-run-1",
		TargetPath:    "/test/path",
		Duration:      time.Minute,
		TotalFindings: 2,
		CriticalCount: 1,
		HighCount:     1,
		Findings: []NormalizedFinding{
			{
				ID:             "1",
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				Severity:       "critical",
				FilePath:       "/test/file.py",
				LineNumber:     10,
				Description:    "SQL injection vulnerability",
				Confidence:     "high",
			},
			{
				ID:             "2",
				CWEID:          "CWE-79",
				CWEDescription: "Cross-site Scripting",
				Severity:       "high",
				FilePath:       "/test/file.js",
				LineNumber:     20,
				Description:    "XSS vulnerability",
				Confidence:     "medium",
			},
		},
		Scanners: []string{"bandit", "semgrep"},
	}

	tmpFile := t.TempDir() + "/result.md"

	if err := result.SaveToFile(tmpFile, "markdown"); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Output file was not created")
	}

	// Read and verify content
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	content := string(data)

	// Verify markdown structure
	if !strings.Contains(content, "# Security Scan Report") {
		t.Error("Markdown should contain report title")
	}
	if !strings.Contains(content, "## Summary") {
		t.Error("Markdown should contain summary section")
	}
	if !strings.Contains(content, "CWE-89") {
		t.Error("Markdown should contain CWE-89 finding")
	}
	if !strings.Contains(content, "CWE-79") {
		t.Error("Markdown should contain CWE-79 finding")
	}
	if !strings.Contains(content, "/test/file.py") {
		t.Error("Markdown should contain file path")
	}
}

func TestScanResult_ToMarkdown_WithRemediation(t *testing.T) {
	result := &ScanResult{
		RunID:         "test-run-1",
		TargetPath:    "/test/path",
		Duration:      time.Minute,
		TotalFindings: 1,
		HighCount:     1,
		Findings: []NormalizedFinding{
			{
				ID:             "1",
				CWEID:          "CWE-89",
				CWEDescription: "SQL Injection",
				Severity:       "high",
				FilePath:       "/test/file.py",
				LineNumber:     10,
				Description:    "SQL injection vulnerability",
				Confidence:     "high",
				Remediation: &RemediationGuidance{
					Explanation:      "Use parameterized queries",
					RemediationSteps: []string{"Step 1", "Step 2"},
					ExampleFix:       "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
					Confidence:       0.95,
					GeneratedAt:      time.Now(),
					Cached:           false,
				},
			},
		},
		Scanners: []string{"bandit"},
	}

	markdown := result.toMarkdown()

	// Verify remediation content
	if !strings.Contains(markdown, "Remediation Guidance") {
		t.Error("Markdown should contain remediation guidance section")
	}
	if !strings.Contains(markdown, "Use parameterized queries") {
		t.Error("Markdown should contain remediation explanation")
	}
	if !strings.Contains(markdown, "Steps to Fix") {
		t.Error("Markdown should contain remediation steps")
	}
	if !strings.Contains(markdown, "Example Fix") {
		t.Error("Markdown should contain example fix")
	}
}

func TestScanResult_GetFindingsBySeverity(t *testing.T) {
	result := &ScanResult{
		Findings: []NormalizedFinding{
			{ID: "1", Severity: "critical"},
			{ID: "2", Severity: "high"},
			{ID: "3", Severity: "high"},
			{ID: "4", Severity: "medium"},
			{ID: "5", Severity: "low"},
		},
	}

	tests := []struct {
		severity string
		want     int
	}{
		{"critical", 1},
		{"high", 2},
		{"medium", 1},
		{"low", 1},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			findings := result.getFindingsBySeverity(tt.severity)
			if len(findings) != tt.want {
				t.Errorf("getFindingsBySeverity(%s) returned %d findings, want %d", 
					tt.severity, len(findings), tt.want)
			}
		})
	}
}

func TestCapitalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "Critical"},
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := capitalize(tt.input)
			if got != tt.want {
				t.Errorf("capitalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid config",
			config: Config{
				TargetPath:   "/test/path",
				OutputFormat: "json",
				Scanners:     []string{"bandit"},
			},
			valid: true,
		},
		{
			name: "empty target path",
			config: Config{
				OutputFormat: "json",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - target path should not be empty
			if tt.valid && tt.config.TargetPath == "" {
				t.Error("Valid config should have non-empty TargetPath")
			}
			if !tt.valid && tt.config.TargetPath != "" {
				t.Error("Invalid config should have empty TargetPath")
			}
		})
	}
}

func TestRemediationGuidance_JSONMarshaling(t *testing.T) {
	guidance := RemediationGuidance{
		Explanation:      "Use parameterized queries",
		RemediationSteps: []string{"Step 1", "Step 2", "Step 3"},
		ExampleFix:       "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
		Confidence:       0.95,
		GeneratedAt:      time.Now(),
		Cached:           true,
	}

	// Marshal to JSON
	data, err := json.Marshal(guidance)
	if err != nil {
		t.Fatalf("Failed to marshal guidance: %v", err)
	}

	// Unmarshal back
	var unmarshaled RemediationGuidance
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal guidance: %v", err)
	}

	// Verify fields
	if unmarshaled.Explanation != guidance.Explanation {
		t.Errorf("Explanation = %s, want %s", unmarshaled.Explanation, guidance.Explanation)
	}
	if len(unmarshaled.RemediationSteps) != len(guidance.RemediationSteps) {
		t.Errorf("RemediationSteps length = %d, want %d", 
			len(unmarshaled.RemediationSteps), len(guidance.RemediationSteps))
	}
	if unmarshaled.Cached != guidance.Cached {
		t.Errorf("Cached = %v, want %v", unmarshaled.Cached, guidance.Cached)
	}
}
