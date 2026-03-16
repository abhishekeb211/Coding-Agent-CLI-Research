package scanner

import (
	"context"
	"os"
	"testing"
)

// MockScanner is a mock scanner for testing
type MockScanner struct {
	name      string
	available bool
	findings  []RawFinding
	err       error
}

func (m *MockScanner) Name() string {
	return m.name
}

func (m *MockScanner) Scan(ctx context.Context, path string) ([]RawFinding, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

func (m *MockScanner) IsAvailable() bool {
	return m.available
}

func TestNewOrchestrator(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "basic configuration",
			config: Config{
				TargetPath:   "/test/path",
				OutputFormat: "json",
			},
		},
		{
			name: "offline mode configuration",
			config: Config{
				TargetPath:  "/test/path",
				OfflineMode: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := NewOrchestrator(tt.config)
			if orch == nil {
				t.Fatal("NewOrchestrator returned nil")
			}
			if orch.config.TargetPath != tt.config.TargetPath {
				t.Errorf("TargetPath = %v, want %v", orch.config.TargetPath, tt.config.TargetPath)
			}
			if orch.llmEnabled {
				t.Error("LLM should not be enabled by default")
			}
			if orch.policyEnabled {
				t.Error("Policy should not be enabled by default")
			}
		})
	}
}

func TestOrchestrator_RegisterScanner(t *testing.T) {
	tests := []struct {
		name            string
		scanner         Scanner
		wantRegistered  bool
	}{
		{
			name: "available scanner",
			scanner: &MockScanner{
				name:      "test-scanner",
				available: true,
			},
			wantRegistered: true,
		},
		{
			name: "unavailable scanner",
			scanner: &MockScanner{
				name:      "unavailable-scanner",
				available: false,
			},
			wantRegistered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := NewOrchestrator(Config{})
			initialCount := len(orch.scanners)
			
			orch.RegisterScanner(tt.scanner)
			
			finalCount := len(orch.scanners)
			if tt.wantRegistered {
				if finalCount != initialCount+1 {
					t.Errorf("Scanner not registered, count = %d, want %d", finalCount, initialCount+1)
				}
			} else {
				if finalCount != initialCount {
					t.Errorf("Unavailable scanner was registered, count = %d, want %d", finalCount, initialCount)
				}
			}
		})
	}
}

func TestOrchestrator_NormalizeSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{"critical uppercase", "CRITICAL", "critical"},
		{"critical lowercase", "critical", "critical"},
		{"error maps to critical", "ERROR", "critical"},
		{"high uppercase", "HIGH", "high"},
		{"high lowercase", "high", "high"},
		{"warning maps to high", "WARNING", "high"},
		{"medium uppercase", "MEDIUM", "medium"},
		{"medium lowercase", "medium", "medium"},
		{"info maps to medium", "INFO", "medium"},
		{"low uppercase", "LOW", "low"},
		{"low lowercase", "low", "low"},
		{"note maps to low", "NOTE", "low"},
		{"unknown defaults to medium", "unknown", "medium"},
	}

	orch := NewOrchestrator(Config{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orch.normalizeSeverity(tt.severity)
			if got != tt.want {
				t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestOrchestrator_GenerateFingerprint(t *testing.T) {
	orch := NewOrchestrator(Config{})

	finding1 := RawFinding{
		FilePath:   "/test/file.py",
		RuleID:     "B101",
		LineNumber: 10,
		Message:    "Test message",
	}

	finding2 := RawFinding{
		FilePath:   "/test/file.py",
		RuleID:     "B101",
		LineNumber: 10,
		Message:    "Test message",
	}

	finding3 := RawFinding{
		FilePath:   "/test/file.py",
		RuleID:     "B101",
		LineNumber: 11, // Different line
		Message:    "Test message",
	}

	fp1 := orch.generateFingerprint(finding1)
	fp2 := orch.generateFingerprint(finding2)
	fp3 := orch.generateFingerprint(finding3)

	// Same findings should have same fingerprint
	if fp1 != fp2 {
		t.Error("Identical findings should have same fingerprint")
	}

	// Different findings should have different fingerprints
	if fp1 == fp3 {
		t.Error("Different findings should have different fingerprints")
	}

	// Fingerprint should be non-empty
	if fp1 == "" {
		t.Error("Fingerprint should not be empty")
	}
}

func TestOrchestrator_DeduplicateFindings(t *testing.T) {
	orch := NewOrchestrator(Config{})

	findings := []NormalizedFinding{
		{
			ID:              "1",
			CodeFingerprint: "fp1",
			Description:     "Finding 1",
		},
		{
			ID:              "2",
			CodeFingerprint: "fp1", // Duplicate
			Description:     "Finding 1 duplicate",
		},
		{
			ID:              "3",
			CodeFingerprint: "fp2",
			Description:     "Finding 2",
		},
		{
			ID:              "4",
			CodeFingerprint: "fp2", // Duplicate
			Description:     "Finding 2 duplicate",
		},
		{
			ID:              "5",
			CodeFingerprint: "fp3",
			Description:     "Finding 3",
		},
	}

	deduplicated := orch.deduplicateFindings(findings)

	if len(deduplicated) != 3 {
		t.Errorf("Expected 3 unique findings, got %d", len(deduplicated))
	}

	// Verify unique fingerprints
	seen := make(map[string]bool)
	for _, f := range deduplicated {
		if seen[f.CodeFingerprint] {
			t.Errorf("Duplicate fingerprint found: %s", f.CodeFingerprint)
		}
		seen[f.CodeFingerprint] = true
	}
}

func TestOrchestrator_CountBySeverity(t *testing.T) {
	orch := NewOrchestrator(Config{})

	findings := []NormalizedFinding{
		{Severity: "critical"},
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "medium"},
		{Severity: "low"},
	}

	critical, high, medium, low := orch.countBySeverity(findings)

	if critical != 2 {
		t.Errorf("Critical count = %d, want 2", critical)
	}
	if high != 3 {
		t.Errorf("High count = %d, want 3", high)
	}
	if medium != 2 {
		t.Errorf("Medium count = %d, want 2", medium)
	}
	if low != 1 {
		t.Errorf("Low count = %d, want 1", low)
	}
}

func TestOrchestrator_NormalizeFindings(t *testing.T) {
	orch := NewOrchestrator(Config{})

	rawFindings := []RawFinding{
		{
			ID:         "raw1",
			ToolName:   "bandit",
			Message:    "SQL injection vulnerability",
			FilePath:   "/test/file.py",
			LineNumber: 10,
			Severity:   "HIGH",
			Confidence: "high",
			RuleID:     "B608",
			Category:   "sql",
		},
		{
			ID:         "raw2",
			ToolName:   "semgrep",
			Message:    "XSS vulnerability",
			FilePath:   "/test/file.js",
			LineNumber: 20,
			Severity:   "MEDIUM",
			Confidence: "medium",
			RuleID:     "javascript.xss",
			Category:   "xss",
		},
	}

	normalized := orch.normalizeFindings(rawFindings, "test-run-id")

	if len(normalized) != 2 {
		t.Fatalf("Expected 2 normalized findings, got %d", len(normalized))
	}

	// Check first finding
	if normalized[0].FindingID != "raw1" {
		t.Errorf("FindingID = %s, want raw1", normalized[0].FindingID)
	}
	if normalized[0].Severity != "high" {
		t.Errorf("Severity = %s, want high", normalized[0].Severity)
	}
	if normalized[0].FilePath != "/test/file.py" {
		t.Errorf("FilePath = %s, want /test/file.py", normalized[0].FilePath)
	}
	if normalized[0].CodeFingerprint == "" {
		t.Error("CodeFingerprint should not be empty")
	}

	// Check second finding
	if normalized[1].Severity != "medium" {
		t.Errorf("Severity = %s, want medium", normalized[1].Severity)
	}
}

func TestOrchestrator_ExtractCodeSnippet(t *testing.T) {
	// Create a temporary test file
	content := `line 1
line 2
line 3
line 4
line 5
line 6
line 7
line 8
line 9
line 10
line 11
line 12`

	tmpFile := t.TempDir() + "/test.txt"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	orch := NewOrchestrator(Config{})

	tests := []struct {
		name       string
		lineNumber int
		wantLines  int
	}{
		{
			name:       "middle of file",
			lineNumber: 6,
			wantLines:  11, // 5 before + target + 5 after
		},
		{
			name:       "near start",
			lineNumber: 2,
			wantLines:  7, // Limited by file start
		},
		{
			name:       "near end",
			lineNumber: 11,
			wantLines:  7, // 5 before + target + 1 after (limited by file end at line 12)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snippet := orch.extractCodeSnippet(tmpFile, tt.lineNumber)
			if snippet == "" {
				t.Error("Snippet should not be empty")
			}
			
			lines := splitLines(snippet)
			// Account for trailing newline creating empty line
			actualLines := len(lines)
			if lines[len(lines)-1] == "" {
				actualLines--
			}
			
			if actualLines != tt.wantLines {
				t.Errorf("Expected %d lines, got %d", tt.wantLines, actualLines)
			}
		})
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name:    "single line",
			content: "line 1",
			want:    1,
		},
		{
			name:    "multiple lines",
			content: "line 1\nline 2\nline 3",
			want:    3,
		},
		{
			name:    "empty string",
			content: "",
			want:    0,
		},
		{
			name:    "trailing newline",
			content: "line 1\nline 2\n",
			want:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := splitLines(tt.content)
			if len(lines) != tt.want {
				t.Errorf("splitLines() returned %d lines, want %d", len(lines), tt.want)
			}
		})
	}
}

func TestMaxMin(t *testing.T) {
	if max(5, 10) != 10 {
		t.Error("max(5, 10) should be 10")
	}
	if max(10, 5) != 10 {
		t.Error("max(10, 5) should be 10")
	}
	if min(5, 10) != 5 {
		t.Error("min(5, 10) should be 5")
	}
	if min(10, 5) != 5 {
		t.Error("min(10, 5) should be 5")
	}
}
