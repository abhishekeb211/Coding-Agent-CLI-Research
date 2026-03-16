package sarif

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/coding-agent/cli/internal/scanner"
)

// TestConvertToSARIF tests SARIF document generation from findings
func TestConvertToSARIF(t *testing.T) {
	tests := []struct {
		name    string
		result  *scanner.ScanResult
		wantErr bool
	}{
		{
			name: "valid scan result with findings",
			result: &scanner.ScanResult{
				RunID:      "test-run-1",
				TargetPath: "/test/path",
				StartTime:  time.Now(),
				EndTime:    time.Now().Add(time.Minute),
				Findings: []scanner.NormalizedFinding{
					{
						ID:              "finding-1",
						CWEID:           "CWE-89",
						CWEDescription:  "SQL Injection",
						Severity:        "high",
						Confidence:      "high",
						CodeFingerprint: "abc123",
						FilePath:        "/test/file.py",
						LineNumber:      42,
						Description:     "SQL injection vulnerability detected",
					},
					{
						ID:              "finding-2",
						CWEID:           "CWE-79",
						CWEDescription:  "Cross-site Scripting",
						Severity:        "medium",
						Confidence:      "medium",
						CodeFingerprint: "def456",
						FilePath:        "/test/file2.js",
						LineNumber:      10,
						Description:     "XSS vulnerability detected",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty findings",
			result: &scanner.ScanResult{
				RunID:      "test-run-2",
				TargetPath: "/test/path",
				StartTime:  time.Now(),
				EndTime:    time.Now().Add(time.Minute),
				Findings:   []scanner.NormalizedFinding{},
			},
			wantErr: false,
		},
		{
			name: "multiple findings same CWE",
			result: &scanner.ScanResult{
				RunID:      "test-run-3",
				TargetPath: "/test/path",
				StartTime:  time.Now(),
				EndTime:    time.Now().Add(time.Minute),
				Findings: []scanner.NormalizedFinding{
					{
						ID:              "finding-1",
						CWEID:           "CWE-89",
						CWEDescription:  "SQL Injection",
						Severity:        "high",
						FilePath:        "/test/file1.py",
						LineNumber:      10,
						Description:     "SQL injection in query 1",
					},
					{
						ID:              "finding-2",
						CWEID:           "CWE-89",
						CWEDescription:  "SQL Injection",
						Severity:        "high",
						FilePath:        "/test/file2.py",
						LineNumber:      20,
						Description:     "SQL injection in query 2",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertToSARIF(tt.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertToSARIF() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify SARIF version
				if got.Version != "2.1.0" {
					t.Errorf("ConvertToSARIF() version = %v, want 2.1.0", got.Version)
				}

				// Verify schema
				expectedSchema := "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
				if got.Schema != expectedSchema {
					t.Errorf("ConvertToSARIF() schema = %v, want %v", got.Schema, expectedSchema)
				}

				// Verify runs
				if len(got.Runs) != 1 {
					t.Errorf("ConvertToSARIF() runs count = %v, want 1", len(got.Runs))
				}

				if len(got.Runs) > 0 {
					run := got.Runs[0]

					// Verify tool info
					if run.Tool.Driver.Name != "Coding Agent CLI" {
						t.Errorf("ConvertToSARIF() tool name = %v, want Coding Agent CLI", run.Tool.Driver.Name)
					}

					// Verify results count matches findings
					if len(run.Results) != len(tt.result.Findings) {
						t.Errorf("ConvertToSARIF() results count = %v, want %v", len(run.Results), len(tt.result.Findings))
					}

					// Verify invocations
					if len(run.Invocations) != 1 {
						t.Errorf("ConvertToSARIF() invocations count = %v, want 1", len(run.Invocations))
					}

					if len(run.Invocations) > 0 {
						if !run.Invocations[0].ExecutionSuccessful {
							t.Error("ConvertToSARIF() execution should be successful")
						}
					}

					// Verify originalUriBaseIds
					if _, exists := run.OriginalUriBaseIds["ROOTPATH"]; !exists {
						t.Error("ConvertToSARIF() missing ROOTPATH in originalUriBaseIds")
					}
				}
			}
		})
	}
}

// TestSARIFRuleGeneration tests SARIF rule generation
func TestSARIFRuleGeneration(t *testing.T) {
	result := &scanner.ScanResult{
		RunID:      "test-run",
		TargetPath: "/test/path",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Minute),
		Findings: []scanner.NormalizedFinding{
			{
				ID:              "finding-1",
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "high",
				Confidence:      "high",
				FilePath:        "/test/file.py",
				LineNumber:      42,
				Description:     "SQL injection vulnerability",
			},
			{
				ID:              "finding-2",
				CWEID:           "CWE-79",
				CWEDescription:  "Cross-site Scripting",
				Severity:        "medium",
				Confidence:      "medium",
				FilePath:        "/test/file.js",
				LineNumber:      10,
				Description:     "XSS vulnerability",
			},
		},
	}

	sarif, err := ConvertToSARIF(result)
	if err != nil {
		t.Fatalf("ConvertToSARIF() error = %v", err)
	}

	run := sarif.Runs[0]

	// Verify rules are generated for unique CWEs
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Verify rule IDs match CWE IDs
	ruleIDs := make(map[string]bool)
	for _, rule := range run.Tool.Driver.Rules {
		ruleIDs[rule.ID] = true

		// Verify rule has required fields
		if rule.ID == "" {
			t.Error("Rule ID should not be empty")
		}
		if rule.ShortDescription == nil {
			t.Error("Rule should have short description")
		}
		if rule.Properties == nil {
			t.Error("Rule should have properties")
		}
	}

	if !ruleIDs["CWE-89"] {
		t.Error("Missing rule for CWE-89")
	}
	if !ruleIDs["CWE-79"] {
		t.Error("Missing rule for CWE-79")
	}
}

// TestSARIFLocationMapping tests SARIF location mapping
func TestSARIFLocationMapping(t *testing.T) {
	result := &scanner.ScanResult{
		RunID:      "test-run",
		TargetPath: "/test/path",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Minute),
		Findings: []scanner.NormalizedFinding{
			{
				ID:         "finding-1",
				CWEID:      "CWE-89",
				FilePath:   "/test/file.py",
				LineNumber: 42,
			},
		},
	}

	sarif, err := ConvertToSARIF(result)
	if err != nil {
		t.Fatalf("ConvertToSARIF() error = %v", err)
	}

	run := sarif.Runs[0]
	if len(run.Results) == 0 {
		t.Fatal("Expected at least one result")
	}

	result1 := run.Results[0]

	// Verify location structure
	if len(result1.Locations) != 1 {
		t.Errorf("Expected 1 location, got %d", len(result1.Locations))
	}

	location := result1.Locations[0]

	// Verify artifact location
	if location.PhysicalLocation.ArtifactLocation.URI != "/test/file.py" {
		t.Errorf("Expected URI /test/file.py, got %s", location.PhysicalLocation.ArtifactLocation.URI)
	}

	if location.PhysicalLocation.ArtifactLocation.URIBaseID != "ROOTPATH" {
		t.Errorf("Expected URIBaseID ROOTPATH, got %s", location.PhysicalLocation.ArtifactLocation.URIBaseID)
	}

	// Verify region
	if location.PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("Expected StartLine 42, got %d", location.PhysicalLocation.Region.StartLine)
	}
}

// TestMapSeverityToLevel tests severity to SARIF level mapping
func TestMapSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "warning"},
		{"", "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := mapSeverityToLevel(tt.severity)
			if got != tt.want {
				t.Errorf("mapSeverityToLevel(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

// TestMapSeverityToScore tests severity to security score mapping
func TestMapSeverityToScore(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "9.0"},
		{"high", "7.0"},
		{"medium", "5.0"},
		{"low", "3.0"},
		{"unknown", "5.0"},
		{"", "5.0"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := mapSeverityToScore(tt.severity)
			if got != tt.want {
				t.Errorf("mapSeverityToScore(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

// TestSARIFToJSON tests JSON serialization
func TestSARIFToJSON(t *testing.T) {
	sarif := &SARIF{
		Version: "2.1.0",
		Schema:  "https://example.com/schema.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:    "Test Tool",
						Version: "1.0.0",
					},
				},
				Results: []Result{},
			},
		},
	}

	data, err := sarif.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed SARIF
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("ToJSON() produced invalid JSON: %v", err)
	}

	// Verify content
	if parsed.Version != "2.1.0" {
		t.Errorf("Parsed version = %v, want 2.1.0", parsed.Version)
	}
}

// TestSARIFCompliance tests SARIF 2.1.0 format compliance
func TestSARIFCompliance(t *testing.T) {
	result := &scanner.ScanResult{
		RunID:      "test-run",
		TargetPath: "/test/path",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Minute),
		Findings: []scanner.NormalizedFinding{
			{
				ID:              "finding-1",
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "high",
				Confidence:      "high",
				CodeFingerprint: "abc123",
				FilePath:        "/test/file.py",
				LineNumber:      42,
				Description:     "SQL injection vulnerability",
			},
		},
	}

	sarif, err := ConvertToSARIF(result)
	if err != nil {
		t.Fatalf("ConvertToSARIF() error = %v", err)
	}

	// Verify required SARIF fields
	if sarif.Version == "" {
		t.Error("SARIF version is required")
	}
	if sarif.Schema == "" {
		t.Error("SARIF schema is required")
	}
	if len(sarif.Runs) == 0 {
		t.Error("SARIF must have at least one run")
	}

	run := sarif.Runs[0]

	// Verify required run fields
	if run.Tool.Driver.Name == "" {
		t.Error("Tool driver name is required")
	}

	// Verify result structure
	if len(run.Results) > 0 {
		result := run.Results[0]

		if result.RuleID == "" {
			t.Error("Result ruleId is required")
		}
		if result.Level == "" {
			t.Error("Result level is required")
		}
		if result.Message.Text == "" {
			t.Error("Result message text is required")
		}
		if len(result.Locations) == 0 {
			t.Error("Result must have at least one location")
		}
	}
}

// TestSARIFWithMultipleRuns tests SARIF with multiple runs
func TestSARIFWithMultipleRuns(t *testing.T) {
	result := &scanner.ScanResult{
		RunID:      "test-run",
		TargetPath: "/test/path",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Minute),
		Findings: []scanner.NormalizedFinding{
			{
				ID:         "finding-1",
				CWEID:      "CWE-89",
				FilePath:   "/test/file.py",
				LineNumber: 42,
			},
		},
	}

	sarif, err := ConvertToSARIF(result)
	if err != nil {
		t.Fatalf("ConvertToSARIF() error = %v", err)
	}

	// Current implementation creates one run per scan
	if len(sarif.Runs) != 1 {
		t.Errorf("Expected 1 run, got %d", len(sarif.Runs))
	}
}

// TestSARIFResultProperties tests result properties
func TestSARIFResultProperties(t *testing.T) {
	result := &scanner.ScanResult{
		RunID:      "test-run",
		TargetPath: "/test/path",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Minute),
		Findings: []scanner.NormalizedFinding{
			{
				ID:              "finding-1",
				CWEID:           "CWE-89",
				Severity:        "high",
				Confidence:      "high",
				CodeFingerprint: "abc123",
				FilePath:        "/test/file.py",
				LineNumber:      42,
			},
		},
	}

	sarif, err := ConvertToSARIF(result)
	if err != nil {
		t.Fatalf("ConvertToSARIF() error = %v", err)
	}

	run := sarif.Runs[0]
	if len(run.Results) == 0 {
		t.Fatal("Expected at least one result")
	}

	result1 := run.Results[0]

	// Verify properties are set
	if result1.Properties == nil {
		t.Fatal("Result properties should not be nil")
	}

	if result1.Properties.Fingerprint != "abc123" {
		t.Errorf("Expected fingerprint abc123, got %s", result1.Properties.Fingerprint)
	}

	if result1.Properties.CWE != "CWE-89" {
		t.Errorf("Expected CWE CWE-89, got %s", result1.Properties.CWE)
	}

	if result1.Properties.Confidence != "high" {
		t.Errorf("Expected confidence high, got %s", result1.Properties.Confidence)
	}
}

// TestSARIFRuleIndex tests rule index mapping
func TestSARIFRuleIndex(t *testing.T) {
	result := &scanner.ScanResult{
		RunID:      "test-run",
		TargetPath: "/test/path",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Minute),
		Findings: []scanner.NormalizedFinding{
			{
				ID:         "finding-1",
				CWEID:      "CWE-89",
				FilePath:   "/test/file.py",
				LineNumber: 10,
			},
			{
				ID:         "finding-2",
				CWEID:      "CWE-79",
				FilePath:   "/test/file.js",
				LineNumber: 20,
			},
			{
				ID:         "finding-3",
				CWEID:      "CWE-89",
				FilePath:   "/test/file2.py",
				LineNumber: 30,
			},
		},
	}

	sarif, err := ConvertToSARIF(result)
	if err != nil {
		t.Fatalf("ConvertToSARIF() error = %v", err)
	}

	run := sarif.Runs[0]

	// Verify rule indices are correct
	for _, result := range run.Results {
		if result.RuleIndex < 0 || result.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("Invalid rule index %d for result %s", result.RuleIndex, result.RuleID)
		}

		// Verify rule index points to correct rule
		rule := run.Tool.Driver.Rules[result.RuleIndex]
		if rule.ID != result.RuleID {
			t.Errorf("Rule index mismatch: result ruleId=%s, rule id=%s", result.RuleID, rule.ID)
		}
	}
}

// TestSARIFEdgeCases tests edge cases
func TestSARIFEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		result  *scanner.ScanResult
		wantErr bool
	}{
		{
			name: "finding with missing file path",
			result: &scanner.ScanResult{
				RunID:      "test-run",
				TargetPath: "/test/path",
				StartTime:  time.Now(),
				EndTime:    time.Now().Add(time.Minute),
				Findings: []scanner.NormalizedFinding{
					{
						ID:         "finding-1",
						CWEID:      "CWE-89",
						FilePath:   "",
						LineNumber: 42,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "finding with zero line number",
			result: &scanner.ScanResult{
				RunID:      "test-run",
				TargetPath: "/test/path",
				StartTime:  time.Now(),
				EndTime:    time.Now().Add(time.Minute),
				Findings: []scanner.NormalizedFinding{
					{
						ID:         "finding-1",
						CWEID:      "CWE-89",
						FilePath:   "/test/file.py",
						LineNumber: 0,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "finding with special characters in description",
			result: &scanner.ScanResult{
				RunID:      "test-run",
				TargetPath: "/test/path",
				StartTime:  time.Now(),
				EndTime:    time.Now().Add(time.Minute),
				Findings: []scanner.NormalizedFinding{
					{
						ID:          "finding-1",
						CWEID:       "CWE-89",
						FilePath:    "/test/file.py",
						LineNumber:  42,
						Description: "SQL injection with <special> & \"characters\"",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ConvertToSARIF(tt.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertToSARIF() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
