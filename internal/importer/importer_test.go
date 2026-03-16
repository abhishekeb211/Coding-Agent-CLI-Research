package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/coding-agent/cli/internal/sarif"
	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
)

func setupTestDB(t *testing.T) (*storage.Database, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	cleanup := func() {
		db.Close()
	}

	return db, cleanup
}

func TestImporter_ImportFromJSON_ScanResult(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create test scan result
	scanResult := scanner.ScanResult{
		RunID:      "test-run-123",
		TargetPath: "/test/path",
		Findings: []scanner.NormalizedFinding{
			{
				ID:              "finding-1",
				FindingID:       "raw-1",
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "high",
				Confidence:      "high",
				CodeFingerprint: "test-fingerprint-1",
				FilePath:        "test.py",
				LineNumber:      10,
				Description:     "SQL injection vulnerability",
			},
		},
	}

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "scan-result.json")
	data, err := json.Marshal(scanResult)
	if err != nil {
		t.Fatalf("Failed to marshal scan result: %v", err)
	}
	err = os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Import
	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:     ImportModeReplace,
		ToolName: "test-tool",
	}

	result, err := imp.ImportFromJSON(tmpFile, opts)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result is nil")
	}
	if result.TotalFindings != 1 {
		t.Errorf("Expected 1 total finding, got %d", result.TotalFindings)
	}
	if result.ImportedFindings != 1 {
		t.Errorf("Expected 1 imported finding, got %d", result.ImportedFindings)
	}

	// Verify finding was saved
	findings, err := db.GetFindingsByRun("test-run-123")
	if err != nil {
		t.Fatalf("Failed to get findings: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].CWEID != "CWE-89" {
		t.Errorf("Expected CWE-89, got %s", findings[0].CWEID)
	}
}

func TestImporter_ImportFromSARIF(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create test SARIF document
	sarifDoc := sarif.SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: sarif.Driver{
						Name:    "Test Scanner",
						Version: "1.0.0",
						Rules: []sarif.Rule{
							{
								ID:   "CWE-89",
								Name: "SQL Injection",
								ShortDescription: &sarif.Message{
									Text: "SQL Injection vulnerability",
								},
							},
						},
					},
				},
				Results: []sarif.Result{
					{
						RuleID: "CWE-89",
						Level:  "error",
						Message: sarif.Message{
							Text: "Possible SQL injection",
						},
						Locations: []sarif.Location{
							{
								PhysicalLocation: sarif.PhysicalLocation{
									ArtifactLocation: sarif.ArtifactLocation{
										URI: "database.py",
									},
									Region: sarif.Region{
										StartLine: 42,
									},
								},
							},
						},
						Properties: &sarif.ResultProperties{
							Fingerprint: "sarif-fingerprint-1",
							CWE:         "CWE-89",
							Confidence:  "high",
						},
					},
				},
			},
		},
	}

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "results.sarif")
	data, err := json.Marshal(sarifDoc)
	if err != nil {
		t.Fatalf("Failed to marshal SARIF: %v", err)
	}
	err = os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Import
	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:       ImportModeReplace,
		RunID:      "sarif-run-789",
		TargetPath: "/test/sarif",
		ToolName:   "test-scanner",
	}

	result, err := imp.ImportFromSARIF(tmpFile, opts)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result is nil")
	}
	if result.TotalFindings != 1 {
		t.Errorf("Expected 1 total finding, got %d", result.TotalFindings)
	}
	if result.ImportedFindings != 1 {
		t.Errorf("Expected 1 imported finding, got %d", result.ImportedFindings)
	}

	// Verify finding was saved
	findings, err := db.GetFindingsByRun("sarif-run-789")
	if err != nil {
		t.Fatalf("Failed to get findings: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].CWEID != "CWE-89" {
		t.Errorf("Expected CWE-89, got %s", findings[0].CWEID)
	}
	if findings[0].FilePath != "database.py" {
		t.Errorf("Expected database.py, got %s", findings[0].FilePath)
	}
	if findings[0].LineNumber != 42 {
		t.Errorf("Expected line 42, got %d", findings[0].LineNumber)
	}
}

func TestImporter_ValidateOnly(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	findings := []scanner.NormalizedFinding{
		{
			ID:              "finding-1",
			FindingID:       "raw-1",
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "high",
			Confidence:      "high",
			CodeFingerprint: "test-fingerprint",
			FilePath:        "test.py",
			LineNumber:      10,
			Description:     "SQL injection vulnerability",
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "findings.json")
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("Failed to marshal findings: %v", err)
	}
	err = os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:         ImportModeReplace,
		RunID:        "validate-run",
		TargetPath:   "/test",
		ToolName:     "test",
		ValidateOnly: true,
	}

	result, err := imp.ImportFromJSON(tmpFile, opts)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}
	if result.TotalFindings != 1 {
		t.Errorf("Expected 1 total finding, got %d", result.TotalFindings)
	}
	if result.ImportedFindings != 0 {
		t.Errorf("Expected 0 imported findings in validate mode, got %d", result.ImportedFindings)
	}

	// Verify nothing was saved
	savedFindings, err := db.GetFindingsByRun("validate-run")
	if err != nil {
		t.Fatalf("Failed to get findings: %v", err)
	}
	if len(savedFindings) != 0 {
		t.Errorf("Expected 0 findings in validate mode, got %d", len(savedFindings))
	}
}

func TestValidateSARIF(t *testing.T) {
	tests := []struct {
		name    string
		sarif   *sarif.SARIF
		wantErr bool
	}{
		{
			name: "valid SARIF",
			sarif: &sarif.SARIF{
				Version: "2.1.0",
				Runs: []sarif.Run{
					{
						Tool: sarif.Tool{
							Driver: sarif.Driver{
								Name: "Test",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing version",
			sarif: &sarif.SARIF{
				Version: "",
				Runs: []sarif.Run{
					{},
				},
			},
			wantErr: true,
		},
		{
			name: "no runs",
			sarif: &sarif.SARIF{
				Version: "2.1.0",
				Runs:    []sarif.Run{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSARIF(tt.sarif)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSARIF() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMapLevelToSeverity(t *testing.T) {
	tests := []struct {
		level    string
		expected string
	}{
		{"error", "high"},
		{"warning", "medium"},
		{"note", "low"},
		{"unknown", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			result := mapLevelToSeverity(tt.level)
			if result != tt.expected {
				t.Errorf("mapLevelToSeverity(%s) = %s, want %s", tt.level, result, tt.expected)
			}
		})
	}
}

func TestImporter_ImportPoliciesFromYAML(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create test policy YAML
	policyYAML := `
policies:
  - id: test-sql-injection
    name: "SQL Injection Prevention"
    description: "Prevent SQL injection vulnerabilities"
    cwe: ["89"]
    severity: critical
    action: deny
    enabled: true
  - id: test-xss
    name: "XSS Prevention"
    description: "Prevent cross-site scripting"
    cwe: ["79"]
    severity: high
    action: deny
    enabled: true
`

	tmpFile := filepath.Join(t.TempDir(), "policies.yaml")
	err := os.WriteFile(tmpFile, []byte(policyYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      false,
		OverwriteExisting: false,
	}

	result, err := imp.ImportPoliciesFromYAML(tmpFile, opts)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result is nil")
	}
	if result.TotalPolicies != 2 {
		t.Errorf("Expected 2 total policies, got %d", result.TotalPolicies)
	}
	if result.ImportedPolicies != 2 {
		t.Errorf("Expected 2 imported policies, got %d", result.ImportedPolicies)
	}
	if result.FailedPolicies != 0 {
		t.Errorf("Expected 0 failed policies, got %d", result.FailedPolicies)
	}
}

func TestImporter_ImportPoliciesFromYAML_ValidateOnly(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	policyYAML := `
policies:
  - id: test-policy
    name: "Test Policy"
    description: "Test"
    cwe: ["89"]
    severity: high
    action: deny
    enabled: true
`

	tmpFile := filepath.Join(t.TempDir(), "policies.yaml")
	err := os.WriteFile(tmpFile, []byte(policyYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      true,
		OverwriteExisting: false,
	}

	result, err := imp.ImportPoliciesFromYAML(tmpFile, opts)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}
	if result.TotalPolicies != 1 {
		t.Errorf("Expected 1 total policy, got %d", result.TotalPolicies)
	}
	if result.ImportedPolicies != 0 {
		t.Errorf("Expected 0 imported policies in validate mode, got %d", result.ImportedPolicies)
	}
}

func TestImporter_ImportPoliciesFromYAML_OverwriteExisting(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// First import
	policyYAML1 := `
policies:
  - id: test-policy
    name: "Original Policy"
    description: "Original"
    cwe: ["89"]
    severity: high
    action: deny
    enabled: true
`

	tmpFile1 := filepath.Join(t.TempDir(), "policies1.yaml")
	err := os.WriteFile(tmpFile1, []byte(policyYAML1), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      false,
		OverwriteExisting: false,
	}

	result1, err := imp.ImportPoliciesFromYAML(tmpFile1, opts)
	if err != nil {
		t.Fatalf("First import failed: %v", err)
	}
	if result1.ImportedPolicies != 1 {
		t.Errorf("Expected 1 imported policy, got %d", result1.ImportedPolicies)
	}

	// Second import without overwrite (should skip)
	policyYAML2 := `
policies:
  - id: test-policy
    name: "Updated Policy"
    description: "Updated"
    cwe: ["89"]
    severity: critical
    action: deny
    enabled: true
`

	tmpFile2 := filepath.Join(t.TempDir(), "policies2.yaml")
	err = os.WriteFile(tmpFile2, []byte(policyYAML2), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	result2, err := imp.ImportPoliciesFromYAML(tmpFile2, opts)
	if err != nil {
		t.Fatalf("Second import failed: %v", err)
	}
	if result2.SkippedPolicies != 1 {
		t.Errorf("Expected 1 skipped policy, got %d", result2.SkippedPolicies)
	}

	// Third import with overwrite (should replace)
	opts.OverwriteExisting = true
	result3, err := imp.ImportPoliciesFromYAML(tmpFile2, opts)
	if err != nil {
		t.Fatalf("Third import failed: %v", err)
	}
	if result3.ImportedPolicies != 1 {
		t.Errorf("Expected 1 imported policy with overwrite, got %d", result3.ImportedPolicies)
	}
}

func TestImporter_ImportPoliciesFromYAML_InvalidPolicy(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Policy with missing required fields
	policyYAML := `
policies:
  - id: test-policy
    name: "Test Policy"
    description: "Test"
    cwe: []
    severity: high
    action: deny
    enabled: true
`

	tmpFile := filepath.Join(t.TempDir(), "invalid-policies.yaml")
	err := os.WriteFile(tmpFile, []byte(policyYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      false,
		OverwriteExisting: false,
	}

	_, err = imp.ImportPoliciesFromYAML(tmpFile, opts)
	if err == nil {
		t.Error("Expected error for invalid policy, got nil")
	}
}

func TestImporter_ImportPoliciesFromTemplate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create a temporary template directory
	tmpDir := t.TempDir()
	templateDir := filepath.Join(tmpDir, "templates")
	err := os.MkdirAll(templateDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create template directory: %v", err)
	}

	// Create a template file
	templateYAML := `
policies:
  - id: template-policy
    name: "Template Policy"
    description: "From template"
    cwe: ["89"]
    severity: high
    action: deny
    enabled: true
`

	templateFile := filepath.Join(templateDir, "test-template.yaml")
	err = os.WriteFile(templateFile, []byte(templateYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write template file: %v", err)
	}

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      false,
		OverwriteExisting: false,
		TemplateDir:       templateDir,
	}

	result, err := imp.ImportPoliciesFromTemplate("test-template", opts)
	if err != nil {
		t.Fatalf("Template import failed: %v", err)
	}
	if result.ImportedPolicies != 1 {
		t.Errorf("Expected 1 imported policy from template, got %d", result.ImportedPolicies)
	}
}

func TestImporter_ImportPoliciesFromTemplate_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      false,
		OverwriteExisting: false,
		TemplateDir:       tmpDir,
	}

	_, err := imp.ImportPoliciesFromTemplate("nonexistent-template", opts)
	if err == nil {
		t.Error("Expected error for nonexistent template, got nil")
	}
}

func TestListAvailableTemplates(t *testing.T) {
	// Create a temporary template directory
	tmpDir := t.TempDir()
	
	// Create some template files
	templates := []string{"template1.yaml", "template2.yml", "readme.txt"}
	for _, tmpl := range templates {
		path := filepath.Join(tmpDir, tmpl)
		err := os.WriteFile(path, []byte("test"), 0644)
		if err != nil {
			t.Fatalf("Failed to write template file: %v", err)
		}
	}

	result, err := ListAvailableTemplates(tmpDir)
	if err != nil {
		t.Fatalf("ListAvailableTemplates failed: %v", err)
	}

	// Should only include YAML files
	if len(result) != 2 {
		t.Errorf("Expected 2 templates, got %d", len(result))
	}

	// Check template names (without extensions)
	expectedTemplates := map[string]bool{"template1": true, "template2": true}
	for _, tmpl := range result {
		if !expectedTemplates[tmpl] {
			t.Errorf("Unexpected template: %s", tmpl)
		}
	}
}

func TestListAvailableTemplates_DirectoryNotFound(t *testing.T) {
	_, err := ListAvailableTemplates("/nonexistent/directory")
	if err == nil {
		t.Error("Expected error for nonexistent directory, got nil")
	}
}

func TestImporter_ImportFromJSON_MalformedJSON(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create malformed JSON file
	tmpFile := filepath.Join(t.TempDir(), "malformed.json")
	err := os.WriteFile(tmpFile, []byte("{invalid json"), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:       ImportModeReplace,
		RunID:      "test-run",
		TargetPath: "/test",
		ToolName:   "test",
	}

	_, err = imp.ImportFromJSON(tmpFile, opts)
	if err == nil {
		t.Error("Expected error for malformed JSON, got nil")
	}
}

func TestImporter_ImportFromSARIF_MalformedSARIF(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create malformed SARIF file
	tmpFile := filepath.Join(t.TempDir(), "malformed.sarif")
	err := os.WriteFile(tmpFile, []byte("{\"version\": \"2.1.0\"}"), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:       ImportModeReplace,
		RunID:      "test-run",
		TargetPath: "/test",
		ToolName:   "test",
	}

	_, err = imp.ImportFromSARIF(tmpFile, opts)
	if err == nil {
		t.Error("Expected error for malformed SARIF (no runs), got nil")
	}
}

func TestImporter_ImportFromJSON_MergeMode(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// First import
	findings1 := []scanner.NormalizedFinding{
		{
			ID:              "finding-1",
			FindingID:       "raw-1",
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "high",
			Confidence:      "high",
			CodeFingerprint: "fingerprint-1",
			FilePath:        "test.py",
			LineNumber:      10,
			Description:     "First finding",
		},
	}

	tmpFile1 := filepath.Join(t.TempDir(), "findings1.json")
	data1, _ := json.Marshal(findings1)
	os.WriteFile(tmpFile1, data1, 0644)

	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:       ImportModeReplace,
		RunID:      "run-1",
		TargetPath: "/test",
		ToolName:   "test",
	}

	result1, err := imp.ImportFromJSON(tmpFile1, opts)
	if err != nil {
		t.Fatalf("First import failed: %v", err)
	}
	if result1.ImportedFindings != 1 {
		t.Errorf("Expected 1 imported finding, got %d", result1.ImportedFindings)
	}

	// Second import with same fingerprint but merge mode
	findings2 := []scanner.NormalizedFinding{
		{
			ID:              "finding-2",
			FindingID:       "raw-2",
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "high",
			Confidence:      "high",
			CodeFingerprint: "fingerprint-1", // Same fingerprint
			FilePath:        "test.py",
			LineNumber:      10,
			Description:     "Second finding (same issue)",
		},
	}

	tmpFile2 := filepath.Join(t.TempDir(), "findings2.json")
	data2, _ := json.Marshal(findings2)
	os.WriteFile(tmpFile2, data2, 0644)

	opts.Mode = ImportModeMerge
	opts.RunID = "run-2"

	result2, err := imp.ImportFromJSON(tmpFile2, opts)
	if err != nil {
		t.Fatalf("Second import failed: %v", err)
	}
	// In merge mode, should import as new finding
	if result2.ImportedFindings != 1 {
		t.Errorf("Expected 1 imported finding in merge mode, got %d", result2.ImportedFindings)
	}
}

func TestImporter_ImportFromJSON_SkipMode(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// First import
	findings := []scanner.NormalizedFinding{
		{
			ID:              "finding-1",
			FindingID:       "raw-1",
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "high",
			Confidence:      "high",
			CodeFingerprint: "fingerprint-1",
			FilePath:        "test.py",
			LineNumber:      10,
			Description:     "Test finding",
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "findings.json")
	data, _ := json.Marshal(findings)
	os.WriteFile(tmpFile, data, 0644)

	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:       ImportModeReplace,
		RunID:      "run-1",
		TargetPath: "/test",
		ToolName:   "test",
	}

	result1, err := imp.ImportFromJSON(tmpFile, opts)
	if err != nil {
		t.Fatalf("First import failed: %v", err)
	}
	if result1.ImportedFindings != 1 {
		t.Errorf("Expected 1 imported finding, got %d", result1.ImportedFindings)
	}

	// Second import with skip mode
	opts.Mode = ImportModeSkip
	opts.RunID = "run-2"

	result2, err := imp.ImportFromJSON(tmpFile, opts)
	if err != nil {
		t.Fatalf("Second import failed: %v", err)
	}
	// Should skip existing finding
	if result2.SkippedFindings != 1 {
		t.Errorf("Expected 1 skipped finding, got %d", result2.SkippedFindings)
	}
	if result2.ImportedFindings != 0 {
		t.Errorf("Expected 0 imported findings in skip mode, got %d", result2.ImportedFindings)
	}
}

func TestImporter_ImportFromSARIF_NoLocations(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SARIF with result that has no locations
	sarifDoc := sarif.SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: sarif.Driver{
						Name:    "Test Scanner",
						Version: "1.0.0",
					},
				},
				Results: []sarif.Result{
					{
						RuleID: "CWE-89",
						Level:  "error",
						Message: sarif.Message{
							Text: "Finding without location",
						},
						Locations: []sarif.Location{}, // Empty locations
					},
				},
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "no-locations.sarif")
	data, _ := json.Marshal(sarifDoc)
	os.WriteFile(tmpFile, data, 0644)

	imp := NewImporter(db)
	opts := ImportOptions{
		Mode:       ImportModeReplace,
		RunID:      "test-run",
		TargetPath: "/test",
		ToolName:   "test",
	}

	result, err := imp.ImportFromSARIF(tmpFile, opts)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	// Should skip results without locations
	if result.ImportedFindings != 0 {
		t.Errorf("Expected 0 imported findings (no locations), got %d", result.ImportedFindings)
	}
}

func TestImporter_ImportFromJSON_MissingRequiredFields(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name    string
		finding scanner.NormalizedFinding
		wantErr bool
	}{
		{
			name: "Missing CWE ID",
			finding: scanner.NormalizedFinding{
				ID:              "finding-1",
				FindingID:       "raw-1",
				CWEID:           "", // Missing
				CWEDescription:  "SQL Injection",
				Severity:        "high",
				Confidence:      "high",
				CodeFingerprint: "fingerprint-1",
				FilePath:        "test.py",
				LineNumber:      10,
				Description:     "Test finding",
			},
			wantErr: true,
		},
		{
			name: "Missing file path",
			finding: scanner.NormalizedFinding{
				ID:              "finding-1",
				FindingID:       "raw-1",
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "high",
				Confidence:      "high",
				CodeFingerprint: "fingerprint-1",
				FilePath:        "", // Missing
				LineNumber:      10,
				Description:     "Test finding",
			},
			wantErr: true,
		},
		{
			name: "Missing severity",
			finding: scanner.NormalizedFinding{
				ID:              "finding-1",
				FindingID:       "raw-1",
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "", // Missing
				Confidence:      "high",
				CodeFingerprint: "fingerprint-1",
				FilePath:        "test.py",
				LineNumber:      10,
				Description:     "Test finding",
			},
			wantErr: true,
		},
		{
			name: "Missing description",
			finding: scanner.NormalizedFinding{
				ID:              "finding-1",
				FindingID:       "raw-1",
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "high",
				Confidence:      "high",
				CodeFingerprint: "fingerprint-1",
				FilePath:        "test.py",
				LineNumber:      10,
				Description:     "", // Missing
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []scanner.NormalizedFinding{tt.finding}
			tmpFile := filepath.Join(t.TempDir(), "findings.json")
			data, _ := json.Marshal(findings)
			os.WriteFile(tmpFile, data, 0644)

			imp := NewImporter(db)
			opts := ImportOptions{
				Mode:       ImportModeReplace,
				RunID:      "test-run",
				TargetPath: "/test",
				ToolName:   "test",
			}

			_, err := imp.ImportFromJSON(tmpFile, opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ImportFromJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestImporter_ImportPoliciesFromYAML_MissingCWE(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Policy with empty CWE list (invalid)
	policyYAML := `
policies:
  - id: test-policy
    name: "Test Policy"
    description: "Test"
    cwe: []
    severity: high
    action: deny
    enabled: true
`

	tmpFile := filepath.Join(t.TempDir(), "invalid-policy.yaml")
	err := os.WriteFile(tmpFile, []byte(policyYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      false,
		OverwriteExisting: false,
	}

	_, err = imp.ImportPoliciesFromYAML(tmpFile, opts)
	if err == nil {
		t.Error("Expected error for policy with empty CWE list, got nil")
	}
}

func TestImporter_ImportPoliciesFromYAML_InvalidYAML(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Invalid YAML syntax
	policyYAML := `
policies:
  - id: test-policy
    name: "Test Policy
    description: "Missing quote
`

	tmpFile := filepath.Join(t.TempDir(), "invalid.yaml")
	err := os.WriteFile(tmpFile, []byte(policyYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	imp := NewImporter(db)
	opts := PolicyImportOptions{
		ValidateOnly:      false,
		OverwriteExisting: false,
	}

	_, err = imp.ImportPoliciesFromYAML(tmpFile, opts)
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

func TestGenerateFingerprint(t *testing.T) {
	tests := []struct {
		name       string
		filePath   string
		lineNumber int
		cweID      string
		expected   string
	}{
		{
			name:       "Basic fingerprint",
			filePath:   "test.py",
			lineNumber: 42,
			cweID:      "CWE-89",
			expected:   "test.py:42:CWE-89",
		},
		{
			name:       "Path with slashes",
			filePath:   "src/main/test.py",
			lineNumber: 100,
			cweID:      "CWE-79",
			expected:   "src/main/test.py:100:CWE-79",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateFingerprint(tt.filePath, tt.lineNumber, tt.cweID)
			if result != tt.expected {
				t.Errorf("generateFingerprint() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestValidateFindings_EmptyList(t *testing.T) {
	err := validateFindings([]scanner.NormalizedFinding{})
	if err == nil {
		t.Error("Expected error for empty findings list, got nil")
	}
}
