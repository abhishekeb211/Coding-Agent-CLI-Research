package exporter

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coding-agent/cli/internal/policy"
	"github.com/coding-agent/cli/internal/sarif"
	"github.com/coding-agent/cli/internal/storage"
)

func setupTestDB(t *testing.T) *storage.Database {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	return db
}

func TestExporter_ExportFindingsToJSON(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test data
	run := &storage.Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		EndTime:    time.Now().Unix(),
		Status:     "completed",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	finding := &storage.NormalizedFinding{
		NormID:          "finding-1",
		FindingID:       "raw-finding-1",
		RunID:           "test-run-1",
		CWEID:           "CWE-89",
		CWEDescription:  "SQL Injection",
		Severity:        "high",
		Confidence:      "high",
		CodeFingerprint: "test-fingerprint",
		FilePath:        "/test/file.py",
		LineNumber:      42,
		Description:     "Test finding",
	}
	if err := db.SaveNormalizedFinding(finding); err != nil {
		t.Fatalf("Failed to save finding: %v", err)
	}

	// Export to JSON
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "findings.json")

	opts := FindingsExportOptions{}
	result, err := exporter.ExportFindingsToJSON(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportFindingsToJSON failed: %v", err)
	}

	// Verify result
	if result.TotalRecords != 1 {
		t.Errorf("Expected 1 record, got %d", result.TotalRecords)
	}
	if result.Format != "json" {
		t.Errorf("Expected format 'json', got '%s'", result.Format)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var findings []ExportFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding in JSON, got %d", len(findings))
	}
	if findings[0].CWEID != "CWE-89" {
		t.Errorf("Expected CWE-89, got %s", findings[0].CWEID)
	}
}

func TestExporter_ExportFindingsToCSV(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test data
	run := &storage.Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		EndTime:    time.Now().Unix(),
		Status:     "completed",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	finding := &storage.NormalizedFinding{
		NormID:          "finding-1",
		FindingID:       "raw-finding-1",
		RunID:           "test-run-1",
		CWEID:           "CWE-89",
		CWEDescription:  "SQL Injection",
		Severity:        "high",
		Confidence:      "high",
		CodeFingerprint: "test-fingerprint",
		FilePath:        "/test/file.py",
		LineNumber:      42,
		Description:     "Test finding",
	}
	if err := db.SaveNormalizedFinding(finding); err != nil {
		t.Fatalf("Failed to save finding: %v", err)
	}

	// Export to CSV
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "findings.csv")

	opts := FindingsExportOptions{}
	result, err := exporter.ExportFindingsToCSV(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportFindingsToCSV failed: %v", err)
	}

	// Verify result
	if result.TotalRecords != 1 {
		t.Errorf("Expected 1 record, got %d", result.TotalRecords)
	}
	if result.Format != "csv" {
		t.Errorf("Expected format 'csv', got '%s'", result.Format)
	}

	// Verify file exists and is valid CSV
	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Should have header + 1 data row
	if len(records) != 2 {
		t.Errorf("Expected 2 rows (header + data), got %d", len(records))
	}

	// Verify header
	expectedHeader := []string{
		"ID", "Run ID", "CWE ID", "CWE Description", "Severity",
		"Confidence", "File Path", "Line Number", "Description",
		"Code Fingerprint", "Timestamp",
	}
	if len(records[0]) != len(expectedHeader) {
		t.Errorf("Expected %d columns, got %d", len(expectedHeader), len(records[0]))
	}
}

func TestExporter_ExportFindingsWithFilters(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test data with different severities
	run := &storage.Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		EndTime:    time.Now().Unix(),
		Status:     "completed",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	findings := []storage.NormalizedFinding{
		{
			NormID:          "finding-1",
			FindingID:       "raw-finding-1",
			RunID:           "test-run-1",
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "critical",
			Confidence:      "high",
			CodeFingerprint: "fingerprint-1",
			FilePath:        "/test/file1.py",
			LineNumber:      10,
			Description:     "Critical finding",
		},
		{
			NormID:          "finding-2",
			FindingID:       "raw-finding-2",
			RunID:           "test-run-1",
			CWEID:           "CWE-79",
			CWEDescription:  "XSS",
			Severity:        "high",
			Confidence:      "medium",
			CodeFingerprint: "fingerprint-2",
			FilePath:        "/test/file2.py",
			LineNumber:      20,
			Description:     "High finding",
		},
		{
			NormID:          "finding-3",
			FindingID:       "raw-finding-3",
			RunID:           "test-run-1",
			CWEID:           "CWE-20",
			CWEDescription:  "Input Validation",
			Severity:        "low",
			Confidence:      "low",
			CodeFingerprint: "fingerprint-3",
			FilePath:        "/test/file3.py",
			LineNumber:      30,
			Description:     "Low finding",
		},
	}

	for _, f := range findings {
		if err := db.SaveNormalizedFinding(&f); err != nil {
			t.Fatalf("Failed to save finding: %v", err)
		}
	}

	// Export with severity filter
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "findings.json")

	opts := FindingsExportOptions{
		Severity: []string{"critical", "high"},
	}
	result, err := exporter.ExportFindingsToJSON(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportFindingsToJSON failed: %v", err)
	}

	// Should only export critical and high findings
	if result.TotalRecords != 2 {
		t.Errorf("Expected 2 records with severity filter, got %d", result.TotalRecords)
	}
}

func TestExporter_ExportPoliciesToYAML(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test policy
	pol := &policy.Policy{
		ID:          "test-policy-1",
		Name:        "Test Policy",
		Description: "A test policy",
		CWE:         []string{"CWE-89", "CWE-79"},
		Severity:    "high",
		Action:      "block",
		Enabled:     true,
	}

	// Save policy to database
	cweJSON, _ := json.Marshal(pol.CWE)
	query := `
		INSERT INTO policies (id, name, description, cwe, severity, action, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Query(query, pol.ID, pol.Name, pol.Description, string(cweJSON), pol.Severity, pol.Action, pol.Enabled, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to save policy: %v", err)
	}

	// Export to YAML
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "policies.yaml")

	opts := PoliciesExportOptions{}
	result, err := exporter.ExportPoliciesToYAML(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportPoliciesToYAML failed: %v", err)
	}

	// Verify result
	if result.TotalRecords != 1 {
		t.Errorf("Expected 1 record, got %d", result.TotalRecords)
	}
	if result.Format != "yaml" {
		t.Errorf("Expected format 'yaml', got '%s'", result.Format)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Output file does not exist")
	}
}

func TestExporter_ExportPoliciesToJSON(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test policy
	pol := &policy.Policy{
		ID:          "test-policy-1",
		Name:        "Test Policy",
		Description: "A test policy",
		CWE:         []string{"CWE-89"},
		Severity:    "high",
		Action:      "block",
		Enabled:     true,
	}

	// Save policy to database
	cweJSON, _ := json.Marshal(pol.CWE)
	query := `
		INSERT INTO policies (id, name, description, cwe, severity, action, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Query(query, pol.ID, pol.Name, pol.Description, string(cweJSON), pol.Severity, pol.Action, pol.Enabled, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to save policy: %v", err)
	}

	// Export to JSON
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "policies.json")

	opts := PoliciesExportOptions{}
	result, err := exporter.ExportPoliciesToJSON(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportPoliciesToJSON failed: %v", err)
	}

	// Verify result
	if result.TotalRecords != 1 {
		t.Errorf("Expected 1 record, got %d", result.TotalRecords)
	}
	if result.Format != "json" {
		t.Errorf("Expected format 'json', got '%s'", result.Format)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var policySet policy.PolicySet
	if err := json.Unmarshal(data, &policySet); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if len(policySet.Policies) != 1 {
		t.Errorf("Expected 1 policy in JSON, got %d", len(policySet.Policies))
	}
	if policySet.Policies[0].ID != "test-policy-1" {
		t.Errorf("Expected policy ID 'test-policy-1', got '%s'", policySet.Policies[0].ID)
	}
}

func TestMapSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := mapSeverityToLevel(tt.severity)
			if result != tt.expected {
				t.Errorf("mapSeverityToLevel(%s) = %s, want %s", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestExporter_ExportFindingsToSARIF_MultipleRuns(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test data with multiple runs
	runs := []string{"run-1", "run-2"}
	for _, runID := range runs {
		run := &storage.Run{
			RunID:      runID,
			TargetPath: "/test/path",
			StartTime:  time.Now().Unix(),
			EndTime:    time.Now().Unix(),
			Status:     "completed",
		}
		if err := db.SaveRun(run); err != nil {
			t.Fatalf("Failed to save run: %v", err)
		}

		finding := &storage.NormalizedFinding{
			NormID:          runID + "-finding",
			FindingID:       runID + "-raw",
			RunID:           runID,
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "high",
			Confidence:      "high",
			CodeFingerprint: runID + "-fingerprint",
			FilePath:        "/test/file.py",
			LineNumber:      42,
			Description:     "Test finding for " + runID,
		}
		if err := db.SaveNormalizedFinding(finding); err != nil {
			t.Fatalf("Failed to save finding: %v", err)
		}
	}

	// Export to SARIF
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "findings.sarif")

	opts := FindingsExportOptions{}
	result, err := exporter.ExportFindingsToSARIF(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportFindingsToSARIF failed: %v", err)
	}

	// Verify result
	if result.TotalRecords != 2 {
		t.Errorf("Expected 2 records, got %d", result.TotalRecords)
	}

	// Verify SARIF structure
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var sarifDoc sarif.SARIF
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		t.Fatalf("Failed to parse SARIF: %v", err)
	}

	// Should have 2 runs
	if len(sarifDoc.Runs) != 2 {
		t.Errorf("Expected 2 SARIF runs, got %d", len(sarifDoc.Runs))
	}
}

func TestExporter_ExportFindingsToSARIF_EmptyResults(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Export with no findings
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "empty.sarif")

	opts := FindingsExportOptions{}
	result, err := exporter.ExportFindingsToSARIF(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportFindingsToSARIF failed: %v", err)
	}

	// Verify result
	if result.TotalRecords != 0 {
		t.Errorf("Expected 0 records, got %d", result.TotalRecords)
	}

	// Verify SARIF structure
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var sarifDoc sarif.SARIF
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		t.Fatalf("Failed to parse SARIF: %v", err)
	}

	// Should have 0 runs
	if len(sarifDoc.Runs) != 0 {
		t.Errorf("Expected 0 SARIF runs, got %d", len(sarifDoc.Runs))
	}
}

func TestExporter_ExportFindingsWithDateRange(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test data with different timestamps
	run := &storage.Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		EndTime:    time.Now().Unix(),
		Status:     "completed",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	// Create findings with different dates
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	findings := []struct {
		id   string
		date time.Time
	}{
		{"finding-1", baseTime},
		{"finding-2", baseTime.AddDate(0, 0, 5)},
		{"finding-3", baseTime.AddDate(0, 0, 10)},
	}

	for _, f := range findings {
		finding := &storage.NormalizedFinding{
			NormID:          f.id,
			FindingID:       f.id + "-raw",
			RunID:           "test-run-1",
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "high",
			Confidence:      "high",
			CodeFingerprint: f.id + "-fingerprint",
			FilePath:        "/test/file.py",
			LineNumber:      42,
			Description:     "Test finding",
		}
		if err := db.SaveNormalizedFinding(finding); err != nil {
			t.Fatalf("Failed to save finding: %v", err)
		}

		// Update timestamp manually
		query := `UPDATE findings_normalized SET created_at = ? WHERE norm_id = ?`
		_, err := db.Query(query, f.date.Unix(), f.id)
		if err != nil {
			t.Fatalf("Failed to update timestamp: %v", err)
		}
	}

	// Export with date range filter
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "findings.json")

	opts := FindingsExportOptions{
		StartDate: "2024-01-03",
		EndDate:   "2024-01-08",
	}
	result, err := exporter.ExportFindingsToJSON(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportFindingsToJSON failed: %v", err)
	}

	// Should only export finding-2 (Jan 6)
	if result.TotalRecords != 1 {
		t.Errorf("Expected 1 record with date filter, got %d", result.TotalRecords)
	}
}

func TestExporter_ExportFindingsInvalidDateFormat(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "findings.json")

	// Test invalid start date
	opts := FindingsExportOptions{
		StartDate: "invalid-date",
	}
	_, err := exporter.ExportFindingsToJSON(outputPath, opts)
	if err == nil {
		t.Error("Expected error for invalid start date, got nil")
	}

	// Test invalid end date
	opts = FindingsExportOptions{
		EndDate: "2024-13-45", // Invalid month and day
	}
	_, err = exporter.ExportFindingsToJSON(outputPath, opts)
	if err == nil {
		t.Error("Expected error for invalid end date, got nil")
	}
}

func TestExporter_ExportPoliciesToYAML_EmptyResults(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Export with no policies
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "policies.yaml")

	opts := PoliciesExportOptions{}
	result, err := exporter.ExportPoliciesToYAML(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportPoliciesToYAML failed: %v", err)
	}

	// Verify result
	if result.TotalRecords != 0 {
		t.Errorf("Expected 0 records, got %d", result.TotalRecords)
	}
}

func TestExporter_ExportPoliciesToJSON_FilterByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create multiple test policies
	policies := []policy.Policy{
		{
			ID:          "policy-1",
			Name:        "Policy 1",
			Description: "First policy",
			CWE:         []string{"CWE-89"},
			Severity:    "high",
			Action:      "block",
			Enabled:     true,
		},
		{
			ID:          "policy-2",
			Name:        "Policy 2",
			Description: "Second policy",
			CWE:         []string{"CWE-79"},
			Severity:    "medium",
			Action:      "warn",
			Enabled:     true,
		},
	}

	for _, pol := range policies {
		cweJSON, _ := json.Marshal(pol.CWE)
		query := `
			INSERT INTO policies (id, name, description, cwe, severity, action, enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`
		_, err := db.Query(query, pol.ID, pol.Name, pol.Description, string(cweJSON), pol.Severity, pol.Action, pol.Enabled, time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to save policy: %v", err)
		}
	}

	// Export specific policy
	exporter := NewExporter(db)
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "policy.json")

	opts := PoliciesExportOptions{
		PolicyID: "policy-1",
	}
	result, err := exporter.ExportPoliciesToJSON(outputPath, opts)
	if err != nil {
		t.Fatalf("ExportPoliciesToJSON failed: %v", err)
	}

	// Should only export policy-1
	if result.TotalRecords != 1 {
		t.Errorf("Expected 1 record with policy filter, got %d", result.TotalRecords)
	}

	// Verify correct policy was exported
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var policySet policy.PolicySet
	if err := json.Unmarshal(data, &policySet); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if len(policySet.Policies) != 1 {
		t.Errorf("Expected 1 policy in JSON, got %d", len(policySet.Policies))
	}
	if policySet.Policies[0].ID != "policy-1" {
		t.Errorf("Expected policy ID 'policy-1', got '%s'", policySet.Policies[0].ID)
	}
}
