package exporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/coding-agent/cli/internal/policy"
	"github.com/coding-agent/cli/internal/sarif"
	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// FindingsExportOptions configures findings export behavior
type FindingsExportOptions struct {
	// RunID filters findings by scan run ID
	RunID string
	// Severity filters findings by severity levels
	Severity []string
	// StartDate filters findings from this date (YYYY-MM-DD)
	StartDate string
	// EndDate filters findings until this date (YYYY-MM-DD)
	EndDate string
}

// PoliciesExportOptions configures policies export behavior
type PoliciesExportOptions struct {
	// PolicyID exports a specific policy by ID
	PolicyID string
}

// ExportResult contains the results of an export operation
type ExportResult struct {
	TotalRecords int
	FileSize     int64
	Format       string
	OutputPath   string
}

// Exporter handles exporting findings and policies to various formats
type Exporter struct {
	db *storage.Database
}

// NewExporter creates a new exporter
func NewExporter(db *storage.Database) *Exporter {
	return &Exporter{db: db}
}

// ExportFindingsToJSON exports findings to JSON format
func (e *Exporter) ExportFindingsToJSON(outputPath string, opts FindingsExportOptions) (*ExportResult, error) {
	log.Info().Str("output", outputPath).Msg("Exporting findings to JSON")

	// Query findings
	findings, err := e.queryFindings(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Encode to JSON with pretty printing
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(findings); err != nil {
		return nil, fmt.Errorf("failed to encode JSON: %w", err)
	}

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &ExportResult{
		TotalRecords: len(findings),
		FileSize:     fileInfo.Size(),
		Format:       "json",
		OutputPath:   outputPath,
	}, nil
}

// ExportFindingsToCSV exports findings to CSV format
func (e *Exporter) ExportFindingsToCSV(outputPath string, opts FindingsExportOptions) (*ExportResult, error) {
	log.Info().Str("output", outputPath).Msg("Exporting findings to CSV")

	// Query findings
	findings, err := e.queryFindings(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID",
		"Run ID",
		"CWE ID",
		"CWE Description",
		"Severity",
		"Confidence",
		"File Path",
		"Line Number",
		"Description",
		"Code Fingerprint",
		"Timestamp",
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write findings
	for _, finding := range findings {
		record := []string{
			finding.ID,
			finding.RunID,
			finding.CWEID,
			finding.CWEDescription,
			finding.Severity,
			finding.Confidence,
			finding.FilePath,
			fmt.Sprintf("%d", finding.LineNumber),
			finding.Description,
			finding.CodeFingerprint,
			finding.Timestamp.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &ExportResult{
		TotalRecords: len(findings),
		FileSize:     fileInfo.Size(),
		Format:       "csv",
		OutputPath:   outputPath,
	}, nil
}

// ExportFindingsToExcel exports findings to Excel format
func (e *Exporter) ExportFindingsToExcel(outputPath string, opts FindingsExportOptions) (*ExportResult, error) {
	// For now, fallback to CSV as Excel requires external library (excelize)
	// This can be enhanced later with proper Excel support
	log.Warn().Msg("Excel export not fully implemented, falling back to CSV format")
	
	// Change extension to .csv
	csvPath := outputPath
	if len(csvPath) > 5 && csvPath[len(csvPath)-5:] == ".xlsx" {
		csvPath = csvPath[:len(csvPath)-5] + ".csv"
	}
	
	result, err := e.ExportFindingsToCSV(csvPath, opts)
	if err != nil {
		return nil, err
	}
	
	result.Format = "csv (excel not available)"
	return result, nil
}

// ExportFindingsToSARIF exports findings to SARIF format
func (e *Exporter) ExportFindingsToSARIF(outputPath string, opts FindingsExportOptions) (*ExportResult, error) {
	log.Info().Str("output", outputPath).Msg("Exporting findings to SARIF")

	// Query findings
	findings, err := e.queryFindings(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}

	// Convert findings to SARIF
	sarifDoc := e.convertFindingsToSARIF(findings)

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Encode to JSON with pretty printing
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sarifDoc); err != nil {
		return nil, fmt.Errorf("failed to encode SARIF: %w", err)
	}

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &ExportResult{
		TotalRecords: len(findings),
		FileSize:     fileInfo.Size(),
		Format:       "sarif",
		OutputPath:   outputPath,
	}, nil
}

// ExportPoliciesToYAML exports policies to YAML format
func (e *Exporter) ExportPoliciesToYAML(outputPath string, opts PoliciesExportOptions) (*ExportResult, error) {
	log.Info().Str("output", outputPath).Msg("Exporting policies to YAML")

	// Query policies
	policies, err := e.queryPolicies(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query policies: %w", err)
	}

	// Create policy set
	policySet := policy.PolicySet{
		Policies: policies,
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Encode to YAML
	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	if err := encoder.Encode(policySet); err != nil {
		return nil, fmt.Errorf("failed to encode YAML: %w", err)
	}

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &ExportResult{
		TotalRecords: len(policies),
		FileSize:     fileInfo.Size(),
		Format:       "yaml",
		OutputPath:   outputPath,
	}, nil
}

// ExportPoliciesToJSON exports policies to JSON format
func (e *Exporter) ExportPoliciesToJSON(outputPath string, opts PoliciesExportOptions) (*ExportResult, error) {
	log.Info().Str("output", outputPath).Msg("Exporting policies to JSON")

	// Query policies
	policies, err := e.queryPolicies(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query policies: %w", err)
	}

	// Create policy set
	policySet := policy.PolicySet{
		Policies: policies,
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Encode to JSON with pretty printing
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(policySet); err != nil {
		return nil, fmt.Errorf("failed to encode JSON: %w", err)
	}

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &ExportResult{
		TotalRecords: len(policies),
		FileSize:     fileInfo.Size(),
		Format:       "json",
		OutputPath:   outputPath,
	}, nil
}

// ExportFinding represents a finding for export with additional metadata
type ExportFinding struct {
	scanner.NormalizedFinding
	RunID string `json:"run_id"`
}

// queryFindings queries findings from the database based on options
func (e *Exporter) queryFindings(opts FindingsExportOptions) ([]ExportFinding, error) {
	// Build query
	query := `
		SELECT 
			norm_id, finding_id, run_id, cwe_id, cwe_description,
			severity, confidence, code_fingerprint, file_path,
			line_number, description, created_at
		FROM findings_normalized
		WHERE 1=1
	`
	args := []interface{}{}

	// Add filters
	if opts.RunID != "" {
		query += " AND run_id = ?"
		args = append(args, opts.RunID)
	}

	if len(opts.Severity) > 0 {
		placeholders := ""
		for i, sev := range opts.Severity {
			if i > 0 {
				placeholders += ", "
			}
			placeholders += "?"
			args = append(args, sev)
		}
		query += fmt.Sprintf(" AND severity IN (%s)", placeholders)
	}

	if opts.StartDate != "" {
		startTime, err := time.Parse("2006-01-02", opts.StartDate)
		if err != nil {
			return nil, fmt.Errorf("invalid start date format: %w", err)
		}
		query += " AND created_at >= ?"
		args = append(args, startTime.Unix())
	}

	if opts.EndDate != "" {
		endTime, err := time.Parse("2006-01-02", opts.EndDate)
		if err != nil {
			return nil, fmt.Errorf("invalid end date format: %w", err)
		}
		// Add 24 hours to include the entire end date
		endTime = endTime.Add(24 * time.Hour)
		query += " AND created_at < ?"
		args = append(args, endTime.Unix())
	}

	query += " ORDER BY created_at DESC"

	// Execute query
	rows, err := e.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	// Parse results
	var findings []ExportFinding
	for rows.Next() {
		var finding ExportFinding
		var createdAt int64
		var runID string

		err := rows.Scan(
			&finding.ID,
			&finding.FindingID,
			&runID,
			&finding.CWEID,
			&finding.CWEDescription,
			&finding.Severity,
			&finding.Confidence,
			&finding.CodeFingerprint,
			&finding.FilePath,
			&finding.LineNumber,
			&finding.Description,
			&createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}

		finding.RunID = runID
		finding.Timestamp = time.Unix(createdAt, 0)
		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating findings: %w", err)
	}

	log.Info().Int("count", len(findings)).Msg("Queried findings")
	return findings, nil
}

// queryPolicies queries policies from the database based on options
func (e *Exporter) queryPolicies(opts PoliciesExportOptions) ([]policy.Policy, error) {
	// Build query
	query := `
		SELECT id, name, description, cwe, severity, action, enabled
		FROM policies
		WHERE 1=1
	`
	args := []interface{}{}

	// Add filters
	if opts.PolicyID != "" {
		query += " AND id = ?"
		args = append(args, opts.PolicyID)
	}

	query += " ORDER BY name"

	// Execute query
	rows, err := e.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query policies: %w", err)
	}
	defer rows.Close()

	// Parse results
	var policies []policy.Policy
	for rows.Next() {
		var pol policy.Policy
		var cweJSON string

		err := rows.Scan(
			&pol.ID,
			&pol.Name,
			&pol.Description,
			&cweJSON,
			&pol.Severity,
			&pol.Action,
			&pol.Enabled,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		// Parse CWE JSON array
		if err := json.Unmarshal([]byte(cweJSON), &pol.CWE); err != nil {
			return nil, fmt.Errorf("failed to parse CWE list: %w", err)
		}

		policies = append(policies, pol)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating policies: %w", err)
	}

	log.Info().Int("count", len(policies)).Msg("Queried policies")
	return policies, nil
}

// convertFindingsToSARIF converts findings to SARIF format
func (e *Exporter) convertFindingsToSARIF(findings []ExportFinding) *sarif.SARIF {
	// Group findings by run ID
	runMap := make(map[string][]ExportFinding)
	for _, finding := range findings {
		runMap[finding.RunID] = append(runMap[finding.RunID], finding)
	}

	// Create SARIF document
	sarifDoc := &sarif.SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []sarif.Run{},
	}

	// Create a run for each run ID
	for _, runFindings := range runMap {
		// Build rule map
		ruleMap := make(map[string]sarif.Rule)
		for _, finding := range runFindings {
			if _, exists := ruleMap[finding.CWEID]; !exists {
				ruleMap[finding.CWEID] = sarif.Rule{
					ID: finding.CWEID,
					ShortDescription: &sarif.Message{
						Text: finding.CWEDescription,
					},
					FullDescription: &sarif.Message{
						Text: finding.CWEDescription,
					},
				}
			}
		}

		// Convert map to slice
		var rules []sarif.Rule
		for _, rule := range ruleMap {
			rules = append(rules, rule)
		}

		// Create results
		var results []sarif.Result
		for _, finding := range runFindings {
			result := sarif.Result{
				RuleID: finding.CWEID,
				Level:  mapSeverityToLevel(finding.Severity),
				Message: sarif.Message{
					Text: finding.Description,
				},
				Locations: []sarif.Location{
					{
						PhysicalLocation: sarif.PhysicalLocation{
							ArtifactLocation: sarif.ArtifactLocation{
								URI: finding.FilePath,
							},
							Region: sarif.Region{
								StartLine: finding.LineNumber,
							},
						},
					},
				},
				Properties: &sarif.ResultProperties{
					CWE:         finding.CWEID,
					Confidence:  finding.Confidence,
					Fingerprint: finding.CodeFingerprint,
				},
			}
			results = append(results, result)
		}

		// Create run
		run := sarif.Run{
			Tool: sarif.Tool{
				Driver: sarif.Driver{
					Name:    "Coding Agent CLI",
					Version: "1.2.0",
					Rules:   rules,
				},
			},
			Results: results,
		}

		sarifDoc.Runs = append(sarifDoc.Runs, run)
	}

	return sarifDoc
}

// mapSeverityToLevel maps internal severity to SARIF level
func mapSeverityToLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}
