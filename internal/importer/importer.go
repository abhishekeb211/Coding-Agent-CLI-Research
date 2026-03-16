package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/coding-agent/cli/internal/policy"
	"github.com/coding-agent/cli/internal/sarif"
	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// ImportMode defines how to handle conflicts during import
type ImportMode string

const (
	// ImportModeReplace replaces existing findings with imported ones
	ImportModeReplace ImportMode = "replace"
	// ImportModeMerge merges imported findings with existing ones
	ImportModeMerge ImportMode = "merge"
	// ImportModeSkip skips importing if findings already exist
	ImportModeSkip ImportMode = "skip"
)

// ImportOptions configures the import behavior
type ImportOptions struct {
	// Mode determines how to handle conflicts
	Mode ImportMode
	// RunID is the scan run ID to associate findings with
	RunID string
	// TargetPath is the path that was scanned
	TargetPath string
	// ValidateOnly performs validation without importing
	ValidateOnly bool
	// ToolName is the name of the tool that generated the findings
	ToolName string
}

// ImportResult contains the results of an import operation
type ImportResult struct {
	TotalFindings    int
	ImportedFindings int
	SkippedFindings  int
	FailedFindings   int
	Errors           []string
	RunID            string
}

// Importer handles importing findings from various formats
type Importer struct {
	db *storage.Database
}

// NewImporter creates a new importer
func NewImporter(db *storage.Database) *Importer {
	return &Importer{db: db}
}

// ImportFromSARIF imports findings from a SARIF file
func (i *Importer) ImportFromSARIF(path string, opts ImportOptions) (*ImportResult, error) {
	log.Info().Str("path", path).Msg("Importing findings from SARIF")

	// Read SARIF file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read SARIF file: %w", err)
	}

	// Parse SARIF
	var sarifDoc sarif.SARIF
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF: %w", err)
	}

	// Validate SARIF
	if err := validateSARIF(&sarifDoc); err != nil {
		return nil, fmt.Errorf("invalid SARIF: %w", err)
	}

	// Convert SARIF to findings
	findings, err := convertSARIFToFindings(&sarifDoc, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SARIF: %w", err)
	}

	// Validate only mode
	if opts.ValidateOnly {
		return &ImportResult{
			TotalFindings:    len(findings),
			ImportedFindings: 0,
			SkippedFindings:  0,
			FailedFindings:   0,
			Errors:           []string{},
			RunID:            opts.RunID,
		}, nil
	}

	// Import findings
	return i.importFindings(findings, opts)
}

// ImportFromJSON imports findings from a JSON file
func (i *Importer) ImportFromJSON(path string, opts ImportOptions) (*ImportResult, error) {
	log.Info().Str("path", path).Msg("Importing findings from JSON")

	// Read JSON file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON file: %w", err)
	}

	// Try to parse as ScanResult first
	var scanResult scanner.ScanResult
	if err := json.Unmarshal(data, &scanResult); err == nil {
		// Validate scan result
		if err := validateScanResult(&scanResult); err != nil {
			return nil, fmt.Errorf("invalid scan result: %w", err)
		}

		// Use run ID from scan result if not provided
		if opts.RunID == "" {
			opts.RunID = scanResult.RunID
		}
		if opts.TargetPath == "" {
			opts.TargetPath = scanResult.TargetPath
		}

		// Validate only mode
		if opts.ValidateOnly {
			return &ImportResult{
				TotalFindings:    len(scanResult.Findings),
				ImportedFindings: 0,
				SkippedFindings:  0,
				FailedFindings:   0,
				Errors:           []string{},
				RunID:            opts.RunID,
			}, nil
		}

		// Import findings
		return i.importFindings(scanResult.Findings, opts)
	}

	// Try to parse as array of findings
	var findings []scanner.NormalizedFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: not a valid ScanResult or findings array: %w", err)
	}

	// Validate findings
	if err := validateFindings(findings); err != nil {
		return nil, fmt.Errorf("invalid findings: %w", err)
	}

	// Validate only mode
	if opts.ValidateOnly {
		return &ImportResult{
			TotalFindings:    len(findings),
			ImportedFindings: 0,
			SkippedFindings:  0,
			FailedFindings:   0,
			Errors:           []string{},
			RunID:            opts.RunID,
		}, nil
	}

	// Import findings
	return i.importFindings(findings, opts)
}

// importFindings imports a list of findings into the database
func (i *Importer) importFindings(findings []scanner.NormalizedFinding, opts ImportOptions) (*ImportResult, error) {
	result := &ImportResult{
		TotalFindings: len(findings),
		RunID:         opts.RunID,
		Errors:        []string{},
	}

	// Generate run ID if not provided
	if opts.RunID == "" {
		opts.RunID = uuid.New().String()
		result.RunID = opts.RunID
	}

	// Create or update run record
	if err := i.ensureRun(opts); err != nil {
		return nil, fmt.Errorf("failed to create run: %w", err)
	}

	// Import each finding
	for _, finding := range findings {
		// Check for existing finding based on fingerprint
		exists, err := i.findingExists(finding.CodeFingerprint, opts)
		if err != nil {
			result.FailedFindings++
			result.Errors = append(result.Errors, fmt.Sprintf("failed to check finding %s: %v", finding.ID, err))
			continue
		}

		// Handle conflict based on mode
		if exists {
			switch opts.Mode {
			case ImportModeSkip:
				result.SkippedFindings++
				log.Debug().Str("fingerprint", finding.CodeFingerprint).Msg("Skipping existing finding")
				continue
			case ImportModeReplace:
				// Delete existing finding
				if err := i.deleteFinding(finding.CodeFingerprint); err != nil {
					result.FailedFindings++
					result.Errors = append(result.Errors, fmt.Sprintf("failed to delete existing finding %s: %v", finding.ID, err))
					continue
				}
			case ImportModeMerge:
				// Merge mode: import as new finding with different ID
				// This allows tracking the same vulnerability from different scans
			}
		}

		// Import finding
		if err := i.saveFinding(&finding, opts); err != nil {
			result.FailedFindings++
			result.Errors = append(result.Errors, fmt.Sprintf("failed to import finding %s: %v", finding.ID, err))
			continue
		}

		result.ImportedFindings++
	}

	log.Info().
		Int("total", result.TotalFindings).
		Int("imported", result.ImportedFindings).
		Int("skipped", result.SkippedFindings).
		Int("failed", result.FailedFindings).
		Msg("Import completed")

	return result, nil
}

// ensureRun creates or updates a run record
func (i *Importer) ensureRun(opts ImportOptions) error {
	// Check if run exists
	_, err := i.db.GetRun(opts.RunID)
	if err == nil {
		// Run exists, nothing to do
		return nil
	}

	// Create new run
	run := &storage.Run{
		RunID:           opts.RunID,
		TargetPath:      opts.TargetPath,
		StartTime:       time.Now().Unix(),
		EndTime:         time.Now().Unix(),
		Duration:        0,
		Status:          "imported",
		OfflineVerified: false,
		ConfigHash:      "imported",
	}

	return i.db.SaveRun(run)
}

// findingExists checks if a finding with the given fingerprint already exists
func (i *Importer) findingExists(fingerprint string, opts ImportOptions) (bool, error) {
	cluster, err := i.db.GetDedupeCluster(fingerprint)
	if err != nil {
		return false, err
	}
	return cluster != nil, nil
}

// deleteFinding deletes a finding by fingerprint
func (i *Importer) deleteFinding(fingerprint string) error {
	// Note: This is a simplified implementation
	// In a real system, we'd need to handle cascading deletes properly
	query := `DELETE FROM findings_normalized WHERE code_fingerprint = ?`
	_, err := i.db.Query(query, fingerprint)
	return err
}

// saveFinding saves a finding to the database
func (i *Importer) saveFinding(finding *scanner.NormalizedFinding, opts ImportOptions) error {
	// Generate IDs if not present
	if finding.ID == "" {
		finding.ID = uuid.New().String()
	}
	if finding.FindingID == "" {
		finding.FindingID = uuid.New().String()
	}

	// Save raw finding first
	rawFinding := &storage.RawFinding{
		FindingID:     finding.FindingID,
		RunID:         opts.RunID,
		ToolName:      opts.ToolName,
		ToolFindingID: finding.ID,
		Message:       finding.Description,
		FilePath:      finding.FilePath,
		LineNumber:    finding.LineNumber,
		Severity:      finding.Severity,
		Confidence:    finding.Confidence,
		RuleID:        finding.CWEID,
		Category:      "imported",
		RawJSON:       "{}",
	}

	if err := i.db.SaveRawFinding(rawFinding); err != nil {
		return fmt.Errorf("failed to save raw finding: %w", err)
	}

	// Save normalized finding
	normFinding := &storage.NormalizedFinding{
		NormID:          finding.ID,
		FindingID:       finding.FindingID,
		RunID:           opts.RunID,
		CWEID:           finding.CWEID,
		CWEDescription:  finding.CWEDescription,
		Severity:        finding.Severity,
		Confidence:      finding.Confidence,
		CodeFingerprint: finding.CodeFingerprint,
		FilePath:        finding.FilePath,
		LineNumber:      finding.LineNumber,
		Description:     finding.Description,
	}

	if err := i.db.SaveNormalizedFinding(normFinding); err != nil {
		return fmt.Errorf("failed to save normalized finding: %w", err)
	}

	// Update dedupe cluster
	cluster, err := i.db.GetDedupeCluster(finding.CodeFingerprint)
	if err != nil {
		return fmt.Errorf("failed to get dedupe cluster: %w", err)
	}

	if cluster == nil {
		// Create new cluster
		cluster = &storage.DedupeCluster{
			ClusterID:       uuid.New().String(),
			CodeFingerprint: finding.CodeFingerprint,
			NormFindingIDs:  fmt.Sprintf(`["%s"]`, finding.ID),
			FirstSeen:       time.Now().Unix(),
			LastSeen:        time.Now().Unix(),
			OccurrenceCount: 1,
		}
	} else {
		// Update existing cluster
		cluster.LastSeen = time.Now().Unix()
		cluster.OccurrenceCount++
		// Note: In a real implementation, we'd properly update the JSON array
	}

	return i.db.SaveDedupeCluster(cluster)
}

// Validation functions

func validateSARIF(sarifDoc *sarif.SARIF) error {
	if sarifDoc.Version == "" {
		return fmt.Errorf("SARIF version is required")
	}
	if len(sarifDoc.Runs) == 0 {
		return fmt.Errorf("SARIF must contain at least one run")
	}
	return nil
}

func validateScanResult(result *scanner.ScanResult) error {
	if result.RunID == "" {
		return fmt.Errorf("run ID is required")
	}
	if result.TargetPath == "" {
		return fmt.Errorf("target path is required")
	}
	return validateFindings(result.Findings)
}

func validateFindings(findings []scanner.NormalizedFinding) error {
	if len(findings) == 0 {
		return fmt.Errorf("no findings to import")
	}

	for i, f := range findings {
		if f.CWEID == "" {
			return fmt.Errorf("finding %d: CWE ID is required", i)
		}
		if f.FilePath == "" {
			return fmt.Errorf("finding %d: file path is required", i)
		}
		if f.Severity == "" {
			return fmt.Errorf("finding %d: severity is required", i)
		}
		if f.Description == "" {
			return fmt.Errorf("finding %d: description is required", i)
		}
	}

	return nil
}

// convertSARIFToFindings converts SARIF results to normalized findings
func convertSARIFToFindings(sarifDoc *sarif.SARIF, opts ImportOptions) ([]scanner.NormalizedFinding, error) {
	var findings []scanner.NormalizedFinding

	for _, run := range sarifDoc.Runs {
		// Build rule map for quick lookup
		ruleMap := make(map[string]sarif.Rule)
		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = rule
		}

		// Convert each result to a finding
		for _, result := range run.Results {
			if len(result.Locations) == 0 {
				log.Warn().Str("rule_id", result.RuleID).Msg("Skipping result with no locations")
				continue
			}

			location := result.Locations[0].PhysicalLocation

			// Get rule information
			rule, hasRule := ruleMap[result.RuleID]
			description := result.Message.Text
			cweDescription := result.RuleID
			if hasRule && rule.ShortDescription != nil {
				cweDescription = rule.ShortDescription.Text
			}

			// Extract CWE ID from properties or rule ID
			cweID := result.RuleID
			if result.Properties != nil && result.Properties.CWE != "" {
				cweID = result.Properties.CWE
			}

			// Map SARIF level to severity
			severity := mapLevelToSeverity(result.Level)

			// Get confidence
			confidence := "medium"
			if result.Properties != nil && result.Properties.Confidence != "" {
				confidence = result.Properties.Confidence
			}

			// Generate fingerprint if not provided
			fingerprint := ""
			if result.Properties != nil && result.Properties.Fingerprint != "" {
				fingerprint = result.Properties.Fingerprint
			} else {
				fingerprint = generateFingerprint(location.ArtifactLocation.URI, location.Region.StartLine, cweID)
			}

			finding := scanner.NormalizedFinding{
				ID:              uuid.New().String(),
				FindingID:       uuid.New().String(),
				CWEID:           cweID,
				CWEDescription:  cweDescription,
				Severity:        severity,
				Confidence:      confidence,
				CodeFingerprint: fingerprint,
				FilePath:        location.ArtifactLocation.URI,
				LineNumber:      location.Region.StartLine,
				Description:     description,
				Timestamp:       time.Now(),
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// mapLevelToSeverity maps SARIF level to internal severity
func mapLevelToSeverity(level string) string {
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "medium"
	}
}

// generateFingerprint generates a fingerprint for a finding
func generateFingerprint(filePath string, lineNumber int, cweID string) string {
	return fmt.Sprintf("%s:%d:%s", filePath, lineNumber, cweID)
}

// PolicyImportOptions configures policy import behavior
type PolicyImportOptions struct {
	// ValidateOnly performs validation without importing
	ValidateOnly bool
	// OverwriteExisting overwrites existing policies with same ID
	OverwriteExisting bool
	// TemplateDir is the directory containing policy templates
	TemplateDir string
}

// PolicyImportResult contains the results of a policy import operation
type PolicyImportResult struct {
	TotalPolicies    int
	ImportedPolicies int
	SkippedPolicies  int
	FailedPolicies   int
	Errors           []string
}

// ImportPoliciesFromYAML imports policies from a YAML file
func (i *Importer) ImportPoliciesFromYAML(path string, opts PolicyImportOptions) (*PolicyImportResult, error) {
	log.Info().Str("path", path).Msg("Importing policies from YAML")

	// Read YAML file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	// Parse YAML
	var policySet policy.PolicySet
	if err := yaml.Unmarshal(data, &policySet); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate policy set
	if err := policySet.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy set: %w", err)
	}

	// Validate only mode
	if opts.ValidateOnly {
		return &PolicyImportResult{
			TotalPolicies:    len(policySet.Policies),
			ImportedPolicies: 0,
			SkippedPolicies:  0,
			FailedPolicies:   0,
			Errors:           []string{},
		}, nil
	}

	// Import policies
	return i.importPolicies(policySet.Policies, opts)
}

// ImportPoliciesFromTemplate imports policies from a template directory
func (i *Importer) ImportPoliciesFromTemplate(templateName string, opts PolicyImportOptions) (*PolicyImportResult, error) {
	log.Info().Str("template", templateName).Msg("Importing policies from template")

	// Determine template directory
	templateDir := opts.TemplateDir
	if templateDir == "" {
		// Default template directories
		templateDir = "examples/policies"
	}

	// Build template path
	templatePath := filepath.Join(templateDir, templateName)
	
	// Check if template exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		// Try with .yaml extension
		templatePath = templatePath + ".yaml"
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			// Try with .yml extension
			templatePath = filepath.Join(templateDir, templateName+".yml")
			if _, err := os.Stat(templatePath); os.IsNotExist(err) {
				return nil, fmt.Errorf("template not found: %s", templateName)
			}
		}
	}

	// Import from the template file
	return i.ImportPoliciesFromYAML(templatePath, opts)
}

// importPolicies imports a list of policies
func (i *Importer) importPolicies(policies []policy.Policy, opts PolicyImportOptions) (*PolicyImportResult, error) {
	result := &PolicyImportResult{
		TotalPolicies: len(policies),
		Errors:        []string{},
	}

	for _, pol := range policies {
		// Validate policy
		if err := pol.Validate(); err != nil {
			result.FailedPolicies++
			result.Errors = append(result.Errors, fmt.Sprintf("invalid policy %s: %v", pol.ID, err))
			continue
		}

		// Check if policy already exists
		exists, err := i.policyExists(pol.ID)
		if err != nil {
			result.FailedPolicies++
			result.Errors = append(result.Errors, fmt.Sprintf("failed to check policy %s: %v", pol.ID, err))
			continue
		}

		// Handle existing policy
		if exists {
			if !opts.OverwriteExisting {
				result.SkippedPolicies++
				log.Debug().Str("policy_id", pol.ID).Msg("Skipping existing policy")
				continue
			}
			// Delete existing policy
			if err := i.deletePolicy(pol.ID); err != nil {
				result.FailedPolicies++
				result.Errors = append(result.Errors, fmt.Sprintf("failed to delete existing policy %s: %v", pol.ID, err))
				continue
			}
		}

		// Save policy
		if err := i.savePolicy(&pol); err != nil {
			result.FailedPolicies++
			result.Errors = append(result.Errors, fmt.Sprintf("failed to import policy %s: %v", pol.ID, err))
			continue
		}

		result.ImportedPolicies++
	}

	log.Info().
		Int("total", result.TotalPolicies).
		Int("imported", result.ImportedPolicies).
		Int("skipped", result.SkippedPolicies).
		Int("failed", result.FailedPolicies).
		Msg("Policy import completed")

	return result, nil
}

// policyExists checks if a policy with the given ID already exists
func (i *Importer) policyExists(policyID string) (bool, error) {
	query := `SELECT COUNT(*) FROM policies WHERE id = ?`
	rows, err := i.db.Query(query, policyID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	if rows.Next() {
		var count int
		if err := rows.Scan(&count); err != nil {
			return false, err
		}
		return count > 0, nil
	}

	return false, nil
}

// deletePolicy deletes a policy by ID
func (i *Importer) deletePolicy(policyID string) error {
	query := `DELETE FROM policies WHERE id = ?`
	_, err := i.db.Query(query, policyID)
	return err
}

// savePolicy saves a policy to the database
func (i *Importer) savePolicy(pol *policy.Policy) error {
	// Convert CWE array to JSON
	cweJSON, err := json.Marshal(pol.CWE)
	if err != nil {
		return fmt.Errorf("failed to marshal CWE list: %w", err)
	}

	query := `
		INSERT INTO policies (id, name, description, cwe, severity, action, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = i.db.Query(query,
		pol.ID,
		pol.Name,
		pol.Description,
		string(cweJSON),
		pol.Severity,
		pol.Action,
		pol.Enabled,
		time.Now().Unix(),
	)

	return err
}

// ListAvailableTemplates lists available policy templates
func ListAvailableTemplates(templateDir string) ([]string, error) {
	if templateDir == "" {
		templateDir = "examples/policies"
	}

	// Check if directory exists
	if _, err := os.Stat(templateDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("template directory not found: %s", templateDir)
	}

	// Read directory
	entries, err := os.ReadDir(templateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read template directory: %w", err)
	}

	var templates []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Only include YAML files
		if filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml" {
			// Remove extension for template name
			templateName := name[:len(name)-len(filepath.Ext(name))]
			templates = append(templates, templateName)
		}
	}

	return templates, nil
}
