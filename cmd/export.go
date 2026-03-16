package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/coding-agent/cli/internal/exporter"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	exportFormat     string
	exportOutput     string
	exportType       string
	exportRunID      string
	exportSeverity   string
	exportStartDate  string
	exportEndDate    string
	exportPolicyID   string
)

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export findings or policies to various formats",
	Long: `Export security findings or policies to various formats for sharing, backup, or analysis.

Export Types:
  - findings: Export security findings (default)
  - policies: Export security policies

Supported formats for findings:
  - JSON: Full fidelity with all metadata (default)
  - CSV: Tabular format for spreadsheet analysis
  - Excel: Formatted workbook with multiple sheets (requires excelize)
  - SARIF: Standard format for tool interoperability

Supported formats for policies:
  - YAML: Portable policy definition format (default)
  - JSON: JSON format for programmatic use

Examples:
  # Export all findings to JSON
  coding-agent-cli export findings --output findings.json

  # Export findings to CSV
  coding-agent-cli export findings --format csv --output findings.csv

  # Export findings from specific run
  coding-agent-cli export findings --run-id abc123 --output findings.json

  # Export findings by severity
  coding-agent-cli export findings --severity critical,high --output critical.json

  # Export findings by date range
  coding-agent-cli export findings --start-date 2024-01-01 --end-date 2024-12-31

  # Export all policies to YAML
  coding-agent-cli export policies --output policies.yaml

  # Export specific policy
  coding-agent-cli export policies --policy-id my-policy --output policy.yaml

  # Export policies to JSON
  coding-agent-cli export policies --format json --output policies.json
`,
	Args: cobra.ExactArgs(1),
	RunE: runExport,
}

func init() {
	rootCmd.AddCommand(exportCmd)

	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "", "Output format (json, csv, excel, sarif for findings; yaml, json for policies) - auto-detected from output file if not specified")
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output file path (required)")
	exportCmd.Flags().StringVar(&exportRunID, "run-id", "", "Export findings from specific run ID (findings only)")
	exportCmd.Flags().StringVar(&exportSeverity, "severity", "", "Filter by severity (comma-separated: critical,high,medium,low) (findings only)")
	exportCmd.Flags().StringVar(&exportStartDate, "start-date", "", "Filter by start date (YYYY-MM-DD) (findings only)")
	exportCmd.Flags().StringVar(&exportEndDate, "end-date", "", "Filter by end date (YYYY-MM-DD) (findings only)")
	exportCmd.Flags().StringVar(&exportPolicyID, "policy-id", "", "Export specific policy by ID (policies only)")

	exportCmd.MarkFlagRequired("output")
}

func runExport(cmd *cobra.Command, args []string) error {
	exportType = args[0]

	// Validate export type
	if exportType != "findings" && exportType != "policies" {
		return fmt.Errorf("invalid export type: %s (supported: findings, policies)", exportType)
	}

	// Auto-detect format from output file if not specified
	if exportFormat == "" {
		exportFormat = detectFormatFromFile(exportOutput)
		log.Info().Str("format", exportFormat).Msg("Auto-detected format from output file")
	}

	// Route to appropriate export handler
	switch exportType {
	case "findings":
		return exportFindings()
	case "policies":
		return exportPolicies()
	default:
		return fmt.Errorf("invalid export type: %s", exportType)
	}
}

func exportFindings() error {
	// Validate format
	validFormats := []string{"json", "csv", "excel", "sarif"}
	if !contains(validFormats, exportFormat) {
		return fmt.Errorf("unsupported format for findings: %s (supported: %s)", exportFormat, strings.Join(validFormats, ", "))
	}

	// Initialize database
	dbPath := getDBPath()
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create exporter
	exp := exporter.NewExporter(db)

	// Prepare export options
	opts := exporter.FindingsExportOptions{
		RunID:      exportRunID,
		Severity:   parseSeverityFilter(exportSeverity),
		StartDate:  exportStartDate,
		EndDate:    exportEndDate,
	}

	// Export findings
	var result *exporter.ExportResult
	switch exportFormat {
	case "json":
		result, err = exp.ExportFindingsToJSON(exportOutput, opts)
	case "csv":
		result, err = exp.ExportFindingsToCSV(exportOutput, opts)
	case "excel":
		result, err = exp.ExportFindingsToExcel(exportOutput, opts)
	case "sarif":
		result, err = exp.ExportFindingsToSARIF(exportOutput, opts)
	default:
		return fmt.Errorf("unsupported format: %s", exportFormat)
	}

	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Display results
	fmt.Printf("✓ Export completed\n")
	fmt.Printf("  Format: %s\n", exportFormat)
	fmt.Printf("  Output: %s\n", exportOutput)
	fmt.Printf("  Total findings: %d\n", result.TotalRecords)
	fmt.Printf("  File size: %s\n", formatFileSize(result.FileSize))

	return nil
}

func exportPolicies() error {
	// Validate format
	validFormats := []string{"yaml", "yml", "json"}
	if !contains(validFormats, exportFormat) {
		return fmt.Errorf("unsupported format for policies: %s (supported: yaml, json)", exportFormat)
	}

	// Initialize database
	dbPath := getDBPath()
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create exporter
	exp := exporter.NewExporter(db)

	// Prepare export options
	opts := exporter.PoliciesExportOptions{
		PolicyID: exportPolicyID,
	}

	// Export policies
	var result *exporter.ExportResult
	switch exportFormat {
	case "yaml", "yml":
		result, err = exp.ExportPoliciesToYAML(exportOutput, opts)
	case "json":
		result, err = exp.ExportPoliciesToJSON(exportOutput, opts)
	default:
		return fmt.Errorf("unsupported format: %s", exportFormat)
	}

	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Display results
	fmt.Printf("✓ Export completed\n")
	fmt.Printf("  Format: %s\n", exportFormat)
	fmt.Printf("  Output: %s\n", exportOutput)
	fmt.Printf("  Total policies: %d\n", result.TotalRecords)
	fmt.Printf("  File size: %s\n", formatFileSize(result.FileSize))

	return nil
}

// Helper functions

func detectFormatFromFile(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	case ".xlsx":
		return "excel"
	case ".sarif":
		return "sarif"
	case ".yaml", ".yml":
		return "yaml"
	default:
		return "json" // default to JSON
	}
}

func parseSeverityFilter(severity string) []string {
	if severity == "" {
		return nil
	}
	parts := strings.Split(severity, ",")
	var result []string
	for _, p := range parts {
		result = append(result, strings.TrimSpace(p))
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
