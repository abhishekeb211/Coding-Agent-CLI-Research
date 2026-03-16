package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coding-agent/cli/internal/importer"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	importFormat          string
	importMode            string
	importRunID           string
	importTargetPath      string
	importToolName        string
	importValidateOnly    bool
	importType            string
	importOverwrite       bool
	importTemplateDir     string
	importListTemplates   bool
)

// importCmd represents the import command
var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import findings or policies from external sources",
	Long: `Import security findings or policies from external tools and formats.

Import Types:
  - findings: Import security findings (default)
  - policies: Import security policies

Supported formats for findings:
  - SARIF (Static Analysis Results Interchange Format)
  - JSON (Coding Agent CLI format or findings array)

Supported formats for policies:
  - YAML (Policy definition files)
  - template (Pre-defined policy templates)

Import modes (findings only):
  - replace: Replace existing findings with imported ones (default)
  - merge: Merge imported findings with existing ones
  - skip: Skip importing if findings already exist

Examples:
  # Import findings from SARIF file
  coding-agent-cli import results.sarif --format sarif

  # Import findings from JSON file with merge mode
  coding-agent-cli import findings.json --format json --mode merge

  # Import policies from YAML file
  coding-agent-cli import policies.yaml --type policies

  # Import policies from template
  coding-agent-cli import owasp-top10 --type policies --format template

  # List available policy templates
  coding-agent-cli import --type policies --list-templates

  # Validate without importing
  coding-agent-cli import results.sarif --validate-only

  # Import with custom run ID (findings only)
  coding-agent-cli import results.sarif --run-id my-scan-123
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)

	importCmd.Flags().StringVarP(&importFormat, "format", "f", "", "Input format (sarif, json, yaml, template) - auto-detected if not specified")
	importCmd.Flags().StringVarP(&importMode, "mode", "m", "replace", "Import mode for findings (replace, merge, skip)")
	importCmd.Flags().StringVar(&importRunID, "run-id", "", "Scan run ID to associate findings with (auto-generated if not specified)")
	importCmd.Flags().StringVar(&importTargetPath, "target-path", "", "Target path that was scanned (extracted from file if not specified)")
	importCmd.Flags().StringVar(&importToolName, "tool-name", "imported", "Name of the tool that generated the findings")
	importCmd.Flags().BoolVar(&importValidateOnly, "validate-only", false, "Validate the input file without importing")
	importCmd.Flags().StringVarP(&importType, "type", "t", "findings", "Import type (findings, policies)")
	importCmd.Flags().BoolVar(&importOverwrite, "overwrite", false, "Overwrite existing policies with same ID (policies only)")
	importCmd.Flags().StringVar(&importTemplateDir, "template-dir", "", "Directory containing policy templates (default: examples/policies)")
	importCmd.Flags().BoolVar(&importListTemplates, "list-templates", false, "List available policy templates")
}

func runImport(cmd *cobra.Command, args []string) error {
	// Handle list templates
	if importListTemplates {
		if importType != "policies" {
			return fmt.Errorf("--list-templates is only valid with --type policies")
		}
		return listPolicyTemplates()
	}

	// Require input file for import
	if len(args) == 0 {
		return fmt.Errorf("input file or template name is required")
	}

	inputFile := args[0]

	// Route to appropriate import handler
	switch importType {
	case "findings":
		return importFindings(inputFile)
	case "policies":
		return importPolicies(inputFile)
	default:
		return fmt.Errorf("invalid import type: %s (supported: findings, policies)", importType)
	}
}

func importFindings(inputFile string) error {
	// Check if file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", inputFile)
	}

	// Auto-detect format if not specified
	if importFormat == "" {
		importFormat = detectFormat(inputFile)
		log.Info().Str("format", importFormat).Msg("Auto-detected format")
	}

	// Validate format
	if importFormat != "sarif" && importFormat != "json" {
		return fmt.Errorf("unsupported format for findings: %s (supported: sarif, json)", importFormat)
	}

	// Validate mode
	mode := importer.ImportMode(importMode)
	if mode != importer.ImportModeReplace && mode != importer.ImportModeMerge && mode != importer.ImportModeSkip {
		return fmt.Errorf("invalid mode: %s (supported: replace, merge, skip)", importMode)
	}

	// Initialize database
	dbPath := getDBPath()
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create importer
	imp := importer.NewImporter(db)

	// Prepare import options
	opts := importer.ImportOptions{
		Mode:         mode,
		RunID:        importRunID,
		TargetPath:   importTargetPath,
		ValidateOnly: importValidateOnly,
		ToolName:     importToolName,
	}

	// Import findings
	var result *importer.ImportResult
	switch importFormat {
	case "sarif":
		result, err = imp.ImportFromSARIF(inputFile, opts)
	case "json":
		result, err = imp.ImportFromJSON(inputFile, opts)
	default:
		return fmt.Errorf("unsupported format: %s", importFormat)
	}

	if err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	// Display results
	if importValidateOnly {
		fmt.Printf("✓ Validation successful\n")
		fmt.Printf("  Total findings: %d\n", result.TotalFindings)
	} else {
		fmt.Printf("✓ Import completed\n")
		fmt.Printf("  Run ID: %s\n", result.RunID)
		fmt.Printf("  Total findings: %d\n", result.TotalFindings)
		fmt.Printf("  Imported: %d\n", result.ImportedFindings)
		fmt.Printf("  Skipped: %d\n", result.SkippedFindings)
		fmt.Printf("  Failed: %d\n", result.FailedFindings)

		if len(result.Errors) > 0 {
			fmt.Printf("\nErrors:\n")
			for _, err := range result.Errors {
				fmt.Printf("  - %s\n", err)
			}
		}
	}

	return nil
}

func importPolicies(input string) error {
	// Initialize database
	dbPath := getDBPath()
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create importer
	imp := importer.NewImporter(db)

	// Prepare import options
	opts := importer.PolicyImportOptions{
		ValidateOnly:      importValidateOnly,
		OverwriteExisting: importOverwrite,
		TemplateDir:       importTemplateDir,
	}

	// Auto-detect format if not specified
	if importFormat == "" {
		// Check if input is a file path
		if _, err := os.Stat(input); err == nil {
			importFormat = "yaml"
		} else {
			// Assume it's a template name
			importFormat = "template"
		}
		log.Info().Str("format", importFormat).Msg("Auto-detected format")
	}

	// Import policies
	var result *importer.PolicyImportResult
	switch importFormat {
	case "yaml", "yml":
		// Check if file exists
		if _, err := os.Stat(input); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", input)
		}
		result, err = imp.ImportPoliciesFromYAML(input, opts)
	case "template":
		result, err = imp.ImportPoliciesFromTemplate(input, opts)
	default:
		return fmt.Errorf("unsupported format for policies: %s (supported: yaml, template)", importFormat)
	}

	if err != nil {
		return fmt.Errorf("policy import failed: %w", err)
	}

	// Display results
	if importValidateOnly {
		fmt.Printf("✓ Validation successful\n")
		fmt.Printf("  Total policies: %d\n", result.TotalPolicies)
	} else {
		fmt.Printf("✓ Policy import completed\n")
		fmt.Printf("  Total policies: %d\n", result.TotalPolicies)
		fmt.Printf("  Imported: %d\n", result.ImportedPolicies)
		fmt.Printf("  Skipped: %d\n", result.SkippedPolicies)
		fmt.Printf("  Failed: %d\n", result.FailedPolicies)

		if len(result.Errors) > 0 {
			fmt.Printf("\nErrors:\n")
			for _, err := range result.Errors {
				fmt.Printf("  - %s\n", err)
			}
		}
	}

	return nil
}

func listPolicyTemplates() error {
	templates, err := importer.ListAvailableTemplates(importTemplateDir)
	if err != nil {
		return fmt.Errorf("failed to list templates: %w", err)
	}

	if len(templates) == 0 {
		fmt.Println("No policy templates found")
		return nil
	}

	fmt.Printf("Available policy templates:\n")
	for _, template := range templates {
		fmt.Printf("  - %s\n", template)
	}
	fmt.Printf("\nUse: coding-agent-cli import <template-name> --type policies --format template\n")

	return nil
}

// detectFormat detects the file format based on extension and content
func detectFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".sarif":
		return "sarif"
	case ".json":
		// Try to detect if it's SARIF or regular JSON
		data, err := os.ReadFile(path)
		if err != nil {
			return "json"
		}

		// Simple heuristic: check if it contains SARIF-specific fields
		content := string(data)
		if strings.Contains(content, `"$schema"`) && strings.Contains(content, "sarif") {
			return "sarif"
		}

		return "json"
	default:
		return "json"
	}
}
