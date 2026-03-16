package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"github.com/coding-agent/cli/internal/llm"
	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/coding-agent/cli/plugins/bandit"
	"github.com/coding-agent/cli/plugins/eslint"
	"github.com/coding-agent/cli/plugins/gosec"
	"github.com/coding-agent/cli/plugins/safety"
	"github.com/coding-agent/cli/plugins/semgrep"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	outputFile   string
	outputFormat string
	scanners     []string
	dbPath       string
	enableLLM    bool
	policyPath   string
	waiverPath   string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a repository for security vulnerabilities",
	Long: `Scan a repository or directory for security vulnerabilities using configured SAST tools.
The scan will run in offline mode with cryptographic verification.

Example:
  coding-agent-cli scan ./my-app
  coding-agent-cli scan ./my-app --output report.json --format json
  coding-agent-cli scan ./my-app --scanners bandit,semgrep`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "output format (json, sarif, markdown)")
	scanCmd.Flags().StringSliceVar(&scanners, "scanners", []string{}, "scanners to use (comma-separated)")
	scanCmd.Flags().StringVar(&dbPath, "db", "./data/findings.db", "database path")
	scanCmd.Flags().BoolVar(&enableLLM, "llm", false, "enable AI-powered remediation guidance")
	scanCmd.Flags().StringVar(&policyPath, "policies", "", "path to policy file or directory")
	scanCmd.Flags().StringVar(&waiverPath, "waivers", "", "path to waiver file")
}

func runScan(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	// Validate target path
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", absPath)
	}

	log.Info().
		Str("path", absPath).
		Str("format", outputFormat).
		Msg("Starting security scan")

	// Initialize database
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create scanner orchestrator
	config := scanner.Config{
		TargetPath:   absPath,
		OutputFormat: outputFormat,
		OutputFile:   outputFile,
		Scanners:     scanners,
		OfflineMode:  GetConfigBool("offline_mode"),
		Verbose:      verbose,
	}

	orchestrator := scanner.NewOrchestrator(config)
	orchestrator.SetDatabase(db)

	// Register scanner plugins
	banditScanner := bandit.New()
	if banditScanner.IsAvailable() {
		orchestrator.RegisterScanner(banditScanner)
		log.Debug().Msg("Bandit scanner registered")
	}

	semgrepScanner := semgrep.New()
	if semgrepScanner.IsAvailable() {
		orchestrator.RegisterScanner(semgrepScanner)
		log.Debug().Msg("Semgrep scanner registered")
	}

	gosecScanner := gosec.New()
	if gosecScanner.IsAvailable() {
		orchestrator.RegisterScanner(gosecScanner)
		log.Debug().Msg("gosec scanner registered")
	}

	eslintScanner := eslint.New()
	if eslintScanner.IsAvailable() {
		orchestrator.RegisterScanner(eslintScanner)
		log.Debug().Msg("eslint scanner registered")
	}

	safetyScanner := safety.New()
	if safetyScanner.IsAvailable() {
		orchestrator.RegisterScanner(safetyScanner)
		log.Debug().Msg("safety scanner registered")
	}

	// Enable LLM if requested
	if enableLLM {
		log.Info().Msg("Enabling AI-powered remediation guidance")
		llmConfig := llm.DefaultConfig()
		if err := orchestrator.EnableLLM(llmConfig); err != nil {
			log.Warn().Err(err).Msg("Failed to enable LLM, continuing without remediation")
		}
	}

	// Enable policy enforcement if requested
	if policyPath != "" {
		log.Info().Str("path", policyPath).Msg("Enabling policy enforcement")
		if err := orchestrator.EnablePolicy(policyPath, waiverPath); err != nil {
			log.Warn().Err(err).Msg("Failed to enable policies, continuing without enforcement")
		}
	}

	// Run scan
	startTime := time.Now()
	result, err := orchestrator.Scan(cmd.Context())
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	duration := time.Since(startTime)

	// Print summary
	log.Info().
		Int("findings", result.TotalFindings).
		Int("critical", result.CriticalCount).
		Int("high", result.HighCount).
		Int("medium", result.MediumCount).
		Int("low", result.LowCount).
		Dur("duration", duration).
		Msg("Scan completed")

	// Save output if specified
	if outputFile != "" {
		if err := result.SaveToFile(outputFile, outputFormat); err != nil {
			return fmt.Errorf("failed to save output: %w", err)
		}
		log.Info().Str("file", outputFile).Msg("Results saved")
	}

	// Print summary to console
	fmt.Printf("\n=== Scan Summary ===\n")
	fmt.Printf("Target: %s\n", result.TargetPath)
	fmt.Printf("Scanners: %v\n", result.Scanners)
	fmt.Printf("Total Findings: %d\n", result.TotalFindings)
	fmt.Printf("  Critical: %d\n", result.CriticalCount)
	fmt.Printf("  High: %d\n", result.HighCount)
	fmt.Printf("  Medium: %d\n", result.MediumCount)
	fmt.Printf("  Low: %d\n", result.LowCount)
	fmt.Printf("Duration: %s\n", duration)
	fmt.Printf("Database: %s\n", dbPath)

	// Print policy summary if enabled
	if result.PolicyDecisions != nil {
		// Type assert to slice
		if decisions, ok := result.PolicyDecisions.([]interface{}); ok && len(decisions) > 0 {
			fmt.Printf("\n=== Policy Compliance ===\n")
			deny := 0
			warn := 0
			allow := 0
			waived := 0
			for _, d := range decisions {
				if decisionMap, ok := d.(map[string]interface{}); ok {
					action, _ := decisionMap["action"].(string)
					waiverApplied, _ := decisionMap["waiver_applied"].(bool)
					
					switch action {
					case "deny":
						deny++
					case "warn":
						warn++
					case "allow":
						allow++
					}
					if waiverApplied {
						waived++
					}
				}
			}
			fmt.Printf("Violations (deny): %d\n", deny)
			fmt.Printf("Warnings: %d\n", warn)
			fmt.Printf("Allowed: %d\n", allow)
			fmt.Printf("Waived: %d\n", waived)
		}
	}

	// Exit with error code if critical findings or policy violations
	if result.CriticalCount > 0 {
		log.Warn().Msg("Critical vulnerabilities found")
		os.Exit(1)
	}

	// Check for policy violations
	if result.PolicyDecisions != nil {
		if decisions, ok := result.PolicyDecisions.([]interface{}); ok {
			for _, d := range decisions {
				if decisionMap, ok := d.(map[string]interface{}); ok {
					action, _ := decisionMap["action"].(string)
					if action == "deny" {
						log.Warn().Msg("Policy violations found")
						os.Exit(1)
					}
				}
			}
		}
	}

	return nil
}
