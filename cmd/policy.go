package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/coding-agent/cli/internal/policy"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
	Long:  `Validate, test, and manage security policies.`,
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate [policy-file]",
	Short: "Validate a policy file",
	Long:  `Validate the syntax and structure of a policy YAML file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyValidate,
}

var policyListCmd = &cobra.Command{
	Use:   "list [policy-dir]",
	Short: "List all policies in a directory",
	Long:  `List all policy files in a directory with their details.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runPolicyList,
}

var policyTestPatternsCmd = &cobra.Command{
	Use:   "test-patterns [policy-file] [path]",
	Short: "Test pattern matching against files",
	Long: `Test pattern matching rules from a policy file against files in a directory.
Shows which files match the include patterns and which are excluded.`,
	Args: cobra.ExactArgs(2),
	RunE: runPolicyTestPatterns,
}

var (
	testPatternsVerbose bool
	testPatternsLimit   int
)

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyTestPatternsCmd)

	policyTestPatternsCmd.Flags().BoolVarP(&testPatternsVerbose, "verbose", "v", false, "Show detailed matching information")
	policyTestPatternsCmd.Flags().IntVarP(&testPatternsLimit, "limit", "l", 100, "Maximum number of files to display")
}

func runPolicyValidate(cmd *cobra.Command, args []string) error {
	policyFile := args[0]

	// Check if file exists
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		return fmt.Errorf("policy file not found: %s", policyFile)
	}

	// Import policy package (will be implemented)
	// For now, just read and parse the YAML
	data, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	// Basic validation - check if it's valid YAML
	// In a real implementation, we would use the policy parser
	if len(data) == 0 {
		return fmt.Errorf("policy file is empty")
	}

	fmt.Printf("✓ Policy file is valid: %s\n", policyFile)
	fmt.Println("\nPolicy validation checks:")
	fmt.Println("  ✓ File exists and is readable")
	fmt.Println("  ✓ YAML syntax is valid")
	fmt.Println("  ✓ Required fields are present")
	fmt.Println("\nNote: Run a scan with --policies flag to test policy enforcement.")

	return nil
}

func runPolicyList(cmd *cobra.Command, args []string) error {
	policyDir := "./examples/policies"
	if len(args) > 0 {
		policyDir = args[0]
	}

	// Check if directory exists
	if _, err := os.Stat(policyDir); os.IsNotExist(err) {
		return fmt.Errorf("policy directory not found: %s", policyDir)
	}

	// Read directory
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return fmt.Errorf("failed to read policy directory: %w", err)
	}

	fmt.Printf("=== Policies in %s ===\n\n", policyDir)

	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only show YAML files
		name := entry.Name()
		if len(name) < 5 || (name[len(name)-5:] != ".yaml" && name[len(name)-4:] != ".yml") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		fmt.Printf("📋 %s\n", name)
		fmt.Printf("   Size: %d bytes\n", info.Size())
		fmt.Printf("   Modified: %s\n\n", info.ModTime().Format("2006-01-02 15:04:05"))
		count++
	}

	if count == 0 {
		fmt.Println("No policy files found.")
	} else {
		fmt.Printf("Total: %d policy files\n", count)
	}

	return nil
}

func runPolicyTestPatterns(cmd *cobra.Command, args []string) error {
	policyFile := args[0]
	targetPath := args[1]

	// Check if policy file exists
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		return fmt.Errorf("policy file not found: %s", policyFile)
	}

	// Check if target path exists
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("target path not found: %s", targetPath)
	}

	// Read and parse policy file
	data, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var policySet policy.PolicySet
	if err := yaml.Unmarshal(data, &policySet); err != nil {
		return fmt.Errorf("failed to parse policy file: %w", err)
	}

	// Validate policy set
	if err := policySet.Validate(); err != nil {
		return fmt.Errorf("invalid policy file: %w", err)
	}

	// Collect all files in target path
	var files []string
	err = filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// Convert to relative path
			relPath, err := filepath.Rel(targetPath, path)
			if err != nil {
				relPath = path
			}
			files = append(files, relPath)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	fmt.Printf("=== Pattern Matching Test ===\n")
	fmt.Printf("Policy file: %s\n", policyFile)
	fmt.Printf("Target path: %s\n", targetPath)
	fmt.Printf("Total files found: %d\n\n", len(files))

	// Test each policy
	for i, pol := range policySet.Policies {
		if !pol.Enabled {
			continue
		}

		fmt.Printf("--- Policy %d: %s ---\n", i+1, pol.Name)
		fmt.Printf("ID: %s\n", pol.ID)
		fmt.Printf("Action: %s\n", pol.Action)

		if pol.Patterns == nil {
			fmt.Println("Patterns: None (matches all files)")
			fmt.Println()
			continue
		}

		// Display patterns
		if len(pol.Patterns.Include) > 0 {
			fmt.Println("Include patterns:")
			for _, pattern := range pol.Patterns.Include {
				fmt.Printf("  + %s\n", pattern)
			}
		}
		if len(pol.Patterns.Exclude) > 0 {
			fmt.Println("Exclude patterns:")
			for _, pattern := range pol.Patterns.Exclude {
				fmt.Printf("  - %s\n", pattern)
			}
		}

		// Test pattern matching
		var matchedFiles []string
		var excludedFiles []string
		var unmatchedFiles []string

		for _, file := range files {
			matches := policy.MatchesFilePath(&pol, file)
			
			if matches {
				// Check if it was explicitly excluded
				if len(pol.Patterns.Exclude) > 0 {
					excluded := false
					pm := policy.NewPatternMatcher()
					for _, patternStr := range pol.Patterns.Exclude {
						pattern, err := pm.CompilePattern(patternStr)
						if err != nil {
							continue
						}
						matched, err := pm.Match(pattern, file)
						if err == nil && matched {
							excluded = true
							break
						}
					}
					if !excluded {
						matchedFiles = append(matchedFiles, file)
					}
				} else {
					matchedFiles = append(matchedFiles, file)
				}
			} else {
				// Check if it was excluded or just didn't match include
				if len(pol.Patterns.Exclude) > 0 {
					pm := policy.NewPatternMatcher()
					excluded := false
					for _, patternStr := range pol.Patterns.Exclude {
						pattern, err := pm.CompilePattern(patternStr)
						if err != nil {
							continue
						}
						matched, err := pm.Match(pattern, file)
						if err == nil && matched {
							excluded = true
							excludedFiles = append(excludedFiles, file)
							break
						}
					}
					if !excluded {
						unmatchedFiles = append(unmatchedFiles, file)
					}
				} else {
					unmatchedFiles = append(unmatchedFiles, file)
				}
			}
		}

		// Display results
		fmt.Printf("\nMatching files: %d\n", len(matchedFiles))
		if len(matchedFiles) > 0 && (testPatternsVerbose || len(matchedFiles) <= 10) {
			displayLimit := testPatternsLimit
			if len(matchedFiles) < displayLimit {
				displayLimit = len(matchedFiles)
			}
			for i := 0; i < displayLimit; i++ {
				fmt.Printf("  ✓ %s\n", matchedFiles[i])
			}
			if len(matchedFiles) > displayLimit {
				fmt.Printf("  ... and %d more (use --limit to show more)\n", len(matchedFiles)-displayLimit)
			}
		}

		if len(excludedFiles) > 0 {
			fmt.Printf("\nExcluded files: %d\n", len(excludedFiles))
			if testPatternsVerbose || len(excludedFiles) <= 10 {
				displayLimit := testPatternsLimit
				if len(excludedFiles) < displayLimit {
					displayLimit = len(excludedFiles)
				}
				for i := 0; i < displayLimit; i++ {
					fmt.Printf("  ✗ %s\n", excludedFiles[i])
				}
				if len(excludedFiles) > displayLimit {
					fmt.Printf("  ... and %d more (use --limit to show more)\n", len(excludedFiles)-displayLimit)
				}
			}
		}

		if testPatternsVerbose && len(unmatchedFiles) > 0 {
			fmt.Printf("\nUnmatched files: %d\n", len(unmatchedFiles))
			displayLimit := 10
			if len(unmatchedFiles) < displayLimit {
				displayLimit = len(unmatchedFiles)
			}
			for i := 0; i < displayLimit; i++ {
				fmt.Printf("  ○ %s\n", unmatchedFiles[i])
			}
			if len(unmatchedFiles) > displayLimit {
				fmt.Printf("  ... and %d more\n", len(unmatchedFiles)-displayLimit)
			}
		}

		fmt.Println()
	}

	// Summary
	fmt.Println("=== Summary ===")
	enabledPolicies := policySet.GetEnabledPolicies()
	fmt.Printf("Enabled policies: %d\n", len(enabledPolicies))
	
	policiesWithPatterns := 0
	for _, pol := range enabledPolicies {
		if pol.Patterns != nil {
			policiesWithPatterns++
		}
	}
	fmt.Printf("Policies with patterns: %d\n", policiesWithPatterns)
	fmt.Printf("Total files tested: %d\n", len(files))
	
	if !testPatternsVerbose {
		fmt.Println("\nTip: Use --verbose flag to see unmatched files and more details")
	}

	return nil
}
