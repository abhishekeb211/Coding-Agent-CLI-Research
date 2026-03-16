package cmd

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	_ "modernc.org/sqlite"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Manage security findings",
	Long:  `List, view, and manage security findings from previous scans.`,
}

var findingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all findings",
	Long:  `List all findings from the database with optional filtering.`,
	RunE:  runFindingsList,
}

var findingsShowCmd = &cobra.Command{
	Use:   "show [finding-id]",
	Short: "Show detailed information about a finding",
	Long:  `Display detailed information about a specific finding including remediation guidance.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingsShow,
}

var (
	listRunID      string
	listSeverity   string
	listCWE        string
	listLimit      int
	showRemediation bool
)

func init() {
	rootCmd.AddCommand(findingsCmd)
	findingsCmd.AddCommand(findingsListCmd)
	findingsCmd.AddCommand(findingsShowCmd)

	// List command flags
	findingsListCmd.Flags().StringVar(&listRunID, "run-id", "", "Filter by run ID")
	findingsListCmd.Flags().StringVar(&listSeverity, "severity", "", "Filter by severity (critical, high, medium, low)")
	findingsListCmd.Flags().StringVar(&listCWE, "cwe", "", "Filter by CWE ID (e.g., CWE-89)")
	findingsListCmd.Flags().IntVar(&listLimit, "limit", 50, "Maximum number of findings to display")

	// Show command flags
	findingsShowCmd.Flags().BoolVar(&showRemediation, "remediation", true, "Show remediation guidance")
}

func runFindingsList(cmd *cobra.Command, args []string) error {
	// Get database path
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = "./data/findings.db"
	}

	// Ensure absolute path
	if !filepath.IsAbs(dbPath) {
		absPath, err := filepath.Abs(dbPath)
		if err != nil {
			return fmt.Errorf("failed to resolve database path: %w", err)
		}
		dbPath = absPath
	}

	// Check if database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("database not found at %s. Run a scan first", dbPath)
	}

	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Build query
	query := `
		SELECT 
			f.norm_id,
			f.cwe_id,
			f.severity,
			f.confidence,
			f.file_path,
			f.line_number,
			f.description,
			r.created_at
		FROM findings_normalized f
		JOIN runs r ON f.run_id = r.run_id
		WHERE 1=1
	`
	queryArgs := []interface{}{}

	if listRunID != "" {
		query += " AND f.run_id = ?"
		queryArgs = append(queryArgs, listRunID)
	}

	if listSeverity != "" {
		query += " AND LOWER(f.severity) = LOWER(?)"
		queryArgs = append(queryArgs, listSeverity)
	}

	if listCWE != "" {
		query += " AND f.cwe_id = ?"
		queryArgs = append(queryArgs, listCWE)
	}

	query += " ORDER BY r.created_at DESC, f.severity DESC LIMIT ?"
	queryArgs = append(queryArgs, listLimit)

	// Execute query
	rows, err := db.Query(query, queryArgs...)
	if err != nil {
		return fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	// Display results
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCWE\tSEVERITY\tFILE\tLINE\tDESCRIPTION")
	fmt.Fprintln(w, strings.Repeat("-", 120))

	count := 0
	for rows.Next() {
		var (
			id          string
			cweID       string
			severity    string
			confidence  string
			filePath    string
			lineNumber  int
			description string
			createdAt   int64
		)

		if err := rows.Scan(&id, &cweID, &severity, &confidence, &filePath, &lineNumber, &description, &createdAt); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}

		// Truncate ID and description for display
		shortID := id
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		shortDesc := description
		if len(shortDesc) > 50 {
			shortDesc = shortDesc[:47] + "..."
		}

		shortFile := filePath
		if len(shortFile) > 30 {
			shortFile = "..." + shortFile[len(shortFile)-27:]
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			shortID, cweID, severity, shortFile, lineNumber, shortDesc)
		count++
	}

	w.Flush()

	if count == 0 {
		fmt.Println("\nNo findings found.")
	} else {
		fmt.Printf("\nTotal: %d findings\n", count)
		fmt.Println("\nUse 'findings show <id>' to view details and remediation guidance.")
	}

	return nil
}

func runFindingsShow(cmd *cobra.Command, args []string) error {
	findingID := args[0]

	// Get database path
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = "./data/findings.db"
	}

	// Ensure absolute path
	if !filepath.IsAbs(dbPath) {
		absPath, err := filepath.Abs(dbPath)
		if err != nil {
			return fmt.Errorf("failed to resolve database path: %w", err)
		}
		dbPath = absPath
	}

	// Check if database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("database not found at %s. Run a scan first", dbPath)
	}

	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Query finding details
	query := `
		SELECT 
			f.norm_id,
			f.finding_id,
			f.cwe_id,
			f.severity,
			f.confidence,
			f.file_path,
			f.line_number,
			f.column_number,
			f.description,
			f.code_snippet,
			f.remediation,
			r.run_id,
			r.target_path,
			r.created_at
		FROM findings_normalized f
		JOIN runs r ON f.run_id = r.run_id
		WHERE f.norm_id LIKE ? OR f.finding_id LIKE ?
		LIMIT 1
	`

	var (
		normID       string
		rawFindingID string
		cweID        string
		severity     string
		confidence   string
		filePath     string
		lineNumber   int
		columnNumber int
		description  string
		codeSnippet  sql.NullString
		remediation  sql.NullString
		runID        string
		targetPath   string
		createdAt    int64
	)

	err = db.QueryRow(query, findingID+"%", findingID+"%").Scan(
		&normID, &rawFindingID, &cweID, &severity, &confidence,
		&filePath, &lineNumber, &columnNumber, &description,
		&codeSnippet, &remediation, &runID, &targetPath, &createdAt,
	)

	if err == sql.ErrNoRows {
		return fmt.Errorf("finding not found: %s", findingID)
	} else if err != nil {
		return fmt.Errorf("failed to query finding: %w", err)
	}

	// Display finding details
	fmt.Println("=== Finding Details ===")
	fmt.Printf("ID: %s\n", normID)
	fmt.Printf("CWE: %s\n", cweID)
	fmt.Printf("Severity: %s\n", severity)
	fmt.Printf("Confidence: %s\n", confidence)
	fmt.Printf("File: %s:%d:%d\n", filePath, lineNumber, columnNumber)
	fmt.Printf("Description: %s\n", description)
	fmt.Printf("Scan Run: %s\n", runID)
	fmt.Printf("Target: %s\n", targetPath)
	fmt.Printf("Detected: %s\n", time.Unix(createdAt, 0).Format(time.RFC3339))

	if codeSnippet.Valid && codeSnippet.String != "" {
		fmt.Println("\n=== Code Snippet ===")
		fmt.Println(codeSnippet.String)
	}

	if showRemediation && remediation.Valid && remediation.String != "" {
		fmt.Println("\n=== Remediation Guidance ===")
		fmt.Println(remediation.String)
	} else if showRemediation {
		fmt.Println("\n=== Remediation Guidance ===")
		fmt.Println("No remediation guidance available. Run scan with --llm flag to generate guidance.")
	}

	return nil
}
