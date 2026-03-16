package cmd

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from scan results",
	Long:  `Generate various reports from stored scan results.`,
}

var reportGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a report from scan results",
	Long:  `Generate a comprehensive report from the most recent scan or a specific run.`,
	RunE:  runReportGenerate,
}

var (
	reportRunID  string
	reportFormat string
	reportOutput string
)

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.AddCommand(reportGenerateCmd)

	reportGenerateCmd.Flags().StringVar(&reportRunID, "run-id", "", "Generate report for specific run ID (default: latest)")
	reportGenerateCmd.Flags().StringVarP(&reportFormat, "format", "f", "markdown", "Report format: markdown, html, json, csv")
	reportGenerateCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Output file path (default: stdout)")
}

func runReportGenerate(cmd *cobra.Command, args []string) error {
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

	// Get run ID (latest if not specified)
	runID := reportRunID
	if runID == "" {
		err := db.QueryRow("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").Scan(&runID)
		if err == sql.ErrNoRows {
			return fmt.Errorf("no scan runs found in database")
		} else if err != nil {
			return fmt.Errorf("failed to get latest run: %w", err)
		}
	}

	// Get run details
	var (
		targetPath string
		status     string
		createdAt  int64
	)
	err = db.QueryRow("SELECT target_path, status, created_at FROM runs WHERE run_id = ?", runID).
		Scan(&targetPath, &status, &createdAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("run not found: %s", runID)
	} else if err != nil {
		return fmt.Errorf("failed to get run details: %w", err)
	}

	// Get findings summary
	var (
		totalFindings   int
		criticalCount   int
		highCount       int
		mediumCount     int
		lowCount        int
	)

	db.QueryRow("SELECT COUNT(*) FROM findings_normalized WHERE run_id = ?", runID).Scan(&totalFindings)
	db.QueryRow("SELECT COUNT(*) FROM findings_normalized WHERE run_id = ? AND LOWER(severity) = 'critical'", runID).Scan(&criticalCount)
	db.QueryRow("SELECT COUNT(*) FROM findings_normalized WHERE run_id = ? AND LOWER(severity) = 'high'", runID).Scan(&highCount)
	db.QueryRow("SELECT COUNT(*) FROM findings_normalized WHERE run_id = ? AND LOWER(severity) = 'medium'", runID).Scan(&mediumCount)
	db.QueryRow("SELECT COUNT(*) FROM findings_normalized WHERE run_id = ? AND LOWER(severity) = 'low'", runID).Scan(&lowCount)

	// Generate report based on format
	var report string
	switch reportFormat {
	case "markdown", "md":
		report = generateMarkdownReport(runID, targetPath, totalFindings, criticalCount, highCount, mediumCount, lowCount)
	case "html":
		report = generateHTMLReport(runID, targetPath, totalFindings, criticalCount, highCount, mediumCount, lowCount)
	case "json":
		report = generateJSONReport(runID, targetPath, totalFindings, criticalCount, highCount, mediumCount, lowCount)
	case "csv":
		report = generateCSVReport(db, runID)
	default:
		return fmt.Errorf("unsupported report format: %s", reportFormat)
	}

	// Output report
	if reportOutput != "" {
		if err := os.WriteFile(reportOutput, []byte(report), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Printf("Report generated: %s\n", reportOutput)
	} else {
		fmt.Println(report)
	}

	return nil
}

func generateMarkdownReport(runID, targetPath string, total, critical, high, medium, low int) string {
	return fmt.Sprintf(`# Security Scan Report

## Summary
- **Run ID**: %s
- **Target**: %s
- **Total Findings**: %d
- **Critical**: %d
- **High**: %d
- **Medium**: %d
- **Low**: %d

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | %d    | %.1f%%     |
| High     | %d    | %.1f%%     |
| Medium   | %d    | %.1f%%     |
| Low      | %d    | %.1f%%     |

## Recommendations

1. **Immediate Action Required**: Address all %d critical findings
2. **High Priority**: Review and fix %d high severity findings
3. **Medium Priority**: Plan remediation for %d medium severity findings
4. **Low Priority**: Consider fixing %d low severity findings

Use 'findings list --run-id %s' to see detailed findings.
Use 'findings show <id>' to view remediation guidance.
`,
		runID, targetPath, total, critical, high, medium, low,
		critical, percentage(critical, total),
		high, percentage(high, total),
		medium, percentage(medium, total),
		low, percentage(low, total),
		critical, high, medium, low, runID)
}

func generateHTMLReport(runID, targetPath string, total, critical, high, medium, low int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #007bff; }
        .card h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; }
        .card .value { font-size: 32px; font-weight: bold; color: #333; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #007bff; color: white; }
        tr:hover { background: #f8f9fa; }
        .recommendations { background: #e7f3ff; padding: 20px; border-radius: 6px; margin: 20px 0; }
        .recommendations li { margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Scan Report</h1>
        
        <div class="summary">
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value">%d</div>
            </div>
            <div class="card critical">
                <h3>Critical</h3>
                <div class="value">%d</div>
            </div>
            <div class="card high">
                <h3>High</h3>
                <div class="value">%d</div>
            </div>
            <div class="card medium">
                <h3>Medium</h3>
                <div class="value">%d</div>
            </div>
            <div class="card low">
                <h3>Low</h3>
                <div class="value">%d</div>
            </div>
        </div>

        <h2>Scan Details</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Run ID</td><td>%s</td></tr>
            <tr><td>Target Path</td><td>%s</td></tr>
        </table>

        <h2>Severity Distribution</h2>
        <table>
            <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
            <tr><td>Critical</td><td>%d</td><td>%.1f%%%%</td></tr>
            <tr><td>High</td><td>%d</td><td>%.1f%%%%</td></tr>
            <tr><td>Medium</td><td>%d</td><td>%.1f%%%%</td></tr>
            <tr><td>Low</td><td>%d</td><td>%.1f%%%%</td></tr>
        </table>

        <div class="recommendations">
            <h2>📋 Recommendations</h2>
            <ol>
                <li><strong>Immediate Action Required:</strong> Address all %d critical findings</li>
                <li><strong>High Priority:</strong> Review and fix %d high severity findings</li>
                <li><strong>Medium Priority:</strong> Plan remediation for %d medium severity findings</li>
                <li><strong>Low Priority:</strong> Consider fixing %d low severity findings</li>
            </ol>
        </div>

        <p><em>Generated by Coding Agent CLI</em></p>
    </div>
</body>
</html>`,
		total, critical, high, medium, low,
		runID, targetPath,
		critical, percentage(critical, total),
		high, percentage(high, total),
		medium, percentage(medium, total),
		low, percentage(low, total),
		critical, high, medium, low)
}

func generateJSONReport(runID, targetPath string, total, critical, high, medium, low int) string {
	return fmt.Sprintf(`{
  "run_id": "%s",
  "target_path": "%s",
  "summary": {
    "total_findings": %d,
    "critical": %d,
    "high": %d,
    "medium": %d,
    "low": %d
  },
  "distribution": {
    "critical_percent": %.1f,
    "high_percent": %.1f,
    "medium_percent": %.1f,
    "low_percent": %.1f
  }
}`,
		runID, targetPath, total, critical, high, medium, low,
		percentage(critical, total),
		percentage(high, total),
		percentage(medium, total),
		percentage(low, total))
}

func generateCSVReport(db *sql.DB, runID string) string {
	csv := "ID,CWE,Severity,Confidence,File,Line,Description\n"

	rows, err := db.Query(`
		SELECT norm_id, cwe_id, severity, confidence, file_path, line_number, description
		FROM findings_normalized
		WHERE run_id = ?
		ORDER BY severity DESC
	`, runID)
	if err != nil {
		return csv
	}
	defer rows.Close()

	for rows.Next() {
		var id, cweID, severity, confidence, filePath, description string
		var lineNumber int
		if err := rows.Scan(&id, &cweID, &severity, &confidence, &filePath, &lineNumber, &description); err != nil {
			continue
		}
		csv += fmt.Sprintf("%s,%s,%s,%s,%s,%d,\"%s\"\n",
			id, cweID, severity, confidence, filePath, lineNumber, description)
	}

	return csv
}

func percentage(count, total int) float64 {
	if total == 0 {
		return 0.0
	}
	return float64(count) / float64(total) * 100.0
}
