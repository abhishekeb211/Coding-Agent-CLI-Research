package bandit

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/coding-agent/cli/internal/scanner"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Scanner implements the Bandit security scanner for Python
type Scanner struct {
	execPath string
}

// New creates a new Bandit scanner instance
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "bandit"
}

// IsAvailable checks if Bandit is installed and available
func (s *Scanner) IsAvailable() bool {
	path, err := exec.LookPath("bandit")
	if err != nil {
		log.Debug().Msg("Bandit not found in PATH")
		return false
	}
	s.execPath = path
	log.Debug().Str("path", path).Msg("Bandit found")
	return true
}

// Scan executes Bandit scan on the target path
func (s *Scanner) Scan(ctx context.Context, path string) ([]scanner.RawFinding, error) {
	log.Info().Str("path", path).Msg("Starting Bandit scan")

	// Build command: bandit -r <path> -f json
	args := []string{
		"-r", path,
		"-f", "json",
		"--quiet", // Suppress progress output
	}

	cmd := exec.CommandContext(ctx, s.execPath, args...)
	output, err := cmd.CombinedOutput()

	// Bandit returns exit code 1 if issues found, which is not an error for us
	if err != nil && cmd.ProcessState.ExitCode() != 1 {
		return nil, fmt.Errorf("bandit execution failed: %w, output: %s", err, string(output))
	}

	// Parse JSON output
	var banditOutput BanditOutput
	if err := json.Unmarshal(output, &banditOutput); err != nil {
		return nil, fmt.Errorf("failed to parse bandit output: %w", err)
	}

	// Convert to RawFinding format
	findings := s.convertFindings(banditOutput, path)

	log.Info().
		Int("findings", len(findings)).
		Msg("Bandit scan completed")

	return findings, nil
}

// convertFindings converts Bandit output to RawFinding format
func (s *Scanner) convertFindings(output BanditOutput, basePath string) []scanner.RawFinding {
	var findings []scanner.RawFinding

	for _, result := range output.Results {
		// Make file path relative to base path
		relPath, err := filepath.Rel(basePath, result.Filename)
		if err != nil {
			relPath = result.Filename
		}

		finding := scanner.RawFinding{
			ID:          uuid.New().String(),
			ToolName:    "bandit",
			Message:     result.IssueText,
			FilePath:    relPath,
			LineNumber:  result.LineNumber,
			Severity:    s.mapSeverity(result.IssueSeverity),
			Confidence:  strings.ToLower(result.IssueConfidence),
			RuleID:      result.TestID,
			Category:    result.TestName,
			RawJSON:     s.toJSON(result),
			Timestamp:   time.Now(),
		}

		findings = append(findings, finding)
	}

	return findings
}

// mapSeverity maps Bandit severity to normalized severity
func (s *Scanner) mapSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

// toJSON converts a struct to JSON string
func (s *Scanner) toJSON(v interface{}) map[string]interface{} {
	data, _ := json.Marshal(v)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

// BanditOutput represents the JSON output from Bandit
type BanditOutput struct {
	Errors  []BanditError  `json:"errors"`
	Results []BanditResult `json:"results"`
	Metrics BanditMetrics  `json:"metrics"`
}

// BanditError represents an error from Bandit
type BanditError struct {
	Filename string `json:"filename"`
	Reason   string `json:"reason"`
}

// BanditResult represents a single finding from Bandit
type BanditResult struct {
	Code            string `json:"code"`
	Filename        string `json:"filename"`
	IssueConfidence string `json:"issue_confidence"`
	IssueSeverity   string `json:"issue_severity"`
	IssueText       string `json:"issue_text"`
	LineNumber      int    `json:"line_number"`
	LineRange       []int  `json:"line_range"`
	MoreInfo        string `json:"more_info"`
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
}

// BanditMetrics represents scan metrics from Bandit
type BanditMetrics struct {
	TotalLOC int `json:"_totals.loc"`
	TotalNOSEC int `json:"_totals.nosec"`
}
