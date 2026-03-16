package gosec

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

// Scanner implements the gosec security scanner for Go
type Scanner struct {
	execPath string
}

// New creates a new gosec scanner instance
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "gosec"
}

// IsAvailable checks if gosec is installed and available
func (s *Scanner) IsAvailable() bool {
	path, err := exec.LookPath("gosec")
	if err != nil {
		log.Debug().Msg("gosec not found in PATH")
		return false
	}
	s.execPath = path
	log.Debug().Str("path", path).Msg("gosec found")
	return true
}

// Scan executes gosec scan on the target path
func (s *Scanner) Scan(ctx context.Context, path string) ([]scanner.RawFinding, error) {
	log.Info().Str("path", path).Msg("Starting gosec scan")

	// Build command: gosec -fmt=json -out=stdout ./...
	args := []string{
		"-fmt=json",
		"-no-fail", // Don't fail with exit code 1 when issues found
		"-quiet",   // Suppress progress output
		"./...",    // Scan all packages recursively
	}

	cmd := exec.CommandContext(ctx, s.execPath, args...)
	cmd.Dir = path // Set working directory to target path
	output, err := cmd.CombinedOutput()

	// gosec may return non-zero exit code with findings
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("gosec execution failed: %w, output: %s", err, string(output))
	}

	// Parse JSON output
	var gosecOutput GosecOutput
	if err := json.Unmarshal(output, &gosecOutput); err != nil {
		return nil, fmt.Errorf("failed to parse gosec output: %w", err)
	}

	// Convert to RawFinding format
	findings := s.convertFindings(gosecOutput, path)

	log.Info().
		Int("findings", len(findings)).
		Msg("gosec scan completed")

	return findings, nil
}

// convertFindings converts gosec output to RawFinding format
func (s *Scanner) convertFindings(output GosecOutput, basePath string) []scanner.RawFinding {
	var findings []scanner.RawFinding

	for _, issue := range output.Issues {
		// Make file path relative to base path
		relPath, err := filepath.Rel(basePath, issue.File)
		if err != nil {
			relPath = issue.File
		}

		finding := scanner.RawFinding{
			ID:          uuid.New().String(),
			ToolName:    "gosec",
			Message:     issue.Details,
			FilePath:    relPath,
			LineNumber:  s.parseLineNumber(issue.Line),
			Severity:    s.mapSeverity(issue.Severity),
			Confidence:  s.mapConfidence(issue.Confidence),
			RuleID:      issue.RuleID,
			Category:    s.extractCategory(issue.RuleID),
			RawJSON:     s.toJSON(issue),
			Timestamp:   time.Now(),
		}

		findings = append(findings, finding)
	}

	return findings
}

// parseLineNumber extracts the starting line number from gosec's line field
// gosec returns line as a string like "10" or "10-15"
func (s *Scanner) parseLineNumber(line string) int {
	// Split on dash to handle ranges
	parts := strings.Split(line, "-")
	if len(parts) > 0 {
		var lineNum int
		fmt.Sscanf(parts[0], "%d", &lineNum)
		return lineNum
	}
	return 0
}

// mapSeverity maps gosec severity to normalized severity
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

// mapConfidence maps gosec confidence to normalized confidence
func (s *Scanner) mapConfidence(confidence string) string {
	switch strings.ToUpper(confidence) {
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

// extractCategory extracts category from gosec rule ID
// gosec rule IDs are like "G101", "G102", etc.
func (s *Scanner) extractCategory(ruleID string) string {
	// Map gosec rule IDs to categories
	categoryMap := map[string]string{
		"G101": "credentials",
		"G102": "network",
		"G103": "unsafe",
		"G104": "errors",
		"G105": "integer-overflow",
		"G106": "ssh",
		"G107": "ssrf",
		"G108": "profiling",
		"G109": "integer-conversion",
		"G110": "decompression-bomb",
		"G201": "sql-injection",
		"G202": "sql-injection",
		"G203": "html-template",
		"G204": "command-injection",
		"G301": "file-permissions",
		"G302": "file-permissions",
		"G303": "file-creation",
		"G304": "path-traversal",
		"G305": "path-traversal",
		"G306": "file-permissions",
		"G307": "defer-close",
		"G401": "weak-crypto",
		"G402": "tls-config",
		"G403": "weak-crypto",
		"G404": "weak-random",
		"G501": "import-blocklist",
		"G502": "import-blocklist",
		"G503": "import-blocklist",
		"G504": "import-blocklist",
		"G505": "import-blocklist",
		"G601": "implicit-aliasing",
	}

	if category, exists := categoryMap[ruleID]; exists {
		return category
	}

	return "security"
}

// toJSON converts a struct to JSON map
func (s *Scanner) toJSON(v interface{}) map[string]interface{} {
	data, _ := json.Marshal(v)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

// GosecOutput represents the JSON output from gosec
type GosecOutput struct {
	Issues []GosecIssue `json:"Issues"`
	Stats  GosecStats   `json:"Stats"`
}

// GosecIssue represents a single finding from gosec
type GosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Code       string `json:"code"`
	Line       string `json:"line"`
	Column     string `json:"column"`
	CWE        CWEInfo `json:"cwe,omitempty"`
}

// CWEInfo represents CWE information from gosec
type CWEInfo struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// GosecStats represents scan statistics from gosec
type GosecStats struct {
	Files int `json:"files"`
	Lines int `json:"lines"`
	Found int `json:"found"`
}
