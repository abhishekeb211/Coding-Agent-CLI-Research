package semgrep

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

// Scanner implements the Semgrep security scanner
type Scanner struct {
	execPath string
}

// New creates a new Semgrep scanner instance
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "semgrep"
}

// IsAvailable checks if Semgrep is installed and available
func (s *Scanner) IsAvailable() bool {
	path, err := exec.LookPath("semgrep")
	if err != nil {
		log.Debug().Msg("Semgrep not found in PATH")
		return false
	}
	s.execPath = path
	log.Debug().Str("path", path).Msg("Semgrep found")
	return true
}

// Scan executes Semgrep scan on the target path
func (s *Scanner) Scan(ctx context.Context, path string) ([]scanner.RawFinding, error) {
	log.Info().Str("path", path).Msg("Starting Semgrep scan")

	// Build command: semgrep --config=auto --json <path>
	args := []string{
		"--config=auto", // Use automatic rule selection
		"--json",        // JSON output
		"--quiet",       // Suppress progress
		"--no-git-ignore", // Scan all files
		path,
	}

	cmd := exec.CommandContext(ctx, s.execPath, args...)
	output, err := cmd.CombinedOutput()

	// Semgrep may return non-zero exit code with findings
	if err != nil && !strings.Contains(string(output), "results") {
		return nil, fmt.Errorf("semgrep execution failed: %w, output: %s", err, string(output))
	}

	// Parse JSON output
	var semgrepOutput SemgrepOutput
	if err := json.Unmarshal(output, &semgrepOutput); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	// Convert to RawFinding format
	findings := s.convertFindings(semgrepOutput, path)

	log.Info().
		Int("findings", len(findings)).
		Msg("Semgrep scan completed")

	return findings, nil
}

// convertFindings converts Semgrep output to RawFinding format
func (s *Scanner) convertFindings(output SemgrepOutput, basePath string) []scanner.RawFinding {
	var findings []scanner.RawFinding

	for _, result := range output.Results {
		// Make file path relative to base path
		relPath, err := filepath.Rel(basePath, result.Path)
		if err != nil {
			relPath = result.Path
		}

		// Extract severity from metadata or use default
		severity := s.extractSeverity(result)
		
		finding := scanner.RawFinding{
			ID:          uuid.New().String(),
			ToolName:    "semgrep",
			Message:     result.Extra.Message,
			FilePath:    relPath,
			LineNumber:  result.Start.Line,
			Severity:    severity,
			Confidence:  s.extractConfidence(result),
			RuleID:      result.CheckID,
			Category:    s.extractCategory(result),
			RawJSON:     s.toJSON(result),
			Timestamp:   time.Now(),
		}

		findings = append(findings, finding)
	}

	return findings
}

// extractSeverity extracts severity from Semgrep result
func (s *Scanner) extractSeverity(result SemgrepResult) string {
	if result.Extra.Severity != "" {
		return s.mapSeverity(result.Extra.Severity)
	}
	// Default to medium if not specified
	return "medium"
}

// extractConfidence extracts confidence from Semgrep result
func (s *Scanner) extractConfidence(result SemgrepResult) string {
	// Semgrep doesn't provide confidence, use metadata if available
	if result.Extra.Metadata.Confidence != "" {
		return strings.ToLower(result.Extra.Metadata.Confidence)
	}
	return "medium"
}

// extractCategory extracts category from Semgrep result
func (s *Scanner) extractCategory(result SemgrepResult) string {
	// Try to get category from metadata
	if len(result.Extra.Metadata.Category) > 0 {
		return result.Extra.Metadata.Category[0]
	}
	// Fallback to rule ID prefix
	parts := strings.Split(result.CheckID, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return "security"
}

// mapSeverity maps Semgrep severity to normalized severity
func (s *Scanner) mapSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "ERROR", "CRITICAL":
		return "critical"
	case "WARNING", "HIGH":
		return "high"
	case "INFO", "MEDIUM":
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

// SemgrepOutput represents the JSON output from Semgrep
type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
	Errors  []SemgrepError  `json:"errors"`
	Paths   SemgrepPaths    `json:"paths"`
}

// SemgrepResult represents a single finding from Semgrep
type SemgrepResult struct {
	CheckID string         `json:"check_id"`
	Path    string         `json:"path"`
	Start   SemgrepPos     `json:"start"`
	End     SemgrepPos     `json:"end"`
	Extra   SemgrepExtra   `json:"extra"`
}

// SemgrepPos represents a position in source code
type SemgrepPos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// SemgrepExtra contains additional finding information
type SemgrepExtra struct {
	Message  string           `json:"message"`
	Severity string           `json:"severity"`
	Metadata SemgrepMetadata  `json:"metadata"`
	Lines    string           `json:"lines"`
}

// SemgrepMetadata contains rule metadata
type SemgrepMetadata struct {
	Category   []string `json:"category"`
	Confidence string   `json:"confidence"`
	CWE        []string `json:"cwe"`
	OWASP      []string `json:"owasp"`
	References []string `json:"references"`
}

// SemgrepError represents an error from Semgrep
type SemgrepError struct {
	Type    string `json:"type"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Path    string `json:"path"`
}

// SemgrepPaths contains scan path information
type SemgrepPaths struct {
	Scanned []string `json:"scanned"`
	Skipped []string `json:"skipped"`
}
