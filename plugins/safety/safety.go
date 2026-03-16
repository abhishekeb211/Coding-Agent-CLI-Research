package safety

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

// Scanner implements the safety scanner for Python dependencies
type Scanner struct {
	execPath string
}

// New creates a new safety scanner instance
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "safety"
}

// IsAvailable checks if safety is installed and available
func (s *Scanner) IsAvailable() bool {
	path, err := exec.LookPath("safety")
	if err != nil {
		log.Debug().Msg("safety not found in PATH")
		return false
	}
	s.execPath = path
	log.Debug().Str("path", path).Msg("safety found")
	return true
}

// Scan executes safety scan on the target path
func (s *Scanner) Scan(ctx context.Context, path string) ([]scanner.RawFinding, error) {
	log.Info().Str("path", path).Msg("Starting safety scan")

	// Build command: safety check --json --stdin
	// We'll look for requirements.txt or use --stdin
	requirementsPath := filepath.Join(path, "requirements.txt")
	
	args := []string{
		"check",
		"--json",
		"--file", requirementsPath,
	}

	cmd := exec.CommandContext(ctx, s.execPath, args...)
	cmd.Dir = path
	output, err := cmd.CombinedOutput()

	// safety returns exit code 64 if vulnerabilities found, which is not an error for us
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("safety execution failed: %w, output: %s", err, string(output))
	}

	// Parse JSON output
	var safetyOutput []SafetyVulnerability
	if err := json.Unmarshal(output, &safetyOutput); err != nil {
		return nil, fmt.Errorf("failed to parse safety output: %w", err)
	}

	// Convert to RawFinding format
	findings := s.convertFindings(safetyOutput, path)

	log.Info().
		Int("findings", len(findings)).
		Msg("safety scan completed")

	return findings, nil
}

// convertFindings converts safety output to RawFinding format
func (s *Scanner) convertFindings(output []SafetyVulnerability, basePath string) []scanner.RawFinding {
	var findings []scanner.RawFinding

	for _, vuln := range output {
		// Safety reports vulnerabilities in dependencies, not specific files
		// We'll use requirements.txt as the file path
		filePath := "requirements.txt"

		finding := scanner.RawFinding{
			ID:          uuid.New().String(),
			ToolName:    "safety",
			Message:     s.formatMessage(vuln),
			FilePath:    filePath,
			LineNumber:  0, // No specific line number for dependency vulnerabilities
			Severity:    s.mapSeverity(vuln),
			Confidence:  "high", // Safety reports confirmed CVEs
			RuleID:      s.formatRuleID(vuln),
			Category:    s.extractCategory(vuln),
			RawJSON:     s.toJSON(vuln),
			Timestamp:   time.Now(),
		}

		findings = append(findings, finding)
	}

	return findings
}

// formatMessage creates a descriptive message for the vulnerability
func (s *Scanner) formatMessage(vuln SafetyVulnerability) string {
	var parts []string
	
	// Package and version info
	parts = append(parts, fmt.Sprintf("Package %s version %s has known vulnerabilities", 
		vuln.Package, vuln.InstalledVersion))
	
	// Add vulnerability description
	if vuln.Advisory != "" {
		parts = append(parts, vuln.Advisory)
	}
	
	// Add CVE if available
	if vuln.CVE != "" {
		parts = append(parts, fmt.Sprintf("CVE: %s", vuln.CVE))
	}
	
	// Add affected versions
	if vuln.AffectedVersions != "" {
		parts = append(parts, fmt.Sprintf("Affected versions: %s", vuln.AffectedVersions))
	}
	
	return strings.Join(parts, ". ")
}

// formatRuleID creates a rule ID from the vulnerability data
func (s *Scanner) formatRuleID(vuln SafetyVulnerability) string {
	if vuln.CVE != "" {
		return vuln.CVE
	}
	if vuln.VulnerabilityID != "" {
		return vuln.VulnerabilityID
	}
	return fmt.Sprintf("SAFETY-%s", vuln.Package)
}

// mapSeverity maps safety vulnerability data to normalized severity
func (s *Scanner) mapSeverity(vuln SafetyVulnerability) string {
	// Safety doesn't provide severity in all versions, so we infer it
	// CVEs with CVSS scores would be in metadata, but basic safety output doesn't include it
	// We'll use a heuristic based on the advisory text
	
	advisory := strings.ToLower(vuln.Advisory)
	
	// High severity indicators
	if strings.Contains(advisory, "critical") || 
	   strings.Contains(advisory, "remote code execution") ||
	   strings.Contains(advisory, "rce") ||
	   strings.Contains(advisory, "arbitrary code") {
		return "high"
	}
	
	// Medium severity indicators
	if strings.Contains(advisory, "sql injection") ||
	   strings.Contains(advisory, "xss") ||
	   strings.Contains(advisory, "csrf") ||
	   strings.Contains(advisory, "authentication") ||
	   strings.Contains(advisory, "authorization") {
		return "medium"
	}
	
	// Low severity indicators
	if strings.Contains(advisory, "denial of service") ||
	   strings.Contains(advisory, "dos") ||
	   strings.Contains(advisory, "information disclosure") {
		return "low"
	}
	
	// Default to medium for known CVEs
	return "medium"
}

// extractCategory extracts category from vulnerability data
func (s *Scanner) extractCategory(vuln SafetyVulnerability) string {
	advisory := strings.ToLower(vuln.Advisory)
	
	// Map common vulnerability types to categories
	if strings.Contains(advisory, "sql injection") {
		return "sql-injection"
	}
	if strings.Contains(advisory, "xss") || strings.Contains(advisory, "cross-site scripting") {
		return "xss"
	}
	if strings.Contains(advisory, "remote code execution") || strings.Contains(advisory, "rce") {
		return "code-execution"
	}
	if strings.Contains(advisory, "command injection") {
		return "command-injection"
	}
	if strings.Contains(advisory, "path traversal") {
		return "path-traversal"
	}
	if strings.Contains(advisory, "csrf") || strings.Contains(advisory, "cross-site request") {
		return "csrf"
	}
	if strings.Contains(advisory, "denial of service") || strings.Contains(advisory, "dos") {
		return "denial-of-service"
	}
	if strings.Contains(advisory, "authentication") {
		return "authentication"
	}
	if strings.Contains(advisory, "authorization") {
		return "authorization"
	}
	if strings.Contains(advisory, "deserialization") {
		return "deserialization"
	}
	if strings.Contains(advisory, "xxe") || strings.Contains(advisory, "xml external entity") {
		return "xxe"
	}
	
	// Default category for dependency vulnerabilities
	return "vulnerable-dependency"
}

// toJSON converts a struct to JSON map
func (s *Scanner) toJSON(v interface{}) map[string]interface{} {
	data, _ := json.Marshal(v)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

// SafetyVulnerability represents a single vulnerability from safety
type SafetyVulnerability struct {
	Package           string   `json:"package"`
	InstalledVersion  string   `json:"installed_version"`
	AffectedVersions  string   `json:"affected_versions"`
	VulnerabilityID   string   `json:"vulnerability_id"`
	Advisory          string   `json:"advisory"`
	CVE               string   `json:"cve,omitempty"`
	MoreInfoURL       string   `json:"more_info_url,omitempty"`
}
