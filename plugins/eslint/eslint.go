package eslint

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

// Scanner implements the eslint-plugin-security scanner for JavaScript/TypeScript
type Scanner struct {
	execPath string
}

// New creates a new eslint scanner instance
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "eslint"
}

// IsAvailable checks if eslint is installed and available
func (s *Scanner) IsAvailable() bool {
	path, err := exec.LookPath("eslint")
	if err != nil {
		log.Debug().Msg("eslint not found in PATH")
		return false
	}
	s.execPath = path
	log.Debug().Str("path", path).Msg("eslint found")
	return true
}

// Scan executes eslint scan on the target path
func (s *Scanner) Scan(ctx context.Context, path string) ([]scanner.RawFinding, error) {
	log.Info().Str("path", path).Msg("Starting eslint scan")

	// Build command: eslint --format json --plugin security <path>
	args := []string{
		"--format", "json",
		"--plugin", "security",
		"--no-eslintrc", // Don't use project config
		"--rule", "security/detect-unsafe-regex:error",
		"--rule", "security/detect-buffer-noassert:error",
		"--rule", "security/detect-child-process:error",
		"--rule", "security/detect-disable-mustache-escape:error",
		"--rule", "security/detect-eval-with-expression:error",
		"--rule", "security/detect-no-csrf-before-method-override:error",
		"--rule", "security/detect-non-literal-fs-filename:error",
		"--rule", "security/detect-non-literal-regexp:error",
		"--rule", "security/detect-non-literal-require:error",
		"--rule", "security/detect-object-injection:error",
		"--rule", "security/detect-possible-timing-attacks:error",
		"--rule", "security/detect-pseudoRandomBytes:error",
		"--ext", ".js,.jsx,.ts,.tsx",
		path,
	}

	cmd := exec.CommandContext(ctx, s.execPath, args...)
	output, err := cmd.CombinedOutput()

	// eslint returns exit code 1 if issues found, which is not an error for us
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("eslint execution failed: %w, output: %s", err, string(output))
	}

	// Parse JSON output
	var eslintOutput []ESLintFile
	if err := json.Unmarshal(output, &eslintOutput); err != nil {
		return nil, fmt.Errorf("failed to parse eslint output: %w", err)
	}

	// Convert to RawFinding format
	findings := s.convertFindings(eslintOutput, path)

	log.Info().
		Int("findings", len(findings)).
		Msg("eslint scan completed")

	return findings, nil
}

// convertFindings converts eslint output to RawFinding format
func (s *Scanner) convertFindings(output []ESLintFile, basePath string) []scanner.RawFinding {
	var findings []scanner.RawFinding

	for _, file := range output {
		// Make file path relative to base path
		relPath, err := filepath.Rel(basePath, file.FilePath)
		if err != nil {
			relPath = file.FilePath
		}

		for _, message := range file.Messages {
			// Only include security plugin findings
			if !strings.HasPrefix(message.RuleID, "security/") {
				continue
			}

			finding := scanner.RawFinding{
				ID:          uuid.New().String(),
				ToolName:    "eslint",
				Message:     message.Message,
				FilePath:    relPath,
				LineNumber:  message.Line,
				Severity:    s.mapSeverity(message.Severity),
				Confidence:  "medium", // eslint doesn't provide confidence
				RuleID:      message.RuleID,
				Category:    s.extractCategory(message.RuleID),
				RawJSON:     s.toJSON(message),
				Timestamp:   time.Now(),
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// mapSeverity maps eslint severity to normalized severity
func (s *Scanner) mapSeverity(severity int) string {
	switch severity {
	case 2: // error
		return "high"
	case 1: // warning
		return "medium"
	default:
		return "low"
	}
}

// extractCategory extracts category from eslint rule ID
func (s *Scanner) extractCategory(ruleID string) string {
	// Map eslint-plugin-security rule IDs to categories
	categoryMap := map[string]string{
		"security/detect-unsafe-regex":                    "regex-dos",
		"security/detect-buffer-noassert":                 "buffer-overflow",
		"security/detect-child-process":                   "command-injection",
		"security/detect-disable-mustache-escape":         "xss",
		"security/detect-eval-with-expression":            "code-injection",
		"security/detect-no-csrf-before-method-override":  "csrf",
		"security/detect-non-literal-fs-filename":         "path-traversal",
		"security/detect-non-literal-regexp":              "regex-dos",
		"security/detect-non-literal-require":             "code-injection",
		"security/detect-object-injection":                "prototype-pollution",
		"security/detect-possible-timing-attacks":         "timing-attack",
		"security/detect-pseudoRandomBytes":               "weak-random",
	}

	if category, exists := categoryMap[ruleID]; exists {
		return category
	}

	// Extract from rule ID (e.g., "security/detect-eval-with-expression" -> "eval-with-expression")
	parts := strings.Split(ruleID, "/")
	if len(parts) > 1 {
		return strings.TrimPrefix(parts[1], "detect-")
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

// ESLintFile represents a file in eslint JSON output
type ESLintFile struct {
	FilePath     string          `json:"filePath"`
	Messages     []ESLintMessage `json:"messages"`
	ErrorCount   int             `json:"errorCount"`
	WarningCount int             `json:"warningCount"`
}

// ESLintMessage represents a single finding from eslint
type ESLintMessage struct {
	RuleID    string `json:"ruleId"`
	Severity  int    `json:"severity"` // 1 = warning, 2 = error
	Message   string `json:"message"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	NodeType  string `json:"nodeType,omitempty"`
	MessageID string `json:"messageId,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	EndColumn int    `json:"endColumn,omitempty"`
}
