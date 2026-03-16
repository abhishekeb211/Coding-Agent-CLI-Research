package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds scanner configuration
type Config struct {
	TargetPath   string
	OutputFormat string
	OutputFile   string
	Scanners     []string
	OfflineMode  bool
	Verbose      bool
}

// Scanner interface that all scanner plugins must implement
type Scanner interface {
	Name() string
	Scan(ctx context.Context, path string) ([]RawFinding, error)
	IsAvailable() bool
}

// RawFinding represents a raw finding from a scanner
type RawFinding struct {
	ID          string                 `json:"id"`
	ToolName    string                 `json:"tool_name"`
	Message     string                 `json:"message"`
	FilePath    string                 `json:"file_path"`
	LineNumber  int                    `json:"line_number"`
	Severity    string                 `json:"severity"`
	Confidence  string                 `json:"confidence"`
	RuleID      string                 `json:"rule_id"`
	Category    string                 `json:"category"`
	RawJSON     map[string]interface{} `json:"raw_json,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// NormalizedFinding represents a normalized finding mapped to CWE
type NormalizedFinding struct {
	ID              string    `json:"id"`
	FindingID       string    `json:"finding_id"`
	CWEID           string    `json:"cwe_id"`
	CWEDescription  string    `json:"cwe_description"`
	Severity        string    `json:"severity"`
	Confidence      string    `json:"confidence"`
	CodeFingerprint string    `json:"code_fingerprint"`
	FilePath        string    `json:"file_path"`
	LineNumber      int       `json:"line_number"`
	Description     string    `json:"description"`
	Timestamp       time.Time `json:"timestamp"`
	
	// Remediation guidance (optional, populated if LLM is enabled)
	Remediation *RemediationGuidance `json:"remediation,omitempty"`
}

// RemediationGuidance contains AI-generated remediation guidance
type RemediationGuidance struct {
	Explanation      string   `json:"explanation"`
	RemediationSteps []string `json:"remediation_steps"`
	ExampleFix       string   `json:"example_fix,omitempty"`
	Confidence       float64  `json:"confidence"`
	GeneratedAt      time.Time `json:"generated_at"`
	Cached           bool     `json:"cached"`
}

// ScanResult represents the complete scan result
type ScanResult struct {
	RunID           string              `json:"run_id"`
	TargetPath      string              `json:"target_path"`
	StartTime       time.Time           `json:"start_time"`
	EndTime         time.Time           `json:"end_time"`
	Duration        time.Duration       `json:"duration"`
	TotalFindings   int                 `json:"total_findings"`
	CriticalCount   int                 `json:"critical_count"`
	HighCount       int                 `json:"high_count"`
	MediumCount     int                 `json:"medium_count"`
	LowCount        int                 `json:"low_count"`
	Findings        []NormalizedFinding `json:"findings"`
	Scanners        []string            `json:"scanners_used"`
	OfflineMode     bool                `json:"offline_mode"`
	PolicyDecisions interface{}         `json:"policy_decisions,omitempty"` // Can be []*policy.PolicyDecision
}

// SaveToFile saves the scan result to a file in the specified format
func (r *ScanResult) SaveToFile(path string, format string) error {
	var data []byte
	var err error

	switch format {
	case "json":
		data, err = json.MarshalIndent(r, "", "  ")
	case "sarif":
		// Note: SARIF conversion is handled by the sarif package to avoid import cycles
		return fmt.Errorf("SARIF conversion must be done via sarif.ConvertToSARIF()")
	case "markdown":
		data = []byte(r.toMarkdown())
	default:
		data, err = json.MarshalIndent(r, "", "  ")
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// toMarkdown converts the result to Markdown format
func (r *ScanResult) toMarkdown() string {
	md := "# Security Scan Report\n\n"
	md += "## Summary\n\n"
	md += fmt.Sprintf("- **Target**: %s\n", r.TargetPath)
	md += fmt.Sprintf("- **Scan ID**: %s\n", r.RunID)
	md += fmt.Sprintf("- **Duration**: %s\n", r.Duration)
	md += fmt.Sprintf("- **Scanners**: %v\n", r.Scanners)
	md += fmt.Sprintf("- **Total Findings**: %d\n", r.TotalFindings)
	md += fmt.Sprintf("- **Critical**: %d\n", r.CriticalCount)
	md += fmt.Sprintf("- **High**: %d\n", r.HighCount)
	md += fmt.Sprintf("- **Medium**: %d\n", r.MediumCount)
	md += fmt.Sprintf("- **Low**: %d\n\n", r.LowCount)

	// Group findings by severity
	md += "## Findings by Severity\n\n"
	
	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		findings := r.getFindingsBySeverity(sev)
		if len(findings) == 0 {
			continue
		}
		
		md += fmt.Sprintf("### %s (%d)\n\n", capitalize(sev), len(findings))
		
		for _, f := range findings {
			md += fmt.Sprintf("#### %s: %s\n", f.CWEID, f.CWEDescription)
			md += fmt.Sprintf("- **File**: `%s:%d`\n", f.FilePath, f.LineNumber)
			md += fmt.Sprintf("- **Severity**: %s\n", f.Severity)
			md += fmt.Sprintf("- **Confidence**: %s\n", f.Confidence)
			md += fmt.Sprintf("- **Description**: %s\n", f.Description)
			
			// Add remediation guidance if available
			if f.Remediation != nil {
				md += "\n**Remediation Guidance:**\n\n"
				md += fmt.Sprintf("%s\n\n", f.Remediation.Explanation)
				
				if len(f.Remediation.RemediationSteps) > 0 {
					md += "**Steps to Fix:**\n"
					for i, step := range f.Remediation.RemediationSteps {
						md += fmt.Sprintf("%d. %s\n", i+1, step)
					}
					md += "\n"
				}
				
				if f.Remediation.ExampleFix != "" {
					md += "**Example Fix:**\n```\n"
					md += f.Remediation.ExampleFix
					md += "\n```\n\n"
				}
			} else {
				md += "\n"
			}
		}
	}

	return md
}

// getFindingsBySeverity filters findings by severity
func (r *ScanResult) getFindingsBySeverity(severity string) []NormalizedFinding {
	var filtered []NormalizedFinding
	for _, f := range r.Findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// capitalize capitalizes the first letter of a string
func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return string(s[0]-32) + s[1:]
}
