package policy

import (
	"time"
)

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	RunID            string            `json:"run_id"`
	Timestamp        time.Time         `json:"timestamp"`
	TotalFindings    int               `json:"total_findings"`
	PolicyViolations int               `json:"policy_violations"`
	Warnings         int               `json:"warnings"`
	Allowed          int               `json:"allowed"`
	Waivers          int               `json:"waivers"`
	PolicyCoverage   float64           `json:"policy_coverage"`
	Policies         []PolicySummary   `json:"policies"`
	TopViolations    []ViolationSummary `json:"top_violations"`
}

// PolicySummary represents a summary of a policy's enforcement
type PolicySummary struct {
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	Action      string `json:"action"`
	Matches     int    `json:"matches"`
	Description string `json:"description"`
}

// ViolationSummary represents a summary of violations by CWE
type ViolationSummary struct {
	CWEID       string `json:"cwe_id"`
	CWEName     string `json:"cwe_name"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
}

// GenerateReport generates a compliance report from policy decisions
func GenerateReport(runID string, decisions []*PolicyDecision, findings []*Finding) *ComplianceReport {
	report := &ComplianceReport{
		RunID:          runID,
		Timestamp:      time.Now(),
		TotalFindings:  len(findings),
		Policies:       []PolicySummary{},
		TopViolations:  []ViolationSummary{},
	}

	// Count decisions by action
	stats := GetStatistics(decisions)
	report.PolicyViolations = stats["deny"]
	report.Warnings = stats["warn"]
	report.Allowed = stats["allow"]
	report.Waivers = stats["waived"]

	// Calculate policy coverage (percentage of findings with policy decisions)
	if len(findings) > 0 {
		report.PolicyCoverage = float64(len(decisions)) / float64(len(findings)) * 100
	}

	// Aggregate by policy
	policyMatches := make(map[string]*PolicySummary)
	for _, decision := range decisions {
		if decision.PolicyID == "default" || decision.PolicyID == "waiver" {
			continue
		}

		if _, exists := policyMatches[decision.PolicyID]; !exists {
			policyMatches[decision.PolicyID] = &PolicySummary{
				PolicyID:   decision.PolicyID,
				PolicyName: decision.PolicyName,
				Action:     decision.Action,
				Matches:    0,
			}
		}
		policyMatches[decision.PolicyID].Matches++
	}

	// Convert to slice
	for _, summary := range policyMatches {
		report.Policies = append(report.Policies, *summary)
	}

	// Aggregate by CWE
	cweViolations := make(map[string]*ViolationSummary)
	for i, decision := range decisions {
		if decision.Action == "allow" {
			continue
		}

		if i < len(findings) {
			finding := findings[i]
			if _, exists := cweViolations[finding.CWEID]; !exists {
				cweViolations[finding.CWEID] = &ViolationSummary{
					CWEID:    finding.CWEID,
					CWEName:  finding.CWEID, // In real implementation, lookup CWE name
					Count:    0,
					Severity: finding.Severity,
					Action:   decision.Action,
				}
			}
			cweViolations[finding.CWEID].Count++
		}
	}

	// Convert to slice and sort by count (top violations)
	for _, violation := range cweViolations {
		report.TopViolations = append(report.TopViolations, *violation)
	}

	// Sort top violations by count (descending)
	sortViolationsByCount(report.TopViolations)

	// Limit to top 10
	if len(report.TopViolations) > 10 {
		report.TopViolations = report.TopViolations[:10]
	}

	return report
}

// sortViolationsByCount sorts violations by count in descending order
func sortViolationsByCount(violations []ViolationSummary) {
	// Simple bubble sort for small datasets
	n := len(violations)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if violations[j].Count < violations[j+1].Count {
				violations[j], violations[j+1] = violations[j+1], violations[j]
			}
		}
	}
}
