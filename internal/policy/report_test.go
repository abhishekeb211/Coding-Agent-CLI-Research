package policy

import (
	"testing"
)

// TestGenerateReport tests compliance report generation
func TestGenerateReport(t *testing.T) {
	findings := []*Finding{
		{ID: "f1", CWEID: "CWE-89", Severity: "high"},
		{ID: "f2", CWEID: "CWE-79", Severity: "medium"},
		{ID: "f3", CWEID: "CWE-89", Severity: "high"},
	}

	decisions := []*PolicyDecision{
		{FindingID: "f1", PolicyID: "p1", PolicyName: "SQL Policy", Action: "deny", WaiverApplied: false},
		{FindingID: "f2", PolicyID: "p2", PolicyName: "XSS Policy", Action: "warn", WaiverApplied: false},
		{FindingID: "f3", PolicyID: "p1", PolicyName: "SQL Policy", Action: "deny", WaiverApplied: false},
	}

	report := GenerateReport("run-1", decisions, findings)

	if report.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", report.TotalFindings)
	}
	if report.PolicyViolations != 2 {
		t.Errorf("Expected 2 violations, got %d", report.PolicyViolations)
	}
	if report.Warnings != 1 {
		t.Errorf("Expected 1 warning, got %d", report.Warnings)
	}
}

// TestGenerateReportWithWaivers tests waiver processing
func TestGenerateReportWithWaivers(t *testing.T) {
	findings := []*Finding{
		{ID: "f1", CWEID: "CWE-89", Severity: "high"},
	}

	decisions := []*PolicyDecision{
		{FindingID: "f1", PolicyID: "waiver", Action: "allow", WaiverApplied: true},
	}

	report := GenerateReport("run-1", decisions, findings)

	if report.Waivers != 1 {
		t.Errorf("Expected 1 waiver, got %d", report.Waivers)
	}
}

// TestPolicyCoverage tests policy coverage calculation
func TestPolicyCoverage(t *testing.T) {
	findings := []*Finding{
		{ID: "f1", CWEID: "CWE-89"},
		{ID: "f2", CWEID: "CWE-79"},
	}

	decisions := []*PolicyDecision{
		{FindingID: "f1", Action: "deny"},
		{FindingID: "f2", Action: "warn"},
	}

	report := GenerateReport("run-1", decisions, findings)

	if report.PolicyCoverage != 100.0 {
		t.Errorf("Expected 100%% coverage, got %f", report.PolicyCoverage)
	}
}
