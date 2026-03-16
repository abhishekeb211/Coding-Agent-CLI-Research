// +build integration

package integration

import (
	"testing"

	"github.com/coding-agent/cli/internal/policy"
	"github.com/coding-agent/cli/internal/scanner"
)

func TestPolicyLoadingAndEvaluation(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create test policy
	policyContent := `
name: Test Security Policy
version: 1.0
rules:
  - id: block-sql-injection
    description: Block SQL injection vulnerabilities
    severity: critical
    cwe: ["CWE-89"]
    action: block
  - id: warn-xss
    description: Warn on XSS vulnerabilities
    severity: high
    cwe: ["CWE-79"]
    action: warn
`
	policyPath := ctx.CreateTestPolicy(t, policyContent)

	// Load policy
	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Create test findings
	findings := []scanner.Finding{
		{
			ID:          "finding-1",
			RuleID:      "sql-injection",
			Severity:    "critical",
			CWE:         "CWE-89",
			Description: "SQL injection vulnerability",
		},
		{
			ID:          "finding-2",
			RuleID:      "xss-vuln",
			Severity:    "high",
			CWE:         "CWE-79",
			Description: "XSS vulnerability",
		},
	}

	// Evaluate policy
	evaluator := policy.NewEvaluator(pol)
	results := evaluator.Evaluate(findings)

	// Verify policy actions
	if len(results) != 2 {
		t.Fatalf("Expected 2 policy results, got %d", len(results))
	}

	// Check SQL injection is blocked
	sqlResult := results[0]
	if sqlResult.Action != "block" {
		t.Errorf("Expected SQL injection to be blocked, got action: %s", sqlResult.Action)
	}

	// Check XSS is warned
	xssResult := results[1]
	if xssResult.Action != "warn" {
		t.Errorf("Expected XSS to be warned, got action: %s", xssResult.Action)
	}
}

func TestPolicyViolationDetection(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	policyContent := `
name: Strict Policy
version: 1.0
rules:
  - id: no-high-severity
    description: Block all high severity findings
    severity: high
    action: block
`
	policyPath := ctx.CreateTestPolicy(t, policyContent)

	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	findings := []scanner.Finding{
		{
			ID:       "finding-1",
			Severity: "high",
			CWE:      "CWE-79",
		},
		{
			ID:       "finding-2",
			Severity: "medium",
			CWE:      "CWE-20",
		},
	}

	evaluator := policy.NewEvaluator(pol)
	results := evaluator.Evaluate(findings)

	// Count violations
	violations := 0
	for _, result := range results {
		if result.Action == "block" {
			violations++
		}
	}

	if violations != 1 {
		t.Errorf("Expected 1 violation, got %d", violations)
	}
}

func TestWaiverApplication(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	policyContent := `
name: Policy with Waivers
version: 1.0
rules:
  - id: block-secrets
    description: Block hardcoded secrets
    cwe: ["CWE-798"]
    action: block
waivers:
  - finding_id: finding-1
    reason: Test data only
    approved_by: security-team
    expires: 2025-12-31
`
	policyPath := ctx.CreateTestPolicy(t, policyContent)

	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	findings := []scanner.Finding{
		{
			ID:          "finding-1",
			RuleID:      "hardcoded-secret",
			Severity:    "high",
			CWE:         "CWE-798",
			Description: "Hardcoded password",
		},
		{
			ID:          "finding-2",
			RuleID:      "hardcoded-secret",
			Severity:    "high",
			CWE:         "CWE-798",
			Description: "Hardcoded API key",
		},
	}

	evaluator := policy.NewEvaluator(pol)
	results := evaluator.Evaluate(findings)

	// Verify waiver was applied to finding-1
	var waived, blocked int
	for _, result := range results {
		if result.Waived {
			waived++
		} else if result.Action == "block" {
			blocked++
		}
	}

	if waived != 1 {
		t.Errorf("Expected 1 waived finding, got %d", waived)
	}

	if blocked != 1 {
		t.Errorf("Expected 1 blocked finding, got %d", blocked)
	}
}

func TestComplianceReportGeneration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	policyContent := `
name: OWASP Top 10 Policy
version: 1.0
compliance_framework: OWASP-2021
rules:
  - id: a01-broken-access
    description: Broken Access Control
    cwe: ["CWE-284", "CWE-285"]
    action: block
  - id: a03-injection
    description: Injection
    cwe: ["CWE-89", "CWE-79"]
    action: block
`
	policyPath := ctx.CreateTestPolicy(t, policyContent)

	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	findings := []scanner.Finding{
		{ID: "f1", CWE: "CWE-89", Severity: "critical"},
		{ID: "f2", CWE: "CWE-79", Severity: "high"},
		{ID: "f3", CWE: "CWE-284", Severity: "high"},
	}

	evaluator := policy.NewEvaluator(pol)
	results := evaluator.Evaluate(findings)

	// Generate compliance report
	report := policy.GenerateComplianceReport(pol, results)

	if report.Framework != "OWASP-2021" {
		t.Errorf("Expected framework OWASP-2021, got %s", report.Framework)
	}

	if report.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", report.TotalFindings)
	}

	if report.Violations != 3 {
		t.Errorf("Expected 3 violations, got %d", report.Violations)
	}
}

func TestPolicyRulePriority(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	policyContent := `
name: Priority Test Policy
version: 1.0
rules:
  - id: allow-test-files
    description: Allow findings in test files
    file_pattern: "*_test.py"
    action: allow
    priority: 1
  - id: block-sql-injection
    description: Block SQL injection
    cwe: ["CWE-89"]
    action: block
    priority: 2
`
	policyPath := ctx.CreateTestPolicy(t, policyContent)

	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	findings := []scanner.Finding{
		{
			ID:       "f1",
			CWE:      "CWE-89",
			FilePath: "app_test.py",
		},
		{
			ID:       "f2",
			CWE:      "CWE-89",
			FilePath: "app.py",
		},
	}

	evaluator := policy.NewEvaluator(pol)
	results := evaluator.Evaluate(findings)

	// First finding should be allowed (higher priority rule)
	if results[0].Action != "allow" {
		t.Errorf("Expected test file finding to be allowed, got %s", results[0].Action)
	}

	// Second finding should be blocked
	if results[1].Action != "block" {
		t.Errorf("Expected non-test file finding to be blocked, got %s", results[1].Action)
	}
}

func TestPolicyWithComplexMatching(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	policyContent := `
name: Complex Matching Policy
version: 1.0
rules:
  - id: critical-in-production
    description: Block critical findings in production code
    severity: critical
    file_pattern: "src/**/*.py"
    exclude_pattern: "src/tests/**"
    action: block
`
	policyPath := ctx.CreateTestPolicy(t, policyContent)

	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	findings := []scanner.Finding{
		{
			ID:       "f1",
			Severity: "critical",
			FilePath: "src/app/main.py",
		},
		{
			ID:       "f2",
			Severity: "critical",
			FilePath: "src/tests/test_main.py",
		},
		{
			ID:       "f3",
			Severity: "critical",
			FilePath: "lib/utils.py",
		},
	}

	evaluator := policy.NewEvaluator(pol)
	results := evaluator.Evaluate(findings)

	// Only first finding should be blocked
	blocked := 0
	for _, result := range results {
		if result.Action == "block" {
			blocked++
		}
	}

	if blocked != 1 {
		t.Errorf("Expected 1 blocked finding, got %d", blocked)
	}
}
