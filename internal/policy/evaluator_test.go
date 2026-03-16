package policy

import (
	"testing"
	"time"
)

// TestNewEvaluator tests evaluator initialization
func TestNewEvaluator(t *testing.T) {
	policySet := &PolicySet{
		Policies: []Policy{
			{ID: "test", Name: "Test", Action: "deny", Enabled: true, CWE: []string{"CWE-89"}},
		},
	}

	evaluator := NewEvaluator(policySet)
	if evaluator == nil {
		t.Error("NewEvaluator() returned nil")
	}
}

// TestEvaluateWithMatchingPolicy tests policy evaluation with matching findings
func TestEvaluateWithMatchingPolicy(t *testing.T) {
	policySet := &PolicySet{
		Policies: []Policy{
			{ID: "sql-policy", Name: "SQL Policy", Action: "deny", Enabled: true, Severity: "high", CWE: []string{"CWE-89"}},
		},
	}

	evaluator := NewEvaluator(policySet)

	finding := &Finding{
		ID:       "finding-1",
		CWEID:    "CWE-89",
		Severity: "high",
		FilePath: "/test/file.py",
	}

	decision := evaluator.Evaluate(finding)
	if decision.Action != "deny" {
		t.Errorf("Expected action deny, got %s", decision.Action)
	}
	if decision.PolicyID != "sql-policy" {
		t.Errorf("Expected policy sql-policy, got %s", decision.PolicyID)
	}
}

// TestEvaluateWithNoMatchingPolicy tests evaluation with non-matching findings
func TestEvaluateWithNoMatchingPolicy(t *testing.T) {
	policySet := &PolicySet{
		Policies: []Policy{
			{ID: "sql-policy", Name: "SQL Policy", Action: "deny", Enabled: true, CWE: []string{"CWE-89"}},
		},
	}

	evaluator := NewEvaluator(policySet)

	finding := &Finding{
		ID:       "finding-1",
		CWEID:    "CWE-79", // Different CWE
		Severity: "high",
		FilePath: "/test/file.py",
	}

	decision := evaluator.Evaluate(finding)
	if decision.Action != "allow" {
		t.Errorf("Expected action allow for non-matching policy, got %s", decision.Action)
	}
	if decision.PolicyID != "default" {
		t.Errorf("Expected default policy, got %s", decision.PolicyID)
	}
}

// TestEvaluateWithWaiver tests waiver application
func TestEvaluateWithWaiver(t *testing.T) {
	policySet := &PolicySet{
		Policies: []Policy{
			{ID: "sql-policy", Name: "SQL Policy", Action: "deny", Enabled: true, CWE: []string{"CWE-89"}},
		},
	}

	evaluator := NewEvaluator(policySet)

	waiverSet := &WaiverSet{
		Waivers: []Waiver{
			{
				ID:         "waiver-1",
				FindingID:  "finding-1",
				Reason:     "False positive",
				ApprovedBy: "security-team",
				Expires:    time.Now().Add(24 * time.Hour),
				Status:     "active",
			},
		},
	}
	evaluator.SetWaivers(waiverSet)

	finding := &Finding{
		ID:       "finding-1",
		CWEID:    "CWE-89",
		Severity: "high",
		FilePath: "/test/file.py",
	}

	decision := evaluator.Evaluate(finding)
	if decision.Action != "allow" {
		t.Errorf("Expected action allow for waived finding, got %s", decision.Action)
	}
	if !decision.WaiverApplied {
		t.Error("Expected waiver to be applied")
	}
}

// TestSelectMostRestrictive tests policy priority
func TestSelectMostRestrictive(t *testing.T) {
	evaluator := NewEvaluator(&PolicySet{})

	policies := []Policy{
		{ID: "p1", Action: "warn", Severity: "medium"},
		{ID: "p2", Action: "deny", Severity: "high"},
		{ID: "p3", Action: "allow", Severity: "low"},
	}

	result := evaluator.selectMostRestrictive(policies)
	if result.ID != "p2" {
		t.Errorf("Expected most restrictive policy p2, got %s", result.ID)
	}
}

// TestEvaluateAll tests multiple findings evaluation
func TestEvaluateAll(t *testing.T) {
	policySet := &PolicySet{
		Policies: []Policy{
			{ID: "sql-policy", Name: "SQL Policy", Action: "deny", Enabled: true, CWE: []string{"CWE-89"}},
		},
	}

	evaluator := NewEvaluator(policySet)

	findings := []*Finding{
		{ID: "f1", CWEID: "CWE-89", Severity: "high"},
		{ID: "f2", CWEID: "CWE-79", Severity: "medium"},
		{ID: "f3", CWEID: "CWE-89", Severity: "high"},
	}

	decisions := evaluator.EvaluateAll(findings)
	if len(decisions) != 3 {
		t.Errorf("Expected 3 decisions, got %d", len(decisions))
	}
}

// TestGetStatistics tests policy decision statistics
func TestGetStatistics(t *testing.T) {
	decisions := []*PolicyDecision{
		{Action: "deny", WaiverApplied: false},
		{Action: "deny", WaiverApplied: false},
		{Action: "warn", WaiverApplied: false},
		{Action: "allow", WaiverApplied: true},
	}

	stats := GetStatistics(decisions)
	if stats["total"] != 4 {
		t.Errorf("Expected total 4, got %d", stats["total"])
	}
	if stats["deny"] != 2 {
		t.Errorf("Expected deny 2, got %d", stats["deny"])
	}
	if stats["waived"] != 1 {
		t.Errorf("Expected waived 1, got %d", stats["waived"])
	}
}
