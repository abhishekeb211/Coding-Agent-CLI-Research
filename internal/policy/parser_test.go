package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadPoliciesFromFile tests policy YAML parsing with valid files
func TestLoadPoliciesFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	validPolicy := `
policies:
  - id: test-policy-1
    name: Test Policy
    description: Test policy description
    enabled: true
    action: deny
    severity: high
    cwe:
      - CWE-89
      - CWE-79
`

	policyFile := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(validPolicy), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	policySet, err := LoadPolicies(policyFile)
	if err != nil {
		t.Fatalf("LoadPolicies() error = %v", err)
	}

	if len(policySet.Policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policySet.Policies))
	}

	policy := policySet.Policies[0]
	if policy.ID != "test-policy-1" {
		t.Errorf("Policy ID = %v, want test-policy-1", policy.ID)
	}
	if policy.Action != "deny" {
		t.Errorf("Policy Action = %v, want deny", policy.Action)
	}
}

// TestLoadPoliciesInvalidYAML tests policy parsing with invalid YAML syntax
func TestLoadPoliciesInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()

	invalidPolicy := `
policies:
  - id: test-policy
    name: Test Policy
    invalid yaml syntax here [[[
`

	policyFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(policyFile, []byte(invalidPolicy), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	_, err := LoadPolicies(policyFile)
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

// TestLoadPoliciesMissingFields tests policy parsing with missing required fields
func TestLoadPoliciesMissingFields(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name   string
		policy string
	}{
		{
			name: "missing ID",
			policy: `
policies:
  - name: Test Policy
    action: deny
    cwe:
      - CWE-89
`,
		},
		{
			name: "missing action",
			policy: `
policies:
  - id: test-policy
    name: Test Policy
    cwe:
      - CWE-89
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyFile := filepath.Join(tmpDir, tt.name+".yaml")
			if err := os.WriteFile(policyFile, []byte(tt.policy), 0644); err != nil {
				t.Fatalf("Failed to write test policy: %v", err)
			}

			_, err := LoadPolicies(policyFile)
			if err == nil {
				t.Error("Expected error for missing fields, got nil")
			}
		})
	}
}

// TestLoadPoliciesFromDirectory tests loading policies from directory
func TestLoadPoliciesFromDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	policy1 := `
policies:
  - id: policy-1
    name: Policy 1
    action: deny
    cwe:
      - CWE-89
`

	policy2 := `
policies:
  - id: policy-2
    name: Policy 2
    action: warn
    cwe:
      - CWE-79
`

	if err := os.WriteFile(filepath.Join(tmpDir, "policy1.yaml"), []byte(policy1), 0644); err != nil {
		t.Fatalf("Failed to write policy1: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "policy2.yaml"), []byte(policy2), 0644); err != nil {
		t.Fatalf("Failed to write policy2: %v", err)
	}

	policySet, err := LoadPolicies(tmpDir)
	if err != nil {
		t.Fatalf("LoadPolicies() error = %v", err)
	}

	if len(policySet.Policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(policySet.Policies))
	}
}

// TestLoadWaivers tests waiver loading
func TestLoadWaivers(t *testing.T) {
	tmpDir := t.TempDir()

	waiverYAML := `
waivers:
  - id: waiver-1
    finding_id: finding-123
    reason: False positive
    approved_by: security-team
    expires: 2027-12-31
`

	waiverFile := filepath.Join(tmpDir, "waivers.yaml")
	if err := os.WriteFile(waiverFile, []byte(waiverYAML), 0644); err != nil {
		t.Fatalf("Failed to write waiver file: %v", err)
	}

	waiverSet, err := LoadWaivers(waiverFile)
	if err != nil {
		t.Fatalf("LoadWaivers() error = %v", err)
	}

	if len(waiverSet.Waivers) != 1 {
		t.Errorf("Expected 1 waiver, got %d", len(waiverSet.Waivers))
	}

	waiver := waiverSet.Waivers[0]
	if waiver.ID != "waiver-1" {
		t.Errorf("Waiver ID = %v, want waiver-1", waiver.ID)
	}
	if waiver.Status != "active" {
		t.Errorf("Waiver Status = %v, want active", waiver.Status)
	}
}

// TestSavePolicies tests saving policies to file
func TestSavePolicies(t *testing.T) {
	tmpDir := t.TempDir()

	policySet := &PolicySet{
		Policies: []Policy{
			{
				ID:          "test-policy",
				Name:        "Test Policy",
				Description: "Test description",
				Enabled:     true,
				Action:      "deny",
				Severity:    "high",
				CWE:         []string{"CWE-89"},
			},
		},
	}

	policyFile := filepath.Join(tmpDir, "saved-policy.yaml")
	err := SavePolicies(policySet, policyFile)
	if err != nil {
		t.Fatalf("SavePolicies() error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		t.Error("Policy file was not created")
	}

	// Load it back and verify
	loaded, err := LoadPolicies(policyFile)
	if err != nil {
		t.Fatalf("Failed to load saved policy: %v", err)
	}

	if len(loaded.Policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(loaded.Policies))
	}
}

// TestComplexPolicyRules tests parsing complex nested rules
func TestComplexPolicyRules(t *testing.T) {
	tmpDir := t.TempDir()

	complexPolicy := `
policies:
  - id: complex-policy
    name: Complex Policy
    description: Policy with multiple CWEs and conditions
    enabled: true
    action: deny
    severity: high
    cwe:
      - CWE-89
      - CWE-79
      - CWE-78
      - CWE-22
  - id: warn-policy
    name: Warning Policy
    action: warn
    severity: medium
    cwe:
      - CWE-798
`

	policyFile := filepath.Join(tmpDir, "complex.yaml")
	if err := os.WriteFile(policyFile, []byte(complexPolicy), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	policySet, err := LoadPolicies(policyFile)
	if err != nil {
		t.Fatalf("LoadPolicies() error = %v", err)
	}

	if len(policySet.Policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(policySet.Policies))
	}

	// Verify first policy has multiple CWEs
	if len(policySet.Policies[0].CWE) != 4 {
		t.Errorf("Expected 4 CWEs in first policy, got %d", len(policySet.Policies[0].CWE))
	}
}

// TestLoadPoliciesNonExistentPath tests loading from non-existent path
func TestLoadPoliciesNonExistentPath(t *testing.T) {
	_, err := LoadPolicies("/non/existent/path")
	if err == nil {
		t.Error("Expected error for non-existent path, got nil")
	}
}

// TestLoadPoliciesEmptyDirectory tests loading from empty directory
func TestLoadPoliciesEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := LoadPolicies(tmpDir)
	if err == nil {
		t.Error("Expected error for empty directory, got nil")
	}
}
