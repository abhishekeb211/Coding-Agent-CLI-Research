package policy

import (
	"fmt"
	"time"
)

// PolicyPatterns represents file path patterns for policy matching
type PolicyPatterns struct {
	Include []string `yaml:"include" json:"include"` // Patterns to include
	Exclude []string `yaml:"exclude" json:"exclude"` // Patterns to exclude
}

// Policy represents a security policy rule
type Policy struct {
	ID          string          `yaml:"id" json:"id"`
	Name        string          `yaml:"name" json:"name"`
	Description string          `yaml:"description" json:"description"`
	CWE         []string        `yaml:"cwe" json:"cwe"`
	Severity    string          `yaml:"severity" json:"severity"`
	Action      string          `yaml:"action" json:"action"` // deny, warn, allow
	Enabled     bool            `yaml:"enabled" json:"enabled"`
	Patterns    *PolicyPatterns `yaml:"patterns,omitempty" json:"patterns,omitempty"` // File path patterns (optional)
}

// PolicySet represents a collection of policies
type PolicySet struct {
	Policies []Policy `yaml:"policies" json:"policies"`
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	DecisionID  string    `json:"decision_id"`
	FindingID   string    `json:"finding_id"`
	PolicyID    string    `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	Action      string    `json:"action"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
	WaiverApplied bool    `json:"waiver_applied"`
}

// Waiver represents an exception to a policy
type Waiver struct {
	ID         string    `yaml:"id" json:"id"`
	FindingID  string    `yaml:"finding_id" json:"finding_id"`
	Reason     string    `yaml:"reason" json:"reason"`
	Expires    time.Time `yaml:"expires" json:"expires"`
	ApprovedBy string    `yaml:"approved_by" json:"approved_by"`
	CreatedAt  time.Time `yaml:"created_at" json:"created_at"`
	Status     string    `json:"status"` // active, expired
}

// WaiverSet represents a collection of waivers
type WaiverSet struct {
	Waivers []Waiver `yaml:"waivers" json:"waivers"`
}

// Validate validates a policy
func (p *Policy) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if len(p.CWE) == 0 {
		return fmt.Errorf("policy must specify at least one CWE")
	}
	if p.Action != "deny" && p.Action != "warn" && p.Action != "allow" {
		return fmt.Errorf("policy action must be deny, warn, or allow")
	}
	if p.Severity != "" && p.Severity != "critical" && p.Severity != "high" && p.Severity != "medium" && p.Severity != "low" {
		return fmt.Errorf("policy severity must be critical, high, medium, or low")
	}
	return nil
}

// Validate validates a waiver
func (w *Waiver) Validate() error {
	if w.ID == "" {
		return fmt.Errorf("waiver ID is required")
	}
	if w.FindingID == "" {
		return fmt.Errorf("waiver finding_id is required")
	}
	if w.Reason == "" {
		return fmt.Errorf("waiver reason is required")
	}
	if w.Expires.IsZero() {
		return fmt.Errorf("waiver expiration date is required")
	}
	if w.ApprovedBy == "" {
		return fmt.Errorf("waiver approved_by is required")
	}
	return nil
}

// IsExpired checks if a waiver has expired
func (w *Waiver) IsExpired() bool {
	return time.Now().After(w.Expires)
}

// IsActive checks if a waiver is active (not expired)
func (w *Waiver) IsActive() bool {
	return !w.IsExpired()
}

// Validate validates a policy set
func (ps *PolicySet) Validate() error {
	if len(ps.Policies) == 0 {
		return fmt.Errorf("policy set must contain at least one policy")
	}
	
	// Check for duplicate IDs
	seen := make(map[string]bool)
	for _, policy := range ps.Policies {
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("invalid policy %s: %w", policy.ID, err)
		}
		if seen[policy.ID] {
			return fmt.Errorf("duplicate policy ID: %s", policy.ID)
		}
		seen[policy.ID] = true
	}
	
	return nil
}

// Validate validates a waiver set
func (ws *WaiverSet) Validate() error {
	// Check for duplicate IDs
	seen := make(map[string]bool)
	for _, waiver := range ws.Waivers {
		if err := waiver.Validate(); err != nil {
			return fmt.Errorf("invalid waiver %s: %w", waiver.ID, err)
		}
		if seen[waiver.ID] {
			return fmt.Errorf("duplicate waiver ID: %s", waiver.ID)
		}
		seen[waiver.ID] = true
	}
	
	return nil
}

// GetActiveWaivers returns only active (non-expired) waivers
func (ws *WaiverSet) GetActiveWaivers() []Waiver {
	var active []Waiver
	for _, waiver := range ws.Waivers {
		if waiver.IsActive() {
			active = append(active, waiver)
		}
	}
	return active
}

// GetEnabledPolicies returns only enabled policies
func (ps *PolicySet) GetEnabledPolicies() []Policy {
	var enabled []Policy
	for _, policy := range ps.Policies {
		if policy.Enabled {
			enabled = append(enabled, policy)
		}
	}
	return enabled
}
