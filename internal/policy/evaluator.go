package policy

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Finding represents a security finding for policy evaluation
type Finding struct {
	ID       string
	CWEID    string
	Severity string
	FilePath string
}

// Evaluator evaluates findings against policies
type Evaluator struct {
	policies *PolicySet
	waivers  *WaiverSet
}

// NewEvaluator creates a new policy evaluator
func NewEvaluator(policies *PolicySet) *Evaluator {
	return &Evaluator{
		policies: policies,
		waivers:  &WaiverSet{Waivers: []Waiver{}},
	}
}

// SetWaivers sets the waivers for the evaluator
func (e *Evaluator) SetWaivers(waivers *WaiverSet) {
	e.waivers = waivers
}

// Evaluate evaluates a finding against all policies
func (e *Evaluator) Evaluate(finding *Finding) *PolicyDecision {
	// Check for active waiver first
	if waiver := e.findActiveWaiver(finding.ID); waiver != nil {
		log.Info().
			Str("finding_id", finding.ID).
			Str("waiver_id", waiver.ID).
			Msg("Active waiver found, skipping policy enforcement")
		
		return &PolicyDecision{
			DecisionID:    uuid.New().String(),
			FindingID:     finding.ID,
			PolicyID:      "waiver",
			PolicyName:    "Waived",
			Action:        "allow",
			Reason:        fmt.Sprintf("Waived: %s (expires: %s)", waiver.Reason, waiver.Expires.Format("2006-01-02")),
			Timestamp:     time.Now(),
			WaiverApplied: true,
		}
	}

	// Find all matching policies
	matchingPolicies := e.findMatchingPolicies(finding)

	if len(matchingPolicies) == 0 {
		// No policies match, default to allow
		log.Debug().
			Str("finding_id", finding.ID).
			Str("cwe", finding.CWEID).
			Msg("No matching policies, allowing by default")
		
		return &PolicyDecision{
			DecisionID:    uuid.New().String(),
			FindingID:     finding.ID,
			PolicyID:      "default",
			PolicyName:    "Default Policy",
			Action:        "allow",
			Reason:        "No matching policies found",
			Timestamp:     time.Now(),
			WaiverApplied: false,
		}
	}

	// Apply most restrictive policy
	mostRestrictive := e.selectMostRestrictive(matchingPolicies)

	log.Info().
		Str("finding_id", finding.ID).
		Str("policy_id", mostRestrictive.ID).
		Str("action", mostRestrictive.Action).
		Msg("Policy decision made")

	return &PolicyDecision{
		DecisionID:    uuid.New().String(),
		FindingID:     finding.ID,
		PolicyID:      mostRestrictive.ID,
		PolicyName:    mostRestrictive.Name,
		Action:        mostRestrictive.Action,
		Reason:        fmt.Sprintf("Matched policy: %s", mostRestrictive.Description),
		Timestamp:     time.Now(),
		WaiverApplied: false,
	}
}

// findActiveWaiver finds an active waiver for a finding
func (e *Evaluator) findActiveWaiver(findingID string) *Waiver {
	for _, waiver := range e.waivers.Waivers {
		if waiver.FindingID == findingID && waiver.IsActive() {
			return &waiver
		}
	}
	return nil
}

// findMatchingPolicies finds all policies that match a finding
func (e *Evaluator) findMatchingPolicies(finding *Finding) []Policy {
	var matching []Policy

	for _, policy := range e.policies.GetEnabledPolicies() {
		if Matches(&policy, finding.CWEID, finding.Severity, finding.FilePath) {
			matching = append(matching, policy)
		}
	}

	return matching
}

// selectMostRestrictive selects the most restrictive policy from a list
func (e *Evaluator) selectMostRestrictive(policies []Policy) Policy {
	// Priority: deny > warn > allow
	actionPriority := map[string]int{
		"deny":  3,
		"warn":  2,
		"allow": 1,
	}

	// Severity priority: critical > high > medium > low
	severityPriority := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"":         0, // No severity specified
	}

	mostRestrictive := policies[0]
	maxActionPriority := actionPriority[mostRestrictive.Action]
	maxSeverityPriority := severityPriority[mostRestrictive.Severity]

	for _, policy := range policies[1:] {
		actionPrio := actionPriority[policy.Action]
		severityPrio := severityPriority[policy.Severity]

		// First compare by action priority
		if actionPrio > maxActionPriority {
			mostRestrictive = policy
			maxActionPriority = actionPrio
			maxSeverityPriority = severityPrio
		} else if actionPrio == maxActionPriority {
			// If action is the same, compare by severity
			if severityPrio > maxSeverityPriority {
				mostRestrictive = policy
				maxSeverityPriority = severityPrio
			}
		}
	}

	return mostRestrictive
}

// EvaluateAll evaluates multiple findings
func (e *Evaluator) EvaluateAll(findings []*Finding) []*PolicyDecision {
	decisions := make([]*PolicyDecision, len(findings))
	for i, finding := range findings {
		decisions[i] = e.Evaluate(finding)
	}
	return decisions
}

// GetStatistics returns statistics about policy decisions
func GetStatistics(decisions []*PolicyDecision) map[string]int {
	stats := map[string]int{
		"total":   len(decisions),
		"deny":    0,
		"warn":    0,
		"allow":   0,
		"waived":  0,
	}

	for _, decision := range decisions {
		stats[decision.Action]++
		if decision.WaiverApplied {
			stats["waived"]++
		}
	}

	return stats
}
