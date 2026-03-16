package policy

import (
	"strings"
)

// MatchesCWE checks if a policy matches a given CWE ID
func MatchesCWE(policy *Policy, cweID string) bool {
	// Normalize CWE ID (remove "CWE-" prefix if present)
	normalizedCWE := strings.TrimPrefix(cweID, "CWE-")
	
	for _, policyCWE := range policy.CWE {
		// Normalize policy CWE
		normalizedPolicyCWE := strings.TrimPrefix(policyCWE, "CWE-")
		
		// Check for exact match
		if normalizedPolicyCWE == normalizedCWE {
			return true
		}
		
		// Check for wildcard match (e.g., "89*" matches "89", "890", "891")
		if strings.HasSuffix(normalizedPolicyCWE, "*") {
			prefix := strings.TrimSuffix(normalizedPolicyCWE, "*")
			if strings.HasPrefix(normalizedCWE, prefix) {
				return true
			}
		}
	}
	
	return false
}

// MatchesSeverity checks if a policy matches a given severity level
func MatchesSeverity(policy *Policy, severity string) bool {
	// If policy doesn't specify severity, it matches all severities
	if policy.Severity == "" {
		return true
	}
	
	// Normalize severity strings
	policySeverity := strings.ToLower(policy.Severity)
	findingSeverity := strings.ToLower(severity)
	
	// Define severity hierarchy
	severityLevels := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}
	
	policyLevel, policyExists := severityLevels[policySeverity]
	findingLevel, findingExists := severityLevels[findingSeverity]
	
	if !policyExists || !findingExists {
		return false
	}
	
	// Policy matches if finding severity is >= policy severity
	return findingLevel >= policyLevel
}

// MatchesFilePath checks if a policy matches a given file path
func MatchesFilePath(policy *Policy, filePath string) bool {
	// If policy doesn't specify patterns, it matches all files
	if policy.Patterns == nil {
		return true
	}

	pm := NewPatternMatcher()

	// Check include patterns
	if len(policy.Patterns.Include) > 0 {
		includeMatch := false
		for _, patternStr := range policy.Patterns.Include {
			pattern, err := pm.CompilePattern(patternStr)
			if err != nil {
				// If pattern is invalid, skip it
				continue
			}
			matched, err := pm.Match(pattern, filePath)
			if err == nil && matched {
				includeMatch = true
				break
			}
		}
		// If include patterns are specified but none match, return false
		if !includeMatch {
			return false
		}
	}

	// Check exclude patterns
	if len(policy.Patterns.Exclude) > 0 {
		for _, patternStr := range policy.Patterns.Exclude {
			pattern, err := pm.CompilePattern(patternStr)
			if err != nil {
				// If pattern is invalid, skip it
				continue
			}
			matched, err := pm.Match(pattern, filePath)
			if err == nil && matched {
				// File matches an exclude pattern, so it's excluded
				return false
			}
		}
	}

	return true
}

// Matches checks if a policy matches a finding
func Matches(policy *Policy, cweID string, severity string, filePath string) bool {
	if !policy.Enabled {
		return false
	}
	
	if !MatchesCWE(policy, cweID) {
		return false
	}
	
	if !MatchesSeverity(policy, severity) {
		return false
	}
	
	if !MatchesFilePath(policy, filePath) {
		return false
	}
	
	return true
}
