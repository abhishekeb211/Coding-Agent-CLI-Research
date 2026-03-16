package policy

import (
	"testing"
)

// TestMatchesCWE tests CWE matching
func TestMatchesCWE(t *testing.T) {
	tests := []struct {
		name      string
		policy    *Policy
		cweID     string
		wantMatch bool
	}{
		{
			name:      "exact match",
			policy:    &Policy{CWE: []string{"CWE-89"}},
			cweID:     "CWE-89",
			wantMatch: true,
		},
		{
			name:      "match without prefix",
			policy:    &Policy{CWE: []string{"89"}},
			cweID:     "CWE-89",
			wantMatch: true,
		},
		{
			name:      "wildcard match",
			policy:    &Policy{CWE: []string{"89*"}},
			cweID:     "CWE-890",
			wantMatch: true,
		},
		{
			name:      "no match",
			policy:    &Policy{CWE: []string{"CWE-89"}},
			cweID:     "CWE-79",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesCWE(tt.policy, tt.cweID)
			if got != tt.wantMatch {
				t.Errorf("MatchesCWE() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

// TestMatchesSeverity tests severity matching
func TestMatchesSeverity(t *testing.T) {
	tests := []struct {
		name      string
		policy    *Policy
		severity  string
		wantMatch bool
	}{
		{
			name:      "exact match",
			policy:    &Policy{Severity: "high"},
			severity:  "high",
			wantMatch: true,
		},
		{
			name:      "higher severity matches",
			policy:    &Policy{Severity: "medium"},
			severity:  "high",
			wantMatch: true,
		},
		{
			name:      "lower severity doesn't match",
			policy:    &Policy{Severity: "high"},
			severity:  "medium",
			wantMatch: false,
		},
		{
			name:      "empty policy severity matches all",
			policy:    &Policy{Severity: ""},
			severity:  "low",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesSeverity(tt.policy, tt.severity)
			if got != tt.wantMatch {
				t.Errorf("MatchesSeverity() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

// TestMatches tests combined criteria matching
func TestMatches(t *testing.T) {
	tests := []struct {
		name      string
		policy    *Policy
		cweID     string
		severity  string
		filePath  string
		wantMatch bool
	}{
		{
			name: "all criteria match",
			policy: &Policy{
				Enabled:  true,
				CWE:      []string{"CWE-89"},
				Severity: "high",
			},
			cweID:     "CWE-89",
			severity:  "high",
			filePath:  "/test/file.py",
			wantMatch: true,
		},
		{
			name: "disabled policy doesn't match",
			policy: &Policy{
				Enabled:  false,
				CWE:      []string{"CWE-89"},
				Severity: "high",
			},
			cweID:     "CWE-89",
			severity:  "high",
			filePath:  "/test/file.py",
			wantMatch: false,
		},
		{
			name: "CWE doesn't match",
			policy: &Policy{
				Enabled:  true,
				CWE:      []string{"CWE-79"},
				Severity: "high",
			},
			cweID:     "CWE-89",
			severity:  "high",
			filePath:  "/test/file.py",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Matches(tt.policy, tt.cweID, tt.severity, tt.filePath)
			if got != tt.wantMatch {
				t.Errorf("Matches() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

// TestMatchesFilePath tests file path pattern matching
func TestMatchesFilePath(t *testing.T) {
	tests := []struct {
		name      string
		policy    *Policy
		filePath  string
		wantMatch bool
	}{
		{
			name: "no patterns - matches all",
			policy: &Policy{
				Patterns: nil,
			},
			filePath:  "src/main.go",
			wantMatch: true,
		},
		{
			name: "include pattern - match",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go"},
				},
			},
			filePath:  "src/main.go",
			wantMatch: true,
		},
		{
			name: "include pattern - no match",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go"},
				},
			},
			filePath:  "src/main.py",
			wantMatch: false,
		},
		{
			name: "exclude pattern - excluded",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go"},
					Exclude: []string{"**/*_test.go"},
				},
			},
			filePath:  "src/main_test.go",
			wantMatch: false,
		},
		{
			name: "exclude pattern - not excluded",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go"},
					Exclude: []string{"**/*_test.go"},
				},
			},
			filePath:  "src/main.go",
			wantMatch: true,
		},
		{
			name: "multiple include patterns - match first",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go", "**/*.py"},
				},
			},
			filePath:  "src/main.go",
			wantMatch: true,
		},
		{
			name: "multiple include patterns - match second",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go", "**/*.py"},
				},
			},
			filePath:  "src/main.py",
			wantMatch: true,
		},
		{
			name: "multiple include patterns - no match",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go", "**/*.py"},
				},
			},
			filePath:  "src/main.js",
			wantMatch: false,
		},
		{
			name: "directory exclusion",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*.go"},
					Exclude: []string{"vendor/**"},
				},
			},
			filePath:  "vendor/pkg/lib.go",
			wantMatch: false,
		},
		{
			name: "test file pattern",
			policy: &Policy{
				Patterns: &PolicyPatterns{
					Include: []string{"**/*_test.go", "**/test_*.py"},
				},
			},
			filePath:  "src/helper_test.go",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesFilePath(tt.policy, tt.filePath)
			if got != tt.wantMatch {
				t.Errorf("MatchesFilePath() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}
