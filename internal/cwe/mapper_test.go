package cwe

import (
	"testing"
)

// TestMapRuleToCWE tests CWE mapping for known vulnerability types
func TestMapRuleToCWE(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string
		category string
		want     string
	}{
		// Bandit rules - exact matches
		{
			name:     "bandit SQL injection",
			ruleID:   "B608",
			category: "",
			want:     "CWE-89",
		},
		{
			name:     "bandit command injection",
			ruleID:   "B602",
			category: "",
			want:     "CWE-78",
		},
		{
			name:     "bandit hardcoded password",
			ruleID:   "B105",
			category: "",
			want:     "CWE-798",
		},
		{
			name:     "bandit weak crypto",
			ruleID:   "B303",
			category: "",
			want:     "CWE-327",
		},
		{
			name:     "bandit pickle deserialization",
			ruleID:   "B301",
			category: "",
			want:     "CWE-502",
		},
		{
			name:     "bandit XXE",
			ruleID:   "B313",
			category: "",
			want:     "CWE-611",
		},
		{
			name:     "bandit weak random",
			ruleID:   "B311",
			category: "",
			want:     "CWE-330",
		},
		{
			name:     "bandit open redirect",
			ruleID:   "B310",
			category: "",
			want:     "CWE-601",
		},

		// Semgrep rules - exact matches
		{
			name:     "semgrep SQL injection",
			ruleID:   "python.lang.security.audit.sqli",
			category: "",
			want:     "CWE-89",
		},
		{
			name:     "semgrep command injection",
			ruleID:   "python.lang.security.audit.dangerous-system-call",
			category: "",
			want:     "CWE-78",
		},
		{
			name:     "semgrep XSS",
			ruleID:   "javascript.lang.security.audit.xss",
			category: "",
			want:     "CWE-79",
		},
		{
			name:     "semgrep path traversal",
			ruleID:   "python.lang.security.audit.path-traversal",
			category: "",
			want:     "CWE-22",
		},
		{
			name:     "semgrep hardcoded secret",
			ruleID:   "javascript.lang.security.audit.hardcoded-secret",
			category: "",
			want:     "CWE-798",
		},
		{
			name:     "semgrep SSRF",
			ruleID:   "javascript.lang.security.audit.ssrf",
			category: "",
			want:     "CWE-918",
		},

		// eslint-plugin-security rules - exact matches
		{
			name:     "eslint unsafe regex",
			ruleID:   "security/detect-unsafe-regex",
			category: "",
			want:     "CWE-1333",
		},
		{
			name:     "eslint buffer noassert",
			ruleID:   "security/detect-buffer-noassert",
			category: "",
			want:     "CWE-120",
		},
		{
			name:     "eslint child process",
			ruleID:   "security/detect-child-process",
			category: "",
			want:     "CWE-78",
		},
		{
			name:     "eslint disable mustache escape",
			ruleID:   "security/detect-disable-mustache-escape",
			category: "",
			want:     "CWE-79",
		},
		{
			name:     "eslint eval with expression",
			ruleID:   "security/detect-eval-with-expression",
			category: "",
			want:     "CWE-94",
		},
		{
			name:     "eslint no csrf",
			ruleID:   "security/detect-no-csrf-before-method-override",
			category: "",
			want:     "CWE-352",
		},
		{
			name:     "eslint non-literal fs filename",
			ruleID:   "security/detect-non-literal-fs-filename",
			category: "",
			want:     "CWE-22",
		},
		{
			name:     "eslint non-literal regexp",
			ruleID:   "security/detect-non-literal-regexp",
			category: "",
			want:     "CWE-1333",
		},
		{
			name:     "eslint non-literal require",
			ruleID:   "security/detect-non-literal-require",
			category: "",
			want:     "CWE-94",
		},
		{
			name:     "eslint object injection",
			ruleID:   "security/detect-object-injection",
			category: "",
			want:     "CWE-1321",
		},
		{
			name:     "eslint timing attacks",
			ruleID:   "security/detect-possible-timing-attacks",
			category: "",
			want:     "CWE-208",
		},
		{
			name:     "eslint pseudoRandomBytes",
			ruleID:   "security/detect-pseudoRandomBytes",
			category: "",
			want:     "CWE-330",
		},

		// Pattern matching - SQL injection
		{
			name:     "pattern match SQL",
			ruleID:   "custom-sql-check",
			category: "",
			want:     "CWE-89",
		},
		{
			name:     "pattern match sqli",
			ruleID:   "detect-sqli-vulnerability",
			category: "",
			want:     "CWE-89",
		},

		// Pattern matching - Command injection
		{
			name:     "pattern match command",
			ruleID:   "command-execution-risk",
			category: "",
			want:     "CWE-78",
		},
		{
			name:     "pattern match exec",
			ruleID:   "unsafe-exec-call",
			category: "",
			want:     "CWE-78",
		},
		{
			name:     "pattern match shell",
			ruleID:   "shell-injection-detected",
			category: "",
			want:     "CWE-78",
		},

		// Pattern matching - XSS
		{
			name:     "pattern match xss",
			ruleID:   "xss-vulnerability",
			category: "",
			want:     "CWE-79",
		},
		{
			name:     "pattern match cross-site",
			ruleID:   "cross-site-scripting",
			category: "",
			want:     "CWE-79",
		},

		// Pattern matching - Path traversal
		{
			name:     "pattern match path",
			ruleID:   "path-injection",
			category: "",
			want:     "CWE-22",
		},
		{
			name:     "pattern match traversal",
			ruleID:   "directory-traversal",
			category: "",
			want:     "CWE-22",
		},

		// Pattern matching - Hardcoded credentials
		{
			name:     "pattern match password",
			ruleID:   "hardcoded-password-found",
			category: "",
			want:     "CWE-798",
		},
		{
			name:     "pattern match secret",
			ruleID:   "secret-in-code",
			category: "",
			want:     "CWE-798",
		},
		{
			name:     "pattern match api-key",
			ruleID:   "api-key-hardcoded",
			category: "",
			want:     "CWE-798",
		},

		// Pattern matching - Crypto
		{
			name:     "pattern match crypto",
			ruleID:   "weak-crypto-algorithm",
			category: "",
			want:     "CWE-327",
		},
		{
			name:     "pattern match md5",
			ruleID:   "md5-hash-used",
			category: "",
			want:     "CWE-327",
		},

		// Pattern matching - Deserialization
		{
			name:     "pattern match pickle",
			ruleID:   "pickle-usage-detected",
			category: "",
			want:     "CWE-502",
		},
		{
			name:     "pattern match deserial",
			ruleID:   "unsafe-deserialization",
			category: "",
			want:     "CWE-502",
		},

		// Pattern matching - XXE
		{
			name:     "pattern match xxe",
			ruleID:   "xxe-vulnerability",
			category: "",
			want:     "CWE-611",
		},
		{
			name:     "pattern match xml",
			ruleID:   "xml-external-entity",
			category: "",
			want:     "CWE-611",
		},

		// Pattern matching - Random
		{
			name:     "pattern match random",
			ruleID:   "weak-random-generator",
			category: "",
			want:     "CWE-330",
		},

		// Pattern matching - Redirect
		{
			name:     "pattern match redirect",
			ruleID:   "open-redirect-found",
			category: "",
			want:     "CWE-601",
		},

		// Pattern matching - SSRF
		{
			name:     "pattern match ssrf",
			ruleID:   "ssrf-detected",
			category: "",
			want:     "CWE-918",
		},

		// Category-based mapping
		{
			name:     "category injection",
			ruleID:   "unknown-rule",
			category: "injection",
			want:     "CWE-89",
		},
		{
			name:     "category crypto",
			ruleID:   "unknown-rule",
			category: "cryptography",
			want:     "CWE-327",
		},
		{
			name:     "category auth",
			ruleID:   "unknown-rule",
			category: "authentication",
			want:     "CWE-798",
		},

		// Unknown mapping
		{
			name:     "unknown rule and category",
			ruleID:   "completely-unknown-rule",
			category: "unknown-category",
			want:     "CWE-000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapRuleToCWE(tt.ruleID, tt.category)
			if got != tt.want {
				t.Errorf("MapRuleToCWE(%q, %q) = %v, want %v", tt.ruleID, tt.category, got, tt.want)
			}
		})
	}
}

// TestExtractCWEFromMetadata tests CWE extraction from scanner metadata
func TestExtractCWEFromMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		want     string
	}{
		{
			name: "CWE as string with prefix",
			metadata: map[string]interface{}{
				"cwe": "CWE-89",
			},
			want: "CWE-89",
		},
		{
			name: "CWE as string without prefix",
			metadata: map[string]interface{}{
				"cwe": "89",
			},
			want: "CWE-89",
		},
		{
			name: "CWE as array with prefix",
			metadata: map[string]interface{}{
				"cwe": []interface{}{"CWE-79", "CWE-20"},
			},
			want: "CWE-79",
		},
		{
			name: "CWE as array without prefix",
			metadata: map[string]interface{}{
				"cwe": []interface{}{"79", "20"},
			},
			want: "CWE-79",
		},
		{
			name: "OWASP A03:2021 (Injection)",
			metadata: map[string]interface{}{
				"owasp": []interface{}{"A03:2021"},
			},
			want: "CWE-89",
		},
		{
			name: "OWASP A02:2021 (Cryptographic Failures)",
			metadata: map[string]interface{}{
				"owasp": []interface{}{"A02:2021"},
			},
			want: "CWE-327",
		},
		{
			name: "OWASP A05:2021 (Security Misconfiguration)",
			metadata: map[string]interface{}{
				"owasp": []interface{}{"A05:2021"},
			},
			want: "CWE-798",
		},
		{
			name: "OWASP A10:2021 (SSRF)",
			metadata: map[string]interface{}{
				"owasp": []interface{}{"A10:2021"},
			},
			want: "CWE-918",
		},
		{
			name:     "empty metadata",
			metadata: map[string]interface{}{},
			want:     "",
		},
		{
			name: "metadata without CWE or OWASP",
			metadata: map[string]interface{}{
				"severity": "high",
				"category": "security",
			},
			want: "",
		},
		{
			name: "CWE as empty array",
			metadata: map[string]interface{}{
				"cwe": []interface{}{},
			},
			want: "",
		},
		{
			name: "unknown OWASP category",
			metadata: map[string]interface{}{
				"owasp": []interface{}{"A99:2021"},
			},
			want: "",
		},
		{
			name: "gosec CWE object format",
			metadata: map[string]interface{}{
				"cwe": map[string]interface{}{
					"id":  "22",
					"url": "https://cwe.mitre.org/data/definitions/22.html",
				},
			},
			want: "CWE-22",
		},
		{
			name: "gosec CWE object with CWE prefix",
			metadata: map[string]interface{}{
				"cwe": map[string]interface{}{
					"id":  "CWE-798",
					"url": "https://cwe.mitre.org/data/definitions/798.html",
				},
			},
			want: "CWE-798",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCWEFromMetadata(tt.metadata)
			if got != tt.want {
				t.Errorf("ExtractCWEFromMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapOWASPToCWE tests OWASP to CWE mapping
func TestMapOWASPToCWE(t *testing.T) {
	tests := []struct {
		name  string
		owasp string
		want  string
	}{
		{
			name:  "A01:2021 Broken Access Control",
			owasp: "A01:2021",
			want:  "CWE-20",
		},
		{
			name:  "A02:2021 Cryptographic Failures",
			owasp: "A02:2021",
			want:  "CWE-327",
		},
		{
			name:  "A03:2021 Injection",
			owasp: "A03:2021",
			want:  "CWE-89",
		},
		{
			name:  "A04:2021 Insecure Design",
			owasp: "A04:2021",
			want:  "CWE-20",
		},
		{
			name:  "A05:2021 Security Misconfiguration",
			owasp: "A05:2021",
			want:  "CWE-798",
		},
		{
			name:  "A06:2021 Vulnerable Components",
			owasp: "A06:2021",
			want:  "CWE-327",
		},
		{
			name:  "A07:2021 Auth Failures",
			owasp: "A07:2021",
			want:  "CWE-798",
		},
		{
			name:  "A08:2021 Data Integrity Failures",
			owasp: "A08:2021",
			want:  "CWE-502",
		},
		{
			name:  "A09:2021 Logging Failures",
			owasp: "A09:2021",
			want:  "CWE-200",
		},
		{
			name:  "A10:2021 SSRF",
			owasp: "A10:2021",
			want:  "CWE-918",
		},
		{
			name:  "unknown OWASP category",
			owasp: "A99:2021",
			want:  "",
		},
		{
			name:  "empty string",
			owasp: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapOWASPToCWE(tt.owasp)
			if got != tt.want {
				t.Errorf("mapOWASPToCWE(%q) = %v, want %v", tt.owasp, got, tt.want)
			}
		})
	}
}

// TestRuleToCWEMapCompleteness tests that all rules in the map are valid
func TestRuleToCWEMapCompleteness(t *testing.T) {
	for ruleID, cweID := range RuleToCWEMap {
		if ruleID == "" {
			t.Errorf("Found empty rule ID in RuleToCWEMap")
		}
		if cweID == "" {
			t.Errorf("Found empty CWE ID for rule %s", ruleID)
		}
		if cweID != "CWE-000" && len(cweID) < 5 {
			t.Errorf("Invalid CWE ID format for rule %s: %s", ruleID, cweID)
		}
	}
}

// TestGosecRuleMappings tests all gosec rule mappings
func TestGosecRuleMappings(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		// Credentials and secrets
		{"G101", "CWE-798"},
		
		// Network and binding
		{"G102", "CWE-200"},
		
		// Unsafe operations
		{"G103", "CWE-242"},
		
		// Error handling
		{"G104", "CWE-703"},
		
		// Integer operations
		{"G105", "CWE-190"},
		{"G109", "CWE-190"},
		
		// SSH and network security
		{"G106", "CWE-322"},
		
		// SSRF
		{"G107", "CWE-918"},
		
		// Profiling endpoints
		{"G108", "CWE-200"},
		
		// Decompression bomb
		{"G110", "CWE-409"},
		
		// SQL injection
		{"G201", "CWE-89"},
		{"G202", "CWE-89"},
		
		// XSS/HTML template
		{"G203", "CWE-79"},
		
		// Command injection
		{"G204", "CWE-78"},
		
		// File permissions
		{"G301", "CWE-732"},
		{"G302", "CWE-732"},
		{"G306", "CWE-732"},
		
		// Temp file creation
		{"G303", "CWE-377"},
		
		// Path traversal
		{"G304", "CWE-22"},
		{"G305", "CWE-22"},
		
		// Defer close error
		{"G307", "CWE-703"},
		
		// Weak cryptography
		{"G401", "CWE-327"},
		{"G403", "CWE-327"},
		{"G501", "CWE-327"},
		{"G502", "CWE-327"},
		{"G503", "CWE-327"},
		{"G504", "CWE-327"},
		{"G505", "CWE-327"},
		
		// TLS configuration
		{"G402", "CWE-295"},
		
		// Weak random
		{"G404", "CWE-330"},
		
		// Implicit aliasing
		{"G601", "CWE-118"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := MapRuleToCWE(tt.ruleID, "")
			if got != tt.want {
				t.Errorf("MapRuleToCWE(%q, \"\") = %v, want %v", tt.ruleID, got, tt.want)
			}
		})
	}
}

// TestESLintRuleMappings tests all eslint-plugin-security rule mappings
func TestESLintRuleMappings(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"security/detect-unsafe-regex", "CWE-1333"},
		{"security/detect-buffer-noassert", "CWE-120"},
		{"security/detect-child-process", "CWE-78"},
		{"security/detect-disable-mustache-escape", "CWE-79"},
		{"security/detect-eval-with-expression", "CWE-94"},
		{"security/detect-no-csrf-before-method-override", "CWE-352"},
		{"security/detect-non-literal-fs-filename", "CWE-22"},
		{"security/detect-non-literal-regexp", "CWE-1333"},
		{"security/detect-non-literal-require", "CWE-94"},
		{"security/detect-object-injection", "CWE-1321"},
		{"security/detect-possible-timing-attacks", "CWE-208"},
		{"security/detect-pseudoRandomBytes", "CWE-330"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := MapRuleToCWE(tt.ruleID, "")
			if got != tt.want {
				t.Errorf("MapRuleToCWE(%q, \"\") = %v, want %v", tt.ruleID, got, tt.want)
			}
		})
	}
}

// TestCaseInsensitiveMatching tests that pattern matching is case-insensitive
func TestCaseInsensitiveMatching(t *testing.T) {
	tests := []struct {
		name   string
		ruleID string
		want   string
	}{
		{
			name:   "uppercase SQL",
			ruleID: "DETECT-SQL-INJECTION",
			want:   "CWE-89",
		},
		{
			name:   "mixed case XSS",
			ruleID: "XsS-VuLnErAbIlItY",
			want:   "CWE-79",
		},
		{
			name:   "lowercase command",
			ruleID: "command-injection",
			want:   "CWE-78",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapRuleToCWE(tt.ruleID, "")
			if got != tt.want {
				t.Errorf("MapRuleToCWE(%q, \"\") = %v, want %v", tt.ruleID, got, tt.want)
			}
		})
	}
}

// TestEdgeCases tests edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string
		category string
		want     string
	}{
		{
			name:     "empty rule ID",
			ruleID:   "",
			category: "",
			want:     "CWE-000",
		},
		{
			name:     "empty rule ID with category",
			ruleID:   "",
			category: "injection",
			want:     "CWE-89",
		},
		{
			name:     "whitespace only rule ID",
			ruleID:   "   ",
			category: "",
			want:     "CWE-000",
		},
		{
			name:     "special characters",
			ruleID:   "rule-@#$%-test",
			category: "",
			want:     "CWE-000",
		},
		{
			name:     "very long rule ID",
			ruleID:   "this.is.a.very.long.rule.id.with.many.segments.that.should.still.work.sql",
			category: "",
			want:     "CWE-89",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapRuleToCWE(tt.ruleID, tt.category)
			if got != tt.want {
				t.Errorf("MapRuleToCWE(%q, %q) = %v, want %v", tt.ruleID, tt.category, got, tt.want)
			}
		})
	}
}

// TestMetadataEdgeCases tests edge cases for metadata extraction
func TestMetadataEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		want     string
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			want:     "",
		},
		{
			name: "CWE as integer (invalid)",
			metadata: map[string]interface{}{
				"cwe": 89,
			},
			want: "",
		},
		{
			name: "CWE as nested structure",
			metadata: map[string]interface{}{
				"cwe": map[string]interface{}{
					"id": "89",
				},
			},
			want: "CWE-89",
		},
		{
			name: "OWASP as string (not array)",
			metadata: map[string]interface{}{
				"owasp": "A03:2021",
			},
			want: "",
		},
		{
			name: "OWASP array with non-string",
			metadata: map[string]interface{}{
				"owasp": []interface{}{123},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCWEFromMetadata(tt.metadata)
			if got != tt.want {
				t.Errorf("ExtractCWEFromMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGosecCWEExtraction tests CWE extraction from gosec output format
func TestGosecCWEExtraction(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		want     string
	}{
		{
			name: "gosec G101 with CWE object",
			metadata: map[string]interface{}{
				"severity":   "HIGH",
				"confidence": "HIGH",
				"rule_id":    "G101",
				"cwe": map[string]interface{}{
					"id":  "798",
					"url": "https://cwe.mitre.org/data/definitions/798.html",
				},
			},
			want: "CWE-798",
		},
		{
			name: "gosec G204 with CWE object",
			metadata: map[string]interface{}{
				"severity":   "MEDIUM",
				"confidence": "HIGH",
				"rule_id":    "G204",
				"cwe": map[string]interface{}{
					"id":  "78",
					"url": "https://cwe.mitre.org/data/definitions/78.html",
				},
			},
			want: "CWE-78",
		},
		{
			name: "gosec G304 with CWE object",
			metadata: map[string]interface{}{
				"severity":   "MEDIUM",
				"confidence": "HIGH",
				"rule_id":    "G304",
				"cwe": map[string]interface{}{
					"id":  "22",
					"url": "https://cwe.mitre.org/data/definitions/22.html",
				},
			},
			want: "CWE-22",
		},
		{
			name: "gosec with invalid CWE object (missing id)",
			metadata: map[string]interface{}{
				"severity":   "HIGH",
				"confidence": "HIGH",
				"rule_id":    "G101",
				"cwe": map[string]interface{}{
					"url": "https://cwe.mitre.org/data/definitions/798.html",
				},
			},
			want: "",
		},
		{
			name: "gosec with CWE object (id as integer)",
			metadata: map[string]interface{}{
				"severity":   "HIGH",
				"confidence": "HIGH",
				"rule_id":    "G101",
				"cwe": map[string]interface{}{
					"id":  798,
					"url": "https://cwe.mitre.org/data/definitions/798.html",
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCWEFromMetadata(tt.metadata)
			if got != tt.want {
				t.Errorf("ExtractCWEFromMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}
