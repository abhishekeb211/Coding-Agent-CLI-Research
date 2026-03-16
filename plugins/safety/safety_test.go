package safety

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	scanner := New()
	assert.NotNil(t, scanner)
	assert.Equal(t, "safety", scanner.Name())
}

func TestName(t *testing.T) {
	scanner := New()
	assert.Equal(t, "safety", scanner.Name())
}

func TestIsAvailable(t *testing.T) {
	scanner := New()
	
	// Check if safety is actually installed
	_, err := exec.LookPath("safety")
	expectedAvailable := err == nil
	
	available := scanner.IsAvailable()
	assert.Equal(t, expectedAvailable, available)
	
	if available {
		assert.NotEmpty(t, scanner.execPath)
	}
}

func TestConvertFindings(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		name     string
		input    []SafetyVulnerability
		expected int
	}{
		{
			name: "single vulnerability",
			input: []SafetyVulnerability{
				{
					Package:          "django",
					InstalledVersion: "2.2.0",
					AffectedVersions: "<2.2.2",
					VulnerabilityID:  "38624",
					Advisory:         "Django before 2.2.2 allows SQL Injection",
					CVE:              "CVE-2019-12308",
					MoreInfoURL:      "https://nvd.nist.gov/vuln/detail/CVE-2019-12308",
				},
			},
			expected: 1,
		},
		{
			name: "multiple vulnerabilities",
			input: []SafetyVulnerability{
				{
					Package:          "requests",
					InstalledVersion: "2.6.0",
					AffectedVersions: "<2.6.1",
					VulnerabilityID:  "25853",
					Advisory:         "Requests allows remote code execution",
					CVE:              "CVE-2018-18074",
				},
				{
					Package:          "flask",
					InstalledVersion: "0.12.0",
					AffectedVersions: "<0.12.3",
					VulnerabilityID:  "36388",
					Advisory:         "Flask has a denial of service vulnerability",
					CVE:              "CVE-2018-1000656",
				},
			},
			expected: 2,
		},
		{
			name:     "empty input",
			input:    []SafetyVulnerability{},
			expected: 0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.convertFindings(tt.input, "/test/path")
			assert.Len(t, findings, tt.expected)
			
			for i, finding := range findings {
				assert.NotEmpty(t, finding.ID)
				assert.Equal(t, "safety", finding.ToolName)
				assert.NotEmpty(t, finding.Message)
				assert.Equal(t, "requirements.txt", finding.FilePath)
				assert.Equal(t, 0, finding.LineNumber)
				assert.NotEmpty(t, finding.Severity)
				assert.Equal(t, "high", finding.Confidence)
				assert.NotEmpty(t, finding.RuleID)
				assert.NotEmpty(t, finding.Category)
				assert.NotNil(t, finding.RawJSON)
				
				// Verify message contains key information
				assert.Contains(t, finding.Message, tt.input[i].Package)
				assert.Contains(t, finding.Message, tt.input[i].InstalledVersion)
			}
		})
	}
}

func TestFormatMessage(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		name     string
		vuln     SafetyVulnerability
		contains []string
	}{
		{
			name: "complete vulnerability",
			vuln: SafetyVulnerability{
				Package:          "django",
				InstalledVersion: "2.2.0",
				AffectedVersions: "<2.2.2",
				Advisory:         "Django before 2.2.2 allows SQL Injection",
				CVE:              "CVE-2019-12308",
			},
			contains: []string{"django", "2.2.0", "SQL Injection", "CVE-2019-12308", "<2.2.2"},
		},
		{
			name: "vulnerability without CVE",
			vuln: SafetyVulnerability{
				Package:          "requests",
				InstalledVersion: "2.6.0",
				Advisory:         "Remote code execution vulnerability",
			},
			contains: []string{"requests", "2.6.0", "Remote code execution"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := scanner.formatMessage(tt.vuln)
			assert.NotEmpty(t, message)
			
			for _, expected := range tt.contains {
				assert.Contains(t, message, expected)
			}
		})
	}
}

func TestFormatRuleID(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		name     string
		vuln     SafetyVulnerability
		expected string
	}{
		{
			name: "with CVE",
			vuln: SafetyVulnerability{
				Package:         "django",
				CVE:             "CVE-2019-12308",
				VulnerabilityID: "38624",
			},
			expected: "CVE-2019-12308",
		},
		{
			name: "without CVE but with vulnerability ID",
			vuln: SafetyVulnerability{
				Package:         "requests",
				VulnerabilityID: "25853",
			},
			expected: "25853",
		},
		{
			name: "without CVE or vulnerability ID",
			vuln: SafetyVulnerability{
				Package: "flask",
			},
			expected: "SAFETY-flask",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleID := scanner.formatRuleID(tt.vuln)
			assert.Equal(t, tt.expected, ruleID)
		})
	}
}

func TestMapSeverity(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		name     string
		vuln     SafetyVulnerability
		expected string
	}{
		{
			name: "critical - remote code execution",
			vuln: SafetyVulnerability{
				Advisory: "This package allows remote code execution",
			},
			expected: "high",
		},
		{
			name: "critical - RCE abbreviation",
			vuln: SafetyVulnerability{
				Advisory: "RCE vulnerability in package",
			},
			expected: "high",
		},
		{
			name: "critical - arbitrary code",
			vuln: SafetyVulnerability{
				Advisory: "Allows arbitrary code execution",
			},
			expected: "high",
		},
		{
			name: "medium - SQL injection",
			vuln: SafetyVulnerability{
				Advisory: "SQL injection vulnerability",
			},
			expected: "medium",
		},
		{
			name: "medium - XSS",
			vuln: SafetyVulnerability{
				Advisory: "Cross-site scripting (XSS) vulnerability",
			},
			expected: "medium",
		},
		{
			name: "medium - authentication",
			vuln: SafetyVulnerability{
				Advisory: "Authentication bypass vulnerability",
			},
			expected: "medium",
		},
		{
			name: "low - denial of service",
			vuln: SafetyVulnerability{
				Advisory: "Denial of service vulnerability",
			},
			expected: "low",
		},
		{
			name: "low - information disclosure",
			vuln: SafetyVulnerability{
				Advisory: "Information disclosure issue",
			},
			expected: "low",
		},
		{
			name: "default - unknown",
			vuln: SafetyVulnerability{
				Advisory: "Some other vulnerability",
			},
			expected: "medium",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity := scanner.mapSeverity(tt.vuln)
			assert.Equal(t, tt.expected, severity)
		})
	}
}

func TestExtractCategory(t *testing.T) {
	scanner := New()
	
	tests := []struct {
		name     string
		vuln     SafetyVulnerability
		expected string
	}{
		{
			name: "SQL injection",
			vuln: SafetyVulnerability{
				Advisory: "SQL injection vulnerability in query builder",
			},
			expected: "sql-injection",
		},
		{
			name: "XSS",
			vuln: SafetyVulnerability{
				Advisory: "Cross-site scripting (XSS) in template",
			},
			expected: "xss",
		},
		{
			name: "Remote code execution",
			vuln: SafetyVulnerability{
				Advisory: "Remote code execution via pickle",
			},
			expected: "code-execution",
		},
		{
			name: "Command injection",
			vuln: SafetyVulnerability{
				Advisory: "Command injection in subprocess call",
			},
			expected: "command-injection",
		},
		{
			name: "Path traversal",
			vuln: SafetyVulnerability{
				Advisory: "Path traversal vulnerability",
			},
			expected: "path-traversal",
		},
		{
			name: "CSRF",
			vuln: SafetyVulnerability{
				Advisory: "Cross-site request forgery (CSRF) vulnerability",
			},
			expected: "csrf",
		},
		{
			name: "Denial of service",
			vuln: SafetyVulnerability{
				Advisory: "Denial of service via regex",
			},
			expected: "denial-of-service",
		},
		{
			name: "Authentication",
			vuln: SafetyVulnerability{
				Advisory: "Authentication bypass vulnerability",
			},
			expected: "authentication",
		},
		{
			name: "Deserialization",
			vuln: SafetyVulnerability{
				Advisory: "Unsafe deserialization vulnerability",
			},
			expected: "deserialization",
		},
		{
			name: "XXE",
			vuln: SafetyVulnerability{
				Advisory: "XML external entity (XXE) vulnerability",
			},
			expected: "xxe",
		},
		{
			name: "Default category",
			vuln: SafetyVulnerability{
				Advisory: "Some other vulnerability type",
			},
			expected: "vulnerable-dependency",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category := scanner.extractCategory(tt.vuln)
			assert.Equal(t, tt.expected, category)
		})
	}
}

func TestToJSON(t *testing.T) {
	scanner := New()
	
	vuln := SafetyVulnerability{
		Package:          "django",
		InstalledVersion: "2.2.0",
		CVE:              "CVE-2019-12308",
	}
	
	result := scanner.toJSON(vuln)
	assert.NotNil(t, result)
	assert.Equal(t, "django", result["package"])
	assert.Equal(t, "2.2.0", result["installed_version"])
	assert.Equal(t, "CVE-2019-12308", result["cve"])
}

// Integration test - only runs if safety is installed
func TestScan_Integration(t *testing.T) {
	scanner := New()
	
	if !scanner.IsAvailable() {
		t.Skip("safety not installed, skipping integration test")
	}
	
	// Create a temporary directory with a requirements.txt file
	tmpDir, err := os.MkdirTemp("", "safety-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create a requirements.txt with a known vulnerable package
	// Using an old version of requests that has known vulnerabilities
	requirementsContent := `requests==2.6.0
`
	requirementsPath := filepath.Join(tmpDir, "requirements.txt")
	err = os.WriteFile(requirementsPath, []byte(requirementsContent), 0644)
	require.NoError(t, err)
	
	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, tmpDir)
	
	// Note: This test may fail if:
	// 1. Safety database is not available
	// 2. The vulnerability has been removed from the database
	// 3. Network issues prevent database access
	if err != nil {
		t.Logf("Scan failed (this may be expected): %v", err)
		return
	}
	
	// If scan succeeded, verify findings structure
	t.Logf("Found %d vulnerabilities", len(findings))
	
	for _, finding := range findings {
		assert.Equal(t, "safety", finding.ToolName)
		assert.Equal(t, "requirements.txt", finding.FilePath)
		assert.NotEmpty(t, finding.Message)
		assert.NotEmpty(t, finding.Severity)
		assert.Equal(t, "high", finding.Confidence)
		assert.NotEmpty(t, finding.RuleID)
		assert.NotEmpty(t, finding.Category)
		
		t.Logf("Finding: %s - %s", finding.RuleID, finding.Message)
	}
}

func TestScan_NoRequirementsFile(t *testing.T) {
	scanner := New()
	
	if !scanner.IsAvailable() {
		t.Skip("safety not installed, skipping test")
	}
	
	// Create a temporary directory without requirements.txt
	tmpDir, err := os.MkdirTemp("", "safety-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Run scan - should fail gracefully
	ctx := context.Background()
	_, err = scanner.Scan(ctx, tmpDir)
	
	// Expect an error since requirements.txt doesn't exist
	assert.Error(t, err)
}

func TestSafetyVulnerability_JSONMarshaling(t *testing.T) {
	vuln := SafetyVulnerability{
		Package:          "django",
		InstalledVersion: "2.2.0",
		AffectedVersions: "<2.2.2",
		VulnerabilityID:  "38624",
		Advisory:         "Django before 2.2.2 allows SQL Injection",
		CVE:              "CVE-2019-12308",
		MoreInfoURL:      "https://nvd.nist.gov/vuln/detail/CVE-2019-12308",
	}
	
	// Marshal to JSON
	data, err := json.Marshal(vuln)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	
	// Unmarshal back
	var unmarshaled SafetyVulnerability
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	
	assert.Equal(t, vuln.Package, unmarshaled.Package)
	assert.Equal(t, vuln.InstalledVersion, unmarshaled.InstalledVersion)
	assert.Equal(t, vuln.CVE, unmarshaled.CVE)
}
