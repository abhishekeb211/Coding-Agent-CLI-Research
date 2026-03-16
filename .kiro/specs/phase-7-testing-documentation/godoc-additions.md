# Godoc Comments - Implementation Guide

This document outlines the godoc comments that should be added to all packages in the Coding Agent CLI project.

## Package-Level Documentation

### internal/scanner
```go
// Package scanner provides the core scanning orchestration functionality for the Coding Agent CLI.
// It coordinates multiple security scanner plugins, normalizes their findings, and manages
// the complete scan lifecycle including CWE mapping, deduplication, and policy evaluation.
//
// The scanner package supports:
//   - Multiple scanner plugins (Bandit, Semgrep, etc.)
//   - Offline-first operation with network verification
//   - Finding normalization and CWE mapping
//   - LLM-powered remediation guidance
//   - Policy-based enforcement and waivers
//
// Example usage:
//
//	config := scanner.Config{
//	    TargetPath: "/path/to/code",
//	    OfflineMode: true,
//	}
//	orch := scanner.NewOrchestrator(config)
//	orch.SetDatabase(db)
//	result, err := orch.Scan(context.Background())
package scanner
```

### internal/storage
```go
// Package storage provides persistent storage for security scan findings and metadata.
// It uses SQLite for local, offline-first data storage with support for:
//   - Raw scanner findings
//   - Normalized findings with CWE mappings
//   - Scan run metadata and history
//   - Policy decisions and waivers
//
// The storage layer is designed for:
//   - Fast local queries
//   - Concurrent read/write access
//   - Efficient finding deduplication
//   - Historical scan comparison
//
// Example usage:
//
//	db, err := storage.NewDatabase("findings.db")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer db.Close()
//	
//	finding := &storage.NormalizedFinding{
//	    CWEID: "CWE-89",
//	    Severity: "high",
//	}
//	err = db.SaveNormalizedFinding(finding)
package storage
```

### internal/cwe
```go
// Package cwe provides CWE (Common Weakness Enumeration) mapping and lookup functionality.
// It maps scanner-specific rule IDs to standardized CWE identifiers and provides
// descriptions for security weaknesses.
//
// The package includes:
//   - Comprehensive CWE database
//   - Rule ID to CWE mapping
//   - CWE descriptions and categories
//   - Support for multiple scanner formats
//
// Example usage:
//
//	cweID := cwe.MapRuleToCWE("B608", "bandit")
//	description := cwe.GetCWEDescription(cweID)
package cwe
```

### internal/sarif
```go
// Package sarif provides SARIF (Static Analysis Results Interchange Format) 2.1.0
// report generation. It converts normalized findings into the industry-standard
// SARIF format for integration with CI/CD pipelines and security dashboards.
//
// Features:
//   - SARIF 2.1.0 compliant output
//   - Multiple run support
//   - Rich location and context information
//   - Tool metadata and versioning
//
// Example usage:
//
//	report := sarif.NewReport()
//	report.AddFindings(findings)
//	err := report.WriteToFile("results.sarif")
package sarif
```

### internal/llm
```go
// Package llm provides LLM-powered remediation guidance for security findings.
// It supports multiple LLM providers (OpenAI, Anthropic, local models) with
// intelligent caching and PII redaction.
//
// Features:
//   - Multi-provider support (OpenAI, Anthropic, local)
//   - Intelligent caching for repeated findings
//   - PII redaction in code snippets
//   - Context-aware remediation suggestions
//   - Offline mode support
//
// Example usage:
//
//	config := llm.Config{
//	    Provider: "openai",
//	    APIKey: "sk-...",
//	    CacheEnabled: true,
//	}
//	manager, err := llm.NewManager(config)
//	resp, err := manager.GenerateRemediation(ctx, request)
package llm
```

### internal/policy
```go
// Package policy provides policy-based security enforcement and compliance checking.
// It evaluates findings against customizable security policies with support for
// waivers, compliance frameworks, and flexible rule matching.
//
// Features:
//   - YAML-based policy definitions
//   - CWE, severity, and file pattern matching
//   - Waiver management with approvals
//   - Compliance framework support (OWASP, CWE Top 25, PCI-DSS)
//   - Policy actions: deny, warn, allow
//
// Example usage:
//
//	policies, err := policy.LoadPolicies("security-policy.yaml")
//	evaluator := policy.NewEvaluator(policies)
//	decision := evaluator.Evaluate(finding)
package policy
```

### plugins/bandit
```go
// Package bandit provides integration with the Bandit Python security scanner.
// Bandit is a tool designed to find common security issues in Python code.
//
// The plugin:
//   - Executes Bandit scanner
//   - Parses JSON output
//   - Converts to normalized findings
//   - Handles scanner errors gracefully
//
// Example usage:
//
//	scanner := bandit.New()
//	if scanner.IsAvailable() {
//	    findings, err := scanner.Scan(ctx, "/path/to/python/code")
//	}
package bandit
```

### plugins/semgrep
```go
// Package semgrep provides integration with the Semgrep multi-language security scanner.
// Semgrep supports Python, JavaScript, Go, Java, and many other languages.
//
// The plugin:
//   - Executes Semgrep scanner
//   - Parses JSON output
//   - Converts to normalized findings
//   - Supports custom rulesets
//
// Example usage:
//
//	scanner := semgrep.New()
//	if scanner.IsAvailable() {
//	    findings, err := scanner.Scan(ctx, "/path/to/code")
//	}
package semgrep
```

## Function-Level Documentation Examples

### Orchestrator Functions

```go
// NewOrchestrator creates a new scanner orchestrator with the provided configuration.
// The orchestrator manages the complete scan lifecycle including scanner execution,
// finding normalization, policy evaluation, and remediation generation.
//
// Parameters:
//   - config: Configuration for the scan including target path and options
//
// Returns:
//   - *Orchestrator: A new orchestrator instance ready for scanning
//
// Example:
//
//	config := Config{TargetPath: "/code", OfflineMode: true}
//	orch := NewOrchestrator(config)
func NewOrchestrator(config Config) *Orchestrator

// Scan executes a complete security scan of the target codebase.
// It coordinates multiple scanners, normalizes findings, applies policies,
// and optionally generates LLM-powered remediation guidance.
//
// The scan process:
//   1. Discovers and registers available scanners
//   2. Executes each scanner in parallel
//   3. Normalizes findings with CWE mapping
//   4. Deduplicates findings by fingerprint
//   5. Generates remediation guidance (if LLM enabled)
//   6. Evaluates policy compliance (if policies enabled)
//   7. Stores results in database
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - *ScanResult: Complete scan results with findings and metadata
//   - error: Any error encountered during scanning
//
// Example:
//
//	ctx := context.WithTimeout(context.Background(), 10*time.Minute)
//	result, err := orch.Scan(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d issues\n", result.TotalFindings)
func (o *Orchestrator) Scan(ctx context.Context) (*ScanResult, error)

// EnableLLM enables LLM-powered remediation guidance for findings.
// When enabled, the orchestrator will generate AI-powered fix suggestions
// for each security finding using the configured LLM provider.
//
// Parameters:
//   - llmConfig: Configuration for the LLM provider (API keys, model, etc.)
//
// Returns:
//   - error: Any error encountered during LLM initialization
//
// Example:
//
//	llmConfig := llm.Config{
//	    Provider: "openai",
//	    APIKey: os.Getenv("OPENAI_API_KEY"),
//	    CacheEnabled: true,
//	}
//	err := orch.EnableLLM(llmConfig)
func (o *Orchestrator) EnableLLM(llmConfig llm.Config) error

// EnablePolicy enables policy-based enforcement for scan findings.
// Policies define rules for which findings should be denied, warned, or allowed
// based on CWE, severity, file patterns, and other criteria.
//
// Parameters:
//   - policyPath: Path to the policy YAML file
//   - waiverPath: Path to the waiver YAML file (optional, can be empty)
//
// Returns:
//   - error: Any error encountered during policy loading
//
// Example:
//
//	err := orch.EnablePolicy("security-policy.yaml", "waivers.yaml")
func (o *Orchestrator) EnablePolicy(policyPath string, waiverPath string) error
```

### Storage Functions

```go
// NewDatabase creates a new database connection to the specified SQLite file.
// If the database doesn't exist, it will be created with the required schema.
//
// Parameters:
//   - dbPath: Path to the SQLite database file
//
// Returns:
//   - *Database: Database connection ready for use
//   - error: Any error encountered during initialization
//
// Example:
//
//	db, err := NewDatabase("./findings.db")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer db.Close()
func NewDatabase(dbPath string) (*Database, error)

// SaveNormalizedFinding saves a normalized finding to the database.
// Normalized findings include CWE mappings, standardized severity levels,
// and unique fingerprints for deduplication.
//
// Parameters:
//   - finding: The normalized finding to save
//
// Returns:
//   - error: Any error encountered during save operation
//
// Example:
//
//	finding := &NormalizedFinding{
//	    CWEID: "CWE-89",
//	    Severity: "high",
//	    FilePath: "app.py",
//	}
//	err := db.SaveNormalizedFinding(finding)
func (db *Database) SaveNormalizedFinding(finding *NormalizedFinding) error
```

### LLM Functions

```go
// NewManager creates a new LLM manager with the specified configuration.
// The manager handles provider initialization, caching, and request routing.
//
// Parameters:
//   - config: LLM configuration including provider, API keys, and options
//
// Returns:
//   - *Manager: LLM manager ready to generate remediations
//   - error: Any error encountered during initialization
//
// Example:
//
//	config := Config{
//	    Provider: "openai",
//	    APIKey: "sk-...",
//	    Model: "gpt-4",
//	}
//	manager, err := NewManager(config)
func NewManager(config Config) (*Manager, error)

// GenerateRemediation generates AI-powered remediation guidance for a finding.
// It uses the configured LLM provider to analyze the vulnerability and suggest
// specific fix steps with code examples.
//
// The function automatically:
//   - Checks cache for previous remediations
//   - Redacts PII from code snippets
//   - Formats prompts for optimal results
//   - Caches responses for future use
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - request: Remediation request with finding details
//
// Returns:
//   - *RemediationResponse: Generated remediation with explanation and fix
//   - error: Any error encountered during generation
//
// Example:
//
//	req := RemediationRequest{
//	    CWEID: "CWE-89",
//	    CodeSnippet: "query = 'SELECT * FROM users WHERE id = ' + user_id",
//	}
//	resp, err := manager.GenerateRemediation(ctx, req)
func (m *Manager) GenerateRemediation(ctx context.Context, request RemediationRequest) (*RemediationResponse, error)
```

### Policy Functions

```go
// LoadPolicies loads security policies from a YAML file.
// Policies define rules for evaluating findings and determining actions.
//
// Parameters:
//   - policyPath: Path to the policy YAML file
//
// Returns:
//   - *Policies: Loaded policies ready for evaluation
//   - error: Any error encountered during loading or parsing
//
// Example:
//
//	policies, err := LoadPolicies("security-policy.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadPolicies(policyPath string) (*Policies, error)

// NewEvaluator creates a new policy evaluator with the provided policies.
// The evaluator matches findings against policy rules and determines actions.
//
// Parameters:
//   - policies: Policies to use for evaluation
//
// Returns:
//   - *Evaluator: Policy evaluator ready to evaluate findings
//
// Example:
//
//	evaluator := NewEvaluator(policies)
//	decision := evaluator.Evaluate(finding)
func NewEvaluator(policies *Policies) *Evaluator

// Evaluate evaluates a finding against all loaded policies.
// It returns a decision indicating whether the finding should be denied,
// warned, allowed, or waived based on matching rules.
//
// Parameters:
//   - finding: The finding to evaluate
//
// Returns:
//   - *PolicyDecision: Decision with action, matched policy, and reason
//
// Example:
//
//	decision := evaluator.Evaluate(finding)
//	if decision.Action == "deny" {
//	    fmt.Printf("Policy violation: %s\n", decision.Reason)
//	}
func (e *Evaluator) Evaluate(finding *Finding) *PolicyDecision
```

## Type Documentation Examples

```go
// Config holds the configuration for a security scan.
// It specifies the target path, scanner options, and operational modes.
type Config struct {
	// TargetPath is the path to the codebase to scan
	TargetPath string
	
	// OfflineMode enables offline-first operation with network verification
	OfflineMode bool
	
	// Scanners is a list of scanner names to use (empty = auto-discover)
	Scanners []string
	
	// OutputFormat specifies the output format (json, sarif, markdown, html, csv)
	OutputFormat string
}

// ScanResult contains the complete results of a security scan.
// It includes all findings, metadata, and policy decisions.
type ScanResult struct {
	// RunID is the unique identifier for this scan run
	RunID string
	
	// TargetPath is the path that was scanned
	TargetPath string
	
	// StartTime is when the scan started
	StartTime time.Time
	
	// EndTime is when the scan completed
	EndTime time.Time
	
	// Duration is the total scan time
	Duration time.Duration
	
	// TotalFindings is the total number of findings
	TotalFindings int
	
	// CriticalCount is the number of critical severity findings
	CriticalCount int
	
	// HighCount is the number of high severity findings
	HighCount int
	
	// MediumCount is the number of medium severity findings
	MediumCount int
	
	// LowCount is the number of low severity findings
	LowCount int
	
	// Findings is the list of all findings
	Findings []NormalizedFinding
	
	// Scanners is the list of scanners that were used
	Scanners []string
	
	// OfflineMode indicates if the scan was run in offline mode
	OfflineMode bool
	
	// PolicyDecisions contains policy evaluation results
	PolicyDecisions []*policy.PolicyDecision
}

// NormalizedFinding represents a security finding in normalized format.
// All findings from different scanners are converted to this common format.
type NormalizedFinding struct {
	// ID is the unique identifier for this finding
	ID string
	
	// FindingID is the original scanner finding ID
	FindingID string
	
	// CWEID is the CWE identifier (e.g., "CWE-89")
	CWEID string
	
	// CWEDescription is the human-readable CWE description
	CWEDescription string
	
	// Severity is the normalized severity (critical, high, medium, low)
	Severity string
	
	// Confidence is the scanner's confidence level
	Confidence string
	
	// CodeFingerprint is a unique hash for deduplication
	CodeFingerprint string
	
	// FilePath is the path to the file containing the finding
	FilePath string
	
	// LineNumber is the line number where the finding was detected
	LineNumber int
	
	// Description is a human-readable description of the finding
	Description string
	
	// Timestamp is when the finding was detected
	Timestamp time.Time
	
	// Remediation contains AI-generated fix guidance (if LLM enabled)
	Remediation *RemediationGuidance
}
```

## Implementation Status

- [ ] Add package-level godoc to internal/scanner
- [ ] Add package-level godoc to internal/storage
- [ ] Add package-level godoc to internal/cwe
- [ ] Add package-level godoc to internal/sarif
- [ ] Add package-level godoc to internal/llm
- [ ] Add package-level godoc to internal/policy
- [ ] Add package-level godoc to plugins/bandit
- [ ] Add package-level godoc to plugins/semgrep
- [ ] Add function-level godoc to all exported functions
- [ ] Add type-level godoc to all exported types
- [ ] Add field-level godoc to all exported struct fields
- [ ] Validate godoc completeness with `go vet`
- [ ] Generate and review godoc HTML

## Notes

- All exported identifiers (functions, types, constants, variables) must have godoc comments
- Comments should start with the name of the identifier
- Use complete sentences with proper punctuation
- Include examples for complex functions
- Document parameters and return values
- Explain error conditions
- Link to related functions and types using standard godoc syntax
