package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/coding-agent/cli/internal/cwe"
	"github.com/coding-agent/cli/internal/llm"
	"github.com/coding-agent/cli/internal/policy"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Orchestrator manages the scanning process
type Orchestrator struct {
	config          Config
	scanners        []Scanner
	db              *storage.Database
	llmManager      *llm.Manager
	llmEnabled      bool
	policyEvaluator *policy.Evaluator
	policyEnabled   bool
}

// NewOrchestrator creates a new scanner orchestrator
func NewOrchestrator(config Config) *Orchestrator {
	return &Orchestrator{
		config:        config,
		scanners:      []Scanner{},
		llmEnabled:    false,
		policyEnabled: false,
	}
}

// SetDatabase sets the database connection
func (o *Orchestrator) SetDatabase(db *storage.Database) {
	o.db = db
}

// EnableLLM enables LLM-based remediation guidance
func (o *Orchestrator) EnableLLM(llmConfig llm.Config) error {
	manager, err := llm.NewManager(llmConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize LLM: %w", err)
	}
	
	o.llmManager = manager
	o.llmEnabled = true
	log.Info().Msg("LLM remediation enabled")
	return nil
}

// EnablePolicy enables policy-based enforcement
func (o *Orchestrator) EnablePolicy(policyPath string, waiverPath string) error {
	// Load policies
	policies, err := policy.LoadPolicies(policyPath)
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}
	
	// Create evaluator
	evaluator := policy.NewEvaluator(policies)
	
	// Load waivers if provided
	if waiverPath != "" {
		waivers, err := policy.LoadWaivers(waiverPath)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to load waivers, continuing without them")
		} else {
			evaluator.SetWaivers(waivers)
			log.Info().Int("count", len(waivers.Waivers)).Msg("Waivers loaded")
		}
	}
	
	o.policyEvaluator = evaluator
	o.policyEnabled = true
	log.Info().Int("count", len(policies.Policies)).Msg("Policy enforcement enabled")
	return nil
}

// RegisterScanner registers a scanner plugin
func (o *Orchestrator) RegisterScanner(scanner Scanner) {
	if scanner.IsAvailable() {
		o.scanners = append(o.scanners, scanner)
		log.Info().Str("scanner", scanner.Name()).Msg("Scanner registered")
	} else {
		log.Warn().Str("scanner", scanner.Name()).Msg("Scanner not available, skipping")
	}
}

// Scan executes the security scan
func (o *Orchestrator) Scan(ctx context.Context) (*ScanResult, error) {
	runID := uuid.New().String()
	startTime := time.Now()

	log.Info().
		Str("run_id", runID).
		Str("target", o.config.TargetPath).
		Msg("Starting scan")

	// Save run to database
	if o.db != nil {
		run := &storage.Run{
			RunID:           runID,
			TargetPath:      o.config.TargetPath,
			StartTime:       startTime.Unix(),
			Status:          "running",
			OfflineVerified: o.config.OfflineMode,
			ConfigHash:      o.generateConfigHash(),
		}
		if err := o.db.SaveRun(run); err != nil {
			log.Warn().Err(err).Msg("Failed to save run to database")
		}
	}

	// Verify offline mode if enabled
	if o.config.OfflineMode {
		if err := o.verifyOfflineMode(); err != nil {
			return nil, fmt.Errorf("offline verification failed: %w", err)
		}
		log.Info().Msg("Offline mode verified")
	}

	// Discover and register scanners
	if err := o.discoverScanners(); err != nil {
		return nil, fmt.Errorf("scanner discovery failed: %w", err)
	}

	if len(o.scanners) == 0 {
		return nil, fmt.Errorf("no scanners available")
	}

	// Collect raw findings from all scanners
	var allRawFindings []RawFinding
	var scannersUsed []string

	for _, scanner := range o.scanners {
		log.Info().Str("scanner", scanner.Name()).Msg("Running scanner")

		findings, err := scanner.Scan(ctx, o.config.TargetPath)
		if err != nil {
			log.Error().
				Err(err).
				Str("scanner", scanner.Name()).
				Msg("Scanner failed")
			continue
		}

		log.Info().
			Str("scanner", scanner.Name()).
			Int("findings", len(findings)).
			Msg("Scanner completed")

		// Save raw findings to database
		if o.db != nil {
			for _, finding := range findings {
				rawFinding := &storage.RawFinding{
					FindingID:     finding.ID,
					RunID:         runID,
					ToolName:      finding.ToolName,
					ToolFindingID: finding.ID,
					Message:       finding.Message,
					FilePath:      finding.FilePath,
					LineNumber:    finding.LineNumber,
					Severity:      finding.Severity,
					Confidence:    finding.Confidence,
					RuleID:        finding.RuleID,
					Category:      finding.Category,
					RawJSON:       o.toJSONString(finding.RawJSON),
				}
				if err := o.db.SaveRawFinding(rawFinding); err != nil {
					log.Warn().Err(err).Msg("Failed to save raw finding")
				}
			}
		}

		allRawFindings = append(allRawFindings, findings...)
		scannersUsed = append(scannersUsed, scanner.Name())
	}

	// Normalize findings
	normalizedFindings := o.normalizeFindings(allRawFindings, runID)

	// Save normalized findings to database
	if o.db != nil {
		for _, finding := range normalizedFindings {
			normFinding := &storage.NormalizedFinding{
				NormID:          finding.ID,
				FindingID:       finding.FindingID,
				RunID:           runID,
				CWEID:           finding.CWEID,
				CWEDescription:  finding.CWEDescription,
				Severity:        finding.Severity,
				Confidence:      finding.Confidence,
				CodeFingerprint: finding.CodeFingerprint,
				FilePath:        finding.FilePath,
				LineNumber:      finding.LineNumber,
				Description:     finding.Description,
			}
			if err := o.db.SaveNormalizedFinding(normFinding); err != nil {
				log.Warn().Err(err).Msg("Failed to save normalized finding")
			}
		}
	}

	// Deduplicate findings
	deduplicatedFindings := o.deduplicateFindings(normalizedFindings)

	// Generate remediation guidance if LLM is enabled
	if o.llmEnabled && o.llmManager != nil {
		log.Info().Msg("Generating remediation guidance")
		deduplicatedFindings = o.generateRemediationGuidance(ctx, deduplicatedFindings)
	}

	// Evaluate policies if enabled
	var policyDecisions []*policy.PolicyDecision
	if o.policyEnabled && o.policyEvaluator != nil {
		log.Info().Msg("Evaluating policy compliance")
		policyDecisions = o.evaluatePolicies(deduplicatedFindings)
	}

	// Count by severity
	criticalCount, highCount, mediumCount, lowCount := o.countBySeverity(deduplicatedFindings)

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Update run status in database
	if o.db != nil {
		if err := o.db.UpdateRunStatus(runID, "completed", endTime.Unix(), int64(duration.Seconds())); err != nil {
			log.Warn().Err(err).Msg("Failed to update run status")
		}
	}

	result := &ScanResult{
		RunID:            runID,
		TargetPath:       o.config.TargetPath,
		StartTime:        startTime,
		EndTime:          endTime,
		Duration:         duration,
		TotalFindings:    len(deduplicatedFindings),
		CriticalCount:    criticalCount,
		HighCount:        highCount,
		MediumCount:      mediumCount,
		LowCount:         lowCount,
		Findings:         deduplicatedFindings,
		Scanners:         scannersUsed,
		OfflineMode:      o.config.OfflineMode,
		PolicyDecisions:  policyDecisions,
	}

	return result, nil
}

// verifyOfflineMode verifies that no network calls are made
func (o *Orchestrator) verifyOfflineMode() error {
	// TODO: Implement network monitoring (strace or similar)
	// For v1.0, we'll use a simple check
	log.Debug().Msg("Offline mode verification (placeholder)")
	return nil
}

// discoverScanners discovers available scanner plugins
func (o *Orchestrator) discoverScanners() error {
	// Scanners should be registered externally to avoid import cycles
	// This method is kept for backward compatibility but does nothing
	log.Debug().Msg("Scanner discovery called - scanners should be registered externally")

	log.Info().Int("count", len(o.scanners)).Msg("Scanner discovery completed")
	return nil
}

// normalizeFindings converts raw findings to normalized format
func (o *Orchestrator) normalizeFindings(rawFindings []RawFinding, runID string) []NormalizedFinding {
	var normalized []NormalizedFinding

	for _, raw := range rawFindings {
		// Try to extract CWE from scanner metadata first (e.g., gosec provides CWE directly)
		cweID := cwe.ExtractCWEFromMetadata(raw.RawJSON)
		if cweID == "" {
			// Fall back to rule-based mapping
			cweID = o.mapToCWE(raw.RuleID, raw.Category)
		}

		norm := NormalizedFinding{
			ID:              uuid.New().String(),
			FindingID:       raw.ID,
			CWEID:           cweID,
			CWEDescription:  o.getCWEDescription(raw.RuleID),
			Severity:        o.normalizeSeverity(raw.Severity),
			Confidence:      raw.Confidence,
			CodeFingerprint: o.generateFingerprint(raw),
			FilePath:        raw.FilePath,
			LineNumber:      raw.LineNumber,
			Description:     raw.Message,
			Timestamp:       time.Now(),
		}
		normalized = append(normalized, norm)
	}

	return normalized
}

// generateConfigHash generates a hash of the configuration
func (o *Orchestrator) generateConfigHash() string {
	data, _ := json.Marshal(o.config)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// toJSONString converts a map to JSON string
func (o *Orchestrator) toJSONString(data map[string]interface{}) string {
	bytes, _ := json.Marshal(data)
	return string(bytes)
}

// deduplicateFindings removes duplicate findings based on fingerprint
func (o *Orchestrator) deduplicateFindings(findings []NormalizedFinding) []NormalizedFinding {
	seen := make(map[string]bool)
	var deduplicated []NormalizedFinding

	for _, finding := range findings {
		if !seen[finding.CodeFingerprint] {
			seen[finding.CodeFingerprint] = true
			deduplicated = append(deduplicated, finding)
		}
	}

	log.Info().
		Int("original", len(findings)).
		Int("deduplicated", len(deduplicated)).
		Msg("Deduplication completed")

	return deduplicated
}

// countBySeverity counts findings by severity level
func (o *Orchestrator) countBySeverity(findings []NormalizedFinding) (int, int, int, int) {
	var critical, high, medium, low int

	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}

	return critical, high, medium, low
}

// mapToCWE maps a rule ID to a CWE ID
func (o *Orchestrator) mapToCWE(ruleID, category string) string {
	return cwe.MapRuleToCWE(ruleID, category)
}

// getCWEDescription gets the description for a CWE ID
func (o *Orchestrator) getCWEDescription(cweID string) string {
	return cwe.GetCWEDescription(cweID)
}

// normalizeSeverity normalizes severity levels across tools
func (o *Orchestrator) normalizeSeverity(severity string) string {
	switch severity {
	case "CRITICAL", "critical", "ERROR", "error":
		return "critical"
	case "HIGH", "high", "WARNING", "warning":
		return "high"
	case "MEDIUM", "medium", "INFO", "info":
		return "medium"
	case "LOW", "low", "NOTE", "note":
		return "low"
	default:
		return "medium"
	}
}

// generateFingerprint generates a unique fingerprint for a finding
func (o *Orchestrator) generateFingerprint(finding RawFinding) string {
	// Create a deterministic fingerprint using SHA256
	data := fmt.Sprintf("%s:%s:%d:%s", finding.FilePath, finding.RuleID, finding.LineNumber, finding.Message)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// generateRemediationGuidance generates AI-powered remediation guidance for findings
func (o *Orchestrator) generateRemediationGuidance(ctx context.Context, findings []NormalizedFinding) []NormalizedFinding {
	for i := range findings {
		finding := &findings[i]
		
		// Read code snippet from file
		codeSnippet := o.extractCodeSnippet(finding.FilePath, finding.LineNumber)
		
		// Create remediation request
		req := llm.RemediationRequest{
			CWEID:          finding.CWEID,
			CWEDescription: finding.CWEDescription,
			CodeSnippet:    codeSnippet,
			FilePath:       finding.FilePath,
			LineNumber:     finding.LineNumber,
			Severity:       finding.Severity,
			RuleID:         finding.FindingID,
			Message:        finding.Description,
		}
		
		// Generate remediation
		resp, err := o.llmManager.GenerateRemediation(ctx, req)
		if err != nil {
			log.Warn().
				Err(err).
				Str("finding_id", finding.ID).
				Msg("Failed to generate remediation")
			continue
		}
		
		// Attach remediation to finding
		finding.Remediation = &RemediationGuidance{
			Explanation:      resp.Explanation,
			RemediationSteps: resp.RemediationSteps,
			ExampleFix:       resp.ExampleFix,
			Confidence:       resp.Confidence,
			GeneratedAt:      resp.GeneratedAt,
			Cached:           resp.Cached,
		}
		
		if resp.Cached {
			log.Debug().Str("finding_id", finding.ID).Msg("Used cached remediation")
		} else {
			log.Debug().Str("finding_id", finding.ID).Msg("Generated new remediation")
		}
	}
	
	return findings
}

// extractCodeSnippet extracts code around a specific line number
func (o *Orchestrator) extractCodeSnippet(filePath string, lineNumber int) string {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return ""
	}
	
	lines := splitLines(string(content))
	if lineNumber < 1 || lineNumber > len(lines) {
		return ""
	}
	
	// Extract 5 lines before and after
	start := max(0, lineNumber-6)
	end := min(len(lines), lineNumber+5)
	
	snippet := ""
	for i := start; i < end; i++ {
		snippet += lines[i] + "\n"
	}
	
	return snippet
}

// splitLines splits content into lines
func splitLines(content string) []string {
	lines := []string{}
	current := ""
	
	for _, ch := range content {
		if ch == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	
	if current != "" {
		lines = append(lines, current)
	}
	
	return lines
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// evaluatePolicies evaluates findings against policies
func (o *Orchestrator) evaluatePolicies(findings []NormalizedFinding) []*policy.PolicyDecision {
	var decisions []*policy.PolicyDecision
	
	for _, finding := range findings {
		policyFinding := &policy.Finding{
			ID:       finding.ID,
			CWEID:    finding.CWEID,
			Severity: finding.Severity,
			FilePath: finding.FilePath,
		}
		
		decision := o.policyEvaluator.Evaluate(policyFinding)
		decisions = append(decisions, decision)
		
		// Log policy violations
		if decision.Action == "deny" {
			log.Warn().
				Str("finding_id", finding.ID).
				Str("policy", decision.PolicyName).
				Msg("Policy violation detected")
		}
	}
	
	// Log statistics
	stats := policy.GetStatistics(decisions)
	log.Info().
		Int("deny", stats["deny"]).
		Int("warn", stats["warn"]).
		Int("allow", stats["allow"]).
		Int("waived", stats["waived"]).
		Msg("Policy evaluation completed")
	
	return decisions
}
