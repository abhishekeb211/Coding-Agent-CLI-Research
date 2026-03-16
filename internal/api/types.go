package api

import (
	"encoding/json"
	"net/http"

	"github.com/coding-agent/cli/internal/scanner"
	"github.com/rs/zerolog/log"
)

// Standard error codes
const (
	ErrCodeInvalidRequest = "INVALID_REQUEST"
	ErrCodeNotFound       = "NOT_FOUND"
	ErrCodeUnauthorized   = "UNAUTHORIZED"
	ErrCodeInternalError  = "INTERNAL_ERROR"
	ErrCodeScannerFailed  = "SCANNER_FAILED"
	ErrCodeLLMFailed      = "LLM_FAILED"
)

// APIError represents a standard API error response
type APIError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ScanRequest represents a request to create a new scan
type ScanRequest struct {
	Path     string   `json:"path"`
	Scanners []string `json:"scanners,omitempty"`
	Policies []string `json:"policies,omitempty"`
}

// ScanResponse represents the response from creating a scan
type ScanResponse struct {
	ScanID  string `json:"scan_id"`
	Status  string `json:"status"`
	Started string `json:"started"`
}

// ScanListResponse represents a list of scans with pagination
type ScanListResponse struct {
	Scans    []ScanSummary `json:"scans"`
	Total    int           `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

// ScanSummary represents a summary of a scan
type ScanSummary struct {
	ScanID       string `json:"scan_id"`
	TargetPath   string `json:"target_path"`
	Status       string `json:"status"`
	StartTime    string `json:"start_time"`
	EndTime      string `json:"end_time,omitempty"`
	Duration     int64  `json:"duration"`
	TotalFindings int   `json:"total_findings"`
}

// ScanDetail represents detailed information about a scan
type ScanDetail struct {
	ScanID          string                      `json:"scan_id"`
	TargetPath      string                      `json:"target_path"`
	Status          string                      `json:"status"`
	StartTime       string                      `json:"start_time"`
	EndTime         string                      `json:"end_time,omitempty"`
	Duration        int64                       `json:"duration"`
	OfflineVerified bool                        `json:"offline_verified"`
	ConfigHash      string                      `json:"config_hash"`
	TotalFindings   int                         `json:"total_findings"`
	CriticalCount   int                         `json:"critical_count"`
	HighCount       int                         `json:"high_count"`
	MediumCount     int                         `json:"medium_count"`
	LowCount        int                         `json:"low_count"`
	Findings        []scanner.NormalizedFinding `json:"findings"`
}

// FindingsResponse represents a list of findings with pagination
type FindingsResponse struct {
	Findings []scanner.NormalizedFinding `json:"findings"`
	Total    int                         `json:"total"`
	Page     int                         `json:"page"`
	PageSize int                         `json:"page_size"`
}

// TrendsResponse represents analytics trend data
type TrendsResponse struct {
	Dates            []string `json:"dates"`
	Critical         []int    `json:"critical"`
	High             []int    `json:"high"`
	Medium           []int    `json:"medium"`
	Low              []int    `json:"low"`
	Total            []int    `json:"total"`
	NewFindings      []int    `json:"new_findings"`
	ResolvedFindings []int    `json:"resolved_findings"`
}

// MTTRResponse represents Mean Time To Remediation metrics
type MTTRResponse struct {
	MeanTTR       string                      `json:"mean_ttr"`        // Duration as string (e.g., "2h30m")
	MedianTTR     string                      `json:"median_ttr"`
	P75TTR        string                      `json:"p75_ttr"`
	P90TTR        string                      `json:"p90_ttr"`
	P95TTR        string                      `json:"p95_ttr"`
	MinTTR        string                      `json:"min_ttr"`
	MaxTTR        string                      `json:"max_ttr"`
	TotalResolved int                         `json:"total_resolved"`
	BySeverity    map[string]*MTTRResponse    `json:"by_severity,omitempty"`
}

// SecurityScoreResponse represents the security score
type SecurityScoreResponse struct {
	Score           float64 `json:"score"`
	Grade           string  `json:"grade"`
	Timestamp       string  `json:"timestamp"`
	TotalFindings   int     `json:"total_findings"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
	TrendDirection  string  `json:"trend_direction"`
	ChangeFromPrev  float64 `json:"change_from_prev"`
}

// HotspotsResponse represents file hotspot analysis
type HotspotsResponse struct {
	Hotspots      []FileHotspotResponse `json:"hotspots"`
	TotalFiles    int                   `json:"total_files"`
	TotalFindings int                   `json:"total_findings"`
	AnalyzedAt    string                `json:"analyzed_at"`
}

// FileHotspotResponse represents a single file hotspot
type FileHotspotResponse struct {
	FilePath       string  `json:"file_path"`
	TotalFindings  int     `json:"total_findings"`
	CriticalCount  int     `json:"critical_count"`
	HighCount      int     `json:"high_count"`
	MediumCount    int     `json:"medium_count"`
	LowCount       int     `json:"low_count"`
	FindingDensity float64 `json:"finding_density"`
	SeverityScore  float64 `json:"severity_score"`
	UniqueFindings int     `json:"unique_findings"`
}

// PolicyValidateRequest represents a policy validation request
type PolicyValidateRequest struct {
	PolicyYAML string `json:"policy_yaml"`
}

// PolicyValidateResponse represents a policy validation response
type PolicyValidateResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ImportRequest represents a request to import findings
type ImportRequest struct {
	Format     string `json:"format"`      // sarif or json
	Mode       string `json:"mode"`        // replace, merge, or skip
	RunID      string `json:"run_id"`      // optional
	TargetPath string `json:"target_path"` // optional
	ToolName   string `json:"tool_name"`   // optional
	Data       string `json:"data"`        // base64 encoded file content or raw JSON
}

// ImportResponse represents the response from importing findings
type ImportResponse struct {
	RunID            string   `json:"run_id"`
	TotalFindings    int      `json:"total_findings"`
	ImportedFindings int      `json:"imported_findings"`
	SkippedFindings  int      `json:"skipped_findings"`
	FailedFindings   int      `json:"failed_findings"`
	Errors           []string `json:"errors,omitempty"`
}

// respondJSON sends a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

// respondError sends an error response
func respondError(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
	respondJSON(w, status, APIError{
		Code:    code,
		Message: message,
		Details: details,
	})
}

// parseJSON parses JSON request body
func parseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}
