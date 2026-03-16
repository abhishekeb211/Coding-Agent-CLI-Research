package analytics

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Engine provides analytics and trend analysis for security findings
type Engine struct {
	db    *sql.DB
	cache *Cache
}

// NewEngine creates a new analytics engine
func NewEngine(db *sql.DB) *Engine {
	return &Engine{
		db:    db,
		cache: NewCache(5 * time.Minute), // 5 minute cache TTL
	}
}

// TrendData represents time-series data for findings
type TrendData struct {
	Dates            []string `json:"dates"`
	Critical         []int    `json:"critical"`
	High             []int    `json:"high"`
	Medium           []int    `json:"medium"`
	Low              []int    `json:"low"`
	Total            []int    `json:"total"`
	NewFindings      []int    `json:"new_findings"`
	ResolvedFindings []int    `json:"resolved_findings"`
}

// SeverityMetrics represents aggregate metrics by severity
type SeverityMetrics struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// CWEStat represents statistics for a CWE category
type CWEStat struct {
	CWEID       string `json:"cwe_id"`
	Description string `json:"description"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
}

// ScanComparison represents comparison between two scans
type ScanComparison struct {
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
	UnchangedCount   int `json:"unchanged_count"`
}

// TrendSummary represents aggregate statistics for a trend period
type TrendSummary struct {
	TotalNew        int `json:"total_new"`
	TotalResolved   int `json:"total_resolved"`
	NetChange       int `json:"net_change"`
	AverageTotal    int `json:"average_total"`
	MaxTotal        int `json:"max_total"`
	MinTotal        int `json:"min_total"`
	AverageCritical int `json:"average_critical"`
	AverageHigh     int `json:"average_high"`
	AverageMedium   int `json:"average_medium"`
	AverageLow      int `json:"average_low"`
}

// GetTrends retrieves finding trends over a date range with enhanced analytics
func (e *Engine) GetTrends(start, end time.Time) (*TrendData, error) {
	cacheKey := fmt.Sprintf("trends:%s:%s", start.Format("2006-01-02"), end.Format("2006-01-02"))
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if trends, ok := cached.(*TrendData); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for trends")
			return trends, nil
		}
	}

	query := `
		SELECT date, critical, high, medium, low, total, new_findings, resolved_findings
		FROM finding_trends
		WHERE date >= ? AND date <= ?
		ORDER BY date ASC
	`

	rows, err := e.db.Query(query, start.Format("2006-01-02"), end.Format("2006-01-02"))
	if err != nil {
		return nil, fmt.Errorf("failed to query trends: %w", err)
	}
	defer rows.Close()

	trends := &TrendData{
		Dates:            make([]string, 0),
		Critical:         make([]int, 0),
		High:             make([]int, 0),
		Medium:           make([]int, 0),
		Low:              make([]int, 0),
		Total:            make([]int, 0),
		NewFindings:      make([]int, 0),
		ResolvedFindings: make([]int, 0),
	}

	for rows.Next() {
		var date string
		var critical, high, medium, low, total, newFindings, resolvedFindings int
		if err := rows.Scan(&date, &critical, &high, &medium, &low, &total, &newFindings, &resolvedFindings); err != nil {
			return nil, fmt.Errorf("failed to scan trend row: %w", err)
		}
		trends.Dates = append(trends.Dates, date)
		trends.Critical = append(trends.Critical, critical)
		trends.High = append(trends.High, high)
		trends.Medium = append(trends.Medium, medium)
		trends.Low = append(trends.Low, low)
		trends.Total = append(trends.Total, total)
		trends.NewFindings = append(trends.NewFindings, newFindings)
		trends.ResolvedFindings = append(trends.ResolvedFindings, resolvedFindings)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating trend rows: %w", err)
	}

	// If no data found, return empty trends with a message
	if len(trends.Dates) == 0 {
		log.Debug().Msg("No trend data found for date range")
	}

	// Cache the result
	e.cache.Set(cacheKey, trends)
	log.Debug().Str("key", cacheKey).Int("data_points", len(trends.Dates)).Msg("Cached trends data")

	return trends, nil
}

// GetCurrentMetrics retrieves current severity metrics across all findings
func (e *Engine) GetCurrentMetrics() (*SeverityMetrics, error) {
	cacheKey := "metrics:current"
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if metrics, ok := cached.(*SeverityMetrics); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for current metrics")
			return metrics, nil
		}
	}

	query := `
		SELECT 
			LOWER(severity) as severity,
			COUNT(*) as count
		FROM findings_normalized
		GROUP BY LOWER(severity)
	`

	rows, err := e.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query metrics: %w", err)
	}
	defer rows.Close()

	metrics := &SeverityMetrics{}
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("failed to scan metric row: %w", err)
		}

		switch severity {
		case "critical":
			metrics.Critical = count
		case "high":
			metrics.High = count
		case "medium":
			metrics.Medium = count
		case "low":
			metrics.Low = count
		}
		metrics.Total += count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating metric rows: %w", err)
	}

	// Cache the result
	e.cache.Set(cacheKey, metrics)
	log.Debug().Str("key", cacheKey).Msg("Cached current metrics")

	return metrics, nil
}

// GetScanMetrics retrieves metrics for a specific scan
func (e *Engine) GetScanMetrics(scanID string) (*SeverityMetrics, error) {
	cacheKey := fmt.Sprintf("metrics:scan:%s", scanID)
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if metrics, ok := cached.(*SeverityMetrics); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for scan metrics")
			return metrics, nil
		}
	}

	// First try scan_metrics table
	query := `
		SELECT total_findings, critical, high, medium, low
		FROM scan_metrics
		WHERE scan_id = ?
	`

	var metrics SeverityMetrics
	err := e.db.QueryRow(query, scanID).Scan(
		&metrics.Total,
		&metrics.Critical,
		&metrics.High,
		&metrics.Medium,
		&metrics.Low,
	)

	if err == sql.ErrNoRows {
		// Fallback: calculate from findings_normalized
		return e.calculateScanMetricsFromFindings(scanID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query scan metrics: %w", err)
	}

	// Cache the result
	e.cache.Set(cacheKey, &metrics)
	log.Debug().Str("key", cacheKey).Msg("Cached scan metrics")

	return &metrics, nil
}

// calculateScanMetricsFromFindings calculates metrics by querying findings directly
func (e *Engine) calculateScanMetricsFromFindings(scanID string) (*SeverityMetrics, error) {
	query := `
		SELECT 
			LOWER(severity) as severity,
			COUNT(*) as count
		FROM findings_normalized
		WHERE run_id = ?
		GROUP BY LOWER(severity)
	`

	rows, err := e.db.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings for metrics: %w", err)
	}
	defer rows.Close()

	metrics := &SeverityMetrics{}
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("failed to scan finding metric row: %w", err)
		}

		switch severity {
		case "critical":
			metrics.Critical = count
		case "high":
			metrics.High = count
		case "medium":
			metrics.Medium = count
		case "low":
			metrics.Low = count
		}
		metrics.Total += count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating finding metric rows: %w", err)
	}

	return metrics, nil
}

// GetTopCWEs retrieves the most common CWE categories
func (e *Engine) GetTopCWEs(limit int) ([]CWEStat, error) {
	cacheKey := fmt.Sprintf("cwe:top:%d", limit)
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if stats, ok := cached.([]CWEStat); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for top CWEs")
			return stats, nil
		}
	}

	query := `
		SELECT 
			cwe_id,
			cwe_description,
			COUNT(*) as count,
			severity
		FROM findings_normalized
		WHERE cwe_id != '' AND cwe_id IS NOT NULL
		GROUP BY cwe_id, cwe_description, severity
		ORDER BY count DESC
		LIMIT ?
	`

	rows, err := e.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query top CWEs: %w", err)
	}
	defer rows.Close()

	stats := make([]CWEStat, 0, limit)
	for rows.Next() {
		var stat CWEStat
		if err := rows.Scan(&stat.CWEID, &stat.Description, &stat.Count, &stat.Severity); err != nil {
			return nil, fmt.Errorf("failed to scan CWE stat row: %w", err)
		}
		stats = append(stats, stat)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating CWE stat rows: %w", err)
	}

	// Cache the result
	e.cache.Set(cacheKey, stats)
	log.Debug().Str("key", cacheKey).Msg("Cached top CWEs")

	return stats, nil
}

// CompareScanFindings compares findings between two scans
func (e *Engine) CompareScanFindings(oldScanID, newScanID string) (*ScanComparison, error) {
	cacheKey := fmt.Sprintf("compare:%s:%s", oldScanID, newScanID)
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if comparison, ok := cached.(*ScanComparison); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for scan comparison")
			return comparison, nil
		}
	}

	// Get fingerprints from old scan
	oldFingerprints := make(map[string]bool)
	oldQuery := `SELECT DISTINCT code_fingerprint FROM findings_normalized WHERE run_id = ?`
	rows, err := e.db.Query(oldQuery, oldScanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query old scan fingerprints: %w", err)
	}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan old fingerprint: %w", err)
		}
		oldFingerprints[fp] = true
	}
	rows.Close()

	// Get fingerprints from new scan
	newFingerprints := make(map[string]bool)
	newQuery := `SELECT DISTINCT code_fingerprint FROM findings_normalized WHERE run_id = ?`
	rows, err = e.db.Query(newQuery, newScanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query new scan fingerprints: %w", err)
	}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan new fingerprint: %w", err)
		}
		newFingerprints[fp] = true
	}
	rows.Close()

	// Calculate differences
	comparison := &ScanComparison{}
	
	// New findings: in new but not in old
	for fp := range newFingerprints {
		if !oldFingerprints[fp] {
			comparison.NewFindings++
		}
	}

	// Resolved findings: in old but not in new
	for fp := range oldFingerprints {
		if !newFingerprints[fp] {
			comparison.ResolvedFindings++
		}
	}

	// Unchanged: in both
	for fp := range newFingerprints {
		if oldFingerprints[fp] {
			comparison.UnchangedCount++
		}
	}

	// Cache the result
	e.cache.Set(cacheKey, comparison)
	log.Debug().Str("key", cacheKey).Msg("Cached scan comparison")

	return comparison, nil
}

// RecordScanMetrics stores aggregate metrics for a scan
func (e *Engine) RecordScanMetrics(scanID string, metrics *SeverityMetrics, duration int64) error {
	query := `
		INSERT INTO scan_metrics (scan_id, total_findings, critical, high, medium, low, scan_duration, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := e.db.Exec(query,
		scanID,
		metrics.Total,
		metrics.Critical,
		metrics.High,
		metrics.Medium,
		metrics.Low,
		duration,
		time.Now().Unix(),
	)

	if err != nil {
		return fmt.Errorf("failed to record scan metrics: %w", err)
	}

	// Invalidate cache for this scan
	cacheKey := fmt.Sprintf("metrics:scan:%s", scanID)
	e.cache.Delete(cacheKey)
	e.cache.Delete("metrics:current")

	log.Debug().Str("scan_id", scanID).Msg("Recorded scan metrics")
	return nil
}

// RecordDailyTrend stores daily trend data
func (e *Engine) RecordDailyTrend(date time.Time, metrics *SeverityMetrics, newFindings, resolvedFindings int) error {
	dateStr := date.Format("2006-01-02")
	
	query := `
		INSERT OR REPLACE INTO finding_trends 
		(date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := e.db.Exec(query,
		dateStr,
		metrics.Critical,
		metrics.High,
		metrics.Medium,
		metrics.Low,
		metrics.Total,
		newFindings,
		resolvedFindings,
		time.Now().Unix(),
	)

	if err != nil {
		return fmt.Errorf("failed to record daily trend: %w", err)
	}

	// Invalidate trend cache
	e.cache.DeletePattern("trends:")

	log.Debug().Str("date", dateStr).Msg("Recorded daily trend")
	return nil
}

// ClearCache clears all cached analytics data
func (e *Engine) ClearCache() {
	e.cache.Clear()
	log.Debug().Msg("Cleared analytics cache")
}

// GetSeverityTrends retrieves trends for a specific severity level
func (e *Engine) GetSeverityTrends(severity string, start, end time.Time) ([]int, []string, error) {
	cacheKey := fmt.Sprintf("severity_trends:%s:%s:%s", severity, start.Format("2006-01-02"), end.Format("2006-01-02"))
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if data, ok := cached.(map[string]interface{}); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for severity trends")
			return data["counts"].([]int), data["dates"].([]string), nil
		}
	}

	// Validate severity
	severityColumn := strings.ToLower(severity)
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if !validSeverities[severityColumn] {
		return nil, nil, fmt.Errorf("invalid severity level: %s", severity)
	}

	query := fmt.Sprintf(`
		SELECT date, %s
		FROM finding_trends
		WHERE date >= ? AND date <= ?
		ORDER BY date ASC
	`, severityColumn)

	rows, err := e.db.Query(query, start.Format("2006-01-02"), end.Format("2006-01-02"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query severity trends: %w", err)
	}
	defer rows.Close()

	counts := make([]int, 0)
	dates := make([]string, 0)

	for rows.Next() {
		var date string
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			return nil, nil, fmt.Errorf("failed to scan severity trend row: %w", err)
		}
		dates = append(dates, date)
		counts = append(counts, count)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating severity trend rows: %w", err)
	}

	// Cache the result
	cacheData := map[string]interface{}{
		"counts": counts,
		"dates":  dates,
	}
	e.cache.Set(cacheKey, cacheData)
	log.Debug().Str("key", cacheKey).Int("data_points", len(dates)).Msg("Cached severity trends")

	return counts, dates, nil
}

// GetNewVsResolvedTrends retrieves new vs resolved findings over time
func (e *Engine) GetNewVsResolvedTrends(start, end time.Time) ([]int, []int, []string, error) {
	cacheKey := fmt.Sprintf("new_vs_resolved:%s:%s", start.Format("2006-01-02"), end.Format("2006-01-02"))
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if data, ok := cached.(map[string]interface{}); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for new vs resolved trends")
			return data["new"].([]int), data["resolved"].([]int), data["dates"].([]string), nil
		}
	}

	query := `
		SELECT date, new_findings, resolved_findings
		FROM finding_trends
		WHERE date >= ? AND date <= ?
		ORDER BY date ASC
	`

	rows, err := e.db.Query(query, start.Format("2006-01-02"), end.Format("2006-01-02"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to query new vs resolved trends: %w", err)
	}
	defer rows.Close()

	newFindings := make([]int, 0)
	resolvedFindings := make([]int, 0)
	dates := make([]string, 0)

	for rows.Next() {
		var date string
		var newCount, resolvedCount int
		if err := rows.Scan(&date, &newCount, &resolvedCount); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to scan new vs resolved row: %w", err)
		}
		dates = append(dates, date)
		newFindings = append(newFindings, newCount)
		resolvedFindings = append(resolvedFindings, resolvedCount)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("error iterating new vs resolved rows: %w", err)
	}

	// Cache the result
	cacheData := map[string]interface{}{
		"new":      newFindings,
		"resolved": resolvedFindings,
		"dates":    dates,
	}
	e.cache.Set(cacheKey, cacheData)
	log.Debug().Str("key", cacheKey).Int("data_points", len(dates)).Msg("Cached new vs resolved trends")

	return newFindings, resolvedFindings, dates, nil
}

// CalculateTrendSummary calculates summary statistics for a trend period
func (e *Engine) CalculateTrendSummary(start, end time.Time) (*TrendSummary, error) {
	cacheKey := fmt.Sprintf("trend_summary:%s:%s", start.Format("2006-01-02"), end.Format("2006-01-02"))
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if summary, ok := cached.(*TrendSummary); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for trend summary")
			return summary, nil
		}
	}

	query := `
		SELECT 
			SUM(new_findings) as total_new,
			SUM(resolved_findings) as total_resolved,
			AVG(total) as avg_total,
			MAX(total) as max_total,
			MIN(total) as min_total,
			AVG(critical) as avg_critical,
			AVG(high) as avg_high,
			AVG(medium) as avg_medium,
			AVG(low) as avg_low
		FROM finding_trends
		WHERE date >= ? AND date <= ?
	`

	summary := &TrendSummary{}
	var avgTotal, avgCritical, avgHigh, avgMedium, avgLow sql.NullFloat64
	var maxTotal, minTotal sql.NullInt64

	err := e.db.QueryRow(query, start.Format("2006-01-02"), end.Format("2006-01-02")).Scan(
		&summary.TotalNew,
		&summary.TotalResolved,
		&avgTotal,
		&maxTotal,
		&minTotal,
		&avgCritical,
		&avgHigh,
		&avgMedium,
		&avgLow,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to calculate trend summary: %w", err)
	}

	// Handle NULL values
	if avgTotal.Valid {
		summary.AverageTotal = int(avgTotal.Float64)
	}
	if maxTotal.Valid {
		summary.MaxTotal = int(maxTotal.Int64)
	}
	if minTotal.Valid {
		summary.MinTotal = int(minTotal.Int64)
	}
	if avgCritical.Valid {
		summary.AverageCritical = int(avgCritical.Float64)
	}
	if avgHigh.Valid {
		summary.AverageHigh = int(avgHigh.Float64)
	}
	if avgMedium.Valid {
		summary.AverageMedium = int(avgMedium.Float64)
	}
	if avgLow.Valid {
		summary.AverageLow = int(avgLow.Float64)
	}

	// Calculate net change
	summary.NetChange = summary.TotalNew - summary.TotalResolved

	// Cache the result
	e.cache.Set(cacheKey, summary)
	log.Debug().Str("key", cacheKey).Msg("Cached trend summary")

	return summary, nil
}

// MTTRMetrics represents Mean Time To Remediation statistics
type MTTRMetrics struct {
	MeanTTR       time.Duration            `json:"mean_ttr"`
	MedianTTR     time.Duration            `json:"median_ttr"`
	P75TTR        time.Duration            `json:"p75_ttr"`
	P90TTR        time.Duration            `json:"p90_ttr"`
	P95TTR        time.Duration            `json:"p95_ttr"`
	MinTTR        time.Duration            `json:"min_ttr"`
	MaxTTR        time.Duration            `json:"max_ttr"`
	TotalResolved int                      `json:"total_resolved"`
	BySeverity    map[string]*MTTRMetrics  `json:"by_severity,omitempty"`
}
// SecurityScore represents the overall security posture score
type SecurityScore struct {
	Score           float64           `json:"score"`            // 0-100 scale
	Grade           string            `json:"grade"`            // A, B, C, D, F
	Timestamp       time.Time         `json:"timestamp"`
	TotalFindings   int               `json:"total_findings"`
	CriticalCount   int               `json:"critical_count"`
	HighCount       int               `json:"high_count"`
	MediumCount     int               `json:"medium_count"`
	LowCount        int               `json:"low_count"`
	TrendDirection  string            `json:"trend_direction"`  // improving, declining, stable
	ChangeFromPrev  float64           `json:"change_from_prev"` // percentage change
}

// ScoreHistory represents historical security scores
type ScoreHistory struct {
	Dates  []string  `json:"dates"`
	Scores []float64 `json:"scores"`
	Grades []string  `json:"grades"`
}

// FindingLifecycle represents the lifecycle of a finding
type FindingLifecycle struct {
	CodeFingerprint string
	FirstSeen       time.Time
	LastSeen        time.Time
	Resolved        bool
	Severity        string
	CWEID           string
}

// GetMTTR calculates Mean Time To Remediation for resolved findings
func (e *Engine) GetMTTR() (*MTTRMetrics, error) {
	return e.GetMTTRWithFilter(time.Time{}, time.Time{}, "")
}

// GetMTTRWithFilter calculates MTTR with optional date range and severity filtering
func (e *Engine) GetMTTRWithFilter(start, end time.Time, severity string) (*MTTRMetrics, error) {
	cacheKey := fmt.Sprintf("mttr:%s:%s:%s", start.Format("2006-01-02"), end.Format("2006-01-02"), severity)
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if metrics, ok := cached.(*MTTRMetrics); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for MTTR")
			return metrics, nil
		}
	}

	// Get finding lifecycles
	lifecycles, err := e.getFindingLifecycles(start, end, severity)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding lifecycles: %w", err)
	}

	// Filter for resolved findings only
	resolvedLifecycles := make([]FindingLifecycle, 0)
	for _, lc := range lifecycles {
		if lc.Resolved {
			resolvedLifecycles = append(resolvedLifecycles, lc)
		}
	}

	if len(resolvedLifecycles) == 0 {
		log.Debug().Msg("No resolved findings found for MTTR calculation")
		return &MTTRMetrics{
			TotalResolved: 0,
			BySeverity:    make(map[string]*MTTRMetrics),
		}, nil
	}

	// Calculate MTTR metrics
	metrics := e.calculateMTTRMetrics(resolvedLifecycles)

	// Calculate MTTR by severity if no severity filter
	if severity == "" {
		metrics.BySeverity = make(map[string]*MTTRMetrics)
		severityGroups := make(map[string][]FindingLifecycle)
		
		for _, lc := range resolvedLifecycles {
			sev := strings.ToLower(lc.Severity)
			severityGroups[sev] = append(severityGroups[sev], lc)
		}

		for sev, group := range severityGroups {
			if len(group) > 0 {
				metrics.BySeverity[sev] = e.calculateMTTRMetrics(group)
			}
		}
	}

	// Cache the result
	e.cache.Set(cacheKey, metrics)
	log.Debug().Str("key", cacheKey).Int("resolved", len(resolvedLifecycles)).Msg("Cached MTTR metrics")

	return metrics, nil
}

// getFindingLifecycles retrieves finding lifecycles from the database
func (e *Engine) getFindingLifecycles(start, end time.Time, severity string) ([]FindingLifecycle, error) {
	// Build query to track finding lifecycles using code_fingerprint
	query := `
		SELECT 
			code_fingerprint,
			MIN(created_at) as first_seen,
			MAX(created_at) as last_seen,
			severity,
			cwe_id
		FROM findings_normalized
		WHERE 1=1
	`
	args := make([]interface{}, 0)

	// Add date range filter if specified
	if !start.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, start.Unix())
	}
	if !end.IsZero() {
		query += " AND created_at <= ?"
		args = append(args, end.Unix())
	}

	// Add severity filter if specified
	if severity != "" {
		query += " AND LOWER(severity) = LOWER(?)"
		args = append(args, severity)
	}

	query += `
		GROUP BY code_fingerprint, severity, cwe_id
		ORDER BY first_seen ASC
	`

	rows, err := e.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query finding lifecycles: %w", err)
	}
	defer rows.Close()

	lifecycles := make([]FindingLifecycle, 0)
	for rows.Next() {
		var lc FindingLifecycle
		var firstSeenUnix, lastSeenUnix int64
		var cweID sql.NullString

		if err := rows.Scan(&lc.CodeFingerprint, &firstSeenUnix, &lastSeenUnix, &lc.Severity, &cweID); err != nil {
			return nil, fmt.Errorf("failed to scan lifecycle row: %w", err)
		}

		lc.FirstSeen = time.Unix(firstSeenUnix, 0)
		lc.LastSeen = time.Unix(lastSeenUnix, 0)
		if cweID.Valid {
			lc.CWEID = cweID.String
		}

		// Check if finding is resolved by seeing if it appears in recent scans
		lc.Resolved = e.isFindingResolved(lc.CodeFingerprint, lc.LastSeen)

		lifecycles = append(lifecycles, lc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating lifecycle rows: %w", err)
	}

	return lifecycles, nil
}

// isFindingResolved checks if a finding has been resolved (not in recent scans)
func (e *Engine) isFindingResolved(fingerprint string, lastSeen time.Time) bool {
	// Check if the finding appears in any scan after lastSeen
	// If it doesn't appear in scans after lastSeen, it's considered resolved
	query := `
		SELECT COUNT(*) 
		FROM findings_normalized 
		WHERE code_fingerprint = ? AND created_at > ?
	`

	var count int
	err := e.db.QueryRow(query, fingerprint, lastSeen.Unix()).Scan(&count)
	if err != nil {
		log.Warn().Err(err).Str("fingerprint", fingerprint).Msg("Failed to check if finding is resolved")
		return false
	}

	// If count is 0, the finding hasn't appeared in scans after lastSeen, so it's resolved
	return count == 0
}

// calculateMTTRMetrics calculates MTTR statistics from lifecycles
func (e *Engine) calculateMTTRMetrics(lifecycles []FindingLifecycle) *MTTRMetrics {
	if len(lifecycles) == 0 {
		return &MTTRMetrics{TotalResolved: 0}
	}

	// Calculate remediation times
	remediationTimes := make([]time.Duration, 0, len(lifecycles))
	for _, lc := range lifecycles {
		ttr := lc.LastSeen.Sub(lc.FirstSeen)
		if ttr >= 0 {
			remediationTimes = append(remediationTimes, ttr)
		}
	}

	if len(remediationTimes) == 0 {
		return &MTTRMetrics{TotalResolved: len(lifecycles)}
	}

	// Sort for percentile calculations
	sort.Slice(remediationTimes, func(i, j int) bool {
		return remediationTimes[i] < remediationTimes[j]
	})

	metrics := &MTTRMetrics{
		TotalResolved: len(remediationTimes),
		MinTTR:        remediationTimes[0],
		MaxTTR:        remediationTimes[len(remediationTimes)-1],
	}

	// Calculate mean (simple average as fallback)
	var totalDuration time.Duration
	for _, d := range remediationTimes {
		totalDuration += d
	}
	metrics.MeanTTR = totalDuration / time.Duration(len(remediationTimes))

	// Calculate percentiles
	metrics.MedianTTR = e.calculatePercentile(remediationTimes, 50)
	metrics.P75TTR = e.calculatePercentile(remediationTimes, 75)
	metrics.P90TTR = e.calculatePercentile(remediationTimes, 90)
	metrics.P95TTR = e.calculatePercentile(remediationTimes, 95)

	return metrics
}

// calculatePercentile calculates the nth percentile from sorted durations
func (e *Engine) calculatePercentile(sortedDurations []time.Duration, percentile int) time.Duration {
	if len(sortedDurations) == 0 {
		return 0
	}

	if percentile < 0 || percentile > 100 {
		return 0
	}

	// Calculate index for percentile
	index := (float64(percentile) / 100.0) * float64(len(sortedDurations)-1)
	lowerIndex := int(index)
	upperIndex := lowerIndex + 1

	// Handle edge cases
	if upperIndex >= len(sortedDurations) {
		return sortedDurations[len(sortedDurations)-1]
	}

	// Linear interpolation between two closest values
	fraction := index - float64(lowerIndex)
	lower := sortedDurations[lowerIndex]
	upper := sortedDurations[upperIndex]
	
	interpolated := float64(lower) + fraction*(float64(upper)-float64(lower))
	return time.Duration(interpolated)
}

// GetTrendsWithFilter retrieves trends with optional severity filtering
func (e *Engine) GetTrendsWithFilter(start, end time.Time, severities []string) (*TrendData, error) {
	// If no filter, use standard GetTrends
	if len(severities) == 0 {
		return e.GetTrends(start, end)
	}

	cacheKey := fmt.Sprintf("trends_filtered:%s:%s:%v", start.Format("2006-01-02"), end.Format("2006-01-02"), severities)
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if trends, ok := cached.(*TrendData); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for filtered trends")
			return trends, nil
		}
	}

	// Get full trends first
	fullTrends, err := e.GetTrends(start, end)
	if err != nil {
		return nil, err
	}

	// Filter based on requested severities
	trends := &TrendData{
		Dates:            fullTrends.Dates,
		NewFindings:      fullTrends.NewFindings,
		ResolvedFindings: fullTrends.ResolvedFindings,
		Total:            make([]int, len(fullTrends.Dates)),
	}

	// Initialize severity arrays
	severityMap := make(map[string]bool)
	for _, s := range severities {
		severityMap[strings.ToLower(s)] = true
	}

	if severityMap["critical"] {
		trends.Critical = fullTrends.Critical
	} else {
		trends.Critical = make([]int, len(fullTrends.Dates))
	}

	if severityMap["high"] {
		trends.High = fullTrends.High
	} else {
		trends.High = make([]int, len(fullTrends.Dates))
	}

	if severityMap["medium"] {
		trends.Medium = fullTrends.Medium
	} else {
		trends.Medium = make([]int, len(fullTrends.Dates))
	}

	if severityMap["low"] {
		trends.Low = fullTrends.Low
	} else {
		trends.Low = make([]int, len(fullTrends.Dates))
	}

	// Recalculate totals based on filtered severities
	for i := range trends.Dates {
		trends.Total[i] = trends.Critical[i] + trends.High[i] + trends.Medium[i] + trends.Low[i]
	}

	// Cache the result
	e.cache.Set(cacheKey, trends)
	log.Debug().Str("key", cacheKey).Msg("Cached filtered trends")

	return trends, nil
}

// GetSecurityScore calculates the current security score based on findings
func (e *Engine) GetSecurityScore() (*SecurityScore, error) {
	cacheKey := "security_score:current"
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if score, ok := cached.(*SecurityScore); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for security score")
			return score, nil
		}
	}

	// Get current metrics
	metrics, err := e.GetCurrentMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to get current metrics: %w", err)
	}

	// Calculate score
	score := e.calculateSecurityScore(metrics)
	score.Timestamp = time.Now()

	// Get previous score for trend calculation
	prevScore, err := e.getPreviousScore()
	if err == nil && prevScore != nil {
		score.ChangeFromPrev = score.Score - prevScore.Score
		score.TrendDirection = e.determineTrendDirection(score.ChangeFromPrev)
	} else {
		score.TrendDirection = "stable"
	}

	// Store score in history
	if err := e.recordSecurityScore(score); err != nil {
		log.Warn().Err(err).Msg("Failed to record security score")
	}

	// Cache the result
	e.cache.Set(cacheKey, score)
	log.Debug().Str("key", cacheKey).Float64("score", score.Score).Msg("Cached security score")

	return score, nil
}

// calculateSecurityScore implements the scoring algorithm
// Score is calculated on a 0-100 scale where:
// - Start with 100 (perfect score)
// - Deduct points based on severity and count of findings
// - Critical: -10 points each
// - High: -5 points each
// - Medium: -2 points each
// - Low: -0.5 points each
// - Minimum score is 0
func (e *Engine) calculateSecurityScore(metrics *SeverityMetrics) *SecurityScore {
	score := &SecurityScore{
		TotalFindings: metrics.Total,
		CriticalCount: metrics.Critical,
		HighCount:     metrics.High,
		MediumCount:   metrics.Medium,
		LowCount:      metrics.Low,
	}

	// Start with perfect score
	rawScore := 100.0

	// Deduct points based on severity (fallback: simple severity-based scoring)
	rawScore -= float64(metrics.Critical) * 10.0
	rawScore -= float64(metrics.High) * 5.0
	rawScore -= float64(metrics.Medium) * 2.0
	rawScore -= float64(metrics.Low) * 0.5

	// Ensure score doesn't go below 0
	if rawScore < 0 {
		rawScore = 0
	}

	score.Score = rawScore
	score.Grade = e.calculateGrade(rawScore)

	return score
}

// calculateGrade converts a numeric score to a letter grade
func (e *Engine) calculateGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// determineTrendDirection determines if the score is improving, declining, or stable
func (e *Engine) determineTrendDirection(change float64) string {
	threshold := 2.0 // 2 point threshold for stability
	switch {
	case change > threshold:
		return "improving"
	case change < -threshold:
		return "declining"
	default:
		return "stable"
	}
}

// getPreviousScore retrieves the most recent security score from history
func (e *Engine) getPreviousScore() (*SecurityScore, error) {
	query := `
		SELECT score, grade, total_findings, critical_count, high_count, medium_count, low_count, created_at
		FROM security_scores
		ORDER BY created_at DESC
		LIMIT 1
	`

	var score SecurityScore
	var createdAtUnix int64

	err := e.db.QueryRow(query).Scan(
		&score.Score,
		&score.Grade,
		&score.TotalFindings,
		&score.CriticalCount,
		&score.HighCount,
		&score.MediumCount,
		&score.LowCount,
		&createdAtUnix,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No previous score
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query previous score: %w", err)
	}

	score.Timestamp = time.Unix(createdAtUnix, 0)
	return &score, nil
}

// recordSecurityScore stores a security score in the history
func (e *Engine) recordSecurityScore(score *SecurityScore) error {
	query := `
		INSERT INTO security_scores 
		(score, grade, total_findings, critical_count, high_count, medium_count, low_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := e.db.Exec(query,
		score.Score,
		score.Grade,
		score.TotalFindings,
		score.CriticalCount,
		score.HighCount,
		score.MediumCount,
		score.LowCount,
		score.Timestamp.Unix(),
	)

	if err != nil {
		return fmt.Errorf("failed to record security score: %w", err)
	}

	// Invalidate cache
	e.cache.Delete("security_score:current")
	e.cache.DeletePattern("score_history:")

	log.Debug().Float64("score", score.Score).Str("grade", score.Grade).Msg("Recorded security score")
	return nil
}

// GetScoreHistory retrieves historical security scores
func (e *Engine) GetScoreHistory(start, end time.Time, limit int) (*ScoreHistory, error) {
	cacheKey := fmt.Sprintf("score_history:%s:%s:%d", start.Format("2006-01-02"), end.Format("2006-01-02"), limit)
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if history, ok := cached.(*ScoreHistory); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for score history")
			return history, nil
		}
	}

	query := `
		SELECT DATE(created_at, 'unixepoch') as date, score, grade
		FROM security_scores
		WHERE created_at >= ? AND created_at <= ?
		GROUP BY date
		ORDER BY date ASC
	`
	
	args := []interface{}{start.Unix(), end.Unix()}
	
	// Add limit if specified
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := e.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query score history: %w", err)
	}
	defer rows.Close()

	history := &ScoreHistory{
		Dates:  make([]string, 0),
		Scores: make([]float64, 0),
		Grades: make([]string, 0),
	}

	for rows.Next() {
		var date, grade string
		var score float64
		if err := rows.Scan(&date, &score, &grade); err != nil {
			return nil, fmt.Errorf("failed to scan score history row: %w", err)
		}
		history.Dates = append(history.Dates, date)
		history.Scores = append(history.Scores, score)
		history.Grades = append(history.Grades, grade)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating score history rows: %w", err)
	}

	// Cache the result
	e.cache.Set(cacheKey, history)
	log.Debug().Str("key", cacheKey).Int("data_points", len(history.Dates)).Msg("Cached score history")

	return history, nil
}

// GetScoreForScan calculates the security score for a specific scan
func (e *Engine) GetScoreForScan(scanID string) (*SecurityScore, error) {
	cacheKey := fmt.Sprintf("security_score:scan:%s", scanID)
	
	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if score, ok := cached.(*SecurityScore); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for scan security score")
			return score, nil
		}
	}

	// Get scan metrics
	metrics, err := e.GetScanMetrics(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan metrics: %w", err)
	}

	// Calculate score
	score := e.calculateSecurityScore(metrics)
	score.Timestamp = time.Now()
	score.TrendDirection = "stable" // No trend for individual scans

	// Cache the result
	e.cache.Set(cacheKey, score)
	log.Debug().Str("key", cacheKey).Float64("score", score.Score).Msg("Cached scan security score")

	return score, nil
}
// FileHotspot represents a file with security findings
type FileHotspot struct {
	FilePath        string  `json:"file_path"`
	TotalFindings   int     `json:"total_findings"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
	FindingDensity  float64 `json:"finding_density"` // Findings per line of code (if available)
	SeverityScore   float64 `json:"severity_score"`  // Weighted score based on severity
	UniqueFindings  int     `json:"unique_findings"` // Count of unique finding types (by CWE)
}

// HotspotAnalysis represents the complete hotspot analysis
type HotspotAnalysis struct {
	Hotspots      []FileHotspot `json:"hotspots"`
	TotalFiles    int           `json:"total_files"`
	TotalFindings int           `json:"total_findings"`
	AnalyzedAt    time.Time     `json:"analyzed_at"`
}

// GetHotspots identifies files with the most security findings
// Returns top N files ranked by severity score
func (e *Engine) GetHotspots(limit int) (*HotspotAnalysis, error) {
	cacheKey := fmt.Sprintf("hotspots:%d", limit)

	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if analysis, ok := cached.(*HotspotAnalysis); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for hotspots")
			return analysis, nil
		}
	}

	// Query to get file-level statistics
	query := `
		SELECT
			file_path,
			COUNT(*) as total_findings,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count,
			COUNT(DISTINCT cwe_id) as unique_findings
		FROM findings_normalized
		WHERE run_id IN (
			SELECT run_id FROM runs ORDER BY start_time DESC LIMIT 1
		)
		GROUP BY file_path
		ORDER BY
			(SUM(CASE WHEN severity = 'critical' THEN 10 ELSE 0 END) +
			 SUM(CASE WHEN severity = 'high' THEN 5 ELSE 0 END) +
			 SUM(CASE WHEN severity = 'medium' THEN 2 ELSE 0 END) +
			 SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)) DESC
		LIMIT ?
	`

	rows, err := e.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query hotspots: %w", err)
	}
	defer rows.Close()

	var hotspots []FileHotspot
	totalFindings := 0

	for rows.Next() {
		var h FileHotspot
		err := rows.Scan(
			&h.FilePath,
			&h.TotalFindings,
			&h.CriticalCount,
			&h.HighCount,
			&h.MediumCount,
			&h.LowCount,
			&h.UniqueFindings,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan hotspot row: %w", err)
		}

		// Calculate severity score (weighted by severity)
		h.SeverityScore = float64(h.CriticalCount*10 + h.HighCount*5 + h.MediumCount*2 + h.LowCount)

		// Calculate finding density (findings per 100 lines, estimated)
		// For now, we'll use a simple metric based on total findings
		// In a real implementation, you'd want to count actual lines of code
		h.FindingDensity = float64(h.TotalFindings)

		hotspots = append(hotspots, h)
		totalFindings += h.TotalFindings
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating hotspot rows: %w", err)
	}

	// Get total file count
	var totalFiles int
	err = e.db.QueryRow(`
		SELECT COUNT(DISTINCT file_path)
		FROM findings_normalized
		WHERE run_id IN (
			SELECT run_id FROM runs ORDER BY start_time DESC LIMIT 1
		)
	`).Scan(&totalFiles)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get total file count")
		totalFiles = len(hotspots)
	}

	analysis := &HotspotAnalysis{
		Hotspots:      hotspots,
		TotalFiles:    totalFiles,
		TotalFindings: totalFindings,
		AnalyzedAt:    time.Now(),
	}

	// Cache the result
	e.cache.Set(cacheKey, analysis)
	log.Debug().Str("key", cacheKey).Msg("Cached hotspots")

	return analysis, nil
}

// GetHotspotsForScan identifies files with the most security findings for a specific scan
func (e *Engine) GetHotspotsForScan(scanID string, limit int) (*HotspotAnalysis, error) {
	cacheKey := fmt.Sprintf("hotspots:%s:%d", scanID, limit)

	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if analysis, ok := cached.(*HotspotAnalysis); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for scan hotspots")
			return analysis, nil
		}
	}

	// Query to get file-level statistics for specific scan
	query := `
		SELECT
			file_path,
			COUNT(*) as total_findings,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count,
			COUNT(DISTINCT cwe_id) as unique_findings
		FROM findings_normalized
		WHERE run_id = ?
		GROUP BY file_path
		ORDER BY
			(SUM(CASE WHEN severity = 'critical' THEN 10 ELSE 0 END) +
			 SUM(CASE WHEN severity = 'high' THEN 5 ELSE 0 END) +
			 SUM(CASE WHEN severity = 'medium' THEN 2 ELSE 0 END) +
			 SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)) DESC
		LIMIT ?
	`

	rows, err := e.db.Query(query, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan hotspots: %w", err)
	}
	defer rows.Close()

	var hotspots []FileHotspot
	totalFindings := 0

	for rows.Next() {
		var h FileHotspot
		err := rows.Scan(
			&h.FilePath,
			&h.TotalFindings,
			&h.CriticalCount,
			&h.HighCount,
			&h.MediumCount,
			&h.LowCount,
			&h.UniqueFindings,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan hotspot row: %w", err)
		}

		// Calculate severity score (weighted by severity)
		h.SeverityScore = float64(h.CriticalCount*10 + h.HighCount*5 + h.MediumCount*2 + h.LowCount)

		// Calculate finding density
		h.FindingDensity = float64(h.TotalFindings)

		hotspots = append(hotspots, h)
		totalFindings += h.TotalFindings
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating scan hotspot rows: %w", err)
	}

	// Get total file count for this scan
	var totalFiles int
	err = e.db.QueryRow(`
		SELECT COUNT(DISTINCT file_path)
		FROM findings_normalized
		WHERE run_id = ?
	`, scanID).Scan(&totalFiles)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get total file count for scan")
		totalFiles = len(hotspots)
	}

	analysis := &HotspotAnalysis{
		Hotspots:      hotspots,
		TotalFiles:    totalFiles,
		TotalFindings: totalFindings,
		AnalyzedAt:    time.Now(),
	}

	// Cache the result
	e.cache.Set(cacheKey, analysis)
	log.Debug().Str("key", cacheKey).Msg("Cached scan hotspots")

	return analysis, nil
}

// GetHotspotTrends shows how hotspots have changed over time
func (e *Engine) GetHotspotTrends(filePath string, start, end time.Time) ([]FileHotspot, error) {
	cacheKey := fmt.Sprintf("hotspot_trends:%s:%s:%s", filePath, start.Format("2006-01-02"), end.Format("2006-01-02"))

	// Check cache
	if cached, ok := e.cache.Get(cacheKey); ok {
		if trends, ok := cached.([]FileHotspot); ok {
			log.Debug().Str("key", cacheKey).Msg("Cache hit for hotspot trends")
			return trends, nil
		}
	}

	query := `
		SELECT
			r.run_id,
			f.file_path,
			COUNT(*) as total_findings,
			SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
			SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high_count,
			SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
			SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) as low_count,
			COUNT(DISTINCT f.cwe_id) as unique_findings
		FROM findings_normalized f
		JOIN runs r ON f.run_id = r.run_id
		WHERE f.file_path = ?
			AND r.start_time >= ?
			AND r.start_time <= ?
		GROUP BY r.run_id, f.file_path
		ORDER BY r.start_time ASC
	`

	rows, err := e.db.Query(query, filePath, start.Unix(), end.Unix())
	if err != nil {
		return nil, fmt.Errorf("failed to query hotspot trends: %w", err)
	}
	defer rows.Close()

	var trends []FileHotspot
	for rows.Next() {
		var runID string
		var h FileHotspot
		err := rows.Scan(
			&runID,
			&h.FilePath,
			&h.TotalFindings,
			&h.CriticalCount,
			&h.HighCount,
			&h.MediumCount,
			&h.LowCount,
			&h.UniqueFindings,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan hotspot trend row: %w", err)
		}

		// Calculate severity score
		h.SeverityScore = float64(h.CriticalCount*10 + h.HighCount*5 + h.MediumCount*2 + h.LowCount)
		h.FindingDensity = float64(h.TotalFindings)

		trends = append(trends, h)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating hotspot trend rows: %w", err)
	}

	// Cache the result
	e.cache.Set(cacheKey, trends)
	log.Debug().Str("key", cacheKey).Msg("Cached hotspot trends")

	return trends, nil
}

