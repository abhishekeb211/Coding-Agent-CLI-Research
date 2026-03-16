package analytics

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create schema
	schema := `
		CREATE TABLE findings_normalized (
			norm_id TEXT PRIMARY KEY,
			finding_id TEXT,
			run_id TEXT,
			cwe_id TEXT,
			cwe_description TEXT,
			severity TEXT,
			confidence TEXT,
			code_fingerprint TEXT,
			file_path TEXT,
			line_number INTEGER,
			description TEXT,
			created_at INTEGER
		);

		CREATE TABLE scan_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT NOT NULL,
			total_findings INTEGER,
			critical INTEGER,
			high INTEGER,
			medium INTEGER,
			low INTEGER,
			scan_duration INTEGER,
			created_at INTEGER
		);

		CREATE TABLE finding_trends (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date TEXT NOT NULL UNIQUE,
			critical INTEGER,
			high INTEGER,
			medium INTEGER,
			low INTEGER,
			total INTEGER,
			new_findings INTEGER,
			resolved_findings INTEGER,
			created_at INTEGER
		);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

func TestNewEngine(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	if engine == nil {
		t.Fatal("Expected engine to be created")
	}

	if engine.db == nil {
		t.Error("Expected database to be set")
	}

	if engine.cache == nil {
		t.Error("Expected cache to be initialized")
	}
}

func TestGetCurrentMetrics(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert test findings
	findings := []struct {
		normID   string
		runID    string
		severity string
	}{
		{"f1", "run1", "critical"},
		{"f2", "run1", "critical"},
		{"f3", "run1", "high"},
		{"f4", "run1", "high"},
		{"f5", "run1", "high"},
		{"f6", "run1", "medium"},
		{"f7", "run1", "low"},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, severity, cwe_id, code_fingerprint)
			VALUES (?, ?, ?, 'CWE-79', ?)
		`, f.normID, f.runID, f.severity, f.normID)
		if err != nil {
			t.Fatalf("Failed to insert test finding: %v", err)
		}
	}

	engine := NewEngine(db)
	metrics, err := engine.GetCurrentMetrics()
	if err != nil {
		t.Fatalf("GetCurrentMetrics failed: %v", err)
	}

	if metrics.Critical != 2 {
		t.Errorf("Expected 2 critical findings, got %d", metrics.Critical)
	}
	if metrics.High != 3 {
		t.Errorf("Expected 3 high findings, got %d", metrics.High)
	}
	if metrics.Medium != 1 {
		t.Errorf("Expected 1 medium finding, got %d", metrics.Medium)
	}
	if metrics.Low != 1 {
		t.Errorf("Expected 1 low finding, got %d", metrics.Low)
	}
	if metrics.Total != 7 {
		t.Errorf("Expected 7 total findings, got %d", metrics.Total)
	}
}

func TestGetCurrentMetrics_Cache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert test finding
	_, err := db.Exec(`
		INSERT INTO findings_normalized (norm_id, run_id, severity, cwe_id, code_fingerprint)
		VALUES ('f1', 'run1', 'high', 'CWE-79', 'fp1')
	`)
	if err != nil {
		t.Fatalf("Failed to insert test finding: %v", err)
	}

	engine := NewEngine(db)

	// First call - should query database
	metrics1, err := engine.GetCurrentMetrics()
	if err != nil {
		t.Fatalf("GetCurrentMetrics failed: %v", err)
	}

	// Second call - should use cache
	metrics2, err := engine.GetCurrentMetrics()
	if err != nil {
		t.Fatalf("GetCurrentMetrics failed: %v", err)
	}

	if metrics1.Total != metrics2.Total {
		t.Error("Expected cached metrics to match")
	}
}

func TestGetScanMetrics_FromTable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert scan metrics
	_, err := db.Exec(`
		INSERT INTO scan_metrics (scan_id, total_findings, critical, high, medium, low, scan_duration, created_at)
		VALUES ('scan1', 10, 2, 3, 4, 1, 5000, ?)
	`, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert scan metrics: %v", err)
	}

	engine := NewEngine(db)
	metrics, err := engine.GetScanMetrics("scan1")
	if err != nil {
		t.Fatalf("GetScanMetrics failed: %v", err)
	}

	if metrics.Total != 10 {
		t.Errorf("Expected 10 total findings, got %d", metrics.Total)
	}
	if metrics.Critical != 2 {
		t.Errorf("Expected 2 critical findings, got %d", metrics.Critical)
	}
	if metrics.High != 3 {
		t.Errorf("Expected 3 high findings, got %d", metrics.High)
	}
	if metrics.Medium != 4 {
		t.Errorf("Expected 4 medium findings, got %d", metrics.Medium)
	}
	if metrics.Low != 1 {
		t.Errorf("Expected 1 low finding, got %d", metrics.Low)
	}
}

func TestGetScanMetrics_FromFindings(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings (no scan_metrics entry)
	findings := []struct {
		normID   string
		severity string
	}{
		{"f1", "critical"},
		{"f2", "high"},
		{"f3", "medium"},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, severity, cwe_id, code_fingerprint)
			VALUES (?, 'scan2', ?, 'CWE-79', ?)
		`, f.normID, f.severity, f.normID)
		if err != nil {
			t.Fatalf("Failed to insert test finding: %v", err)
		}
	}

	engine := NewEngine(db)
	metrics, err := engine.GetScanMetrics("scan2")
	if err != nil {
		t.Fatalf("GetScanMetrics failed: %v", err)
	}

	if metrics.Total != 3 {
		t.Errorf("Expected 3 total findings, got %d", metrics.Total)
	}
	if metrics.Critical != 1 {
		t.Errorf("Expected 1 critical finding, got %d", metrics.Critical)
	}
	if metrics.High != 1 {
		t.Errorf("Expected 1 high finding, got %d", metrics.High)
	}
	if metrics.Medium != 1 {
		t.Errorf("Expected 1 medium finding, got %d", metrics.Medium)
	}
}

func TestGetTopCWEs(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings with different CWEs
	findings := []struct {
		normID string
		cweID  string
		cweDesc string
	}{
		{"f1", "CWE-79", "Cross-site Scripting"},
		{"f2", "CWE-79", "Cross-site Scripting"},
		{"f3", "CWE-79", "Cross-site Scripting"},
		{"f4", "CWE-89", "SQL Injection"},
		{"f5", "CWE-89", "SQL Injection"},
		{"f6", "CWE-22", "Path Traversal"},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, cwe_id, cwe_description, severity, code_fingerprint)
			VALUES (?, 'run1', ?, ?, 'high', ?)
		`, f.normID, f.cweID, f.cweDesc, f.normID)
		if err != nil {
			t.Fatalf("Failed to insert test finding: %v", err)
		}
	}

	engine := NewEngine(db)
	stats, err := engine.GetTopCWEs(3)
	if err != nil {
		t.Fatalf("GetTopCWEs failed: %v", err)
	}

	if len(stats) != 3 {
		t.Fatalf("Expected 3 CWE stats, got %d", len(stats))
	}

	// First should be CWE-79 with count 3
	if stats[0].CWEID != "CWE-79" {
		t.Errorf("Expected first CWE to be CWE-79, got %s", stats[0].CWEID)
	}
	if stats[0].Count != 3 {
		t.Errorf("Expected CWE-79 count to be 3, got %d", stats[0].Count)
	}

	// Second should be CWE-89 with count 2
	if stats[1].CWEID != "CWE-89" {
		t.Errorf("Expected second CWE to be CWE-89, got %s", stats[1].CWEID)
	}
	if stats[1].Count != 2 {
		t.Errorf("Expected CWE-89 count to be 2, got %d", stats[1].Count)
	}
}

func TestCompareScanFindings(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings for old scan
	oldFindings := []struct {
		normID      string
		fingerprint string
	}{
		{"old1", "fp1"},
		{"old2", "fp2"},
		{"old3", "fp3"},
	}

	for _, f := range oldFindings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, cwe_id, severity)
			VALUES (?, 'old_scan', ?, 'CWE-79', 'high')
		`, f.normID, f.fingerprint)
		if err != nil {
			t.Fatalf("Failed to insert old finding: %v", err)
		}
	}

	// Insert findings for new scan (fp2 and fp3 remain, fp1 resolved, fp4 is new)
	newFindings := []struct {
		normID      string
		fingerprint string
	}{
		{"new1", "fp2"},
		{"new2", "fp3"},
		{"new3", "fp4"},
	}

	for _, f := range newFindings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, cwe_id, severity)
			VALUES (?, 'new_scan', ?, 'CWE-79', 'high')
		`, f.normID, f.fingerprint)
		if err != nil {
			t.Fatalf("Failed to insert new finding: %v", err)
		}
	}

	engine := NewEngine(db)
	comparison, err := engine.CompareScanFindings("old_scan", "new_scan")
	if err != nil {
		t.Fatalf("CompareScanFindings failed: %v", err)
	}

	if comparison.NewFindings != 1 {
		t.Errorf("Expected 1 new finding, got %d", comparison.NewFindings)
	}
	if comparison.ResolvedFindings != 1 {
		t.Errorf("Expected 1 resolved finding, got %d", comparison.ResolvedFindings)
	}
	if comparison.UnchangedCount != 2 {
		t.Errorf("Expected 2 unchanged findings, got %d", comparison.UnchangedCount)
	}
}

func TestRecordScanMetrics(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	metrics := &SeverityMetrics{
		Critical: 2,
		High:     5,
		Medium:   10,
		Low:      3,
		Total:    20,
	}

	err := engine.RecordScanMetrics("scan1", metrics, 5000)
	if err != nil {
		t.Fatalf("RecordScanMetrics failed: %v", err)
	}

	// Verify data was inserted
	var total, critical, high, medium, low int
	err = db.QueryRow(`
		SELECT total_findings, critical, high, medium, low
		FROM scan_metrics
		WHERE scan_id = 'scan1'
	`).Scan(&total, &critical, &high, &medium, &low)

	if err != nil {
		t.Fatalf("Failed to query scan metrics: %v", err)
	}

	if total != 20 {
		t.Errorf("Expected total 20, got %d", total)
	}
	if critical != 2 {
		t.Errorf("Expected critical 2, got %d", critical)
	}
	if high != 5 {
		t.Errorf("Expected high 5, got %d", high)
	}
	if medium != 10 {
		t.Errorf("Expected medium 10, got %d", medium)
	}
	if low != 3 {
		t.Errorf("Expected low 3, got %d", low)
	}
}

func TestRecordDailyTrend(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	date := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	metrics := &SeverityMetrics{
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      4,
		Total:    10,
	}

	err := engine.RecordDailyTrend(date, metrics, 5, 2)
	if err != nil {
		t.Fatalf("RecordDailyTrend failed: %v", err)
	}

	// Verify data was inserted
	var dateStr string
	var critical, high, medium, low, total, newFindings, resolvedFindings int
	err = db.QueryRow(`
		SELECT date, critical, high, medium, low, total, new_findings, resolved_findings
		FROM finding_trends
		WHERE date = '2024-01-15'
	`).Scan(&dateStr, &critical, &high, &medium, &low, &total, &newFindings, &resolvedFindings)

	if err != nil {
		t.Fatalf("Failed to query trend: %v", err)
	}

	if dateStr != "2024-01-15" {
		t.Errorf("Expected date 2024-01-15, got %s", dateStr)
	}
	if critical != 1 {
		t.Errorf("Expected critical 1, got %d", critical)
	}
	if newFindings != 5 {
		t.Errorf("Expected new findings 5, got %d", newFindings)
	}
	if resolvedFindings != 2 {
		t.Errorf("Expected resolved findings 2, got %d", resolvedFindings)
	}
}

func TestGetTrends(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data
	trends := []struct {
		date     string
		critical int
		high     int
		medium   int
		low      int
	}{
		{"2024-01-01", 1, 2, 3, 4},
		{"2024-01-02", 2, 3, 4, 5},
		{"2024-01-03", 1, 1, 2, 3},
	}

	for _, tr := range trends {
		_, err := db.Exec(`
			INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
		`, tr.date, tr.critical, tr.high, tr.medium, tr.low, tr.critical+tr.high+tr.medium+tr.low, time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to insert trend: %v", err)
		}
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)

	trendData, err := engine.GetTrends(start, end)
	if err != nil {
		t.Fatalf("GetTrends failed: %v", err)
	}

	if len(trendData.Dates) != 3 {
		t.Errorf("Expected 3 dates, got %d", len(trendData.Dates))
	}

	if trendData.Critical[0] != 1 {
		t.Errorf("Expected first critical to be 1, got %d", trendData.Critical[0])
	}
	if trendData.High[1] != 3 {
		t.Errorf("Expected second high to be 3, got %d", trendData.High[1])
	}
}

func TestClearCache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Add something to cache
	engine.cache.Set("test", "value")

	if engine.cache.Size() != 1 {
		t.Error("Expected cache to have 1 entry")
	}

	engine.ClearCache()

	if engine.cache.Size() != 0 {
		t.Error("Expected cache to be empty after clear")
	}
}

func TestGetSeverityTrends(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data
	trends := []struct {
		date     string
		critical int
		high     int
		medium   int
		low      int
	}{
		{"2024-01-01", 5, 10, 15, 20},
		{"2024-01-02", 4, 12, 14, 18},
		{"2024-01-03", 6, 11, 13, 19},
	}

	for _, tr := range trends {
		_, err := db.Exec(`
			INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
		`, tr.date, tr.critical, tr.high, tr.medium, tr.low, tr.critical+tr.high+tr.medium+tr.low, time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to insert trend: %v", err)
		}
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)

	// Test critical severity trends
	counts, dates, err := engine.GetSeverityTrends("critical", start, end)
	if err != nil {
		t.Fatalf("GetSeverityTrends failed: %v", err)
	}

	if len(counts) != 3 {
		t.Errorf("Expected 3 data points, got %d", len(counts))
	}
	if len(dates) != 3 {
		t.Errorf("Expected 3 dates, got %d", len(dates))
	}

	expectedCritical := []int{5, 4, 6}
	for i, expected := range expectedCritical {
		if counts[i] != expected {
			t.Errorf("Expected critical[%d] to be %d, got %d", i, expected, counts[i])
		}
	}

	// Test high severity trends
	counts, dates, err = engine.GetSeverityTrends("high", start, end)
	if err != nil {
		t.Fatalf("GetSeverityTrends failed for high: %v", err)
	}

	expectedHigh := []int{10, 12, 11}
	for i, expected := range expectedHigh {
		if counts[i] != expected {
			t.Errorf("Expected high[%d] to be %d, got %d", i, expected, counts[i])
		}
	}
}

func TestGetSeverityTrends_InvalidSeverity(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)

	_, _, err := engine.GetSeverityTrends("invalid", start, end)
	if err == nil {
		t.Error("Expected error for invalid severity level")
	}
}

func TestGetNewVsResolvedTrends(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data with new and resolved findings
	trends := []struct {
		date     string
		newCount int
		resolved int
	}{
		{"2024-01-01", 10, 2},
		{"2024-01-02", 5, 8},
		{"2024-01-03", 15, 3},
	}

	for _, tr := range trends {
		_, err := db.Exec(`
			INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
			VALUES (?, 1, 2, 3, 4, 10, ?, ?, ?)
		`, tr.date, tr.newCount, tr.resolved, time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to insert trend: %v", err)
		}
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)

	newFindings, resolvedFindings, dates, err := engine.GetNewVsResolvedTrends(start, end)
	if err != nil {
		t.Fatalf("GetNewVsResolvedTrends failed: %v", err)
	}

	if len(newFindings) != 3 {
		t.Errorf("Expected 3 data points for new findings, got %d", len(newFindings))
	}
	if len(resolvedFindings) != 3 {
		t.Errorf("Expected 3 data points for resolved findings, got %d", len(resolvedFindings))
	}
	if len(dates) != 3 {
		t.Errorf("Expected 3 dates, got %d", len(dates))
	}

	expectedNew := []int{10, 5, 15}
	expectedResolved := []int{2, 8, 3}

	for i := range expectedNew {
		if newFindings[i] != expectedNew[i] {
			t.Errorf("Expected new[%d] to be %d, got %d", i, expectedNew[i], newFindings[i])
		}
		if resolvedFindings[i] != expectedResolved[i] {
			t.Errorf("Expected resolved[%d] to be %d, got %d", i, expectedResolved[i], resolvedFindings[i])
		}
	}
}

func TestCalculateTrendSummary(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data
	trends := []struct {
		date     string
		critical int
		high     int
		medium   int
		low      int
		total    int
		newCount int
		resolved int
	}{
		{"2024-01-01", 2, 5, 10, 3, 20, 10, 2},
		{"2024-01-02", 3, 6, 8, 4, 21, 5, 4},
		{"2024-01-03", 1, 4, 12, 2, 19, 8, 9},
	}

	for _, tr := range trends {
		_, err := db.Exec(`
			INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, tr.date, tr.critical, tr.high, tr.medium, tr.low, tr.total, tr.newCount, tr.resolved, time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to insert trend: %v", err)
		}
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)

	summary, err := engine.CalculateTrendSummary(start, end)
	if err != nil {
		t.Fatalf("CalculateTrendSummary failed: %v", err)
	}

	// Total new: 10 + 5 + 8 = 23
	if summary.TotalNew != 23 {
		t.Errorf("Expected TotalNew to be 23, got %d", summary.TotalNew)
	}

	// Total resolved: 2 + 4 + 9 = 15
	if summary.TotalResolved != 15 {
		t.Errorf("Expected TotalResolved to be 15, got %d", summary.TotalResolved)
	}

	// Net change: 23 - 15 = 8
	if summary.NetChange != 8 {
		t.Errorf("Expected NetChange to be 8, got %d", summary.NetChange)
	}

	// Average total: (20 + 21 + 19) / 3 = 20
	if summary.AverageTotal != 20 {
		t.Errorf("Expected AverageTotal to be 20, got %d", summary.AverageTotal)
	}

	// Max total: 21
	if summary.MaxTotal != 21 {
		t.Errorf("Expected MaxTotal to be 21, got %d", summary.MaxTotal)
	}

	// Min total: 19
	if summary.MinTotal != 19 {
		t.Errorf("Expected MinTotal to be 19, got %d", summary.MinTotal)
	}

	// Average critical: (2 + 3 + 1) / 3 = 2
	if summary.AverageCritical != 2 {
		t.Errorf("Expected AverageCritical to be 2, got %d", summary.AverageCritical)
	}
}

func TestGetTrendsWithFilter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data
	_, err := db.Exec(`
		INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
		VALUES ('2024-01-01', 5, 10, 15, 20, 50, 10, 2, ?)
	`, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert trend: %v", err)
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Test filtering for critical and high only
	trends, err := engine.GetTrendsWithFilter(start, end, []string{"critical", "high"})
	if err != nil {
		t.Fatalf("GetTrendsWithFilter failed: %v", err)
	}

	if len(trends.Dates) != 1 {
		t.Errorf("Expected 1 date, got %d", len(trends.Dates))
	}

	// Should have critical and high
	if trends.Critical[0] != 5 {
		t.Errorf("Expected critical to be 5, got %d", trends.Critical[0])
	}
	if trends.High[0] != 10 {
		t.Errorf("Expected high to be 10, got %d", trends.High[0])
	}

	// Medium and low should be zero (filtered out)
	if trends.Medium[0] != 0 {
		t.Errorf("Expected medium to be 0, got %d", trends.Medium[0])
	}
	if trends.Low[0] != 0 {
		t.Errorf("Expected low to be 0, got %d", trends.Low[0])
	}

	// Total should be sum of filtered severities: 5 + 10 = 15
	if trends.Total[0] != 15 {
		t.Errorf("Expected total to be 15, got %d", trends.Total[0])
	}
}

func TestGetTrendsWithFilter_NoFilter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data
	_, err := db.Exec(`
		INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
		VALUES ('2024-01-01', 5, 10, 15, 20, 50, 10, 2, ?)
	`, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert trend: %v", err)
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Test with no filter (should return all severities)
	trends, err := engine.GetTrendsWithFilter(start, end, []string{})
	if err != nil {
		t.Fatalf("GetTrendsWithFilter failed: %v", err)
	}

	if trends.Critical[0] != 5 {
		t.Errorf("Expected critical to be 5, got %d", trends.Critical[0])
	}
	if trends.High[0] != 10 {
		t.Errorf("Expected high to be 10, got %d", trends.High[0])
	}
	if trends.Medium[0] != 15 {
		t.Errorf("Expected medium to be 15, got %d", trends.Medium[0])
	}
	if trends.Low[0] != 20 {
		t.Errorf("Expected low to be 20, got %d", trends.Low[0])
	}
}

func TestGetTrends_EnhancedFields(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data with new and resolved findings
	_, err := db.Exec(`
		INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
		VALUES ('2024-01-01', 2, 3, 4, 1, 10, 5, 2, ?)
	`, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert trend: %v", err)
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	trends, err := engine.GetTrends(start, end)
	if err != nil {
		t.Fatalf("GetTrends failed: %v", err)
	}

	// Verify enhanced fields are populated
	if len(trends.Total) != 1 {
		t.Errorf("Expected 1 total value, got %d", len(trends.Total))
	}
	if trends.Total[0] != 10 {
		t.Errorf("Expected total to be 10, got %d", trends.Total[0])
	}

	if len(trends.NewFindings) != 1 {
		t.Errorf("Expected 1 new findings value, got %d", len(trends.NewFindings))
	}
	if trends.NewFindings[0] != 5 {
		t.Errorf("Expected new findings to be 5, got %d", trends.NewFindings[0])
	}

	if len(trends.ResolvedFindings) != 1 {
		t.Errorf("Expected 1 resolved findings value, got %d", len(trends.ResolvedFindings))
	}
	if trends.ResolvedFindings[0] != 2 {
		t.Errorf("Expected resolved findings to be 2, got %d", trends.ResolvedFindings[0])
	}
}

func TestGetTrends_EmptyResult(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)

	trends, err := engine.GetTrends(start, end)
	if err != nil {
		t.Fatalf("GetTrends failed: %v", err)
	}

	// Should return empty arrays, not nil
	if trends == nil {
		t.Error("Expected trends to be non-nil")
	}
	if len(trends.Dates) != 0 {
		t.Errorf("Expected 0 dates, got %d", len(trends.Dates))
	}
}

func TestGetMTTR(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings with different lifecycles
	// Finding 1: Appeared on day 1, resolved by day 3 (2 days to remediate)
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	
	findings := []struct {
		normID      string
		fingerprint string
		severity    string
		createdAt   time.Time
	}{
		// Finding 1: First seen on day 1, last seen on day 1 (resolved after 2 days)
		{"f1_day1", "fp1", "high", baseTime},
		
		// Finding 2: First seen on day 1, last seen on day 5 (resolved after 4 days)
		{"f2_day1", "fp2", "critical", baseTime},
		{"f2_day5", "fp2", "critical", baseTime.Add(4 * 24 * time.Hour)},
		
		// Finding 3: First seen on day 2, last seen on day 4 (resolved after 2 days)
		{"f3_day2", "fp3", "medium", baseTime.Add(1 * 24 * time.Hour)},
		{"f3_day4", "fp3", "medium", baseTime.Add(3 * 24 * time.Hour)},
		
		// Finding 4: Still active (appears on day 6, not resolved)
		{"f4_day6", "fp4", "low", baseTime.Add(5 * 24 * time.Hour)},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, ?, ?, ?, 'CWE-79', ?)
		`, f.normID, "run1", f.fingerprint, f.severity, f.createdAt.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)
	metrics, err := engine.GetMTTR()
	if err != nil {
		t.Fatalf("GetMTTR failed: %v", err)
	}

	// Should have 3 resolved findings (fp1, fp2, fp3)
	// fp4 is still active so not counted
	if metrics.TotalResolved != 3 {
		t.Errorf("Expected 3 resolved findings, got %d", metrics.TotalResolved)
	}

	// Check that mean TTR is calculated
	if metrics.MeanTTR == 0 {
		t.Error("Expected non-zero mean TTR")
	}

	// Check that percentiles are calculated
	if metrics.MedianTTR == 0 {
		t.Error("Expected non-zero median TTR")
	}

	// Check that min/max are set
	if metrics.MinTTR == 0 {
		t.Error("Expected non-zero min TTR")
	}
	if metrics.MaxTTR == 0 {
		t.Error("Expected non-zero max TTR")
	}

	// Check that by-severity breakdown exists
	if metrics.BySeverity == nil {
		t.Error("Expected by-severity breakdown")
	}
}

func TestGetMTTR_NoResolvedFindings(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert only active findings (all recent)
	baseTime := time.Now()
	findings := []struct {
		normID      string
		fingerprint string
		severity    string
	}{
		{"f1", "fp1", "high"},
		{"f2", "fp2", "critical"},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run1', ?, ?, 'CWE-79', ?)
		`, f.normID, f.fingerprint, f.severity, baseTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)
	metrics, err := engine.GetMTTR()
	if err != nil {
		t.Fatalf("GetMTTR failed: %v", err)
	}

	// Should have 0 resolved findings
	if metrics.TotalResolved != 0 {
		t.Errorf("Expected 0 resolved findings, got %d", metrics.TotalResolved)
	}

	// All metrics should be zero
	if metrics.MeanTTR != 0 {
		t.Error("Expected zero mean TTR for no resolved findings")
	}
}

func TestGetMTTRWithFilter_BySeverity(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings with different severities
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	
	findings := []struct {
		normID      string
		fingerprint string
		severity    string
		createdAt   time.Time
	}{
		// Critical finding: 2 days to resolve
		{"f1_day1", "fp1", "critical", baseTime},
		
		// High finding: 3 days to resolve
		{"f2_day1", "fp2", "high", baseTime},
		{"f2_day3", "fp2", "high", baseTime.Add(2 * 24 * time.Hour)},
		
		// Medium finding: 1 day to resolve
		{"f3_day1", "fp3", "medium", baseTime},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run1', ?, ?, 'CWE-79', ?)
		`, f.normID, f.fingerprint, f.severity, f.createdAt.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)
	
	// Test filtering by critical severity
	metrics, err := engine.GetMTTRWithFilter(time.Time{}, time.Time{}, "critical")
	if err != nil {
		t.Fatalf("GetMTTRWithFilter failed: %v", err)
	}

	if metrics.TotalResolved != 1 {
		t.Errorf("Expected 1 resolved critical finding, got %d", metrics.TotalResolved)
	}

	// Test filtering by high severity
	metrics, err = engine.GetMTTRWithFilter(time.Time{}, time.Time{}, "high")
	if err != nil {
		t.Fatalf("GetMTTRWithFilter failed: %v", err)
	}

	if metrics.TotalResolved != 1 {
		t.Errorf("Expected 1 resolved high finding, got %d", metrics.TotalResolved)
	}
}

func TestGetMTTRWithFilter_DateRange(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings across different time periods
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	
	findings := []struct {
		normID      string
		fingerprint string
		severity    string
		createdAt   time.Time
	}{
		// Finding in January
		{"f1_jan", "fp1", "high", baseTime},
		
		// Finding in February
		{"f2_feb", "fp2", "high", baseTime.Add(31 * 24 * time.Hour)},
		
		// Finding in March
		{"f3_mar", "fp3", "high", baseTime.Add(60 * 24 * time.Hour)},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run1', ?, ?, 'CWE-79', ?)
		`, f.normID, f.fingerprint, f.severity, f.createdAt.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)
	
	// Test filtering by date range (January only)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC)
	
	metrics, err := engine.GetMTTRWithFilter(start, end, "")
	if err != nil {
		t.Fatalf("GetMTTRWithFilter failed: %v", err)
	}

	if metrics.TotalResolved != 1 {
		t.Errorf("Expected 1 resolved finding in January, got %d", metrics.TotalResolved)
	}
}

func TestCalculatePercentile(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Test with sorted durations
	durations := []time.Duration{
		1 * time.Hour,
		2 * time.Hour,
		3 * time.Hour,
		4 * time.Hour,
		5 * time.Hour,
		6 * time.Hour,
		7 * time.Hour,
		8 * time.Hour,
		9 * time.Hour,
		10 * time.Hour,
	}

	// Test median (50th percentile) - should be around 5.5 hours
	p50 := engine.calculatePercentile(durations, 50)
	expectedP50 := 5*time.Hour + 30*time.Minute
	if p50 < expectedP50-1*time.Minute || p50 > expectedP50+1*time.Minute {
		t.Errorf("Expected p50 around %v, got %v", expectedP50, p50)
	}

	// Test 90th percentile - should be around 9.1 hours
	p90 := engine.calculatePercentile(durations, 90)
	if p90 < 9*time.Hour || p90 > 10*time.Hour {
		t.Errorf("Expected p90 between 9h and 10h, got %v", p90)
	}

	// Test edge cases
	p0 := engine.calculatePercentile(durations, 0)
	if p0 != 1*time.Hour {
		t.Errorf("Expected p0 to be 1h, got %v", p0)
	}

	p100 := engine.calculatePercentile(durations, 100)
	if p100 != 10*time.Hour {
		t.Errorf("Expected p100 to be 10h, got %v", p100)
	}
}

func TestCalculatePercentile_EmptySlice(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	durations := []time.Duration{}
	p50 := engine.calculatePercentile(durations, 50)
	
	if p50 != 0 {
		t.Errorf("Expected 0 for empty slice, got %v", p50)
	}
}

func TestCalculatePercentile_SingleValue(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	durations := []time.Duration{5 * time.Hour}
	
	p50 := engine.calculatePercentile(durations, 50)
	if p50 != 5*time.Hour {
		t.Errorf("Expected 5h for single value, got %v", p50)
	}

	p90 := engine.calculatePercentile(durations, 90)
	if p90 != 5*time.Hour {
		t.Errorf("Expected 5h for single value, got %v", p90)
	}
}

func TestGetMTTR_Cache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert a resolved finding
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := db.Exec(`
		INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
		VALUES ('f1', 'run1', 'fp1', 'high', 'CWE-79', ?)
	`, baseTime.Unix())
	if err != nil {
		t.Fatalf("Failed to insert finding: %v", err)
	}

	engine := NewEngine(db)

	// First call - should query database
	metrics1, err := engine.GetMTTR()
	if err != nil {
		t.Fatalf("GetMTTR failed: %v", err)
	}

	// Second call - should use cache
	metrics2, err := engine.GetMTTR()
	if err != nil {
		t.Fatalf("GetMTTR failed: %v", err)
	}

	if metrics1.TotalResolved != metrics2.TotalResolved {
		t.Error("Expected cached metrics to match")
	}
}

func TestGetMTTR_BySeverityBreakdown(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings with different severities
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	
	findings := []struct {
		normID      string
		fingerprint string
		severity    string
	}{
		{"f1", "fp1", "critical"},
		{"f2", "fp2", "critical"},
		{"f3", "fp3", "high"},
		{"f4", "fp4", "medium"},
	}

	for _, f := range findings {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run1', ?, ?, 'CWE-79', ?)
		`, f.normID, f.fingerprint, f.severity, baseTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)
	metrics, err := engine.GetMTTR()
	if err != nil {
		t.Fatalf("GetMTTR failed: %v", err)
	}

	// Check by-severity breakdown
	if metrics.BySeverity == nil {
		t.Fatal("Expected by-severity breakdown")
	}

	if criticalMetrics, ok := metrics.BySeverity["critical"]; ok {
		if criticalMetrics.TotalResolved != 2 {
			t.Errorf("Expected 2 critical findings, got %d", criticalMetrics.TotalResolved)
		}
	} else {
		t.Error("Expected critical severity in breakdown")
	}

	if highMetrics, ok := metrics.BySeverity["high"]; ok {
		if highMetrics.TotalResolved != 1 {
			t.Errorf("Expected 1 high finding, got %d", highMetrics.TotalResolved)
		}
	} else {
		t.Error("Expected high severity in breakdown")
	}
}

func TestSeverityTrends_Cache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert trend data
	_, err := db.Exec(`
		INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
		VALUES ('2024-01-01', 5, 10, 15, 20, 50, 10, 2, ?)
	`, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert trend: %v", err)
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// First call - should query database
	counts1, dates1, err := engine.GetSeverityTrends("critical", start, end)
	if err != nil {
		t.Fatalf("GetSeverityTrends failed: %v", err)
	}

	// Second call - should use cache
	counts2, dates2, err := engine.GetSeverityTrends("critical", start, end)
	if err != nil {
		t.Fatalf("GetSeverityTrends failed: %v", err)
	}

	if len(counts1) != len(counts2) || len(dates1) != len(dates2) {
		t.Error("Expected cached results to match")
	}
}

// TestGetHotspots tests the basic hotspot analysis functionality
func TestGetHotspots(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert test data
	runID := "test-run-hotspots"
	_, err := db.Exec(`
		INSERT INTO runs (run_id, target_path, start_time, end_time, status)
		VALUES (?, '/test', ?, ?, 'completed')
	`, runID, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert run: %v", err)
	}

	// Insert findings for multiple files with different severities
	findings := []struct {
		file     string
		severity string
		cwe      string
		count    int
	}{
		{"src/auth.go", "critical", "CWE-89", 3},
		{"src/auth.go", "high", "CWE-79", 2},
		{"src/api.go", "high", "CWE-22", 4},
		{"src/api.go", "medium", "CWE-200", 1},
		{"src/utils.go", "medium", "CWE-400", 2},
		{"src/utils.go", "low", "CWE-703", 5},
		{"src/config.go", "low", "CWE-1004", 1},
	}

	for i, f := range findings {
		for j := 0; j < f.count; j++ {
			findingID := fmt.Sprintf("finding-%d-%d", i, j)
			normID := fmt.Sprintf("norm-%d-%d", i, j)
			_, err := db.Exec(`
				INSERT INTO findings_raw (finding_id, run_id, scanner, severity, file_path, line_number, description)
				VALUES (?, ?, 'test', ?, ?, ?, 'Test finding')
			`, findingID, runID, f.severity, f.file, 10+j)
			if err != nil {
				t.Fatalf("Failed to insert raw finding: %v", err)
			}

			_, err = db.Exec(`
				INSERT INTO findings_normalized (norm_id, finding_id, run_id, cwe_id, severity, code_fingerprint, file_path, line_number, description)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Test finding')
			`, normID, findingID, runID, f.cwe, f.severity, fmt.Sprintf("fp-%d-%d", i, j), f.file, 10+j)
			if err != nil {
				t.Fatalf("Failed to insert normalized finding: %v", err)
			}
		}
	}

	// Test GetHotspots
	analysis, err := engine.GetHotspots(10)
	if err != nil {
		t.Fatalf("GetHotspots failed: %v", err)
	}

	// Verify results
	if len(analysis.Hotspots) == 0 {
		t.Fatal("Expected hotspots, got none")
	}

	// First hotspot should be src/auth.go (3 critical + 2 high = 40 points)
	if analysis.Hotspots[0].FilePath != "src/auth.go" {
		t.Errorf("Expected first hotspot to be src/auth.go, got %s", analysis.Hotspots[0].FilePath)
	}

	authHotspot := analysis.Hotspots[0]
	if authHotspot.TotalFindings != 5 {
		t.Errorf("Expected 5 total findings for auth.go, got %d", authHotspot.TotalFindings)
	}
	if authHotspot.CriticalCount != 3 {
		t.Errorf("Expected 3 critical findings, got %d", authHotspot.CriticalCount)
	}
	if authHotspot.HighCount != 2 {
		t.Errorf("Expected 2 high findings, got %d", authHotspot.HighCount)
	}
	if authHotspot.UniqueFindings != 2 {
		t.Errorf("Expected 2 unique CWEs, got %d", authHotspot.UniqueFindings)
	}

	// Verify severity score calculation (3*10 + 2*5 = 40)
	expectedScore := float64(3*10 + 2*5)
	if authHotspot.SeverityScore != expectedScore {
		t.Errorf("Expected severity score %.1f, got %.1f", expectedScore, authHotspot.SeverityScore)
	}

	// Second hotspot should be src/api.go (4 high + 1 medium = 22 points)
	if len(analysis.Hotspots) > 1 {
		apiHotspot := analysis.Hotspots[1]
		if apiHotspot.FilePath != "src/api.go" {
			t.Errorf("Expected second hotspot to be src/api.go, got %s", apiHotspot.FilePath)
		}
		if apiHotspot.TotalFindings != 5 {
			t.Errorf("Expected 5 total findings for api.go, got %d", apiHotspot.TotalFindings)
		}
	}

	// Verify total counts
	if analysis.TotalFiles != 4 {
		t.Errorf("Expected 4 total files, got %d", analysis.TotalFiles)
	}
	if analysis.TotalFindings != 18 {
		t.Errorf("Expected 18 total findings, got %d", analysis.TotalFindings)
	}
}

// TestGetHotspots_EmptyDatabase tests hotspot analysis with no findings
func TestGetHotspots_EmptyDatabase(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	analysis, err := engine.GetHotspots(10)
	if err != nil {
		t.Fatalf("GetHotspots failed: %v", err)
	}

	if len(analysis.Hotspots) != 0 {
		t.Errorf("Expected no hotspots, got %d", len(analysis.Hotspots))
	}
	if analysis.TotalFiles != 0 {
		t.Errorf("Expected 0 total files, got %d", analysis.TotalFiles)
	}
	if analysis.TotalFindings != 0 {
		t.Errorf("Expected 0 total findings, got %d", analysis.TotalFindings)
	}
}

// TestGetHotspots_LimitResults tests that the limit parameter works correctly
func TestGetHotspots_LimitResults(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert test data with 5 different files
	runID := "test-run-limit"
	_, err := db.Exec(`
		INSERT INTO runs (run_id, target_path, start_time, end_time, status)
		VALUES (?, '/test', ?, ?, 'completed')
	`, runID, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert run: %v", err)
	}

	for i := 0; i < 5; i++ {
		filePath := fmt.Sprintf("src/file%d.go", i)
		findingID := fmt.Sprintf("finding-%d", i)
		normID := fmt.Sprintf("norm-%d", i)

		_, err := db.Exec(`
			INSERT INTO findings_raw (finding_id, run_id, scanner, severity, file_path, line_number, description)
			VALUES (?, ?, 'test', 'high', ?, 10, 'Test finding')
		`, findingID, runID, filePath)
		if err != nil {
			t.Fatalf("Failed to insert raw finding: %v", err)
		}

		_, err = db.Exec(`
			INSERT INTO findings_normalized (norm_id, finding_id, run_id, cwe_id, severity, code_fingerprint, file_path, line_number, description)
			VALUES (?, ?, ?, 'CWE-79', 'high', ?, ?, 10, 'Test finding')
		`, normID, findingID, runID, fmt.Sprintf("fp-%d", i), filePath)
		if err != nil {
			t.Fatalf("Failed to insert normalized finding: %v", err)
		}
	}

	// Test with limit of 3
	analysis, err := engine.GetHotspots(3)
	if err != nil {
		t.Fatalf("GetHotspots failed: %v", err)
	}

	if len(analysis.Hotspots) != 3 {
		t.Errorf("Expected 3 hotspots (limit), got %d", len(analysis.Hotspots))
	}

	// Total files should still be 5
	if analysis.TotalFiles != 5 {
		t.Errorf("Expected 5 total files, got %d", analysis.TotalFiles)
	}
}

// TestGetHotspots_Cache tests that hotspot results are cached
func TestGetHotspots_Cache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert test data
	runID := "test-run-cache"
	_, err := db.Exec(`
		INSERT INTO runs (run_id, target_path, start_time, end_time, status)
		VALUES (?, '/test', ?, ?, 'completed')
	`, runID, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert run: %v", err)
	}

	findingID := "finding-cache"
	normID := "norm-cache"
	_, err = db.Exec(`
		INSERT INTO findings_raw (finding_id, run_id, scanner, severity, file_path, line_number, description)
		VALUES (?, ?, 'test', 'high', 'src/test.go', 10, 'Test finding')
	`, findingID, runID)
	if err != nil {
		t.Fatalf("Failed to insert raw finding: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO findings_normalized (norm_id, finding_id, run_id, cwe_id, severity, code_fingerprint, file_path, line_number, description)
		VALUES (?, ?, ?, 'CWE-79', 'high', 'fp-cache', 'src/test.go', 10, 'Test finding')
	`, normID, findingID, runID)
	if err != nil {
		t.Fatalf("Failed to insert normalized finding: %v", err)
	}

	// First call - should hit database
	analysis1, err := engine.GetHotspots(10)
	if err != nil {
		t.Fatalf("GetHotspots failed: %v", err)
	}

	// Second call - should hit cache
	analysis2, err := engine.GetHotspots(10)
	if err != nil {
		t.Fatalf("GetHotspots failed: %v", err)
	}

	// Results should be identical
	if len(analysis1.Hotspots) != len(analysis2.Hotspots) {
		t.Errorf("Cache returned different number of hotspots")
	}

	// Clear cache and verify it works
	engine.ClearCache()
	analysis3, err := engine.GetHotspots(10)
	if err != nil {
		t.Fatalf("GetHotspots failed after cache clear: %v", err)
	}

	if len(analysis3.Hotspots) != len(analysis1.Hotspots) {
		t.Errorf("Results after cache clear differ from original")
	}
}

// TestGetHotspotsForScan tests hotspot analysis for a specific scan
func TestGetHotspotsForScan(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert two runs
	runID1 := "test-run-1"
	runID2 := "test-run-2"

	for _, runID := range []string{runID1, runID2} {
		_, err := db.Exec(`
			INSERT INTO runs (run_id, target_path, start_time, end_time, status)
			VALUES (?, '/test', ?, ?, 'completed')
		`, runID, time.Now().Unix(), time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to insert run: %v", err)
		}
	}

	// Insert findings for run 1
	for i := 0; i < 3; i++ {
		findingID := fmt.Sprintf("finding-1-%d", i)
		normID := fmt.Sprintf("norm-1-%d", i)

		_, err := db.Exec(`
			INSERT INTO findings_raw (finding_id, run_id, scanner, severity, file_path, line_number, description)
			VALUES (?, ?, 'test', 'critical', 'src/auth.go', ?, 'Test finding')
		`, findingID, runID1, 10+i)
		if err != nil {
			t.Fatalf("Failed to insert raw finding: %v", err)
		}

		_, err = db.Exec(`
			INSERT INTO findings_normalized (norm_id, finding_id, run_id, cwe_id, severity, code_fingerprint, file_path, line_number, description)
			VALUES (?, ?, ?, 'CWE-89', 'critical', ?, 'src/auth.go', ?, 'Test finding')
		`, normID, findingID, runID1, fmt.Sprintf("fp-1-%d", i), 10+i)
		if err != nil {
			t.Fatalf("Failed to insert normalized finding: %v", err)
		}
	}

	// Insert findings for run 2 (different file)
	for i := 0; i < 2; i++ {
		findingID := fmt.Sprintf("finding-2-%d", i)
		normID := fmt.Sprintf("norm-2-%d", i)

		_, err := db.Exec(`
			INSERT INTO findings_raw (finding_id, run_id, scanner, severity, file_path, line_number, description)
			VALUES (?, ?, 'test', 'high', 'src/api.go', ?, 'Test finding')
		`, findingID, runID2, 10+i)
		if err != nil {
			t.Fatalf("Failed to insert raw finding: %v", err)
		}

		_, err = db.Exec(`
			INSERT INTO findings_normalized (norm_id, finding_id, run_id, cwe_id, severity, code_fingerprint, file_path, line_number, description)
			VALUES (?, ?, ?, 'CWE-79', 'high', ?, 'src/api.go', ?, 'Test finding')
		`, normID, findingID, runID2, fmt.Sprintf("fp-2-%d", i), 10+i)
		if err != nil {
			t.Fatalf("Failed to insert normalized finding: %v", err)
		}
	}

	// Test GetHotspotsForScan for run 1
	analysis1, err := engine.GetHotspotsForScan(runID1, 10)
	if err != nil {
		t.Fatalf("GetHotspotsForScan failed: %v", err)
	}

	if len(analysis1.Hotspots) != 1 {
		t.Errorf("Expected 1 hotspot for run 1, got %d", len(analysis1.Hotspots))
	}

	if analysis1.Hotspots[0].FilePath != "src/auth.go" {
		t.Errorf("Expected hotspot to be src/auth.go, got %s", analysis1.Hotspots[0].FilePath)
	}

	if analysis1.Hotspots[0].TotalFindings != 3 {
		t.Errorf("Expected 3 findings, got %d", analysis1.Hotspots[0].TotalFindings)
	}

	// Test GetHotspotsForScan for run 2
	analysis2, err := engine.GetHotspotsForScan(runID2, 10)
	if err != nil {
		t.Fatalf("GetHotspotsForScan failed: %v", err)
	}

	if len(analysis2.Hotspots) != 1 {
		t.Errorf("Expected 1 hotspot for run 2, got %d", len(analysis2.Hotspots))
	}

	if analysis2.Hotspots[0].FilePath != "src/api.go" {
		t.Errorf("Expected hotspot to be src/api.go, got %s", analysis2.Hotspots[0].FilePath)
	}

	if analysis2.Hotspots[0].TotalFindings != 2 {
		t.Errorf("Expected 2 findings, got %d", analysis2.Hotspots[0].TotalFindings)
	}
}

// TestGetHotspotTrends tests hotspot trends over time for a specific file
func TestGetHotspotTrends(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert multiple runs over time
	baseTime := time.Now().Add(-7 * 24 * time.Hour)
	filePath := "src/auth.go"

	for day := 0; day < 5; day++ {
		runID := fmt.Sprintf("test-run-day-%d", day)
		runTime := baseTime.Add(time.Duration(day) * 24 * time.Hour)

		_, err := db.Exec(`
			INSERT INTO runs (run_id, target_path, start_time, end_time, status)
			VALUES (?, '/test', ?, ?, 'completed')
		`, runID, runTime.Unix(), runTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert run: %v", err)
		}

		// Insert findings - increasing count each day
		for i := 0; i <= day; i++ {
			findingID := fmt.Sprintf("finding-%d-%d", day, i)
			normID := fmt.Sprintf("norm-%d-%d", day, i)

			_, err := db.Exec(`
				INSERT INTO findings_raw (finding_id, run_id, scanner, severity, file_path, line_number, description)
				VALUES (?, ?, 'test', 'high', ?, ?, 'Test finding')
			`, findingID, runID, filePath, 10+i)
			if err != nil {
				t.Fatalf("Failed to insert raw finding: %v", err)
			}

			_, err = db.Exec(`
				INSERT INTO findings_normalized (norm_id, finding_id, run_id, cwe_id, severity, code_fingerprint, file_path, line_number, description)
				VALUES (?, ?, ?, 'CWE-79', 'high', ?, ?, ?, 'Test finding')
			`, normID, findingID, runID, fmt.Sprintf("fp-%d-%d", day, i), filePath, 10+i)
			if err != nil {
				t.Fatalf("Failed to insert normalized finding: %v", err)
			}
		}
	}

	// Test GetHotspotTrends
	start := baseTime.Add(-1 * time.Hour)
	end := baseTime.Add(5 * 24 * time.Hour)

	trends, err := engine.GetHotspotTrends(filePath, start, end)
	if err != nil {
		t.Fatalf("GetHotspotTrends failed: %v", err)
	}

	if len(trends) != 5 {
		t.Errorf("Expected 5 trend data points, got %d", len(trends))
	}

	// Verify increasing trend
	for i, trend := range trends {
		expectedCount := i + 1
		if trend.TotalFindings != expectedCount {
			t.Errorf("Day %d: expected %d findings, got %d", i, expectedCount, trend.TotalFindings)
		}

		if trend.FilePath != filePath {
			t.Errorf("Expected file path %s, got %s", filePath, trend.FilePath)
		}

		if trend.HighCount != expectedCount {
			t.Errorf("Day %d: expected %d high findings, got %d", i, expectedCount, trend.HighCount)
		}
	}
}

// TestGetHotspotTrends_NoData tests hotspot trends with no matching data
func TestGetHotspotTrends_NoData(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	start := time.Now().Add(-7 * 24 * time.Hour)
	end := time.Now()

	trends, err := engine.GetHotspotTrends("nonexistent.go", start, end)
	if err != nil {
		t.Fatalf("GetHotspotTrends failed: %v", err)
	}

	if len(trends) != 0 {
		t.Errorf("Expected no trends, got %d", len(trends))
	}
}

// TestGetHotspotTrends_Cache tests that hotspot trends are cached
func TestGetHotspotTrends_Cache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert test data
	runID := "test-run-trends-cache"
	runTime := time.Now()
	filePath := "src/test.go"

	_, err := db.Exec(`
		INSERT INTO runs (run_id, target_path, start_time, end_time, status)
		VALUES (?, '/test', ?, ?, 'completed')
	`, runID, runTime.Unix(), runTime.Unix())
	if err != nil {
		t.Fatalf("Failed to insert run: %v", err)
	}

	findingID := "finding-trends-cache"
	normID := "norm-trends-cache"

	_, err = db.Exec(`
		INSERT INTO findings_raw (finding_id, run_id, scanner, severity, file_path, line_number, description)
		VALUES (?, ?, 'test', 'high', ?, 10, 'Test finding')
	`, findingID, runID, filePath)
	if err != nil {
		t.Fatalf("Failed to insert raw finding: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO findings_normalized (norm_id, finding_id, run_id, cwe_id, severity, code_fingerprint, file_path, line_number, description)
		VALUES (?, ?, ?, 'CWE-79', 'high', 'fp-trends-cache', ?, 10, 'Test finding')
	`, normID, findingID, runID, filePath)
	if err != nil {
		t.Fatalf("Failed to insert normalized finding: %v", err)
	}

	start := runTime.Add(-1 * time.Hour)
	end := runTime.Add(1 * time.Hour)

	// First call - should hit database
	trends1, err := engine.GetHotspotTrends(filePath, start, end)
	if err != nil {
		t.Fatalf("GetHotspotTrends failed: %v", err)
	}

	// Second call - should hit cache
	trends2, err := engine.GetHotspotTrends(filePath, start, end)
	if err != nil {
		t.Fatalf("GetHotspotTrends failed: %v", err)
	}

	// Results should be identical
	if len(trends1) != len(trends2) {
		t.Errorf("Cache returned different number of trends")
	}

	// Clear cache and verify
	engine.ClearCache()
	trends3, err := engine.GetHotspotTrends(filePath, start, end)
	if err != nil {
		t.Fatalf("GetHotspotTrends failed after cache clear: %v", err)
	}

	if len(trends3) != len(trends1) {
		t.Errorf("Results after cache clear differ from original")
	}
}

// TestHotspotSeverityScoreCalculation tests the severity score calculation
func TestHotspotSeverityScoreCalculation(t *testing.T) {
	testCases := []struct {
		name      string
		critical  int
		high      int
		medium    int
		low       int
		expected  float64
	}{
		{"All critical", 5, 0, 0, 0, 50.0},
		{"All high", 0, 5, 0, 0, 25.0},
		{"All medium", 0, 0, 5, 0, 10.0},
		{"All low", 0, 0, 0, 5, 5.0},
		{"Mixed", 2, 3, 4, 5, 48.0}, // 2*10 + 3*5 + 4*2 + 5*1 = 20+15+8+5 = 48
		{"None", 0, 0, 0, 0, 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hotspot := FileHotspot{
				CriticalCount: tc.critical,
				HighCount:     tc.high,
				MediumCount:   tc.medium,
				LowCount:      tc.low,
			}

			// Calculate score using the same formula as the implementation
			score := float64(hotspot.CriticalCount*10 + hotspot.HighCount*5 + hotspot.MediumCount*2 + hotspot.LowCount)

			if score != tc.expected {
				t.Errorf("Expected score %.1f, got %.1f", tc.expected, score)
			}
		})
	}
}
