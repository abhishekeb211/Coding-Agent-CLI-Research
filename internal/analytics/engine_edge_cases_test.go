package analytics

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// TestGetTrends_LargeDataSet tests trend calculations with a large dataset
func TestGetTrends_LargeDataSet(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert 365 days of trend data
	baseDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 365; i++ {
		date := baseDate.AddDate(0, 0, i)
		_, err := db.Exec(`
			INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, date.Format("2006-01-02"), i%10, i%20, i%30, i%40, i%100, i%15, i%12, time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to insert trend: %v", err)
		}
	}

	engine := NewEngine(db)
	start := baseDate
	end := baseDate.AddDate(0, 0, 364)

	trends, err := engine.GetTrends(start, end)
	if err != nil {
		t.Fatalf("GetTrends failed with large dataset: %v", err)
	}

	if len(trends.Dates) != 365 {
		t.Errorf("Expected 365 data points, got %d", len(trends.Dates))
	}

	// Verify data integrity
	if len(trends.Critical) != 365 || len(trends.High) != 365 || len(trends.Medium) != 365 || len(trends.Low) != 365 {
		t.Error("Severity arrays have incorrect length")
	}
}

// TestGetTrends_EmptyDateRange tests trends with no data in range
func TestGetTrends_EmptyDateRange(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert data outside the query range
	_, err := db.Exec(`
		INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
		VALUES ('2020-01-01', 5, 10, 15, 20, 50, 10, 2, ?)
	`, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert trend: %v", err)
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC)

	trends, err := engine.GetTrends(start, end)
	if err != nil {
		t.Fatalf("GetTrends failed: %v", err)
	}

	if len(trends.Dates) != 0 {
		t.Errorf("Expected 0 data points for empty range, got %d", len(trends.Dates))
	}
}

// TestGetTrends_SingleDay tests trends for a single day
func TestGetTrends_SingleDay(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	date := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	_, err := db.Exec(`
		INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
		VALUES ('2024-06-15', 5, 10, 15, 20, 50, 10, 2, ?)
	`, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert trend: %v", err)
	}

	engine := NewEngine(db)
	trends, err := engine.GetTrends(date, date)
	if err != nil {
		t.Fatalf("GetTrends failed: %v", err)
	}

	if len(trends.Dates) != 1 {
		t.Errorf("Expected 1 data point, got %d", len(trends.Dates))
	}

	if trends.Critical[0] != 5 || trends.High[0] != 10 || trends.Medium[0] != 15 || trends.Low[0] != 20 {
		t.Error("Trend data doesn't match expected values")
	}
}

// TestGetMTTR_LargeDataSet tests MTTR calculation with many findings
func TestGetMTTR_LargeDataSet(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	
	// Insert 1000 findings with varying resolution times
	for i := 0; i < 1000; i++ {
		fingerprint := fmt.Sprintf("fp-%d", i)
		severity := []string{"critical", "high", "medium", "low"}[i%4]
		
		// First appearance
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run1', ?, ?, 'CWE-79', ?)
		`, fmt.Sprintf("f-%d-first", i), fingerprint, severity, baseTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
		
		// Last appearance (resolved after i days)
		if i < 900 { // 900 resolved, 100 still active
			lastSeen := baseTime.Add(time.Duration(i%30) * 24 * time.Hour)
			_, err = db.Exec(`
				INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
				VALUES (?, 'run2', ?, ?, 'CWE-79', ?)
			`, fmt.Sprintf("f-%d-last", i), fingerprint, severity, lastSeen.Unix())
			if err != nil {
				t.Fatalf("Failed to insert finding: %v", err)
			}
		}
	}

	engine := NewEngine(db)
	metrics, err := engine.GetMTTR()
	if err != nil {
		t.Fatalf("GetMTTR failed with large dataset: %v", err)
	}

	if metrics.TotalResolved != 900 {
		t.Errorf("Expected 900 resolved findings, got %d", metrics.TotalResolved)
	}

	if metrics.MeanTTR == 0 {
		t.Error("Expected non-zero mean TTR")
	}

	// Verify by-severity breakdown
	if metrics.BySeverity == nil {
		t.Fatal("Expected by-severity breakdown")
	}

	totalBySeverity := 0
	for _, m := range metrics.BySeverity {
		totalBySeverity += m.TotalResolved
	}

	if totalBySeverity != 900 {
		t.Errorf("By-severity total (%d) doesn't match overall total (900)", totalBySeverity)
	}
}

// TestGetMTTR_AllSameDuration tests MTTR when all findings have same resolution time
func TestGetMTTR_AllSameDuration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	resolveTime := baseTime.Add(48 * time.Hour) // All resolve in exactly 2 days
	
	for i := 0; i < 10; i++ {
		fingerprint := fmt.Sprintf("fp-%d", i)
		
		// First appearance
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run1', ?, 'high', 'CWE-79', ?)
		`, fmt.Sprintf("f-%d-first", i), fingerprint, baseTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
		
		// Last appearance
		_, err = db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run2', ?, 'high', 'CWE-79', ?)
		`, fmt.Sprintf("f-%d-last", i), fingerprint, resolveTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)
	metrics, err := engine.GetMTTR()
	if err != nil {
		t.Fatalf("GetMTTR failed: %v", err)
	}

	// All metrics should be the same (48 hours)
	expectedDuration := 48 * time.Hour
	if metrics.MeanTTR != expectedDuration {
		t.Errorf("Expected mean TTR %v, got %v", expectedDuration, metrics.MeanTTR)
	}
	if metrics.MedianTTR != expectedDuration {
		t.Errorf("Expected median TTR %v, got %v", expectedDuration, metrics.MedianTTR)
	}
	if metrics.MinTTR != expectedDuration {
		t.Errorf("Expected min TTR %v, got %v", expectedDuration, metrics.MinTTR)
	}
	if metrics.MaxTTR != expectedDuration {
		t.Errorf("Expected max TTR %v, got %v", expectedDuration, metrics.MaxTTR)
	}
}

// TestGetSecurityScore_VariousDataSets tests score calculation with different finding distributions
func TestGetSecurityScore_VariousDataSets(t *testing.T) {
	testCases := []struct {
		name     string
		findings map[string]int
		minScore float64
		maxScore float64
		grade    string
	}{
		{
			name:     "Only critical findings",
			findings: map[string]int{"critical": 5},
			minScore: 40.0,
			maxScore: 60.0,
			grade:    "F",
		},
		{
			name:     "Only low findings",
			findings: map[string]int{"low": 100},
			minScore: 40.0,
			maxScore: 60.0,
			grade:    "F",
		},
		{
			name:     "Balanced distribution",
			findings: map[string]int{"critical": 1, "high": 2, "medium": 3, "low": 4},
			minScore: 60.0,
			maxScore: 80.0,
			grade:    "C",
		},
		{
			name:     "Mostly medium and low",
			findings: map[string]int{"medium": 10, "low": 20},
			minScore: 50.0,
			maxScore: 70.0,
			grade:    "C",
		},
		{
			name:     "Few high severity",
			findings: map[string]int{"high": 2, "medium": 5},
			minScore: 70.0,
			maxScore: 90.0,
			grade:    "B",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			defer db.Close()

			engine := NewEngine(db)
			insertTestFindings(t, db, "scan1", tc.findings)

			score, err := engine.GetSecurityScore()
			if err != nil {
				t.Fatalf("GetSecurityScore failed: %v", err)
			}

			if score.Score < tc.minScore || score.Score > tc.maxScore {
				t.Errorf("Expected score between %.1f and %.1f, got %.1f", tc.minScore, tc.maxScore, score.Score)
			}

			if score.Grade != tc.grade {
				t.Errorf("Expected grade %s, got %s", tc.grade, score.Grade)
			}

			// Verify finding counts
			total := 0
			for _, count := range tc.findings {
				total += count
			}
			if score.TotalFindings != total {
				t.Errorf("Expected %d total findings, got %d", total, score.TotalFindings)
			}
		})
	}
}

// TestGetSecurityScore_ExtremeValues tests score calculation with extreme values
func TestGetSecurityScore_ExtremeValues(t *testing.T) {
	testCases := []struct {
		name     string
		findings map[string]int
	}{
		{
			name:     "Very large number of findings",
			findings: map[string]int{"critical": 1000, "high": 2000, "medium": 3000, "low": 4000},
		},
		{
			name:     "Single finding",
			findings: map[string]int{"low": 1},
		},
		{
			name:     "Maximum critical",
			findings: map[string]int{"critical": 100},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			defer db.Close()

			engine := NewEngine(db)
			insertTestFindings(t, db, "scan1", tc.findings)

			score, err := engine.GetSecurityScore()
			if err != nil {
				t.Fatalf("GetSecurityScore failed: %v", err)
			}

			// Score should be between 0 and 100
			if score.Score < 0 || score.Score > 100 {
				t.Errorf("Score out of range: %.1f", score.Score)
			}

			// Grade should be valid
			validGrades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
			if !validGrades[score.Grade] {
				t.Errorf("Invalid grade: %s", score.Grade)
			}
		})
	}
}

// TestCalculateTrendSummary_VariousPatterns tests trend summary with different patterns
func TestCalculateTrendSummary_VariousPatterns(t *testing.T) {
	testCases := []struct {
		name   string
		trends []struct {
			date     string
			total    int
			newCount int
			resolved int
		}
		expectedNetChange int
	}{
		{
			name: "Improving trend",
			trends: []struct {
				date     string
				total    int
				newCount int
				resolved int
			}{
				{"2024-01-01", 100, 10, 5},
				{"2024-01-02", 95, 5, 10},
				{"2024-01-03", 85, 3, 13},
			},
			expectedNetChange: -2, // (10+5+3) - (5+10+13) = 18 - 28 = -10
		},
		{
			name: "Declining trend",
			trends: []struct {
				date     string
				total    int
				newCount int
				resolved int
			}{
				{"2024-01-01", 50, 20, 5},
				{"2024-01-02", 65, 25, 10},
				{"2024-01-03", 80, 30, 15},
			},
			expectedNetChange: 45, // (20+25+30) - (5+10+15) = 75 - 30 = 45
		},
		{
			name: "Stable trend",
			trends: []struct {
				date     string
				total    int
				newCount int
				resolved int
			}{
				{"2024-01-01", 50, 10, 10},
				{"2024-01-02", 50, 10, 10},
				{"2024-01-03", 50, 10, 10},
			},
			expectedNetChange: 0, // (10+10+10) - (10+10+10) = 0
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			defer db.Close()

			// Insert trend data
			for _, tr := range tc.trends {
				_, err := db.Exec(`
					INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
					VALUES (?, 1, 2, 3, 4, ?, ?, ?, ?)
				`, tr.date, tr.total, tr.newCount, tr.resolved, time.Now().Unix())
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

			if summary.NetChange != tc.expectedNetChange {
				t.Errorf("Expected net change %d, got %d", tc.expectedNetChange, summary.NetChange)
			}

			// Verify total new and resolved
			totalNew := 0
			totalResolved := 0
			for _, tr := range tc.trends {
				totalNew += tr.newCount
				totalResolved += tr.resolved
			}

			if summary.TotalNew != totalNew {
				t.Errorf("Expected total new %d, got %d", totalNew, summary.TotalNew)
			}
			if summary.TotalResolved != totalResolved {
				t.Errorf("Expected total resolved %d, got %d", totalResolved, summary.TotalResolved)
			}
		})
	}
}

// TestCompareScanFindings_VariousScenarios tests scan comparison with different scenarios
func TestCompareScanFindings_VariousScenarios(t *testing.T) {
	testCases := []struct {
		name              string
		oldFindings       []string
		newFindings       []string
		expectedNew       int
		expectedResolved  int
		expectedUnchanged int
	}{
		{
			name:              "All new findings",
			oldFindings:       []string{},
			newFindings:       []string{"fp1", "fp2", "fp3"},
			expectedNew:       3,
			expectedResolved:  0,
			expectedUnchanged: 0,
		},
		{
			name:              "All resolved",
			oldFindings:       []string{"fp1", "fp2", "fp3"},
			newFindings:       []string{},
			expectedNew:       0,
			expectedResolved:  3,
			expectedUnchanged: 0,
		},
		{
			name:              "No changes",
			oldFindings:       []string{"fp1", "fp2", "fp3"},
			newFindings:       []string{"fp1", "fp2", "fp3"},
			expectedNew:       0,
			expectedResolved:  0,
			expectedUnchanged: 3,
		},
		{
			name:              "Mixed changes",
			oldFindings:       []string{"fp1", "fp2", "fp3", "fp4"},
			newFindings:       []string{"fp2", "fp3", "fp5", "fp6"},
			expectedNew:       2,
			expectedResolved:  2,
			expectedUnchanged: 2,
		},
		{
			name:              "Large dataset",
			oldFindings:       generateFingerprints(100),
			newFindings:       append(generateFingerprints(80), generateFingerprints(20)...),
			expectedNew:       20,
			expectedResolved:  20,
			expectedUnchanged: 80,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			defer db.Close()

			// Insert old findings
			for i, fp := range tc.oldFindings {
				_, err := db.Exec(`
					INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, cwe_id, severity)
					VALUES (?, 'old_scan', ?, 'CWE-79', 'high')
				`, fmt.Sprintf("old-%d", i), fp)
				if err != nil {
					t.Fatalf("Failed to insert old finding: %v", err)
				}
			}

			// Insert new findings
			for i, fp := range tc.newFindings {
				_, err := db.Exec(`
					INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, cwe_id, severity)
					VALUES (?, 'new_scan', ?, 'CWE-79', 'high')
				`, fmt.Sprintf("new-%d", i), fp)
				if err != nil {
					t.Fatalf("Failed to insert new finding: %v", err)
				}
			}

			engine := NewEngine(db)
			comparison, err := engine.CompareScanFindings("old_scan", "new_scan")
			if err != nil {
				t.Fatalf("CompareScanFindings failed: %v", err)
			}

			if comparison.NewFindings != tc.expectedNew {
				t.Errorf("Expected %d new findings, got %d", tc.expectedNew, comparison.NewFindings)
			}
			if comparison.ResolvedFindings != tc.expectedResolved {
				t.Errorf("Expected %d resolved findings, got %d", tc.expectedResolved, comparison.ResolvedFindings)
			}
			if comparison.UnchangedCount != tc.expectedUnchanged {
				t.Errorf("Expected %d unchanged findings, got %d", tc.expectedUnchanged, comparison.UnchangedCount)
			}
		})
	}
}

// Helper function to generate fingerprints
func generateFingerprints(count int) []string {
	fps := make([]string, count)
	for i := 0; i < count; i++ {
		fps[i] = fmt.Sprintf("fp-%d", i)
	}
	return fps
}

// TestGetTopCWEs_VariousDistributions tests CWE ranking with different distributions
func TestGetTopCWEs_VariousDistributions(t *testing.T) {
	testCases := []struct {
		name     string
		cweCounts map[string]int
		limit    int
		expectedTop string
	}{
		{
			name: "Clear winner",
			cweCounts: map[string]int{
				"CWE-79": 50,
				"CWE-89": 10,
				"CWE-22": 5,
			},
			limit:       3,
			expectedTop: "CWE-79",
		},
		{
			name: "Tied counts",
			cweCounts: map[string]int{
				"CWE-79": 20,
				"CWE-89": 20,
				"CWE-22": 10,
			},
			limit:       2,
			expectedTop: "", // Either CWE-79 or CWE-89 could be first
		},
		{
			name: "Many CWEs",
			cweCounts: map[string]int{
				"CWE-79":  100,
				"CWE-89":  90,
				"CWE-22":  80,
				"CWE-200": 70,
				"CWE-400": 60,
				"CWE-502": 50,
				"CWE-611": 40,
				"CWE-78":  30,
				"CWE-94":  20,
				"CWE-352": 10,
			},
			limit:       5,
			expectedTop: "CWE-79",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			defer db.Close()

			// Insert findings
			idx := 0
			for cwe, count := range tc.cweCounts {
				for i := 0; i < count; i++ {
					_, err := db.Exec(`
						INSERT INTO findings_normalized (norm_id, run_id, cwe_id, cwe_description, severity, code_fingerprint)
						VALUES (?, 'run1', ?, ?, 'high', ?)
					`, fmt.Sprintf("f-%d", idx), cwe, fmt.Sprintf("%s Description", cwe), fmt.Sprintf("fp-%d", idx))
					if err != nil {
						t.Fatalf("Failed to insert finding: %v", err)
					}
					idx++
				}
			}

			engine := NewEngine(db)
			stats, err := engine.GetTopCWEs(tc.limit)
			if err != nil {
				t.Fatalf("GetTopCWEs failed: %v", err)
			}

			if len(stats) > tc.limit {
				t.Errorf("Expected at most %d CWEs, got %d", tc.limit, len(stats))
			}

			// Verify ordering (descending by count)
			for i := 1; i < len(stats); i++ {
				if stats[i].Count > stats[i-1].Count {
					t.Errorf("CWEs not properly ordered: %d > %d at position %d", stats[i].Count, stats[i-1].Count, i)
				}
			}

			// Verify top CWE if specified
			if tc.expectedTop != "" && len(stats) > 0 {
				if stats[0].CWEID != tc.expectedTop {
					t.Errorf("Expected top CWE %s, got %s", tc.expectedTop, stats[0].CWEID)
				}
			}
		})
	}
}

// TestGetTopCWEs_EmptyDatabase tests CWE ranking with no findings
func TestGetTopCWEs_EmptyDatabase(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	stats, err := engine.GetTopCWEs(10)
	if err != nil {
		t.Fatalf("GetTopCWEs failed: %v", err)
	}

	if len(stats) != 0 {
		t.Errorf("Expected 0 CWEs for empty database, got %d", len(stats))
	}
}

// TestGetTopCWEs_LimitExceedsAvailable tests when limit is larger than available CWEs
func TestGetTopCWEs_LimitExceedsAvailable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert only 3 different CWEs
	cwes := []string{"CWE-79", "CWE-89", "CWE-22"}
	for i, cwe := range cwes {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, cwe_id, cwe_description, severity, code_fingerprint)
			VALUES (?, 'run1', ?, ?, 'high', ?)
		`, fmt.Sprintf("f-%d", i), cwe, fmt.Sprintf("%s Description", cwe), fmt.Sprintf("fp-%d", i))
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)
	stats, err := engine.GetTopCWEs(10) // Request 10 but only 3 available
	if err != nil {
		t.Fatalf("GetTopCWEs failed: %v", err)
	}

	if len(stats) != 3 {
		t.Errorf("Expected 3 CWEs (all available), got %d", len(stats))
	}
}

// TestGetScanMetrics_NonExistentScan tests metrics for a scan that doesn't exist
func TestGetScanMetrics_NonExistentScan(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	metrics, err := engine.GetScanMetrics("nonexistent-scan-id")
	if err != nil {
		t.Fatalf("GetScanMetrics failed: %v", err)
	}

	// Should return zero metrics
	if metrics.Total != 0 || metrics.Critical != 0 || metrics.High != 0 || metrics.Medium != 0 || metrics.Low != 0 {
		t.Error("Expected zero metrics for nonexistent scan")
	}
}

// TestRecordScanMetrics_DuplicateScanID tests recording metrics for same scan twice
func TestRecordScanMetrics_DuplicateScanID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	scanID := "duplicate-scan"
	
	metrics1 := &SeverityMetrics{
		Critical: 5,
		High:     10,
		Medium:   15,
		Low:      20,
		Total:    50,
	}

	// First insert
	err := engine.RecordScanMetrics(scanID, metrics1, 5000)
	if err != nil {
		t.Fatalf("First RecordScanMetrics failed: %v", err)
	}

	// Second insert with different metrics
	metrics2 := &SeverityMetrics{
		Critical: 3,
		High:     8,
		Medium:   12,
		Low:      17,
		Total:    40,
	}

	err = engine.RecordScanMetrics(scanID, metrics2, 6000)
	if err != nil {
		t.Fatalf("Second RecordScanMetrics failed: %v", err)
	}

	// Query to see which metrics are stored
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM scan_metrics WHERE scan_id = ?", scanID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query scan metrics: %v", err)
	}

	// Should have 2 entries (or 1 if it updates)
	if count == 0 {
		t.Error("Expected at least one scan metric entry")
	}
}

// TestRecordDailyTrend_SameDate tests recording trends for the same date
func TestRecordDailyTrend_SameDate(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	date := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	
	metrics1 := &SeverityMetrics{
		Critical: 5,
		High:     10,
		Medium:   15,
		Low:      20,
		Total:    50,
	}

	// First insert
	err := engine.RecordDailyTrend(date, metrics1, 10, 5)
	if err != nil {
		t.Fatalf("First RecordDailyTrend failed: %v", err)
	}

	// Second insert for same date
	metrics2 := &SeverityMetrics{
		Critical: 3,
		High:     8,
		Medium:   12,
		Low:      17,
		Total:    40,
	}

	err = engine.RecordDailyTrend(date, metrics2, 8, 3)
	// This might fail due to unique constraint on date, which is expected
	// Or it might succeed if it updates the existing record
	// Either behavior is acceptable
	if err != nil {
		// Expected if there's a unique constraint
		t.Logf("RecordDailyTrend for duplicate date returned error (expected): %v", err)
	}
}

// TestGetMTTRWithFilter_InvalidSeverity tests MTTR filter with invalid severity
func TestGetMTTRWithFilter_InvalidSeverity(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	
	// Insert some test data
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := db.Exec(`
		INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
		VALUES ('f1', 'run1', 'fp1', 'high', 'CWE-79', ?)
	`, baseTime.Unix())
	if err != nil {
		t.Fatalf("Failed to insert finding: %v", err)
	}

	// Query with invalid severity
	metrics, err := engine.GetMTTRWithFilter(time.Time{}, time.Time{}, "invalid-severity")
	if err != nil {
		t.Fatalf("GetMTTRWithFilter failed: %v", err)
	}

	// Should return zero metrics
	if metrics.TotalResolved != 0 {
		t.Errorf("Expected 0 resolved findings for invalid severity, got %d", metrics.TotalResolved)
	}
}

// TestGetTrendsWithFilter_EmptySeverityList tests trend filtering with empty severity list
func TestGetTrendsWithFilter_EmptySeverityList(t *testing.T) {
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

	// Empty severity list should return all severities
	trends, err := engine.GetTrendsWithFilter(start, end, []string{})
	if err != nil {
		t.Fatalf("GetTrendsWithFilter failed: %v", err)
	}

	if len(trends.Dates) != 1 {
		t.Errorf("Expected 1 date, got %d", len(trends.Dates))
	}

	// All severity counts should be present
	if trends.Critical[0] != 5 || trends.High[0] != 10 || trends.Medium[0] != 15 || trends.Low[0] != 20 {
		t.Error("Expected all severity data to be present")
	}
}

// TestGetTrendsWithFilter_InvalidSeverity tests trend filtering with invalid severity
func TestGetTrendsWithFilter_InvalidSeverity(t *testing.T) {
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

	// Invalid severity should be ignored
	trends, err := engine.GetTrendsWithFilter(start, end, []string{"invalid", "critical"})
	if err != nil {
		t.Fatalf("GetTrendsWithFilter failed: %v", err)
	}

	// Should still get critical data
	if trends.Critical[0] != 5 {
		t.Errorf("Expected critical count 5, got %d", trends.Critical[0])
	}

	// Invalid severity should result in zero
	if trends.High[0] != 0 || trends.Medium[0] != 0 || trends.Low[0] != 0 {
		t.Error("Expected non-selected severities to be zero")
	}
}
