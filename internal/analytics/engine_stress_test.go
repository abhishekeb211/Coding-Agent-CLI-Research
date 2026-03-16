package analytics

import (
	"fmt"
	"testing"
	"time"
)

// TestGetTrends_ConcurrentAccess tests concurrent access to trend data
func TestGetTrends_ConcurrentAccess(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert test data
	for i := 0; i < 10; i++ {
		date := time.Date(2024, 1, i+1, 0, 0, 0, 0, time.UTC)
		_, err := db.Exec(`
			INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, date.Format("2006-01-02"), i, i*2, i*3, i*4, i*10, i, i/2, time.Now().Unix())
		if err != nil {
			t.Fatalf("Failed to insert trend: %v", err)
		}
	}

	engine := NewEngine(db)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC)

	// Run multiple concurrent queries
	done := make(chan bool)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, err := engine.GetTrends(start, end)
			if err != nil {
				errors <- err
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

// TestGetMTTR_ConcurrentAccess tests concurrent MTTR calculations
func TestGetMTTR_ConcurrentAccess(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert test findings
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, severity, cwe_id, created_at)
			VALUES (?, 'run1', ?, 'high', 'CWE-79', ?)
		`, fmt.Sprintf("f-%d", i), fmt.Sprintf("fp-%d", i), baseTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert finding: %v", err)
		}
	}

	engine := NewEngine(db)

	// Run multiple concurrent MTTR calculations
	done := make(chan bool)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, err := engine.GetMTTR()
			if err != nil {
				errors <- err
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent MTTR calculation error: %v", err)
	}
}

// TestGetSecurityScore_ConcurrentAccess tests concurrent score calculations
func TestGetSecurityScore_ConcurrentAccess(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	insertTestFindings(t, db, "scan1", map[string]int{
		"critical": 5,
		"high":     10,
		"medium":   15,
		"low":      20,
	})

	// Run multiple concurrent score calculations
	done := make(chan bool)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, err := engine.GetSecurityScore()
			if err != nil {
				errors <- err
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent score calculation error: %v", err)
	}
}

// TestCache_ConcurrentAccess_Stress tests concurrent cache access under stress conditions
func TestCache_ConcurrentAccess_Stress(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert test data
	insertTestFindings(t, db, "scan1", map[string]int{"high": 10})

	// Run concurrent operations that use cache
	done := make(chan bool)
	errors := make(chan error, 20)

	// Mix of reads and cache clears
	for i := 0; i < 10; i++ {
		go func() {
			_, err := engine.GetCurrentMetrics()
			if err != nil {
				errors <- err
			}
			done <- true
		}()

		go func() {
			engine.ClearCache()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent cache access error: %v", err)
	}
}

// TestGetHotspots_LargeNumberOfFiles tests hotspot analysis with many files
func TestGetHotspots_LargeNumberOfFiles(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert run
	runID := "large-hotspot-test"
	_, err := db.Exec(`
		INSERT INTO runs (run_id, target_path, start_time, end_time, status)
		VALUES (?, '/test', ?, ?, 'completed')
	`, runID, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert run: %v", err)
	}

	// Insert findings for 1000 different files
	for i := 0; i < 1000; i++ {
		filePath := fmt.Sprintf("src/package%d/file%d.go", i/10, i)
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

	// Test with various limits
	limits := []int{10, 50, 100, 500}
	for _, limit := range limits {
		t.Run(fmt.Sprintf("Limit_%d", limit), func(t *testing.T) {
			analysis, err := engine.GetHotspots(limit)
			if err != nil {
				t.Fatalf("GetHotspots failed with limit %d: %v", limit, err)
			}

			if len(analysis.Hotspots) > limit {
				t.Errorf("Expected at most %d hotspots, got %d", limit, len(analysis.Hotspots))
			}

			if analysis.TotalFiles != 1000 {
				t.Errorf("Expected 1000 total files, got %d", analysis.TotalFiles)
			}
		})
	}
}

// TestCompareScanFindings_LargeScans tests comparison with large scan datasets
func TestCompareScanFindings_LargeScans(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert 10,000 findings in old scan
	for i := 0; i < 10000; i++ {
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, cwe_id, severity)
			VALUES (?, 'old_scan', ?, 'CWE-79', 'high')
		`, fmt.Sprintf("old-%d", i), fmt.Sprintf("fp-%d", i))
		if err != nil {
			t.Fatalf("Failed to insert old finding: %v", err)
		}
	}

	// Insert 10,000 findings in new scan (50% overlap)
	for i := 0; i < 10000; i++ {
		fpIndex := i + 5000 // 5000-14999, so 5000-9999 overlap with old scan
		_, err := db.Exec(`
			INSERT INTO findings_normalized (norm_id, run_id, code_fingerprint, cwe_id, severity)
			VALUES (?, 'new_scan', ?, 'CWE-79', 'high')
		`, fmt.Sprintf("new-%d", i), fmt.Sprintf("fp-%d", fpIndex))
		if err != nil {
			t.Fatalf("Failed to insert new finding: %v", err)
		}
	}

	engine := NewEngine(db)
	
	start := time.Now()
	comparison, err := engine.CompareScanFindings("old_scan", "new_scan")
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("CompareScanFindings failed: %v", err)
	}

	t.Logf("Comparison of 20,000 findings took %v", duration)

	// Verify results
	// Old: 0-9999, New: 5000-14999
	// Overlap: 5000-9999 (5000 findings)
	// New only: 10000-14999 (5000 findings)
	// Resolved: 0-4999 (5000 findings)
	
	if comparison.NewFindings != 5000 {
		t.Errorf("Expected 5000 new findings, got %d", comparison.NewFindings)
	}
	if comparison.ResolvedFindings != 5000 {
		t.Errorf("Expected 5000 resolved findings, got %d", comparison.ResolvedFindings)
	}
	if comparison.UnchangedCount != 5000 {
		t.Errorf("Expected 5000 unchanged findings, got %d", comparison.UnchangedCount)
	}

	// Performance check - should complete in reasonable time
	if duration > 10*time.Second {
		t.Errorf("Comparison took too long: %v", duration)
	}
}

// TestGetTopCWEs_ManyUniqueCWEs tests CWE ranking with many unique CWEs
func TestGetTopCWEs_ManyUniqueCWEs(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert findings for 100 different CWEs
	for i := 0; i < 100; i++ {
		cweID := fmt.Sprintf("CWE-%d", 100+i)
		count := 100 - i // Descending counts
		
		for j := 0; j < count; j++ {
			_, err := db.Exec(`
				INSERT INTO findings_normalized (norm_id, run_id, cwe_id, cwe_description, severity, code_fingerprint)
				VALUES (?, 'run1', ?, ?, 'high', ?)
			`, fmt.Sprintf("f-%d-%d", i, j), cweID, fmt.Sprintf("%s Description", cweID), fmt.Sprintf("fp-%d-%d", i, j))
			if err != nil {
				t.Fatalf("Failed to insert finding: %v", err)
			}
		}
	}

	engine := NewEngine(db)
	
	// Test with different limits
	limits := []int{5, 10, 25, 50, 100, 200}
	for _, limit := range limits {
		t.Run(fmt.Sprintf("Limit_%d", limit), func(t *testing.T) {
			stats, err := engine.GetTopCWEs(limit)
			if err != nil {
				t.Fatalf("GetTopCWEs failed: %v", err)
			}

			expectedLen := limit
			if limit > 100 {
				expectedLen = 100 // Only 100 unique CWEs
			}

			if len(stats) != expectedLen {
				t.Errorf("Expected %d CWEs, got %d", expectedLen, len(stats))
			}

			// Verify ordering
			for i := 1; i < len(stats); i++ {
				if stats[i].Count > stats[i-1].Count {
					t.Errorf("CWEs not properly ordered at position %d", i)
				}
			}

			// Verify top CWE
			if len(stats) > 0 && stats[0].CWEID != "CWE-100" {
				t.Errorf("Expected top CWE to be CWE-100, got %s", stats[0].CWEID)
			}
			if len(stats) > 0 && stats[0].Count != 100 {
				t.Errorf("Expected top CWE count to be 100, got %d", stats[0].Count)
			}
		})
	}
}

// TestRecordScanMetrics_HighFrequency tests recording metrics at high frequency
func TestRecordScanMetrics_HighFrequency(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Record 1000 scan metrics rapidly
	start := time.Now()
	for i := 0; i < 1000; i++ {
		scanID := fmt.Sprintf("scan-%d", i)
		metrics := &SeverityMetrics{
			Critical: i % 10,
			High:     i % 20,
			Medium:   i % 30,
			Low:      i % 40,
			Total:    i % 100,
		}

		err := engine.RecordScanMetrics(scanID, metrics, int64(i*1000))
		if err != nil {
			t.Fatalf("RecordScanMetrics failed at iteration %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	t.Logf("Recording 1000 scan metrics took %v", duration)

	// Verify all were recorded
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM scan_metrics").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count scan metrics: %v", err)
	}

	if count < 1000 {
		t.Errorf("Expected at least 1000 scan metrics, got %d", count)
	}

	// Performance check
	if duration > 30*time.Second {
		t.Errorf("Recording took too long: %v", duration)
	}
}

// TestRecordDailyTrend_HighFrequency tests recording daily trends at high frequency
func TestRecordDailyTrend_HighFrequency(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	baseDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Record 365 days of trends
	start := time.Now()
	for i := 0; i < 365; i++ {
		date := baseDate.AddDate(0, 0, i)
		metrics := &SeverityMetrics{
			Critical: i % 10,
			High:     i % 20,
			Medium:   i % 30,
			Low:      i % 40,
			Total:    i % 100,
		}

		err := engine.RecordDailyTrend(date, metrics, i%15, i%12)
		if err != nil {
			t.Fatalf("RecordDailyTrend failed at day %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	t.Logf("Recording 365 daily trends took %v", duration)

	// Verify all were recorded
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM finding_trends").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count trends: %v", err)
	}

	if count != 365 {
		t.Errorf("Expected 365 trends, got %d", count)
	}

	// Performance check
	if duration > 10*time.Second {
		t.Errorf("Recording took too long: %v", duration)
	}
}

// TestGetScoreHistory_LongHistory tests score history with many data points
func TestGetScoreHistory_LongHistory(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	baseTime := time.Now().AddDate(-2, 0, 0) // 2 years ago

	// Insert 730 days of score history (2 years)
	for i := 0; i < 730; i++ {
		timestamp := baseTime.AddDate(0, 0, i)
		score := &SecurityScore{
			Score:         float64(50 + (i % 50)),
			Grade:         "C",
			Timestamp:     timestamp,
			TotalFindings: 100 - (i % 100),
		}
		if err := engine.recordSecurityScore(score); err != nil {
			t.Fatalf("Failed to record score: %v", err)
		}
	}

	// Query full history
	start := baseTime.AddDate(0, 0, -1)
	end := time.Now()

	history, err := engine.GetScoreHistory(start, end, 0)
	if err != nil {
		t.Fatalf("GetScoreHistory failed: %v", err)
	}

	// Should have data (grouped by date)
	if len(history.Dates) == 0 {
		t.Error("Expected score history data")
	}

	// Test with limit
	limitedHistory, err := engine.GetScoreHistory(start, end, 30)
	if err != nil {
		t.Fatalf("GetScoreHistory with limit failed: %v", err)
	}

	if len(limitedHistory.Dates) > 30 {
		t.Errorf("Expected at most 30 results, got %d", len(limitedHistory.Dates))
	}
}

// TestGetHotspotTrends_LongPeriod tests hotspot trends over a long period
func TestGetHotspotTrends_LongPeriod(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)
	baseTime := time.Now().AddDate(-1, 0, 0) // 1 year ago
	filePath := "src/critical.go"

	// Insert findings for 365 days
	for day := 0; day < 365; day++ {
		runID := fmt.Sprintf("run-day-%d", day)
		runTime := baseTime.AddDate(0, 0, day)

		_, err := db.Exec(`
			INSERT INTO runs (run_id, target_path, start_time, end_time, status)
			VALUES (?, '/test', ?, ?, 'completed')
		`, runID, runTime.Unix(), runTime.Unix())
		if err != nil {
			t.Fatalf("Failed to insert run: %v", err)
		}

		// Insert 1-10 findings per day
		findingCount := (day % 10) + 1
		for i := 0; i < findingCount; i++ {
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

	// Query trends
	start := baseTime.AddDate(0, 0, -1)
	end := time.Now()

	trends, err := engine.GetHotspotTrends(filePath, start, end)
	if err != nil {
		t.Fatalf("GetHotspotTrends failed: %v", err)
	}

	if len(trends) != 365 {
		t.Errorf("Expected 365 trend data points, got %d", len(trends))
	}

	// Verify data integrity
	for i, trend := range trends {
		expectedCount := (i % 10) + 1
		if trend.TotalFindings != expectedCount {
			t.Errorf("Day %d: expected %d findings, got %d", i, expectedCount, trend.TotalFindings)
		}
	}
}
