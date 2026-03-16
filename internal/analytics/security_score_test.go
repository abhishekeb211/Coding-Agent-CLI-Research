package analytics

import (
	"database/sql"
	"testing"
	"time"
)

func TestGetSecurityScore(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert test findings
	insertTestFindings(t, db, "scan1", map[string]int{
		"critical": 2,
		"high":     3,
		"medium":   5,
		"low":      10,
	})

	// Get security score
	score, err := engine.GetSecurityScore()
	if err != nil {
		t.Fatalf("GetSecurityScore failed: %v", err)
	}

	// Verify score calculation
	// Expected: 100 - (2*10) - (3*5) - (5*2) - (10*0.5) = 100 - 20 - 15 - 10 - 5 = 50
	expectedScore := 50.0
	if score.Score != expectedScore {
		t.Errorf("Expected score %f, got %f", expectedScore, score.Score)
	}

	// Verify grade
	expectedGrade := "F"
	if score.Grade != expectedGrade {
		t.Errorf("Expected grade %s, got %s", expectedGrade, score.Grade)
	}

	// Verify counts
	if score.CriticalCount != 2 {
		t.Errorf("Expected 2 critical findings, got %d", score.CriticalCount)
	}
	if score.HighCount != 3 {
		t.Errorf("Expected 3 high findings, got %d", score.HighCount)
	}
	if score.MediumCount != 5 {
		t.Errorf("Expected 5 medium findings, got %d", score.MediumCount)
	}
	if score.LowCount != 10 {
		t.Errorf("Expected 10 low findings, got %d", score.LowCount)
	}
	if score.TotalFindings != 20 {
		t.Errorf("Expected 20 total findings, got %d", score.TotalFindings)
	}
}

func TestGetSecurityScore_PerfectScore(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// No findings = perfect score
	score, err := engine.GetSecurityScore()
	if err != nil {
		t.Fatalf("GetSecurityScore failed: %v", err)
	}

	if score.Score != 100.0 {
		t.Errorf("Expected perfect score 100, got %f", score.Score)
	}

	if score.Grade != "A" {
		t.Errorf("Expected grade A, got %s", score.Grade)
	}

	if score.TotalFindings != 0 {
		t.Errorf("Expected 0 findings, got %d", score.TotalFindings)
	}
}

func TestGetSecurityScore_MinimumScore(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert many critical findings to push score below 0
	insertTestFindings(t, db, "scan1", map[string]int{
		"critical": 20, // 20 * 10 = 200 points deducted
	})

	score, err := engine.GetSecurityScore()
	if err != nil {
		t.Fatalf("GetSecurityScore failed: %v", err)
	}

	// Score should be clamped at 0
	if score.Score != 0.0 {
		t.Errorf("Expected minimum score 0, got %f", score.Score)
	}

	if score.Grade != "F" {
		t.Errorf("Expected grade F, got %s", score.Grade)
	}
}

func TestCalculateGrade(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	tests := []struct {
		score         float64
		expectedGrade string
	}{
		{100, "A"},
		{95, "A"},
		{90, "A"},
		{89, "B"},
		{85, "B"},
		{80, "B"},
		{79, "C"},
		{75, "C"},
		{70, "C"},
		{69, "D"},
		{65, "D"},
		{60, "D"},
		{59, "F"},
		{50, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		grade := engine.calculateGrade(tt.score)
		if grade != tt.expectedGrade {
			t.Errorf("For score %f, expected grade %s, got %s", tt.score, tt.expectedGrade, grade)
		}
	}
}

func TestDetermineTrendDirection(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	tests := []struct {
		change            float64
		expectedDirection string
	}{
		{5.0, "improving"},
		{3.0, "improving"},
		{2.1, "improving"},
		{2.0, "stable"},
		{1.0, "stable"},
		{0.0, "stable"},
		{-1.0, "stable"},
		{-2.0, "stable"},
		{-2.1, "declining"},
		{-3.0, "declining"},
		{-5.0, "declining"},
	}

	for _, tt := range tests {
		direction := engine.determineTrendDirection(tt.change)
		if direction != tt.expectedDirection {
			t.Errorf("For change %f, expected direction %s, got %s", tt.change, tt.expectedDirection, direction)
		}
	}
}

func TestGetSecurityScore_WithTrend(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert initial findings and get first score
	insertTestFindings(t, db, "scan1", map[string]int{
		"critical": 5,
		"high":     5,
	})

	score1, err := engine.GetSecurityScore()
	if err != nil {
		t.Fatalf("GetSecurityScore failed: %v", err)
	}

	// First score should have no trend
	if score1.TrendDirection != "stable" {
		t.Errorf("First score should have stable trend, got %s", score1.TrendDirection)
	}

	// Clear cache to force recalculation
	engine.ClearCache()

	// Reduce findings (improvement)
	clearFindings(t, db)
	insertTestFindings(t, db, "scan2", map[string]int{
		"critical": 2,
		"high":     3,
	})

	score2, err := engine.GetSecurityScore()
	if err != nil {
		t.Fatalf("GetSecurityScore failed: %v", err)
	}

	// Score should improve
	if score2.Score <= score1.Score {
		t.Errorf("Expected score to improve from %f to %f", score1.Score, score2.Score)
	}

	// Trend should be improving
	if score2.TrendDirection != "improving" {
		t.Errorf("Expected improving trend, got %s", score2.TrendDirection)
	}

	if score2.ChangeFromPrev <= 0 {
		t.Errorf("Expected positive change, got %f", score2.ChangeFromPrev)
	}
}

func TestGetScoreHistory(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert multiple scores over time
	now := time.Now()
	scores := []struct {
		timestamp time.Time
		score     float64
		grade     string
	}{
		{now.AddDate(0, 0, -3), 80.0, "B"},
		{now.AddDate(0, 0, -2), 75.0, "C"},
		{now.AddDate(0, 0, -1), 85.0, "B"},
		{now, 90.0, "A"},
	}

	for _, s := range scores {
		score := &SecurityScore{
			Score:         s.score,
			Grade:         s.grade,
			Timestamp:     s.timestamp,
			TotalFindings: 10,
		}
		if err := engine.recordSecurityScore(score); err != nil {
			t.Fatalf("Failed to record score: %v", err)
		}
	}

	// Get history
	start := now.AddDate(0, 0, -4)
	end := now.AddDate(0, 0, 1)
	history, err := engine.GetScoreHistory(start, end, 0)
	if err != nil {
		t.Fatalf("GetScoreHistory failed: %v", err)
	}

	// Verify we got all scores (grouped by date)
	if len(history.Dates) == 0 {
		t.Error("Expected score history, got empty")
	}

	if len(history.Scores) != len(history.Dates) {
		t.Errorf("Scores and dates length mismatch: %d vs %d", len(history.Scores), len(history.Dates))
	}

	if len(history.Grades) != len(history.Dates) {
		t.Errorf("Grades and dates length mismatch: %d vs %d", len(history.Grades), len(history.Dates))
	}
}

func TestGetScoreHistory_WithLimit(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert multiple scores
	now := time.Now()
	for i := 0; i < 10; i++ {
		score := &SecurityScore{
			Score:         float64(80 + i),
			Grade:         "B",
			Timestamp:     now.AddDate(0, 0, -i),
			TotalFindings: 10,
		}
		if err := engine.recordSecurityScore(score); err != nil {
			t.Fatalf("Failed to record score: %v", err)
		}
	}

	// Get history with limit
	start := now.AddDate(0, 0, -20)
	end := now.AddDate(0, 0, 1)
	history, err := engine.GetScoreHistory(start, end, 5)
	if err != nil {
		t.Fatalf("GetScoreHistory failed: %v", err)
	}

	// Should respect limit
	if len(history.Dates) > 5 {
		t.Errorf("Expected at most 5 results, got %d", len(history.Dates))
	}
}

func TestGetScoreForScan(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert findings for a specific scan
	scanID := "test-scan-123"
	insertTestFindingsForScan(t, db, scanID, map[string]int{
		"critical": 1,
		"high":     2,
		"medium":   3,
		"low":      4,
	})

	// Get score for scan
	score, err := engine.GetScoreForScan(scanID)
	if err != nil {
		t.Fatalf("GetScoreForScan failed: %v", err)
	}

	// Verify score calculation
	// Expected: 100 - (1*10) - (2*5) - (3*2) - (4*0.5) = 100 - 10 - 10 - 6 - 2 = 72
	expectedScore := 72.0
	if score.Score != expectedScore {
		t.Errorf("Expected score %f, got %f", expectedScore, score.Score)
	}

	if score.Grade != "C" {
		t.Errorf("Expected grade C, got %s", score.Grade)
	}

	if score.TotalFindings != 10 {
		t.Errorf("Expected 10 total findings, got %d", score.TotalFindings)
	}
}

func TestGetSecurityScore_Cache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	engine := NewEngine(db)

	// Insert test findings
	insertTestFindings(t, db, "scan1", map[string]int{
		"critical": 1,
	})

	// First call - should hit database
	score1, err := engine.GetSecurityScore()
	if err != nil {
		t.Fatalf("GetSecurityScore failed: %v", err)
	}

	// Second call - should hit cache
	score2, err := engine.GetSecurityScore()
	if err != nil {
		t.Fatalf("GetSecurityScore failed: %v", err)
	}

	// Scores should be identical
	if score1.Score != score2.Score {
		t.Errorf("Cached score mismatch: %f vs %f", score1.Score, score2.Score)
	}

	// Verify cache is working by checking timestamps are the same
	if !score1.Timestamp.Equal(score2.Timestamp) {
		t.Error("Expected cached score to have same timestamp")
	}
}

// Helper functions

func insertTestFindings(t *testing.T, db *sql.DB, scanID string, counts map[string]int) {
	t.Helper()

	// Insert a run first
	_, err := db.Exec(`
		INSERT INTO runs (run_id, target_path, start_time, end_time, status)
		VALUES (?, '/test/path', ?, ?, 'completed')
	`, scanID, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to insert run: %v", err)
	}

	// Insert findings
	for severity, count := range counts {
		for i := 0; i < count; i++ {
			_, err := db.Exec(`
				INSERT INTO findings_normalized 
				(run_id, scanner, severity, message, file_path, line_number, code_fingerprint, created_at)
				VALUES (?, 'test-scanner', ?, ?, '/test/file.go', 1, ?, ?)
			`, scanID, severity, "Test finding", scanID+severity+string(rune(i)), time.Now().Unix())
			if err != nil {
				t.Fatalf("Failed to insert finding: %v", err)
			}
		}
	}
}

func insertTestFindingsForScan(t *testing.T, db *sql.DB, scanID string, counts map[string]int) {
	t.Helper()
	insertTestFindings(t, db, scanID, counts)
}

func clearFindings(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec("DELETE FROM findings_normalized")
	if err != nil {
		t.Fatalf("Failed to clear findings: %v", err)
	}
}
