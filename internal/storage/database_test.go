package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewDatabase tests database initialization and schema creation
func TestNewDatabase(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid database path",
			path:    filepath.Join(t.TempDir(), "test.db"),
			wantErr: false,
		},
		{
			name:    "nested directory path",
			path:    filepath.Join(t.TempDir(), "subdir", "test.db"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDatabase(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDatabase() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				defer db.Close()

				// Verify database file was created
				if _, err := os.Stat(tt.path); os.IsNotExist(err) {
					t.Errorf("Database file was not created at %s", tt.path)
				}

				// Verify schema was created by checking for tables
				var count int
				err = db.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
				if err != nil {
					t.Errorf("Failed to query tables: %v", err)
				}
				if count == 0 {
					t.Error("No tables were created in database")
				}
			}
		})
	}
}

// TestSaveRun tests saving a scan run record
func TestSaveRun(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tests := []struct {
		name    string
		run     *Run
		wantErr bool
	}{
		{
			name: "valid run",
			run: &Run{
				RunID:           "test-run-1",
				TargetPath:      "/test/path",
				StartTime:       time.Now().Unix(),
				EndTime:         time.Now().Unix() + 100,
				Duration:        100,
				Status:          "completed",
				OfflineVerified: true,
				ConfigHash:      "abc123",
			},
			wantErr: false,
		},
		{
			name: "minimal run",
			run: &Run{
				RunID:      "test-run-2",
				TargetPath: "/test/path2",
				StartTime:  time.Now().Unix(),
				Status:     "running",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.SaveRun(tt.run)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveRun() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify run was saved
				var savedRunID string
				err = db.db.QueryRow("SELECT run_id FROM runs WHERE run_id = ?", tt.run.RunID).Scan(&savedRunID)
				if err != nil {
					t.Errorf("Failed to retrieve saved run: %v", err)
				}
				if savedRunID != tt.run.RunID {
					t.Errorf("SaveRun() saved run_id = %v, want %v", savedRunID, tt.run.RunID)
				}
			}
		})
	}
}

// TestUpdateRunStatus tests updating run status
func TestUpdateRunStatus(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create initial run
	run := &Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		Status:     "running",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save initial run: %v", err)
	}

	tests := []struct {
		name     string
		runID    string
		status   string
		endTime  int64
		duration int64
		wantErr  bool
	}{
		{
			name:     "update to completed",
			runID:    "test-run-1",
			status:   "completed",
			endTime:  time.Now().Unix(),
			duration: 100,
			wantErr:  false,
		},
		{
			name:     "update to failed",
			runID:    "test-run-1",
			status:   "failed",
			endTime:  time.Now().Unix(),
			duration: 50,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.UpdateRunStatus(tt.runID, tt.status, tt.endTime, tt.duration)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateRunStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify status was updated
				var status string
				err = db.db.QueryRow("SELECT status FROM runs WHERE run_id = ?", tt.runID).Scan(&status)
				if err != nil {
					t.Errorf("Failed to retrieve updated status: %v", err)
				}
				if status != tt.status {
					t.Errorf("UpdateRunStatus() status = %v, want %v", status, tt.status)
				}
			}
		})
	}
}

// TestSaveRawFinding tests saving raw findings
func TestSaveRawFinding(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create a run first
	run := &Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		Status:     "running",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	tests := []struct {
		name    string
		finding *RawFinding
		wantErr bool
	}{
		{
			name: "valid raw finding",
			finding: &RawFinding{
				FindingID:     "finding-1",
				RunID:         "test-run-1",
				ToolName:      "bandit",
				ToolFindingID: "B101",
				Message:       "SQL injection vulnerability",
				FilePath:      "/test/file.py",
				LineNumber:    42,
				Severity:      "high",
				Confidence:    "high",
				RuleID:        "B608",
				Category:      "security",
				RawJSON:       `{"test": "data"}`,
			},
			wantErr: false,
		},
		{
			name: "minimal raw finding",
			finding: &RawFinding{
				FindingID:  "finding-2",
				RunID:      "test-run-1",
				ToolName:   "semgrep",
				Message:    "Test finding",
				FilePath:   "/test/file2.py",
				LineNumber: 10,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.SaveRawFinding(tt.finding)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveRawFinding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify finding was saved
				var savedFindingID string
				err = db.db.QueryRow("SELECT finding_id FROM findings_raw WHERE finding_id = ?", tt.finding.FindingID).Scan(&savedFindingID)
				if err != nil {
					t.Errorf("Failed to retrieve saved finding: %v", err)
				}
				if savedFindingID != tt.finding.FindingID {
					t.Errorf("SaveRawFinding() saved finding_id = %v, want %v", savedFindingID, tt.finding.FindingID)
				}
			}
		})
	}
}

// TestSaveNormalizedFinding tests saving normalized findings
func TestSaveNormalizedFinding(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create a run first
	run := &Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		Status:     "running",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	tests := []struct {
		name    string
		finding *NormalizedFinding
		wantErr bool
	}{
		{
			name: "valid normalized finding",
			finding: &NormalizedFinding{
				NormID:          "norm-1",
				FindingID:       "finding-1",
				RunID:           "test-run-1",
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "high",
				Confidence:      "high",
				CodeFingerprint: "abc123",
				FilePath:        "/test/file.py",
				LineNumber:      42,
				Description:     "SQL injection vulnerability detected",
			},
			wantErr: false,
		},
		{
			name: "minimal normalized finding",
			finding: &NormalizedFinding{
				NormID:     "norm-2",
				FindingID:  "finding-2",
				RunID:      "test-run-1",
				CWEID:      "CWE-79",
				FilePath:   "/test/file2.py",
				LineNumber: 10,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.SaveNormalizedFinding(tt.finding)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveNormalizedFinding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify finding was saved
				var savedNormID string
				err = db.db.QueryRow("SELECT norm_id FROM findings_normalized WHERE norm_id = ?", tt.finding.NormID).Scan(&savedNormID)
				if err != nil {
					t.Errorf("Failed to retrieve saved normalized finding: %v", err)
				}
				if savedNormID != tt.finding.NormID {
					t.Errorf("SaveNormalizedFinding() saved norm_id = %v, want %v", savedNormID, tt.finding.NormID)
				}
			}
		})
	}
}

// TestGetFindingsByRun tests retrieving findings by run ID
func TestGetFindingsByRun(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create a run
	run := &Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		Status:     "completed",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	// Save some findings
	findings := []*NormalizedFinding{
		{
			NormID:     "norm-1",
			FindingID:  "finding-1",
			RunID:      "test-run-1",
			CWEID:      "CWE-89",
			Severity:   "high",
			FilePath:   "/test/file.py",
			LineNumber: 42,
		},
		{
			NormID:     "norm-2",
			FindingID:  "finding-2",
			RunID:      "test-run-1",
			CWEID:      "CWE-79",
			Severity:   "medium",
			FilePath:   "/test/file2.py",
			LineNumber: 10,
		},
	}

	for _, f := range findings {
		if err := db.SaveNormalizedFinding(f); err != nil {
			t.Fatalf("Failed to save finding: %v", err)
		}
	}

	tests := []struct {
		name      string
		runID     string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "retrieve existing findings",
			runID:     "test-run-1",
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "retrieve from non-existent run",
			runID:     "non-existent",
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.GetFindingsByRun(tt.runID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFindingsByRun() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantCount {
				t.Errorf("GetFindingsByRun() returned %d findings, want %d", len(got), tt.wantCount)
			}

			// Verify findings are ordered by severity
			if len(got) > 1 {
				severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
				for i := 0; i < len(got)-1; i++ {
					if severityOrder[got[i].Severity] < severityOrder[got[i+1].Severity] {
						t.Errorf("Findings not ordered by severity: %s before %s", got[i].Severity, got[i+1].Severity)
					}
				}
			}
		})
	}
}

// TestSaveDedupeCluster tests saving deduplication clusters
func TestSaveDedupeCluster(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tests := []struct {
		name    string
		cluster *DedupeCluster
		wantErr bool
	}{
		{
			name: "valid cluster",
			cluster: &DedupeCluster{
				ClusterID:       "cluster-1",
				CodeFingerprint: "fp-123",
				NormFindingIDs:  `["norm-1", "norm-2"]`,
				FirstSeen:       time.Now().Unix(),
				LastSeen:        time.Now().Unix(),
				OccurrenceCount: 2,
			},
			wantErr: false,
		},
		{
			name: "update existing cluster",
			cluster: &DedupeCluster{
				ClusterID:       "cluster-1",
				CodeFingerprint: "fp-123",
				NormFindingIDs:  `["norm-1", "norm-2", "norm-3"]`,
				FirstSeen:       time.Now().Unix(),
				LastSeen:        time.Now().Unix() + 100,
				OccurrenceCount: 3,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.SaveDedupeCluster(tt.cluster)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveDedupeCluster() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify cluster was saved
				var count int
				err = db.db.QueryRow("SELECT occurrence_count FROM dedupe_clusters WHERE cluster_id = ?", tt.cluster.ClusterID).Scan(&count)
				if err != nil {
					t.Errorf("Failed to retrieve saved cluster: %v", err)
				}
				if count != tt.cluster.OccurrenceCount {
					t.Errorf("SaveDedupeCluster() saved occurrence_count = %v, want %v", count, tt.cluster.OccurrenceCount)
				}
			}
		})
	}
}

// TestGetDedupeCluster tests retrieving deduplication clusters
func TestGetDedupeCluster(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Save a cluster
	cluster := &DedupeCluster{
		ClusterID:       "cluster-1",
		CodeFingerprint: "fp-123",
		NormFindingIDs:  `["norm-1", "norm-2"]`,
		FirstSeen:       time.Now().Unix(),
		LastSeen:        time.Now().Unix(),
		OccurrenceCount: 2,
	}
	if err := db.SaveDedupeCluster(cluster); err != nil {
		t.Fatalf("Failed to save cluster: %v", err)
	}

	tests := []struct {
		name        string
		fingerprint string
		wantNil     bool
		wantErr     bool
	}{
		{
			name:        "retrieve existing cluster",
			fingerprint: "fp-123",
			wantNil:     false,
			wantErr:     false,
		},
		{
			name:        "retrieve non-existent cluster",
			fingerprint: "non-existent",
			wantNil:     true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.GetDedupeCluster(tt.fingerprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDedupeCluster() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("GetDedupeCluster() returned nil = %v, want nil = %v", got == nil, tt.wantNil)
			}
			if !tt.wantNil && got != nil {
				if got.CodeFingerprint != tt.fingerprint {
					t.Errorf("GetDedupeCluster() fingerprint = %v, want %v", got.CodeFingerprint, tt.fingerprint)
				}
			}
		})
	}
}

// TestSaveIssue tests saving issues
func TestSaveIssue(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tests := []struct {
		name    string
		issue   *Issue
		wantErr bool
	}{
		{
			name: "valid open issue",
			issue: &Issue{
				IssueID:         "issue-1",
				CodeFingerprint: "fp-123",
				CWEID:           "CWE-89",
				Severity:        "high",
				Status:          "open",
				FilePath:        "/test/file.py",
				LineNumber:      42,
				Description:     "SQL injection vulnerability",
				OpenedTS:        time.Now().Unix(),
			},
			wantErr: false,
		},
		{
			name: "closed issue",
			issue: &Issue{
				IssueID:         "issue-2",
				CodeFingerprint: "fp-456",
				CWEID:           "CWE-79",
				Severity:        "medium",
				Status:          "closed",
				FilePath:        "/test/file2.py",
				LineNumber:      10,
				Description:     "XSS vulnerability",
				OpenedTS:        time.Now().Unix() - 1000,
				ClosedTS:        time.Now().Unix(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.SaveIssue(tt.issue)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveIssue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify issue was saved
				var status string
				err = db.db.QueryRow("SELECT status FROM issues WHERE issue_id = ?", tt.issue.IssueID).Scan(&status)
				if err != nil {
					t.Errorf("Failed to retrieve saved issue: %v", err)
				}
				if status != tt.issue.Status {
					t.Errorf("SaveIssue() saved status = %v, want %v", status, tt.issue.Status)
				}
			}
		})
	}
}

// TestGetStats tests retrieving database statistics
func TestGetStats(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create test data
	run := &Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		Status:     "completed",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	finding := &NormalizedFinding{
		NormID:     "norm-1",
		FindingID:  "finding-1",
		RunID:      "test-run-1",
		CWEID:      "CWE-89",
		FilePath:   "/test/file.py",
		LineNumber: 42,
	}
	if err := db.SaveNormalizedFinding(finding); err != nil {
		t.Fatalf("Failed to save finding: %v", err)
	}

	issue := &Issue{
		IssueID:    "issue-1",
		CWEID:      "CWE-89",
		Status:     "open",
		FilePath:   "/test/file.py",
		LineNumber: 42,
		OpenedTS:   time.Now().Unix(),
	}
	if err := db.SaveIssue(issue); err != nil {
		t.Fatalf("Failed to save issue: %v", err)
	}

	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}

	if stats.TotalRuns != 1 {
		t.Errorf("GetStats() TotalRuns = %v, want 1", stats.TotalRuns)
	}
	if stats.TotalFindings != 1 {
		t.Errorf("GetStats() TotalFindings = %v, want 1", stats.TotalFindings)
	}
	if stats.OpenIssues != 1 {
		t.Errorf("GetStats() OpenIssues = %v, want 1", stats.OpenIssues)
	}
}

// TestConcurrentAccess tests concurrent database operations
func TestConcurrentAccess(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create a run
	run := &Run{
		RunID:      "test-run-1",
		TargetPath: "/test/path",
		StartTime:  time.Now().Unix(),
		Status:     "running",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	// Concurrently save findings
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			finding := &NormalizedFinding{
				NormID:     string(rune('a' + id)),
				FindingID:  string(rune('a' + id)),
				RunID:      "test-run-1",
				CWEID:      "CWE-89",
				FilePath:   "/test/file.py",
				LineNumber: id,
			}
			if err := db.SaveNormalizedFinding(finding); err != nil {
				t.Errorf("Concurrent SaveNormalizedFinding() error = %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all findings were saved
	findings, err := db.GetFindingsByRun("test-run-1")
	if err != nil {
		t.Fatalf("GetFindingsByRun() error = %v", err)
	}
	if len(findings) != 10 {
		t.Errorf("Expected 10 findings, got %d", len(findings))
	}
}

// setupTestDB creates a test database with schema
func setupTestDB(t *testing.T) *Database {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	return db
}
