package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
)

func setupTestServer(t *testing.T) (*Server, *storage.Database) {
	// Create temporary database
	db, err := storage.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{
		TargetPath: "./testdata",
	})

	// Create server
	server, err := NewServer(db, orchestrator, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	return server, db
}

func seedTestData(t *testing.T, db *storage.Database) string {
	// Create a test run
	runID := "test-run-123"
	run := &storage.Run{
		RunID:           runID,
		TargetPath:      "./testdata",
		StartTime:       time.Now().Unix(),
		EndTime:         time.Now().Add(5 * time.Minute).Unix(),
		Duration:        300,
		Status:          "completed",
		OfflineVerified: true,
		ConfigHash:      "abc123",
	}

	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save test run: %v", err)
	}

	// Create test findings
	findings := []storage.NormalizedFinding{
		{
			NormID:          "finding-1",
			FindingID:       "raw-1",
			RunID:           runID,
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "critical",
			Confidence:      "high",
			CodeFingerprint: "fp1",
			FilePath:        "/app/db.go",
			LineNumber:      42,
			Description:     "Potential SQL injection",
		},
		{
			NormID:          "finding-2",
			FindingID:       "raw-2",
			RunID:           runID,
			CWEID:           "CWE-79",
			CWEDescription:  "Cross-site Scripting",
			Severity:        "high",
			Confidence:      "medium",
			CodeFingerprint: "fp2",
			FilePath:        "/app/web.go",
			LineNumber:      100,
			Description:     "Potential XSS vulnerability",
		},
		{
			NormID:          "finding-3",
			FindingID:       "raw-3",
			RunID:           runID,
			CWEID:           "CWE-22",
			CWEDescription:  "Path Traversal",
			Severity:        "medium",
			Confidence:      "high",
			CodeFingerprint: "fp3",
			FilePath:        "/app/file.go",
			LineNumber:      25,
			Description:     "Potential path traversal",
		},
	}

	for _, f := range findings {
		if err := db.SaveNormalizedFinding(&f); err != nil {
			t.Fatalf("Failed to save test finding: %v", err)
		}
	}

	return runID
}

func TestHandleListScans(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	seedTestData(t, db)

	// Test list scans
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ScanListResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Total != 1 {
		t.Errorf("Expected 1 scan, got %d", response.Total)
	}

	if len(response.Scans) != 1 {
		t.Errorf("Expected 1 scan in response, got %d", len(response.Scans))
	}

	scan := response.Scans[0]
	if scan.ScanID != "test-run-123" {
		t.Errorf("Expected scan ID 'test-run-123', got %s", scan.ScanID)
	}

	if scan.TotalFindings != 3 {
		t.Errorf("Expected 3 findings, got %d", scan.TotalFindings)
	}
}

func TestHandleListScansWithPagination(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed multiple runs
	for i := 0; i < 5; i++ {
		run := &storage.Run{
			RunID:      "run-" + string(rune('0'+i)),
			TargetPath: "./testdata",
			StartTime:  time.Now().Unix(),
			Status:     "completed",
		}
		if err := db.SaveRun(run); err != nil {
			t.Fatalf("Failed to save run: %v", err)
		}
	}

	// Test pagination
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?page=1&page_size=2", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ScanListResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Total != 5 {
		t.Errorf("Expected total 5, got %d", response.Total)
	}

	if len(response.Scans) != 2 {
		t.Errorf("Expected 2 scans in page, got %d", len(response.Scans))
	}

	if response.Page != 1 {
		t.Errorf("Expected page 1, got %d", response.Page)
	}

	if response.PageSize != 2 {
		t.Errorf("Expected page size 2, got %d", response.PageSize)
	}
}

func TestHandleGetScan(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	runID := seedTestData(t, db)

	// Test get scan
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+runID, nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ScanDetail
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.ScanID != runID {
		t.Errorf("Expected scan ID %s, got %s", runID, response.ScanID)
	}

	if response.TotalFindings != 3 {
		t.Errorf("Expected 3 findings, got %d", response.TotalFindings)
	}

	if response.CriticalCount != 1 {
		t.Errorf("Expected 1 critical finding, got %d", response.CriticalCount)
	}

	if response.HighCount != 1 {
		t.Errorf("Expected 1 high finding, got %d", response.HighCount)
	}

	if response.MediumCount != 1 {
		t.Errorf("Expected 1 medium finding, got %d", response.MediumCount)
	}

	if len(response.Findings) != 3 {
		t.Errorf("Expected 3 findings in response, got %d", len(response.Findings))
	}
}

func TestHandleGetScanNotFound(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Test get non-existent scan
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/nonexistent", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}

	var response APIError
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Code != ErrCodeNotFound {
		t.Errorf("Expected error code %s, got %s", ErrCodeNotFound, response.Code)
	}
}

func TestHandleListFindings(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	seedTestData(t, db)

	// Test list findings
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response FindingsResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Total != 3 {
		t.Errorf("Expected 3 findings, got %d", response.Total)
	}

	if len(response.Findings) != 3 {
		t.Errorf("Expected 3 findings in response, got %d", len(response.Findings))
	}

	// Verify findings are sorted by severity
	if response.Findings[0].Severity != "critical" {
		t.Errorf("Expected first finding to be critical, got %s", response.Findings[0].Severity)
	}
}

func TestHandleListFindingsWithFilters(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	seedTestData(t, db)

	tests := []struct {
		name          string
		query         string
		expectedCount int
	}{
		{
			name:          "Filter by severity",
			query:         "?severity=critical",
			expectedCount: 1,
		},
		{
			name:          "Filter by CWE",
			query:         "?cwe_id=CWE-89",
			expectedCount: 1,
		},
		{
			name:          "Filter by file path",
			query:         "?file_path=db.go",
			expectedCount: 1,
		},
		{
			name:          "Filter by run ID",
			query:         "?run_id=test-run-123",
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/findings"+tt.query, nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			var response FindingsResponse
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if response.Total != tt.expectedCount {
				t.Errorf("Expected %d findings, got %d", tt.expectedCount, response.Total)
			}
		})
	}
}

func TestHandleGetFinding(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	seedTestData(t, db)

	// Test get finding
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/finding-1", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response scanner.NormalizedFinding
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.ID != "finding-1" {
		t.Errorf("Expected finding ID 'finding-1', got %s", response.ID)
	}

	if response.CWEID != "CWE-89" {
		t.Errorf("Expected CWE-89, got %s", response.CWEID)
	}

	if response.Severity != "critical" {
		t.Errorf("Expected critical severity, got %s", response.Severity)
	}
}

func TestHandleGetFindingNotFound(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Test get non-existent finding
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/nonexistent", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}

	var response APIError
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Code != ErrCodeNotFound {
		t.Errorf("Expected error code %s, got %s", ErrCodeNotFound, response.Code)
	}
}

func TestHandleCreateScan(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Test create scan
	reqBody := ScanRequest{
		Path:     "./testdata",
		Scanners: []string{"bandit", "semgrep"},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("Expected status 202, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Status != "running" {
		t.Errorf("Expected status 'running', got %s", response.Status)
	}
}

func TestHandleCreateScanInvalidRequest(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	tests := []struct {
		name    string
		reqBody interface{}
	}{
		{
			name:    "Missing path",
			reqBody: ScanRequest{},
		},
		{
			name:    "Invalid JSON",
			reqBody: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.reqBody)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", w.Code)
			}
		})
	}
}

func TestParsePagination(t *testing.T) {
	tests := []struct {
		name             string
		query            string
		expectedPage     int
		expectedPageSize int
	}{
		{
			name:             "Default values",
			query:            "",
			expectedPage:     1,
			expectedPageSize: 50,
		},
		{
			name:             "Custom page",
			query:            "?page=2",
			expectedPage:     2,
			expectedPageSize: 50,
		},
		{
			name:             "Custom page size",
			query:            "?page_size=10",
			expectedPage:     1,
			expectedPageSize: 10,
		},
		{
			name:             "Both custom",
			query:            "?page=3&page_size=25",
			expectedPage:     3,
			expectedPageSize: 25,
		},
		{
			name:             "Invalid page",
			query:            "?page=invalid",
			expectedPage:     1,
			expectedPageSize: 50,
		},
		{
			name:             "Page size too large",
			query:            "?page_size=200",
			expectedPage:     1,
			expectedPageSize: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test"+tt.query, nil)
			page, pageSize := parsePagination(req)

			if page != tt.expectedPage {
				t.Errorf("Expected page %d, got %d", tt.expectedPage, page)
			}

			if pageSize != tt.expectedPageSize {
				t.Errorf("Expected page size %d, got %d", tt.expectedPageSize, pageSize)
			}
		})
	}
}

func TestParseFilters(t *testing.T) {
	tests := []struct {
		name            string
		query           string
		expectedFilters map[string]string
	}{
		{
			name:            "No filters",
			query:           "",
			expectedFilters: map[string]string{},
		},
		{
			name:  "Severity filter",
			query: "?severity=critical",
			expectedFilters: map[string]string{
				"severity": "critical",
			},
		},
		{
			name:  "Multiple filters",
			query: "?severity=high&cwe_id=CWE-89&run_id=test-123",
			expectedFilters: map[string]string{
				"severity": "high",
				"cwe_id":   "CWE-89",
				"run_id":   "test-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test"+tt.query, nil)
			filters := parseFilters(req)

			if len(filters) != len(tt.expectedFilters) {
				t.Errorf("Expected %d filters, got %d", len(tt.expectedFilters), len(filters))
			}

			for key, expectedValue := range tt.expectedFilters {
				if value, ok := filters[key]; !ok || value != expectedValue {
					t.Errorf("Expected filter %s=%s, got %s", key, expectedValue, value)
				}
			}
		})
	}
}

// Analytics endpoint tests

func seedAnalyticsTestData(t *testing.T, db *storage.Database) {
	// Create multiple runs with findings over time
	baseTime := time.Now().AddDate(0, 0, -30)

	for i := 0; i < 10; i++ {
		runID := "analytics-run-" + string(rune('0'+i))
		runTime := baseTime.AddDate(0, 0, i*3)

		run := &storage.Run{
			RunID:      runID,
			TargetPath: "./testdata",
			StartTime:  runTime.Unix(),
			EndTime:    runTime.Add(5 * time.Minute).Unix(),
			Duration:   300,
			Status:     "completed",
		}

		if err := db.SaveRun(run); err != nil {
			t.Fatalf("Failed to save run: %v", err)
		}

		// Create findings with varying severities
		findings := []storage.NormalizedFinding{
			{
				NormID:          runID + "-finding-1",
				FindingID:       runID + "-raw-1",
				RunID:           runID,
				CWEID:           "CWE-89",
				CWEDescription:  "SQL Injection",
				Severity:        "critical",
				Confidence:      "high",
				CodeFingerprint: "fp-sql-" + string(rune('0'+i)),
				FilePath:        "/app/db.go",
				LineNumber:      42,
				Description:     "SQL injection vulnerability",
			},
			{
				NormID:          runID + "-finding-2",
				FindingID:       runID + "-raw-2",
				RunID:           runID,
				CWEID:           "CWE-79",
				CWEDescription:  "Cross-site Scripting",
				Severity:        "high",
				Confidence:      "medium",
				CodeFingerprint: "fp-xss-" + string(rune('0'+i)),
				FilePath:        "/app/web.go",
				LineNumber:      100,
				Description:     "XSS vulnerability",
			},
			{
				NormID:          runID + "-finding-3",
				FindingID:       runID + "-raw-3",
				RunID:           runID,
				CWEID:           "CWE-22",
				CWEDescription:  "Path Traversal",
				Severity:        "medium",
				Confidence:      "high",
				CodeFingerprint: "fp-path-" + string(rune('0'+i)),
				FilePath:        "/app/file.go",
				LineNumber:      25,
				Description:     "Path traversal vulnerability",
			},
		}

		for _, f := range findings {
			if err := db.SaveNormalizedFinding(&f); err != nil {
				t.Fatalf("Failed to save finding: %v", err)
			}
		}
	}

	// Record some trend data
	for i := 0; i < 10; i++ {
		date := baseTime.AddDate(0, 0, i*3)
		query := `
			INSERT INTO finding_trends 
			(date, critical, high, medium, low, total, new_findings, resolved_findings, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
		_, err := db.DB().Exec(query,
			date.Format("2006-01-02"),
			1, // critical
			1, // high
			1, // medium
			0, // low
			3, // total
			3, // new
			0, // resolved
			date.Unix(),
		)
		if err != nil {
			t.Fatalf("Failed to insert trend data: %v", err)
		}
	}
}

func TestHandleGetTrends(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed analytics test data
	seedAnalyticsTestData(t, db)

	// Test get trends with default date range (last 30 days)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/trends", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response TrendsResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response structure
	if len(response.Dates) == 0 {
		t.Error("Expected trend dates, got empty array")
	}

	if len(response.Critical) != len(response.Dates) {
		t.Errorf("Expected critical array length %d, got %d", len(response.Dates), len(response.Critical))
	}

	if len(response.High) != len(response.Dates) {
		t.Errorf("Expected high array length %d, got %d", len(response.Dates), len(response.High))
	}

	if len(response.Medium) != len(response.Dates) {
		t.Errorf("Expected medium array length %d, got %d", len(response.Dates), len(response.Medium))
	}

	if len(response.Total) != len(response.Dates) {
		t.Errorf("Expected total array length %d, got %d", len(response.Dates), len(response.Total))
	}
}

func TestHandleGetTrendsWithDateRange(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed analytics test data
	seedAnalyticsTestData(t, db)

	// Test with specific date range
	start := time.Now().AddDate(0, 0, -20).Format("2006-01-02")
	end := time.Now().AddDate(0, 0, -5).Format("2006-01-02")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/trends?start="+start+"&end="+end, nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response TrendsResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify we got data for the specified range
	if len(response.Dates) > 0 {
		t.Logf("Got %d data points for date range", len(response.Dates))
	}
}

func TestHandleGetTrendsInvalidDateFormat(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "Invalid start date",
			query: "?start=invalid-date",
		},
		{
			name:  "Invalid end date",
			query: "?end=2024-13-45",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/trends"+tt.query, nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", w.Code)
			}

			var response APIError
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if response.Code != ErrCodeInvalidRequest {
				t.Errorf("Expected error code %s, got %s", ErrCodeInvalidRequest, response.Code)
			}
		})
	}
}

func TestHandleGetMTTR(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed analytics test data
	seedAnalyticsTestData(t, db)

	// Test get MTTR
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/mttr", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response MTTRResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response structure
	if response.TotalResolved < 0 {
		t.Errorf("Expected non-negative total resolved, got %d", response.TotalResolved)
	}

	// MTTR values should be duration strings
	if response.TotalResolved > 0 {
		if response.MeanTTR == "" {
			t.Error("Expected mean TTR value, got empty string")
		}
		if response.MedianTTR == "" {
			t.Error("Expected median TTR value, got empty string")
		}
	}
}

func TestHandleGetMTTRWithFilters(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed analytics test data
	seedAnalyticsTestData(t, db)

	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "Filter by severity",
			query: "?severity=critical",
		},
		{
			name:  "Filter by date range",
			query: "?start=2024-01-01&end=2024-12-31",
		},
		{
			name:  "Combined filters",
			query: "?severity=high&start=2024-01-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/mttr"+tt.query, nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			var response MTTRResponse
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}
		})
	}
}

func TestHandleGetSecurityScore(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	seedTestData(t, db)

	// Test get security score
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/score", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response SecurityScoreResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response structure
	if response.Score < 0 || response.Score > 100 {
		t.Errorf("Expected score between 0-100, got %f", response.Score)
	}

	if response.Grade == "" {
		t.Error("Expected grade value, got empty string")
	}

	validGrades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
	if !validGrades[response.Grade] {
		t.Errorf("Expected valid grade (A-F), got %s", response.Grade)
	}

	if response.Timestamp == "" {
		t.Error("Expected timestamp, got empty string")
	}

	if response.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", response.TotalFindings)
	}

	if response.CriticalCount != 1 {
		t.Errorf("Expected 1 critical finding, got %d", response.CriticalCount)
	}

	validTrends := map[string]bool{"improving": true, "declining": true, "stable": true}
	if !validTrends[response.TrendDirection] {
		t.Errorf("Expected valid trend direction, got %s", response.TrendDirection)
	}
}

func TestHandleGetSecurityScoreForScan(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	runID := seedTestData(t, db)

	// Test get security score for specific scan
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/score?scan_id="+runID, nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response SecurityScoreResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify score is calculated based on scan findings
	if response.TotalFindings != 3 {
		t.Errorf("Expected 3 findings for scan, got %d", response.TotalFindings)
	}
}

func TestHandleGetHotspots(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	seedTestData(t, db)

	// Test get hotspots
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/hotspots", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response HotspotsResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response structure
	if len(response.Hotspots) == 0 {
		t.Error("Expected hotspots, got empty array")
	}

	if response.TotalFiles <= 0 {
		t.Errorf("Expected positive total files, got %d", response.TotalFiles)
	}

	if response.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", response.TotalFindings)
	}

	if response.AnalyzedAt == "" {
		t.Error("Expected analyzed_at timestamp, got empty string")
	}

	// Verify hotspot structure
	for i, hotspot := range response.Hotspots {
		if hotspot.FilePath == "" {
			t.Errorf("Hotspot %d: expected file path, got empty string", i)
		}

		if hotspot.TotalFindings <= 0 {
			t.Errorf("Hotspot %d: expected positive findings count, got %d", i, hotspot.TotalFindings)
		}

		if hotspot.SeverityScore < 0 {
			t.Errorf("Hotspot %d: expected non-negative severity score, got %f", i, hotspot.SeverityScore)
		}
	}
}

func TestHandleGetHotspotsWithLimit(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data with multiple files
	runID := "hotspot-test-run"
	run := &storage.Run{
		RunID:      runID,
		TargetPath: "./testdata",
		StartTime:  time.Now().Unix(),
		Status:     "completed",
	}
	if err := db.SaveRun(run); err != nil {
		t.Fatalf("Failed to save run: %v", err)
	}

	// Create findings in multiple files
	files := []string{"/app/file1.go", "/app/file2.go", "/app/file3.go", "/app/file4.go", "/app/file5.go"}
	for i, file := range files {
		finding := storage.NormalizedFinding{
			NormID:          "hotspot-finding-" + string(rune('0'+i)),
			FindingID:       "raw-" + string(rune('0'+i)),
			RunID:           runID,
			CWEID:           "CWE-89",
			CWEDescription:  "SQL Injection",
			Severity:        "high",
			Confidence:      "high",
			CodeFingerprint: "fp-" + string(rune('0'+i)),
			FilePath:        file,
			LineNumber:      10,
			Description:     "Test finding",
		}
		if err := db.SaveNormalizedFinding(&finding); err != nil {
			t.Fatalf("Failed to save finding: %v", err)
		}
	}

	// Test with limit
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/hotspots?limit=3", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response HotspotsResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify limit is respected
	if len(response.Hotspots) > 3 {
		t.Errorf("Expected at most 3 hotspots, got %d", len(response.Hotspots))
	}
}

func TestHandleGetHotspotsForScan(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Seed test data
	runID := seedTestData(t, db)

	// Test get hotspots for specific scan
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/hotspots?scan_id="+runID, nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response HotspotsResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify hotspots are for the specific scan
	if response.TotalFindings != 3 {
		t.Errorf("Expected 3 findings for scan, got %d", response.TotalFindings)
	}
}

func TestAnalyticsEndpointsWithNoData(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// Test all analytics endpoints with no data
	endpoints := []string{
		"/api/v1/analytics/trends",
		"/api/v1/analytics/mttr",
		"/api/v1/analytics/score",
		"/api/v1/analytics/hotspots",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, endpoint, nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			// Should return 200 with empty/default data, not error
			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for %s, got %d", endpoint, w.Code)
			}
		})
	}
}
