package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coding-agent/cli/internal/analytics"
	"github.com/coding-agent/cli/internal/scanner"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Version: "1.2.0",
	})
}

// handleCreateScan handles POST /api/v1/scans
func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := parseJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid request body", nil)
		return
	}

	// Validate request
	if req.Path == "" {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Path is required", nil)
		return
	}

	log.Info().
		Str("path", req.Path).
		Strs("scanners", req.Scanners).
		Msg("Scan creation requested")

	// Run scan asynchronously
	go func() {
		ctx := context.Background()
		result, err := s.orchestrator.Scan(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Scan failed")
			return
		}
		log.Info().
			Str("scan_id", result.RunID).
			Int("findings", result.TotalFindings).
			Msg("Scan completed")
	}()

	// Return immediate response with scan ID
	// Note: In a real implementation, we'd generate the scan ID before starting
	// For now, we return a placeholder response
	respondJSON(w, http.StatusAccepted, ScanResponse{
		ScanID:  "pending",
		Status:  "running",
		Started: time.Now().Format(time.RFC3339),
	})
}

// handleListScans handles GET /api/v1/scans
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	page, pageSize := parsePagination(r)

	log.Info().
		Int("page", page).
		Int("page_size", pageSize).
		Msg("Scan listing requested")

	// Query scans from database
	scans, total, err := s.listScansFromDB(page, pageSize)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list scans")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to retrieve scans", nil)
		return
	}

	respondJSON(w, http.StatusOK, ScanListResponse{
		Scans:    scans,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// handleGetScan handles GET /api/v1/scans/{id}
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Scan ID is required", nil)
		return
	}

	log.Info().Str("scan_id", scanID).Msg("Scan retrieval requested")

	// Query scan from database
	scan, err := s.getScanFromDB(scanID)
	if err != nil {
		log.Error().Err(err).Str("scan_id", scanID).Msg("Failed to retrieve scan")
		respondError(w, http.StatusNotFound, ErrCodeNotFound, "Scan not found", nil)
		return
	}

	respondJSON(w, http.StatusOK, scan)
}

// handleListFindings handles GET /api/v1/findings
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	page, pageSize := parsePagination(r)

	// Parse filter parameters
	filters := parseFilters(r)

	log.Info().
		Int("page", page).
		Int("page_size", pageSize).
		Interface("filters", filters).
		Msg("Findings listing requested")

	// Query findings from database
	findings, total, err := s.listFindingsFromDB(page, pageSize, filters)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list findings")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to retrieve findings", nil)
		return
	}

	respondJSON(w, http.StatusOK, FindingsResponse{
		Findings: findings,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// handleGetFinding handles GET /api/v1/findings/{id}
func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Finding ID is required", nil)
		return
	}

	log.Info().Str("finding_id", findingID).Msg("Finding retrieval requested")

	// Query finding from database
	finding, err := s.getFindingFromDB(findingID)
	if err != nil {
		log.Error().Err(err).Str("finding_id", findingID).Msg("Failed to retrieve finding")
		respondError(w, http.StatusNotFound, ErrCodeNotFound, "Finding not found", nil)
		return
	}

	respondJSON(w, http.StatusOK, finding)
}

// handleValidatePolicy handles POST /api/v1/policies/validate
func (s *Server) handleValidatePolicy(w http.ResponseWriter, r *http.Request) {
	var req PolicyValidateRequest
	if err := parseJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid request body", nil)
		return
	}

	// TODO: Implement policy validation in task 2.2
	log.Info().Msg("Policy validation requested")

	respondError(w, http.StatusNotImplemented, ErrCodeInternalError, "Policy validation not yet implemented", nil)
}

// handleGenerateReport handles GET /api/v1/reports/{id}
func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "id")
	if reportID == "" {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Report ID is required", nil)
		return
	}

	// TODO: Implement report generation in task 2.2
	log.Info().Str("report_id", reportID).Msg("Report generation requested")

	respondError(w, http.StatusNotImplemented, ErrCodeInternalError, "Report generation not yet implemented", nil)
}

// handleGetTrends handles GET /api/v1/analytics/trends
func (s *Server) handleGetTrends(w http.ResponseWriter, r *http.Request) {
	// Parse date range parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	// Default to last 30 days if not specified
	end := time.Now()
	start := end.AddDate(0, 0, -30)

	if startStr != "" {
		if parsed, err := time.Parse("2006-01-02", startStr); err == nil {
			start = parsed
		} else {
			respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid start date format (use YYYY-MM-DD)", nil)
			return
		}
	}

	if endStr != "" {
		if parsed, err := time.Parse("2006-01-02", endStr); err == nil {
			end = parsed
		} else {
			respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid end date format (use YYYY-MM-DD)", nil)
			return
		}
	}

	log.Info().
		Str("start", start.Format("2006-01-02")).
		Str("end", end.Format("2006-01-02")).
		Msg("Analytics trends requested")

	// Get trends from analytics engine
	trends, err := s.analytics.GetTrends(start, end)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get trends")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to retrieve trends", nil)
		return
	}

	// Convert to response format
	response := TrendsResponse{
		Dates:            trends.Dates,
		Critical:         trends.Critical,
		High:             trends.High,
		Medium:           trends.Medium,
		Low:              trends.Low,
		Total:            trends.Total,
		NewFindings:      trends.NewFindings,
		ResolvedFindings: trends.ResolvedFindings,
	}

	respondJSON(w, http.StatusOK, response)
}

// handleGetMTTR handles GET /api/v1/analytics/mttr
func (s *Server) handleGetMTTR(w http.ResponseWriter, r *http.Request) {
	// Parse optional filters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	severity := r.URL.Query().Get("severity")

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid start date format (use YYYY-MM-DD)", nil)
			return
		}
	}

	if endStr != "" {
		end, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid end date format (use YYYY-MM-DD)", nil)
			return
		}
	}

	log.Info().
		Str("start", startStr).
		Str("end", endStr).
		Str("severity", severity).
		Msg("MTTR metrics requested")

	// Get MTTR from analytics engine
	mttr, err := s.analytics.GetMTTRWithFilter(start, end, severity)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get MTTR")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to retrieve MTTR metrics", nil)
		return
	}

	// Convert to response format
	response := convertMTTRToResponse(mttr)

	respondJSON(w, http.StatusOK, response)
}

// handleGetSecurityScore handles GET /api/v1/analytics/score
func (s *Server) handleGetSecurityScore(w http.ResponseWriter, r *http.Request) {
	// Check if requesting score for a specific scan
	scanID := r.URL.Query().Get("scan_id")

	log.Info().Str("scan_id", scanID).Msg("Security score requested")

	var score *analytics.SecurityScore
	var err error

	if scanID != "" {
		// Get score for specific scan
		score, err = s.analytics.GetScoreForScan(scanID)
	} else {
		// Get current overall score
		score, err = s.analytics.GetSecurityScore()
	}

	if err != nil {
		log.Error().Err(err).Msg("Failed to get security score")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to retrieve security score", nil)
		return
	}

	// Convert to response format
	response := SecurityScoreResponse{
		Score:          score.Score,
		Grade:          score.Grade,
		Timestamp:      score.Timestamp.Format(time.RFC3339),
		TotalFindings:  score.TotalFindings,
		CriticalCount:  score.CriticalCount,
		HighCount:      score.HighCount,
		MediumCount:    score.MediumCount,
		LowCount:       score.LowCount,
		TrendDirection: score.TrendDirection,
		ChangeFromPrev: score.ChangeFromPrev,
	}

	respondJSON(w, http.StatusOK, response)
}

// handleGetHotspots handles GET /api/v1/analytics/hotspots
func (s *Server) handleGetHotspots(w http.ResponseWriter, r *http.Request) {
	// Parse limit parameter
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	// Check if requesting hotspots for a specific scan
	scanID := r.URL.Query().Get("scan_id")

	log.Info().
		Int("limit", limit).
		Str("scan_id", scanID).
		Msg("Hotspots analysis requested")

	var analysis *analytics.HotspotAnalysis
	var err error

	if scanID != "" {
		// Get hotspots for specific scan
		analysis, err = s.analytics.GetHotspotsForScan(scanID, limit)
	} else {
		// Get current hotspots
		analysis, err = s.analytics.GetHotspots(limit)
	}

	if err != nil {
		log.Error().Err(err).Msg("Failed to get hotspots")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to retrieve hotspots", nil)
		return
	}

	// Convert to response format
	hotspots := make([]FileHotspotResponse, len(analysis.Hotspots))
	for i, h := range analysis.Hotspots {
		hotspots[i] = FileHotspotResponse{
			FilePath:       h.FilePath,
			TotalFindings:  h.TotalFindings,
			CriticalCount:  h.CriticalCount,
			HighCount:      h.HighCount,
			MediumCount:    h.MediumCount,
			LowCount:       h.LowCount,
			FindingDensity: h.FindingDensity,
			SeverityScore:  h.SeverityScore,
			UniqueFindings: h.UniqueFindings,
		}
	}

	response := HotspotsResponse{
		Hotspots:      hotspots,
		TotalFiles:    analysis.TotalFiles,
		TotalFindings: analysis.TotalFindings,
		AnalyzedAt:    analysis.AnalyzedAt.Format(time.RFC3339),
	}

	respondJSON(w, http.StatusOK, response)
}

// convertMTTRToResponse converts analytics.MTTRMetrics to MTTRResponse
func convertMTTRToResponse(mttr *analytics.MTTRMetrics) *MTTRResponse {
	response := &MTTRResponse{
		MeanTTR:       mttr.MeanTTR.String(),
		MedianTTR:     mttr.MedianTTR.String(),
		P75TTR:        mttr.P75TTR.String(),
		P90TTR:        mttr.P90TTR.String(),
		P95TTR:        mttr.P95TTR.String(),
		MinTTR:        mttr.MinTTR.String(),
		MaxTTR:        mttr.MaxTTR.String(),
		TotalResolved: mttr.TotalResolved,
	}

	// Convert by-severity metrics if present
	if mttr.BySeverity != nil && len(mttr.BySeverity) > 0 {
		response.BySeverity = make(map[string]*MTTRResponse)
		for severity, metrics := range mttr.BySeverity {
			response.BySeverity[severity] = convertMTTRToResponse(metrics)
		}
	}

	return response
}

// handleImportFindings handles POST /api/v1/findings/import
func (s *Server) handleImportFindings(w http.ResponseWriter, r *http.Request) {
	var req ImportRequest
	if err := parseJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Invalid request body", nil)
		return
	}

	// Validate request
	if req.Format == "" {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Format is required", nil)
		return
	}
	if req.Data == "" {
		respondError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "Data is required", nil)
		return
	}

	log.Info().
		Str("format", req.Format).
		Str("mode", req.Mode).
		Msg("Import findings requested")

	// TODO: Implement import logic using importer package
	// For now, return not implemented
	respondError(w, http.StatusNotImplemented, ErrCodeInternalError, "Import not yet fully implemented via API", nil)
}

// Helper functions for database queries

// parsePagination parses pagination parameters from request
func parsePagination(r *http.Request) (page int, pageSize int) {
	page = 1
	pageSize = 50

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	return page, pageSize
}

// parseFilters parses filter parameters from request
func parseFilters(r *http.Request) map[string]string {
	filters := make(map[string]string)

	if severity := r.URL.Query().Get("severity"); severity != "" {
		filters["severity"] = severity
	}

	if cweID := r.URL.Query().Get("cwe_id"); cweID != "" {
		filters["cwe_id"] = cweID
	}

	if runID := r.URL.Query().Get("run_id"); runID != "" {
		filters["run_id"] = runID
	}

	if filePath := r.URL.Query().Get("file_path"); filePath != "" {
		filters["file_path"] = filePath
	}

	return filters
}

// listScansFromDB retrieves scans from database with pagination
func (s *Server) listScansFromDB(page, pageSize int) ([]ScanSummary, int, error) {
	offset := (page - 1) * pageSize

	// Count total scans
	var total int
	err := s.db.QueryRow("SELECT COUNT(*) FROM runs").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count scans: %w", err)
	}

	// Query scans with pagination
	query := `
		SELECT 
			r.run_id,
			r.target_path,
			r.status,
			r.start_time,
			r.end_time,
			r.duration,
			COUNT(f.norm_id) as total_findings
		FROM runs r
		LEFT JOIN findings_normalized f ON r.run_id = f.run_id
		GROUP BY r.run_id
		ORDER BY r.start_time DESC
		LIMIT ? OFFSET ?
	`

	rows, err := s.db.Query(query, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query scans: %w", err)
	}
	defer rows.Close()

	var scans []ScanSummary
	for rows.Next() {
		var scan ScanSummary
		var startTime, endTime, duration int64

		err := rows.Scan(
			&scan.ScanID,
			&scan.TargetPath,
			&scan.Status,
			&startTime,
			&endTime,
			&duration,
			&scan.TotalFindings,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan row: %w", err)
		}

		scan.StartTime = time.Unix(startTime, 0).Format(time.RFC3339)
		if endTime > 0 {
			scan.EndTime = time.Unix(endTime, 0).Format(time.RFC3339)
		}
		scan.Duration = duration

		scans = append(scans, scan)
	}

	return scans, total, nil
}

// getScanFromDB retrieves a single scan from database
func (s *Server) getScanFromDB(scanID string) (*ScanDetail, error) {
	query := `
		SELECT 
			r.run_id,
			r.target_path,
			r.status,
			r.start_time,
			r.end_time,
			r.duration,
			r.offline_verified,
			r.config_hash
		FROM runs r
		WHERE r.run_id = ?
	`

	var scan ScanDetail
	var startTime, endTime, duration int64

	err := s.db.QueryRow(query, scanID).Scan(
		&scan.ScanID,
		&scan.TargetPath,
		&scan.Status,
		&startTime,
		&endTime,
		&duration,
		&scan.OfflineVerified,
		&scan.ConfigHash,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query scan: %w", err)
	}

	scan.StartTime = time.Unix(startTime, 0).Format(time.RFC3339)
	if endTime > 0 {
		scan.EndTime = time.Unix(endTime, 0).Format(time.RFC3339)
	}
	scan.Duration = duration

	// Get findings for this scan
	findings, err := s.db.GetFindingsByRun(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	// Convert storage findings to scanner findings
	scan.Findings = make([]scanner.NormalizedFinding, len(findings))
	for i, f := range findings {
		scan.Findings[i] = scanner.NormalizedFinding{
			ID:              f.NormID,
			FindingID:       f.FindingID,
			CWEID:           f.CWEID,
			CWEDescription:  f.CWEDescription,
			Severity:        f.Severity,
			Confidence:      f.Confidence,
			CodeFingerprint: f.CodeFingerprint,
			FilePath:        f.FilePath,
			LineNumber:      f.LineNumber,
			Description:     f.Description,
		}
	}

	// Count by severity
	scan.CriticalCount, scan.HighCount, scan.MediumCount, scan.LowCount = countBySeverity(scan.Findings)
	scan.TotalFindings = len(scan.Findings)

	return &scan, nil
}

// listFindingsFromDB retrieves findings from database with pagination and filters
func (s *Server) listFindingsFromDB(page, pageSize int, filters map[string]string) ([]scanner.NormalizedFinding, int, error) {
	offset := (page - 1) * pageSize

	// Build query with filters
	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if severity, ok := filters["severity"]; ok {
		whereClause += " AND LOWER(severity) = LOWER(?)"
		args = append(args, severity)
	}

	if cweID, ok := filters["cwe_id"]; ok {
		whereClause += " AND cwe_id = ?"
		args = append(args, cweID)
	}

	if runID, ok := filters["run_id"]; ok {
		whereClause += " AND run_id = ?"
		args = append(args, runID)
	}

	if filePath, ok := filters["file_path"]; ok {
		whereClause += " AND file_path LIKE ?"
		args = append(args, "%"+filePath+"%")
	}

	// Count total findings
	countQuery := "SELECT COUNT(*) FROM findings_normalized " + whereClause
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count findings: %w", err)
	}

	// Query findings with pagination
	query := `
		SELECT 
			norm_id, finding_id, run_id, cwe_id, cwe_description,
			severity, confidence, code_fingerprint, file_path, line_number, description
		FROM findings_normalized
		` + whereClause + `
		ORDER BY 
			CASE LOWER(severity)
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			file_path, line_number
		LIMIT ? OFFSET ?
	`

	args = append(args, pageSize, offset)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []scanner.NormalizedFinding
	for rows.Next() {
		var f scanner.NormalizedFinding

		err := rows.Scan(
			&f.ID,
			&f.FindingID,
			&f.CWEID,
			&f.CWEDescription,
			&f.Severity,
			&f.Confidence,
			&f.CodeFingerprint,
			&f.FilePath,
			&f.LineNumber,
			&f.Description,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan row: %w", err)
		}

		findings = append(findings, f)
	}

	return findings, total, nil
}

// getFindingFromDB retrieves a single finding from database
func (s *Server) getFindingFromDB(findingID string) (*scanner.NormalizedFinding, error) {
	query := `
		SELECT 
			norm_id, finding_id, run_id, cwe_id, cwe_description,
			severity, confidence, code_fingerprint, file_path, line_number, description
		FROM findings_normalized
		WHERE norm_id = ?
	`

	var f scanner.NormalizedFinding

	err := s.db.QueryRow(query, findingID).Scan(
		&f.ID,
		&f.FindingID,
		&f.CWEID,
		&f.CWEDescription,
		&f.Severity,
		&f.Confidence,
		&f.CodeFingerprint,
		&f.FilePath,
		&f.LineNumber,
		&f.Description,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("finding not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query finding: %w", err)
	}

	return &f, nil
}

// countBySeverity counts findings by severity level
func countBySeverity(findings []scanner.NormalizedFinding) (int, int, int, int) {
	var critical, high, medium, low int

	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
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

// handleOpenAPISpec handles GET /api/v1/openapi.yaml
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	// Read the OpenAPI spec file
	spec, err := readOpenAPISpec()
	if err != nil {
		log.Error().Err(err).Msg("Failed to read OpenAPI spec")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to load API specification", nil)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(spec)
}

// handleOpenAPISpecJSON handles GET /api/v1/openapi.json
func (s *Server) handleOpenAPISpecJSON(w http.ResponseWriter, r *http.Request) {
	// Read the OpenAPI spec file and convert to JSON
	spec, err := readOpenAPISpecJSON()
	if err != nil {
		log.Error().Err(err).Msg("Failed to read OpenAPI spec")
		respondError(w, http.StatusInternalServerError, ErrCodeInternalError, "Failed to load API specification", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(spec)
}

// handleSwaggerUI handles GET /api/docs
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coding Agent CLI API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
    <style>
        body {
            margin: 0;
            padding: 0;
        }
        .topbar {
            display: none;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/api/v1/openapi.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
                docExpansion: "list",
                filter: true,
                showRequestHeaders: true,
                tryItOutEnabled: true
            });
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}
