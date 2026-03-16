package storage

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
	"github.com/rs/zerolog/log"
)

//go:embed schema.sql
var schemaFS embed.FS

// Database represents the SQLite database connection
type Database struct {
	db   *sql.DB
	path string
}

// NewDatabase creates a new database connection and runs migrations
func NewDatabase(path string) (*Database, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Check if database exists (for backup decision)
	dbExists := false
	if _, err := os.Stat(path); err == nil {
		dbExists = true
	}

	// Open database connection
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &Database{db: db, path: path}

	// Run initial schema setup (for new databases)
	if !dbExists {
		if err := database.runInitialSchema(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to run initial schema: %w", err)
		}
	}

	// Run migrations with automatic backup
	if err := database.runMigrations(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Info().Str("path", path).Msg("Database initialized")

	return database, nil
}

// runInitialSchema executes the schema.sql file for new databases
func (d *Database) runInitialSchema() error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("failed to read schema: %w", err)
	}

	if _, err := d.db.Exec(string(schema)); err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	log.Debug().Msg("Initial database schema created")
	return nil
}

// runMigrations executes pending migrations with automatic backup
func (d *Database) runMigrations() error {
	manager := NewMigrationManager(d.db)
	migrations := GetMigrations()

	// Get current version
	currentVersion, err := manager.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Check if there are pending migrations
	hasPending := false
	for _, m := range migrations {
		if m.Version > currentVersion {
			hasPending = true
			break
		}
	}

	// Create backup before applying migrations (if database exists and has pending migrations)
	if hasPending && d.path != "" && currentVersion > 0 {
		backupPath, err := BackupDatabase(d.path)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create database backup before migration")
			// Continue with migration even if backup fails
		} else {
			log.Info().Str("backup", backupPath).Msg("Database backup created before migration")
		}
	}

	// Apply migrations
	if err := manager.ApplyMigrations(migrations); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	// Clean up old backups (keep last 7 days)
	if d.path != "" {
		if err := CleanupOldBackups(d.path, 7); err != nil {
			log.Warn().Err(err).Msg("Failed to cleanup old backups")
		}
	}

	return nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// GetMigrationManager returns a migration manager for this database
func (d *Database) GetMigrationManager() *MigrationManager {
	return NewMigrationManager(d.db)
}

// GetDatabasePath returns the database file path
func (d *Database) GetDatabasePath() string {
	return d.path
}

// DB returns the underlying *sql.DB for use by analytics and other consumers that need direct access
func (d *Database) DB() *sql.DB {
	return d.db
}

// BeginTx starts a new transaction
func (d *Database) BeginTx() (*sql.Tx, error) {
	return d.db.Begin()
}

// SaveRun saves a scan run record
func (d *Database) SaveRun(run *Run) error {
	query := `
		INSERT INTO runs (run_id, target_path, start_time, end_time, duration, status, offline_verified, config_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := d.db.Exec(query,
		run.RunID,
		run.TargetPath,
		run.StartTime,
		run.EndTime,
		run.Duration,
		run.Status,
		run.OfflineVerified,
		run.ConfigHash,
	)
	if err != nil {
		return fmt.Errorf("failed to save run: %w", err)
	}

	log.Debug().Str("run_id", run.RunID).Msg("Run saved to database")
	return nil
}

// UpdateRunStatus updates the status of a run
func (d *Database) UpdateRunStatus(runID string, status string, endTime, duration int64) error {
	query := `UPDATE runs SET status = ?, end_time = ?, duration = ? WHERE run_id = ?`
	_, err := d.db.Exec(query, status, endTime, duration, runID)
	if err != nil {
		return fmt.Errorf("failed to update run status: %w", err)
	}
	return nil
}

// SaveRawFinding saves a raw finding from a scanner
func (d *Database) SaveRawFinding(finding *RawFinding) error {
	query := `
		INSERT INTO findings_raw (
			finding_id, run_id, tool_name, tool_finding_id, message, 
			file_path, line_number, severity, confidence, rule_id, category, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := d.db.Exec(query,
		finding.FindingID,
		finding.RunID,
		finding.ToolName,
		finding.ToolFindingID,
		finding.Message,
		finding.FilePath,
		finding.LineNumber,
		finding.Severity,
		finding.Confidence,
		finding.RuleID,
		finding.Category,
		finding.RawJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to save raw finding: %w", err)
	}
	return nil
}

// SaveNormalizedFinding saves a normalized finding
func (d *Database) SaveNormalizedFinding(finding *NormalizedFinding) error {
	query := `
		INSERT INTO findings_normalized (
			norm_id, finding_id, run_id, cwe_id, cwe_description, 
			severity, confidence, code_fingerprint, file_path, line_number, description
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := d.db.Exec(query,
		finding.NormID,
		finding.FindingID,
		finding.RunID,
		finding.CWEID,
		finding.CWEDescription,
		finding.Severity,
		finding.Confidence,
		finding.CodeFingerprint,
		finding.FilePath,
		finding.LineNumber,
		finding.Description,
	)
	if err != nil {
		return fmt.Errorf("failed to save normalized finding: %w", err)
	}
	return nil
}

// GetFindingsByRun retrieves all normalized findings for a run
func (d *Database) GetFindingsByRun(runID string) ([]NormalizedFinding, error) {
	query := `
		SELECT norm_id, finding_id, run_id, cwe_id, cwe_description, 
		       severity, confidence, code_fingerprint, file_path, line_number, description, created_at
		FROM findings_normalized
		WHERE run_id = ?
		ORDER BY 
			CASE LOWER(severity)
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			file_path, line_number
	`
	rows, err := d.db.Query(query, runID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []NormalizedFinding
	for rows.Next() {
		var f NormalizedFinding
		var createdAt int64
		err := rows.Scan(
			&f.NormID,
			&f.FindingID,
			&f.RunID,
			&f.CWEID,
			&f.CWEDescription,
			&f.Severity,
			&f.Confidence,
			&f.CodeFingerprint,
			&f.FilePath,
			&f.LineNumber,
			&f.Description,
			&createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		findings = append(findings, f)
	}

	return findings, nil
}

// SaveDedupeCluster saves a deduplication cluster
func (d *Database) SaveDedupeCluster(cluster *DedupeCluster) error {
	query := `
		INSERT OR REPLACE INTO dedupe_clusters (
			cluster_id, code_fingerprint, norm_finding_ids, first_seen, last_seen, occurrence_count
		) VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := d.db.Exec(query,
		cluster.ClusterID,
		cluster.CodeFingerprint,
		cluster.NormFindingIDs,
		cluster.FirstSeen,
		cluster.LastSeen,
		cluster.OccurrenceCount,
	)
	if err != nil {
		return fmt.Errorf("failed to save dedupe cluster: %w", err)
	}
	return nil
}

// GetDedupeCluster retrieves a deduplication cluster by fingerprint
func (d *Database) GetDedupeCluster(fingerprint string) (*DedupeCluster, error) {
	query := `
		SELECT cluster_id, code_fingerprint, norm_finding_ids, first_seen, last_seen, occurrence_count
		FROM dedupe_clusters
		WHERE code_fingerprint = ?
	`
	var cluster DedupeCluster
	err := d.db.QueryRow(query, fingerprint).Scan(
		&cluster.ClusterID,
		&cluster.CodeFingerprint,
		&cluster.NormFindingIDs,
		&cluster.FirstSeen,
		&cluster.LastSeen,
		&cluster.OccurrenceCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get dedupe cluster: %w", err)
	}
	return &cluster, nil
}

// SaveIssue saves or updates an issue
func (d *Database) SaveIssue(issue *Issue) error {
	query := `
		INSERT OR REPLACE INTO issues (
			issue_id, code_fingerprint, cwe_id, severity, status, 
			file_path, line_number, description, opened_ts, closed_ts
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := d.db.Exec(query,
		issue.IssueID,
		issue.CodeFingerprint,
		issue.CWEID,
		issue.Severity,
		issue.Status,
		issue.FilePath,
		issue.LineNumber,
		issue.Description,
		issue.OpenedTS,
		issue.ClosedTS,
	)
	if err != nil {
		return fmt.Errorf("failed to save issue: %w", err)
	}
	return nil
}

// GetStats returns database statistics
func (d *Database) GetStats() (*Stats, error) {
	stats := &Stats{}

	// Count runs
	err := d.db.QueryRow("SELECT COUNT(*) FROM runs").Scan(&stats.TotalRuns)
	if err != nil {
		return nil, err
	}

	// Count findings
	err = d.db.QueryRow("SELECT COUNT(*) FROM findings_normalized").Scan(&stats.TotalFindings)
	if err != nil {
		return nil, err
	}

	// Count issues
	err = d.db.QueryRow("SELECT COUNT(*) FROM issues WHERE status = 'open'").Scan(&stats.OpenIssues)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// Run represents a scan run
type Run struct {
	RunID           string
	TargetPath      string
	StartTime       int64
	EndTime         int64
	Duration        int64
	Status          string
	OfflineVerified bool
	ConfigHash      string
}

// RawFinding represents a raw finding from storage
type RawFinding struct {
	FindingID     string
	RunID         string
	ToolName      string
	ToolFindingID string
	Message       string
	FilePath      string
	LineNumber    int
	Severity      string
	Confidence    string
	RuleID        string
	Category      string
	RawJSON       string
}

// NormalizedFinding represents a normalized finding from storage
type NormalizedFinding struct {
	NormID          string
	FindingID       string
	RunID           string
	CWEID           string
	CWEDescription  string
	Severity        string
	Confidence      string
	CodeFingerprint string
	FilePath        string
	LineNumber      int
	Description     string
}

// DedupeCluster represents a deduplication cluster
type DedupeCluster struct {
	ClusterID       string
	CodeFingerprint string
	NormFindingIDs  string // JSON array
	FirstSeen       int64
	LastSeen        int64
	OccurrenceCount int
}

// Issue represents a unique vulnerability
type Issue struct {
	IssueID         string
	CodeFingerprint string
	CWEID           string
	Severity        string
	Status          string
	FilePath        string
	LineNumber      int
	Description     string
	OpenedTS        int64
	ClosedTS        int64
}

// Stats represents database statistics
type Stats struct {
	TotalRuns     int
	TotalFindings int
	OpenIssues    int
}

// Query executes a query that returns rows (for API use)
func (d *Database) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

// QueryRow executes a query that returns at most one row (for API use)
func (d *Database) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.db.QueryRow(query, args...)
}

// GetRun retrieves a single run by ID
func (d *Database) GetRun(runID string) (*Run, error) {
	query := `
		SELECT run_id, target_path, start_time, end_time, duration, status, offline_verified, config_hash
		FROM runs
		WHERE run_id = ?
	`
	var run Run
	err := d.db.QueryRow(query, runID).Scan(
		&run.RunID,
		&run.TargetPath,
		&run.StartTime,
		&run.EndTime,
		&run.Duration,
		&run.Status,
		&run.OfflineVerified,
		&run.ConfigHash,
	)
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// GetNormalizedFinding retrieves a single normalized finding by ID
func (d *Database) GetNormalizedFinding(normID string) (*NormalizedFinding, error) {
	query := `
		SELECT norm_id, finding_id, run_id, cwe_id, cwe_description,
		       severity, confidence, code_fingerprint, file_path, line_number, description
		FROM findings_normalized
		WHERE norm_id = ?
	`
	var f NormalizedFinding
	err := d.db.QueryRow(query, normID).Scan(
		&f.NormID,
		&f.FindingID,
		&f.RunID,
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
		return nil, err
	}
	return &f, nil
}
