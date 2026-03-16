package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
)

// Migration represents a database migration
type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
}

// MigrationManager handles database migrations
type MigrationManager struct {
	db *sql.DB
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *sql.DB) *MigrationManager {
	return &MigrationManager{db: db}
}

// GetCurrentVersion returns the current schema version
func (m *MigrationManager) GetCurrentVersion() (int, error) {
	// Ensure schema_version table exists
	if err := m.ensureVersionTable(); err != nil {
		return 0, err
	}

	var version int
	err := m.db.QueryRow("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1").Scan(&version)
	if err == sql.ErrNoRows {
		return 0, nil // No migrations applied yet
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}

	return version, nil
}

// ensureVersionTable creates the schema_version table if it doesn't exist
func (m *MigrationManager) ensureVersionTable() error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at INTEGER NOT NULL,
			execution_time INTEGER NOT NULL
		)
	`
	_, err := m.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}
	return nil
}

// ApplyMigrations applies all pending migrations
func (m *MigrationManager) ApplyMigrations(migrations []Migration) error {
	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	// Filter pending migrations
	var pending []Migration
	for _, migration := range migrations {
		if migration.Version > currentVersion {
			pending = append(pending, migration)
		}
	}

	if len(pending) == 0 {
		log.Info().Int("version", currentVersion).Msg("Database schema is up to date")
		return nil
	}

	log.Info().
		Int("current_version", currentVersion).
		Int("target_version", pending[len(pending)-1].Version).
		Int("pending_migrations", len(pending)).
		Msg("Applying database migrations")

	// Apply each pending migration
	for _, migration := range pending {
		if err := m.applyMigration(migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
	}

	log.Info().Int("version", pending[len(pending)-1].Version).Msg("All migrations applied successfully")
	return nil
}

// applyMigration applies a single migration
func (m *MigrationManager) applyMigration(migration Migration) error {
	startTime := time.Now()

	log.Info().
		Int("version", migration.Version).
		Str("description", migration.Description).
		Msg("Applying migration")

	// Begin transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute migration
	if _, err := tx.Exec(migration.Up); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	// Record migration
	executionTime := time.Since(startTime).Milliseconds()
	query := `INSERT INTO schema_version (version, description, applied_at, execution_time) VALUES (?, ?, ?, ?)`
	if _, err := tx.Exec(query, migration.Version, migration.Description, time.Now().Unix(), executionTime); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	log.Info().
		Int("version", migration.Version).
		Int64("execution_time_ms", executionTime).
		Msg("Migration applied successfully")

	return nil
}

// Rollback rolls back the last migration
func (m *MigrationManager) Rollback(migrations []Migration) error {
	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if currentVersion == 0 {
		return fmt.Errorf("no migrations to rollback")
	}

	// Find the migration to rollback
	var targetMigration *Migration
	for i := range migrations {
		if migrations[i].Version == currentVersion {
			targetMigration = &migrations[i]
			break
		}
	}

	if targetMigration == nil {
		return fmt.Errorf("migration %d not found", currentVersion)
	}

	if targetMigration.Down == "" {
		return fmt.Errorf("migration %d has no rollback script", currentVersion)
	}

	log.Info().
		Int("version", currentVersion).
		Str("description", targetMigration.Description).
		Msg("Rolling back migration")

	// Begin transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute rollback
	if _, err := tx.Exec(targetMigration.Down); err != nil {
		return fmt.Errorf("failed to execute rollback: %w", err)
	}

	// Remove migration record
	if _, err := tx.Exec("DELETE FROM schema_version WHERE version = ?", currentVersion); err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	log.Info().Int("version", currentVersion).Msg("Migration rolled back successfully")
	return nil
}

// BackupDatabase creates a backup of the database file
func BackupDatabase(dbPath string) (string, error) {
	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.backup_%s", dbPath, timestamp)

	log.Info().
		Str("source", dbPath).
		Str("backup", backupPath).
		Msg("Creating database backup")

	// Check if source database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", fmt.Errorf("database file does not exist: %s", dbPath)
	}

	// Read source database
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to read database: %w", err)
	}

	// Write backup
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	// Verify backup
	backupInfo, err := os.Stat(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to verify backup: %w", err)
	}

	log.Info().
		Str("backup", backupPath).
		Int64("size_bytes", backupInfo.Size()).
		Msg("Database backup created successfully")

	return backupPath, nil
}

// RestoreDatabase restores a database from a backup
func RestoreDatabase(dbPath, backupPath string) error {
	log.Info().
		Str("backup", backupPath).
		Str("target", dbPath).
		Msg("Restoring database from backup")

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	// Read backup
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Write to database location
	if err := os.WriteFile(dbPath, data, 0644); err != nil {
		return fmt.Errorf("failed to restore database: %w", err)
	}

	log.Info().Str("database", dbPath).Msg("Database restored successfully")
	return nil
}

// CleanupOldBackups removes backups older than the specified number of days
func CleanupOldBackups(dbPath string, daysToKeep int) error {
	dir := filepath.Dir(dbPath)
	baseName := filepath.Base(dbPath)
	pattern := fmt.Sprintf("%s.backup_*", baseName)

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return fmt.Errorf("failed to find backups: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -daysToKeep)
	removed := 0

	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			log.Warn().Err(err).Str("file", match).Msg("Failed to stat backup file")
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(match); err != nil {
				log.Warn().Err(err).Str("file", match).Msg("Failed to remove old backup")
			} else {
				removed++
				log.Debug().Str("file", match).Msg("Removed old backup")
			}
		}
	}

	if removed > 0 {
		log.Info().Int("count", removed).Msg("Cleaned up old backups")
	}

	return nil
}
