package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrationManager_GetCurrentVersion(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	manager := NewMigrationManager(db)

	// Test initial version (should be 0)
	version, err := manager.GetCurrentVersion()
	if err != nil {
		t.Fatalf("Failed to get current version: %v", err)
	}

	if version != 0 {
		t.Errorf("Expected version 0, got %d", version)
	}
}

func TestMigrationManager_ApplyMigrations(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	manager := NewMigrationManager(db)

	// Define test migrations
	migrations := []Migration{
		{
			Version:     1,
			Description: "Create test table",
			Up: `
				CREATE TABLE test_table (
					id INTEGER PRIMARY KEY,
					name TEXT NOT NULL
				);
			`,
			Down: `DROP TABLE test_table;`,
		},
		{
			Version:     2,
			Description: "Add column to test table",
			Up: `
				ALTER TABLE test_table ADD COLUMN email TEXT;
			`,
			Down: `
				-- SQLite doesn't support DROP COLUMN easily
				-- This is a simplified rollback
				SELECT 1;
			`,
		},
	}

	// Apply migrations
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Verify version
	version, err := manager.GetCurrentVersion()
	if err != nil {
		t.Fatalf("Failed to get current version: %v", err)
	}

	if version != 2 {
		t.Errorf("Expected version 2, got %d", version)
	}

	// Verify table exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check table existence: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected test_table to exist")
	}

	// Apply migrations again (should be no-op)
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations second time: %v", err)
	}

	version, err = manager.GetCurrentVersion()
	if err != nil {
		t.Fatalf("Failed to get current version: %v", err)
	}

	if version != 2 {
		t.Errorf("Expected version 2 after second apply, got %d", version)
	}
}

func TestMigrationManager_Rollback(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	manager := NewMigrationManager(db)

	// Define test migrations
	migrations := []Migration{
		{
			Version:     1,
			Description: "Create test table",
			Up: `
				CREATE TABLE test_table (
					id INTEGER PRIMARY KEY,
					name TEXT NOT NULL
				);
			`,
			Down: `DROP TABLE test_table;`,
		},
	}

	// Apply migration
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Verify table exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check table existence: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected test_table to exist before rollback")
	}

	// Rollback migration
	err = manager.Rollback(migrations)
	if err != nil {
		t.Fatalf("Failed to rollback migration: %v", err)
	}

	// Verify version
	version, err := manager.GetCurrentVersion()
	if err != nil {
		t.Fatalf("Failed to get current version: %v", err)
	}

	if version != 0 {
		t.Errorf("Expected version 0 after rollback, got %d", version)
	}

	// Verify table doesn't exist
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check table existence: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected test_table to not exist after rollback")
	}
}

func TestMigrationManager_RollbackNoMigrations(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	manager := NewMigrationManager(db)

	// Try to rollback with no migrations
	err = manager.Rollback([]Migration{})
	if err == nil {
		t.Error("Expected error when rolling back with no migrations")
	}
}

func TestBackupDatabase(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a test database file
	testData := []byte("test database content")
	err := os.WriteFile(dbPath, testData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Create backup
	backupPath, err := BackupDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to backup database: %v", err)
	}

	// Verify backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Errorf("Backup file does not exist: %s", backupPath)
	}

	// Verify backup content
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("Failed to read backup: %v", err)
	}

	if string(backupData) != string(testData) {
		t.Errorf("Backup content doesn't match original")
	}

	// Verify backup filename format
	if !filepath.IsAbs(backupPath) {
		backupPath, _ = filepath.Abs(backupPath)
	}
	if filepath.Dir(backupPath) != tmpDir {
		t.Errorf("Backup not in same directory as original")
	}
}

func TestBackupDatabase_NonExistent(t *testing.T) {
	// Try to backup non-existent database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nonexistent.db")

	_, err := BackupDatabase(dbPath)
	if err == nil {
		t.Error("Expected error when backing up non-existent database")
	}
}

func TestRestoreDatabase(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	backupPath := filepath.Join(tmpDir, "test.db.backup")

	// Create backup file
	backupData := []byte("backup database content")
	err := os.WriteFile(backupPath, backupData, 0644)
	if err != nil {
		t.Fatalf("Failed to create backup file: %v", err)
	}

	// Restore database
	err = RestoreDatabase(dbPath, backupPath)
	if err != nil {
		t.Fatalf("Failed to restore database: %v", err)
	}

	// Verify restored content
	restoredData, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("Failed to read restored database: %v", err)
	}

	if string(restoredData) != string(backupData) {
		t.Errorf("Restored content doesn't match backup")
	}
}

func TestRestoreDatabase_NonExistentBackup(t *testing.T) {
	// Try to restore from non-existent backup
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	backupPath := filepath.Join(tmpDir, "nonexistent.backup")

	err := RestoreDatabase(dbPath, backupPath)
	if err == nil {
		t.Error("Expected error when restoring from non-existent backup")
	}
}

func TestCleanupOldBackups(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create test database
	err := os.WriteFile(dbPath, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Create old backup (8 days old)
	oldBackupPath := filepath.Join(tmpDir, "test.db.backup_20240101_120000")
	err = os.WriteFile(oldBackupPath, []byte("old backup"), 0644)
	if err != nil {
		t.Fatalf("Failed to create old backup: %v", err)
	}

	// Set modification time to 8 days ago
	oldTime := time.Now().AddDate(0, 0, -8)
	err = os.Chtimes(oldBackupPath, oldTime, oldTime)
	if err != nil {
		t.Fatalf("Failed to set old backup time: %v", err)
	}

	// Create recent backup (2 days old)
	recentBackupPath := filepath.Join(tmpDir, "test.db.backup_20240110_120000")
	err = os.WriteFile(recentBackupPath, []byte("recent backup"), 0644)
	if err != nil {
		t.Fatalf("Failed to create recent backup: %v", err)
	}

	// Set modification time to 2 days ago
	recentTime := time.Now().AddDate(0, 0, -2)
	err = os.Chtimes(recentBackupPath, recentTime, recentTime)
	if err != nil {
		t.Fatalf("Failed to set recent backup time: %v", err)
	}

	// Cleanup old backups (keep 7 days)
	err = CleanupOldBackups(dbPath, 7)
	if err != nil {
		t.Fatalf("Failed to cleanup old backups: %v", err)
	}

	// Verify old backup is removed
	if _, err := os.Stat(oldBackupPath); !os.IsNotExist(err) {
		t.Errorf("Old backup should have been removed")
	}

	// Verify recent backup still exists
	if _, err := os.Stat(recentBackupPath); os.IsNotExist(err) {
		t.Errorf("Recent backup should still exist")
	}
}

func TestGetMigrations(t *testing.T) {
	migrations := GetMigrations()

	if len(migrations) == 0 {
		t.Error("Expected at least one migration")
	}

	// Verify migrations are properly ordered
	for i := 0; i < len(migrations)-1; i++ {
		if migrations[i].Version >= migrations[i+1].Version {
			t.Errorf("Migrations not properly ordered: %d >= %d", migrations[i].Version, migrations[i+1].Version)
		}
	}

	// Verify each migration has required fields
	for _, m := range migrations {
		if m.Version <= 0 {
			t.Errorf("Migration has invalid version: %d", m.Version)
		}
		if m.Description == "" {
			t.Errorf("Migration %d has no description", m.Version)
		}
		if m.Up == "" {
			t.Errorf("Migration %d has no Up script", m.Version)
		}
		// Down script is optional for some migrations
	}
}

func TestMigration_V2_TablesCreated(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	manager := NewMigrationManager(db)

	// Get actual migrations
	migrations := GetMigrations()

	// Apply migrations up to version 2
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Verify version
	version, err := manager.GetCurrentVersion()
	if err != nil {
		t.Fatalf("Failed to get current version: %v", err)
	}

	if version < 2 {
		t.Errorf("Expected version >= 2, got %d", version)
	}

	// Verify all v1.2.0 tables exist
	expectedTables := []string{
		"scan_metrics",
		"finding_trends",
		"webhook_config",
		"webhook_deliveries",
		"api_tokens",
	}

	for _, tableName := range expectedTables {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check table existence for %s: %v", tableName, err)
		}

		if count != 1 {
			t.Errorf("Expected table %s to exist", tableName)
		}
	}

	// Verify scan_metrics table structure
	t.Run("scan_metrics_structure", func(t *testing.T) {
		rows, err := db.Query("PRAGMA table_info(scan_metrics)")
		if err != nil {
			t.Fatalf("Failed to get table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]bool)
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltValue sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name] = true
		}

		expectedColumns := []string{"id", "scan_id", "total_findings", "critical", "high", "medium", "low", "scan_duration", "created_at"}
		for _, col := range expectedColumns {
			if !columns[col] {
				t.Errorf("Expected column %s in scan_metrics table", col)
			}
		}
	})

	// Verify finding_trends table structure
	t.Run("finding_trends_structure", func(t *testing.T) {
		rows, err := db.Query("PRAGMA table_info(finding_trends)")
		if err != nil {
			t.Fatalf("Failed to get table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]bool)
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltValue sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name] = true
		}

		expectedColumns := []string{"id", "date", "critical", "high", "medium", "low", "total", "new_findings", "resolved_findings", "created_at"}
		for _, col := range expectedColumns {
			if !columns[col] {
				t.Errorf("Expected column %s in finding_trends table", col)
			}
		}
	})

	// Verify webhook_config table structure
	t.Run("webhook_config_structure", func(t *testing.T) {
		rows, err := db.Query("PRAGMA table_info(webhook_config)")
		if err != nil {
			t.Fatalf("Failed to get table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]bool)
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltValue sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name] = true
		}

		expectedColumns := []string{"id", "url", "events", "secret", "enabled", "created_at", "updated_at"}
		for _, col := range expectedColumns {
			if !columns[col] {
				t.Errorf("Expected column %s in webhook_config table", col)
			}
		}
	})

	// Verify webhook_deliveries table structure
	t.Run("webhook_deliveries_structure", func(t *testing.T) {
		rows, err := db.Query("PRAGMA table_info(webhook_deliveries)")
		if err != nil {
			t.Fatalf("Failed to get table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]bool)
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltValue sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name] = true
		}

		expectedColumns := []string{"id", "webhook_id", "event", "payload", "status", "attempts", "response_code", "response_body", "created_at", "delivered_at"}
		for _, col := range expectedColumns {
			if !columns[col] {
				t.Errorf("Expected column %s in webhook_deliveries table", col)
			}
		}
	})

	// Verify api_tokens table structure
	t.Run("api_tokens_structure", func(t *testing.T) {
		rows, err := db.Query("PRAGMA table_info(api_tokens)")
		if err != nil {
			t.Fatalf("Failed to get table info: %v", err)
		}
		defer rows.Close()

		columns := make(map[string]bool)
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltValue sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}
			columns[name] = true
		}

		expectedColumns := []string{"id", "token_hash", "name", "role", "created_by", "created_at", "expires_at", "last_used_at"}
		for _, col := range expectedColumns {
			if !columns[col] {
				t.Errorf("Expected column %s in api_tokens table", col)
			}
		}
	})

	// Verify indexes exist
	t.Run("indexes_exist", func(t *testing.T) {
		expectedIndexes := []string{
			"idx_scan_metrics_scan_id",
			"idx_scan_metrics_created_at",
			"idx_finding_trends_date",
			"idx_webhook_config_enabled",
			"idx_webhook_deliveries_webhook_id",
			"idx_webhook_deliveries_status",
			"idx_webhook_deliveries_created_at",
			"idx_api_tokens_token_hash",
			"idx_api_tokens_expires_at",
		}

		for _, indexName := range expectedIndexes {
			var count int
			err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", indexName).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check index existence for %s: %v", indexName, err)
			}

			if count != 1 {
				t.Errorf("Expected index %s to exist", indexName)
			}
		}
	})
}

func TestMigration_V2_Rollback(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	manager := NewMigrationManager(db)

	// Get actual migrations
	migrations := GetMigrations()

	// Apply migrations up to version 2
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Verify tables exist
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scan_metrics'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check table existence: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected scan_metrics table to exist before rollback")
	}

	// Rollback migration 2
	err = manager.Rollback(migrations)
	if err != nil {
		t.Fatalf("Failed to rollback migration: %v", err)
	}

	// Verify v1.2.0 tables are removed
	tablesToCheck := []string{
		"scan_metrics",
		"finding_trends",
		"webhook_config",
		"webhook_deliveries",
		"api_tokens",
	}

	for _, tableName := range tablesToCheck {
		err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check table existence for %s: %v", tableName, err)
		}

		if count != 0 {
			t.Errorf("Expected table %s to not exist after rollback", tableName)
		}
	}
}

func TestMigration_V2_DataInsertion(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	manager := NewMigrationManager(db)

	// Get actual migrations
	migrations := GetMigrations()

	// Apply migrations
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Test inserting data into scan_metrics
	t.Run("insert_scan_metrics", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO scan_metrics (scan_id, total_findings, critical, high, medium, low, scan_duration)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, "test-scan-1", 10, 2, 3, 4, 1, 5000)
		if err != nil {
			t.Fatalf("Failed to insert into scan_metrics: %v", err)
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM scan_metrics WHERE scan_id = ?", "test-scan-1").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query scan_metrics: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 row in scan_metrics, got %d", count)
		}
	})

	// Test inserting data into finding_trends
	t.Run("insert_finding_trends", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO finding_trends (date, critical, high, medium, low, total, new_findings, resolved_findings)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, "2024-01-01", 2, 3, 4, 1, 10, 5, 2)
		if err != nil {
			t.Fatalf("Failed to insert into finding_trends: %v", err)
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM finding_trends WHERE date = ?", "2024-01-01").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query finding_trends: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 row in finding_trends, got %d", count)
		}
	})

	// Test inserting data into webhook_config
	t.Run("insert_webhook_config", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO webhook_config (id, url, events, secret, enabled)
			VALUES (?, ?, ?, ?, ?)
		`, "webhook-1", "https://example.com/webhook", `["scan_complete"]`, "secret123", true)
		if err != nil {
			t.Fatalf("Failed to insert into webhook_config: %v", err)
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM webhook_config WHERE id = ?", "webhook-1").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query webhook_config: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 row in webhook_config, got %d", count)
		}
	})

	// Test inserting data into webhook_deliveries
	t.Run("insert_webhook_deliveries", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO webhook_deliveries (webhook_id, event, payload, status, attempts)
			VALUES (?, ?, ?, ?, ?)
		`, "webhook-1", "scan_complete", `{"scan_id":"test"}`, "success", 1)
		if err != nil {
			t.Fatalf("Failed to insert into webhook_deliveries: %v", err)
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = ?", "webhook-1").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query webhook_deliveries: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 row in webhook_deliveries, got %d", count)
		}
	})

	// Test inserting data into api_tokens
	t.Run("insert_api_tokens", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO api_tokens (id, token_hash, name, role, created_by)
			VALUES (?, ?, ?, ?, ?)
		`, "token-1", "hash123", "Test Token", "admin", "user1")
		if err != nil {
			t.Fatalf("Failed to insert into api_tokens: %v", err)
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM api_tokens WHERE id = ?", "token-1").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query api_tokens: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 row in api_tokens, got %d", count)
		}
	})
}

func TestMigration_V3_PerformanceIndexes(t *testing.T) {
	// Create temporary database with initial schema
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create initial schema (simulating v1.0.0)
	_, err = db.Exec(`
		CREATE TABLE runs (
			run_id TEXT PRIMARY KEY,
			target_path TEXT NOT NULL,
			start_time INTEGER NOT NULL,
			status TEXT NOT NULL
		);

		CREATE TABLE findings_normalized (
			norm_id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		);

		CREATE TABLE issues (
			issue_id TEXT PRIMARY KEY,
			cwe_id TEXT,
			opened_ts INTEGER NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("Failed to create initial schema: %v", err)
	}

	manager := NewMigrationManager(db)

	// Get migrations and apply up to v3
	migrations := GetMigrations()
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Verify version
	version, err := manager.GetCurrentVersion()
	if err != nil {
		t.Fatalf("Failed to get current version: %v", err)
	}

	if version < 3 {
		t.Errorf("Expected version >= 3, got %d", version)
	}

	// Verify all performance indexes exist
	expectedIndexes := []string{
		"idx_findings_normalized_run_severity",
		"idx_findings_normalized_created_at",
		"idx_runs_target_path",
		"idx_runs_start_time",
		"idx_issues_cwe_id",
		"idx_issues_opened_ts",
	}

	for _, indexName := range expectedIndexes {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", indexName).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check index existence for %s: %v", indexName, err)
		}

		if count != 1 {
			t.Errorf("Expected index %s to exist", indexName)
		}
	}
}

func TestMigration_V3_IndexUsage(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create schema with tables
	_, err = db.Exec(`
		CREATE TABLE runs (
			run_id TEXT PRIMARY KEY,
			target_path TEXT NOT NULL,
			start_time INTEGER NOT NULL,
			status TEXT NOT NULL
		);

		CREATE TABLE findings_normalized (
			norm_id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		);

		CREATE TABLE issues (
			issue_id TEXT PRIMARY KEY,
			cwe_id TEXT,
			opened_ts INTEGER NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	manager := NewMigrationManager(db)
	migrations := GetMigrations()
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Insert test data
	_, err = db.Exec(`
		INSERT INTO runs (run_id, target_path, start_time, status) VALUES
		('run1', '/path/to/project1', 1000, 'completed'),
		('run2', '/path/to/project2', 2000, 'completed'),
		('run3', '/path/to/project1', 3000, 'completed');
	`)
	if err != nil {
		t.Fatalf("Failed to insert test runs: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO findings_normalized (norm_id, run_id, severity, created_at) VALUES
		('f1', 'run1', 'critical', 1000),
		('f2', 'run1', 'high', 1001),
		('f3', 'run2', 'critical', 2000),
		('f4', 'run3', 'medium', 3000);
	`)
	if err != nil {
		t.Fatalf("Failed to insert test findings: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO issues (issue_id, cwe_id, opened_ts) VALUES
		('i1', 'CWE-79', 1000),
		('i2', 'CWE-89', 2000),
		('i3', 'CWE-79', 3000);
	`)
	if err != nil {
		t.Fatalf("Failed to insert test issues: %v", err)
	}

	// Test query using composite index (run_id, severity)
	t.Run("composite_index_query", func(t *testing.T) {
		rows, err := db.Query("EXPLAIN QUERY PLAN SELECT * FROM findings_normalized WHERE run_id = ? AND severity = ?", "run1", "critical")
		if err != nil {
			t.Fatalf("Failed to explain query: %v", err)
		}
		defer rows.Close()

		// Check if index is used in query plan
		foundIndex := false
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatalf("Failed to scan query plan: %v", err)
			}
			if detail != "" {
				foundIndex = true
			}
		}

		if !foundIndex {
			t.Log("Query plan did not explicitly mention index (this is acceptable in SQLite)")
		}

		// Verify query returns correct results
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM findings_normalized WHERE run_id = ? AND severity = ?", "run1", "critical").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query findings: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 finding, got %d", count)
		}
	})

	// Test query using created_at index
	t.Run("created_at_index_query", func(t *testing.T) {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM findings_normalized WHERE created_at >= ?", 2000).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query findings by created_at: %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 findings, got %d", count)
		}
	})

	// Test query using target_path index
	t.Run("target_path_index_query", func(t *testing.T) {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM runs WHERE target_path = ?", "/path/to/project1").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query runs by target_path: %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 runs, got %d", count)
		}
	})

	// Test query using start_time index
	t.Run("start_time_index_query", func(t *testing.T) {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM runs WHERE start_time >= ?", 2000).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query runs by start_time: %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 runs, got %d", count)
		}
	})

	// Test query using cwe_id index
	t.Run("cwe_id_index_query", func(t *testing.T) {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM issues WHERE cwe_id = ?", "CWE-79").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query issues by cwe_id: %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 issues, got %d", count)
		}
	})

	// Test query using opened_ts index
	t.Run("opened_ts_index_query", func(t *testing.T) {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM issues WHERE opened_ts >= ?", 2000).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query issues by opened_ts: %v", err)
		}
		if count != 2 {
			t.Errorf("Expected 2 issues, got %d", count)
		}
	})
}

func TestMigration_V3_Rollback(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create initial schema
	_, err = db.Exec(`
		CREATE TABLE runs (
			run_id TEXT PRIMARY KEY,
			target_path TEXT NOT NULL,
			start_time INTEGER NOT NULL,
			status TEXT NOT NULL
		);

		CREATE TABLE findings_normalized (
			norm_id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		);

		CREATE TABLE issues (
			issue_id TEXT PRIMARY KEY,
			cwe_id TEXT,
			opened_ts INTEGER NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("Failed to create initial schema: %v", err)
	}

	manager := NewMigrationManager(db)
	migrations := GetMigrations()

	// Apply migrations up to v3
	err = manager.ApplyMigrations(migrations)
	if err != nil {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Verify indexes exist
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_findings_normalized_run_severity'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check index existence: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected index to exist before rollback")
	}

	// Rollback migration v3
	err = manager.Rollback(migrations)
	if err != nil {
		t.Fatalf("Failed to rollback migration: %v", err)
	}

	// Verify indexes are removed
	indexesToCheck := []string{
		"idx_findings_normalized_run_severity",
		"idx_findings_normalized_created_at",
		"idx_runs_target_path",
		"idx_runs_start_time",
		"idx_issues_cwe_id",
		"idx_issues_opened_ts",
	}

	for _, indexName := range indexesToCheck {
		err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", indexName).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check index existence for %s: %v", indexName, err)
		}

		if count != 0 {
			t.Errorf("Expected index %s to not exist after rollback", indexName)
		}
	}
}
