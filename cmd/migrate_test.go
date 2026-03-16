package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestMigrateStatusCmd(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Set database path in viper
	viper.Set("database.path", dbPath)
	defer viper.Reset()

	// Run migrate status command
	err := runMigrateStatus(migrateStatusCmd, []string{})
	if err != nil {
		t.Fatalf("Failed to run migrate status: %v", err)
	}
}

func TestMigrateUpCmd(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Set database path in viper
	viper.Set("database.path", dbPath)
	defer viper.Reset()

	// Run migrate up command
	err := runMigrateUp(migrateUpCmd, []string{})
	if err != nil {
		t.Fatalf("Failed to run migrate up: %v", err)
	}

	// Verify database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}
}

func TestMigrateBackupCmd(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a test database
	err := os.WriteFile(dbPath, []byte("test database"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Set database path in viper
	viper.Set("database.path", dbPath)
	defer viper.Reset()

	// Run migrate backup command
	err = runMigrateBackup(migrateBackupCmd, []string{})
	if err != nil {
		t.Fatalf("Failed to run migrate backup: %v", err)
	}

	// Verify backup was created (check for files matching pattern)
	matches, err := filepath.Glob(dbPath + ".backup_*")
	if err != nil {
		t.Fatalf("Failed to find backup files: %v", err)
	}

	if len(matches) == 0 {
		t.Error("No backup file was created")
	}
}

func TestMigrateRestoreCmd(t *testing.T) {
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

	// Set database path in viper
	viper.Set("database.path", dbPath)
	defer viper.Reset()

	// Run migrate restore command
	err = runMigrateRestore(migrateRestoreCmd, []string{backupPath})
	if err != nil {
		t.Fatalf("Failed to run migrate restore: %v", err)
	}

	// Verify database was restored
	restoredData, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("Failed to read restored database: %v", err)
	}

	if string(restoredData) != string(backupData) {
		t.Error("Restored database content doesn't match backup")
	}
}

func TestMigrateDownCmd(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Set database path in viper
	viper.Set("database.path", dbPath)
	defer viper.Reset()

	// First, apply migrations
	err := runMigrateUp(migrateUpCmd, []string{})
	if err != nil {
		t.Fatalf("Failed to run migrate up: %v", err)
	}

	// Then rollback
	err = runMigrateDown(migrateDownCmd, []string{})
	if err != nil {
		t.Fatalf("Failed to run migrate down: %v", err)
	}

	// Verify backup was created during rollback
	matches, err := filepath.Glob(dbPath + ".backup_*")
	if err != nil {
		t.Fatalf("Failed to find backup files: %v", err)
	}

	if len(matches) == 0 {
		t.Error("No backup file was created during rollback")
	}
}
