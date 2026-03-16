package cmd

import (
	"fmt"

	"github.com/coding-agent/cli/internal/storage"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Manage database migrations",
	Long: `Manage database schema migrations.

The migrate command provides tools for managing database schema versions,
including checking current version, applying migrations, and rolling back changes.`,
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current migration status",
	Long:  `Display the current database schema version and available migrations.`,
	RunE:  runMigrateStatus,
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply pending migrations",
	Long: `Apply all pending database migrations.

A backup of the database will be created automatically before applying migrations.`,
	RunE: runMigrateUp,
}

var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Rollback the last migration",
	Long: `Rollback the most recently applied migration.

WARNING: This operation may result in data loss. A backup is recommended before rollback.`,
	RunE: runMigrateDown,
}

var migrateBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a database backup",
	Long:  `Create a backup of the current database.`,
	RunE:  runMigrateBackup,
}

var migrateRestoreCmd = &cobra.Command{
	Use:   "restore [backup-file]",
	Short: "Restore database from backup",
	Long: `Restore the database from a backup file.

WARNING: This will overwrite the current database. Use with caution.`,
	Args: cobra.ExactArgs(1),
	RunE: runMigrateRestore,
}

func init() {
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateBackupCmd)
	migrateCmd.AddCommand(migrateRestoreCmd)
}

func runMigrateStatus(cmd *cobra.Command, args []string) error {
	// Get database path
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = ".coding-agent/database.db"
	}

	// Open database
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Get migration manager
	manager := db.GetMigrationManager()

	// Get current version
	currentVersion, err := manager.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Get available migrations
	migrations := storage.GetMigrations()

	// Display status
	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Current schema version: %d\n\n", currentVersion)

	fmt.Println("Available migrations:")
	for _, m := range migrations {
		status := "pending"
		if m.Version <= currentVersion {
			status = "applied"
		}
		fmt.Printf("  [%s] Version %d: %s\n", status, m.Version, m.Description)
	}

	return nil
}

func runMigrateUp(cmd *cobra.Command, args []string) error {
	// Get database path
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = ".coding-agent/database.db"
	}

	log.Info().Str("database", dbPath).Msg("Applying migrations")

	// Open database (this will automatically apply migrations)
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}
	defer db.Close()

	// Get final version
	manager := db.GetMigrationManager()
	version, err := manager.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	fmt.Printf("✓ Database is now at version %d\n", version)
	return nil
}

func runMigrateDown(cmd *cobra.Command, args []string) error {
	// Get database path
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = ".coding-agent/database.db"
	}

	log.Warn().Msg("Rolling back migration - this may result in data loss")

	// Open database
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Get migration manager
	manager := db.GetMigrationManager()

	// Get current version
	currentVersion, err := manager.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if currentVersion == 0 {
		fmt.Println("No migrations to rollback")
		return nil
	}

	// Create backup before rollback
	backupPath, err := storage.BackupDatabase(dbPath)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create backup before rollback")
	} else {
		fmt.Printf("Backup created: %s\n", backupPath)
	}

	// Rollback
	migrations := storage.GetMigrations()
	if err := manager.Rollback(migrations); err != nil {
		return fmt.Errorf("failed to rollback migration: %w", err)
	}

	// Get new version
	newVersion, err := manager.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	fmt.Printf("✓ Rolled back from version %d to version %d\n", currentVersion, newVersion)
	return nil
}

func runMigrateBackup(cmd *cobra.Command, args []string) error {
	// Get database path
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = ".coding-agent/database.db"
	}

	// Create backup
	backupPath, err := storage.BackupDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	fmt.Printf("✓ Backup created: %s\n", backupPath)
	return nil
}

func runMigrateRestore(cmd *cobra.Command, args []string) error {
	backupPath := args[0]

	// Get database path
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = ".coding-agent/database.db"
	}

	log.Warn().
		Str("backup", backupPath).
		Str("database", dbPath).
		Msg("Restoring database from backup")

	// Restore database
	if err := storage.RestoreDatabase(dbPath, backupPath); err != nil {
		return fmt.Errorf("failed to restore database: %w", err)
	}

	fmt.Printf("✓ Database restored from: %s\n", backupPath)
	return nil
}
