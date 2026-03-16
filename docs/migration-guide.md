# Database Migration Guide

## Overview

The Coding Agent CLI uses a robust migration system to manage database schema evolution. This guide explains how the migration system works and how to use it.

## Features

- **Version Tracking**: Each migration has a version number and is tracked in the database
- **Automatic Migration**: Migrations are applied automatically when the database is opened
- **Rollback Capability**: Migrations can be rolled back to previous versions
- **Automatic Backup**: Database is backed up before applying migrations
- **Transaction Safety**: Each migration runs in a transaction for atomicity
- **Cleanup**: Old backups are automatically cleaned up (keeps last 7 days)

## Migration System Architecture

### Components

1. **MigrationManager**: Manages migration execution and version tracking
2. **Migration Definitions**: SQL scripts for upgrading (Up) and downgrading (Down)
3. **Version Table**: `schema_version` table tracks applied migrations
4. **Backup System**: Creates timestamped backups before migrations

### Migration Flow

```
1. Open Database
   ↓
2. Check Current Version
   ↓
3. Identify Pending Migrations
   ↓
4. Create Backup (if needed)
   ↓
5. Apply Migrations in Transaction
   ↓
6. Update Version Table
   ↓
7. Cleanup Old Backups
```

## Using the Migration System

### Automatic Migration

Migrations are applied automatically when you open the database:

```go
db, err := storage.NewDatabase("path/to/database.db")
if err != nil {
    log.Fatal(err)
}
defer db.Close()
```

### CLI Commands

#### Check Migration Status

```bash
coding-agent-cli migrate status
```

Output:
```
Database: .coding-agent/database.db
Current schema version: 2

Available migrations:
  [applied] Version 1: Initial schema (v1.0.0)
  [applied] Version 2: Add v1.2.0 analytics and webhook tables
  [pending] Version 3: Add performance indexes for v1.2.0
```

#### Apply Pending Migrations

```bash
coding-agent-cli migrate up
```

This will:
1. Create a backup of the current database
2. Apply all pending migrations
3. Update the version table
4. Clean up old backups

#### Rollback Last Migration

```bash
coding-agent-cli migrate down
```

**WARNING**: This may result in data loss. A backup is created before rollback.

#### Create Manual Backup

```bash
coding-agent-cli migrate backup
```

Output:
```
✓ Backup created: .coding-agent/database.db.backup_20240115_143022
```

#### Restore from Backup

```bash
coding-agent-cli migrate restore .coding-agent/database.db.backup_20240115_143022
```

**WARNING**: This will overwrite the current database.

## Migration Versions

### Version 1: Initial Schema (v1.0.0)

The baseline schema from v1.0.0 including:
- runs table
- findings_raw table
- findings_normalized table
- dedupe_clusters table
- issues table
- fix_events table
- policy_decisions table
- waivers table
- provenance table
- llm_cache table

### Version 2: v1.2.0 Analytics and Webhooks

Adds new tables for v1.2.0 features:
- **scan_metrics**: Aggregate statistics per scan
- **finding_trends**: Time-series data for trending
- **webhook_config**: Webhook endpoint configuration
- **webhook_deliveries**: Webhook delivery log
- **api_tokens**: API authentication tokens (optional)

### Version 3: v1.2.0 Performance Indexes

Adds performance indexes:
- Composite index on findings_normalized (run_id, severity)
- Index on findings_normalized (created_at)
- Index on runs (target_path)
- Index on runs (start_time)
- Index on issues (cwe_id)
- Index on issues (opened_ts)

## Creating New Migrations

### Step 1: Define the Migration

Add a new migration to `internal/storage/migration_definitions.go`:

```go
{
    Version:     4,
    Description: "Add new feature table",
    Up: `
        CREATE TABLE new_feature (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        
        CREATE INDEX idx_new_feature_name ON new_feature(name);
    `,
    Down: `
        DROP TABLE IF EXISTS new_feature;
    `,
}
```

### Step 2: Test the Migration

Write tests in `internal/storage/migrations_test.go`:

```go
func TestMigration4(t *testing.T) {
    // Test migration application
    // Test rollback
    // Verify table structure
}
```

### Step 3: Update Documentation

Update this guide with the new migration details.

## Best Practices

### Writing Migrations

1. **Idempotent**: Use `IF NOT EXISTS` and `IF EXISTS` clauses
2. **Atomic**: Keep migrations small and focused
3. **Reversible**: Always provide a Down script when possible
4. **Tested**: Test both Up and Down migrations
5. **Documented**: Add clear descriptions

### Migration Safety

1. **Backup First**: Always backup before manual migrations
2. **Test in Development**: Test migrations in dev environment first
3. **Review Changes**: Review migration SQL before applying
4. **Monitor Execution**: Watch logs during migration
5. **Have Rollback Plan**: Know how to rollback if needed

### SQLite Limitations

SQLite has some limitations for schema changes:
- Cannot drop columns (use CREATE TABLE + INSERT + DROP TABLE pattern)
- Cannot modify column types (use CREATE TABLE + INSERT + DROP TABLE pattern)
- Cannot add constraints to existing tables

Work around these by:
1. Creating a new table with desired schema
2. Copying data from old table
3. Dropping old table
4. Renaming new table

Example:
```sql
-- Create new table with desired schema
CREATE TABLE findings_normalized_new (
    norm_id TEXT PRIMARY KEY,
    -- ... other columns ...
    new_column TEXT  -- New column added
);

-- Copy data
INSERT INTO findings_normalized_new 
SELECT *, NULL as new_column FROM findings_normalized;

-- Drop old table
DROP TABLE findings_normalized;

-- Rename new table
ALTER TABLE findings_normalized_new RENAME TO findings_normalized;

-- Recreate indexes
CREATE INDEX idx_findings_normalized_cwe ON findings_normalized(cwe_id);
```

## Troubleshooting

### Migration Fails

If a migration fails:

1. Check the error message in logs
2. Verify SQL syntax
3. Check for data conflicts
4. Restore from backup if needed:
   ```bash
   coding-agent-cli migrate restore <backup-file>
   ```

### Version Mismatch

If you see version mismatch errors:

1. Check current version:
   ```bash
   coding-agent-cli migrate status
   ```

2. Verify migration definitions match expected versions
3. If needed, manually update version table (advanced):
   ```sql
   UPDATE schema_version SET version = X WHERE version = Y;
   ```

### Backup Issues

If backup creation fails:

1. Check disk space
2. Verify write permissions
3. Check database file is not locked
4. Manually create backup:
   ```bash
   cp .coding-agent/database.db .coding-agent/database.db.manual_backup
   ```

### Rollback Issues

If rollback fails:

1. Check if Down script exists for the migration
2. Verify database is not corrupted
3. Restore from backup:
   ```bash
   coding-agent-cli migrate restore <backup-file>
   ```

## Advanced Usage

### Programmatic Migration Control

```go
// Open database without automatic migration
db, err := sql.Open("sqlite", dbPath)
if err != nil {
    return err
}

// Create migration manager
manager := storage.NewMigrationManager(db)

// Get current version
version, err := manager.GetCurrentVersion()

// Apply specific migrations
migrations := storage.GetMigrations()
err = manager.ApplyMigrations(migrations)

// Rollback
err = manager.Rollback(migrations)
```

### Custom Backup Location

```go
// Create backup with custom path
backupPath := "/custom/path/backup.db"
data, err := os.ReadFile(dbPath)
if err != nil {
    return err
}
err = os.WriteFile(backupPath, data, 0644)
```

### Migration Hooks

You can add hooks before/after migrations:

```go
// Before migration
log.Info().Msg("Starting migration")
backupPath, _ := storage.BackupDatabase(dbPath)

// Apply migration
err := manager.ApplyMigrations(migrations)

// After migration
if err != nil {
    log.Error().Err(err).Msg("Migration failed, restoring backup")
    storage.RestoreDatabase(dbPath, backupPath)
} else {
    log.Info().Msg("Migration completed successfully")
}
```

## Migration History

| Version | Description | Date | Notes |
|---------|-------------|------|-------|
| 1 | Initial schema (v1.0.0) | 2024-01-01 | Baseline schema |
| 2 | Add v1.2.0 analytics and webhook tables | 2024-01-15 | New tables for analytics and webhooks |
| 3 | Add performance indexes for v1.2.0 | 2024-01-15 | Performance optimization |

## References

- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [Database Schema](../internal/storage/schema.sql)
- [Migration Definitions](../internal/storage/migration_definitions.go)
- [Migration Tests](../internal/storage/migrations_test.go)
