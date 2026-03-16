package storage

// GetMigrations returns all available migrations
func GetMigrations() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "Initial schema (v1.0.0)",
			Up: `
				-- This migration represents the existing v1.0.0 schema
				-- It's a no-op since the schema is already created by schema.sql
				SELECT 1;
			`,
			Down: `
				-- Cannot rollback initial schema
				SELECT 1;
			`,
		},
		{
			Version:     2,
			Description: "Add v1.2.0 analytics and webhook tables",
			Up: `
				-- Scan metrics table for aggregate statistics
				CREATE TABLE IF NOT EXISTS scan_metrics (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					scan_id TEXT NOT NULL,
					total_findings INTEGER NOT NULL DEFAULT 0,
					critical INTEGER NOT NULL DEFAULT 0,
					high INTEGER NOT NULL DEFAULT 0,
					medium INTEGER NOT NULL DEFAULT 0,
					low INTEGER NOT NULL DEFAULT 0,
					scan_duration INTEGER NOT NULL DEFAULT 0,
					created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
					FOREIGN KEY (scan_id) REFERENCES runs(run_id) ON DELETE CASCADE
				);

				CREATE INDEX IF NOT EXISTS idx_scan_metrics_scan_id ON scan_metrics(scan_id);
				CREATE INDEX IF NOT EXISTS idx_scan_metrics_created_at ON scan_metrics(created_at);

				-- Finding trends table for time-series data
				CREATE TABLE IF NOT EXISTS finding_trends (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					date TEXT NOT NULL,
					critical INTEGER NOT NULL DEFAULT 0,
					high INTEGER NOT NULL DEFAULT 0,
					medium INTEGER NOT NULL DEFAULT 0,
					low INTEGER NOT NULL DEFAULT 0,
					total INTEGER NOT NULL DEFAULT 0,
					new_findings INTEGER NOT NULL DEFAULT 0,
					resolved_findings INTEGER NOT NULL DEFAULT 0,
					created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
				);

				CREATE INDEX IF NOT EXISTS idx_finding_trends_date ON finding_trends(date);
				CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_trends_date_unique ON finding_trends(date);

				-- Webhook configuration table
				CREATE TABLE IF NOT EXISTS webhook_config (
					id TEXT PRIMARY KEY,
					url TEXT NOT NULL,
					events TEXT NOT NULL,
					secret TEXT,
					enabled BOOLEAN NOT NULL DEFAULT 1,
					created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
					updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
				);

				CREATE INDEX IF NOT EXISTS idx_webhook_config_enabled ON webhook_config(enabled);

				-- Webhook deliveries table for delivery log
				CREATE TABLE IF NOT EXISTS webhook_deliveries (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					webhook_id TEXT NOT NULL,
					event TEXT NOT NULL,
					payload TEXT NOT NULL,
					status TEXT NOT NULL,
					attempts INTEGER NOT NULL DEFAULT 1,
					response_code INTEGER,
					response_body TEXT,
					created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
					delivered_at INTEGER,
					FOREIGN KEY (webhook_id) REFERENCES webhook_config(id) ON DELETE CASCADE
				);

				CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
				CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
				CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_at ON webhook_deliveries(created_at);

				-- API tokens table (optional, for authentication)
				CREATE TABLE IF NOT EXISTS api_tokens (
					id TEXT PRIMARY KEY,
					token_hash TEXT NOT NULL UNIQUE,
					name TEXT NOT NULL,
					role TEXT NOT NULL DEFAULT 'viewer',
					created_by TEXT,
					created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
					expires_at INTEGER,
					last_used_at INTEGER
				);

				CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
				CREATE INDEX IF NOT EXISTS idx_api_tokens_expires_at ON api_tokens(expires_at);
			`,
			Down: `
				-- Rollback v1.2.0 tables
				DROP TABLE IF EXISTS webhook_deliveries;
				DROP TABLE IF EXISTS webhook_config;
				DROP TABLE IF EXISTS finding_trends;
				DROP TABLE IF EXISTS scan_metrics;
				DROP TABLE IF EXISTS api_tokens;
			`,
		},
		{
			Version:     3,
			Description: "Add performance indexes for v1.2.0",
			Up: `
				-- Additional indexes for findings table
				CREATE INDEX IF NOT EXISTS idx_findings_normalized_run_severity ON findings_normalized(run_id, severity);
				CREATE INDEX IF NOT EXISTS idx_findings_normalized_created_at ON findings_normalized(created_at);
				
				-- Additional indexes for runs table
				CREATE INDEX IF NOT EXISTS idx_runs_target_path ON runs(target_path);
				CREATE INDEX IF NOT EXISTS idx_runs_start_time ON runs(start_time);
				
				-- Additional indexes for issues table
				CREATE INDEX IF NOT EXISTS idx_issues_cwe_id ON issues(cwe_id);
				CREATE INDEX IF NOT EXISTS idx_issues_opened_ts ON issues(opened_ts);
			`,
			Down: `
				-- Rollback performance indexes
				DROP INDEX IF EXISTS idx_findings_normalized_run_severity;
				DROP INDEX IF EXISTS idx_findings_normalized_created_at;
				DROP INDEX IF EXISTS idx_runs_target_path;
				DROP INDEX IF EXISTS idx_runs_start_time;
				DROP INDEX IF EXISTS idx_issues_cwe_id;
				DROP INDEX IF EXISTS idx_issues_opened_ts;
			`,
		},
		{
			Version:     4,
			Description: "Add security scores table for analytics",
			Up: `
				-- Security scores table for tracking security posture over time
				CREATE TABLE IF NOT EXISTS security_scores (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					score REAL NOT NULL,
					grade TEXT NOT NULL,
					total_findings INTEGER NOT NULL DEFAULT 0,
					critical_count INTEGER NOT NULL DEFAULT 0,
					high_count INTEGER NOT NULL DEFAULT 0,
					medium_count INTEGER NOT NULL DEFAULT 0,
					low_count INTEGER NOT NULL DEFAULT 0,
					created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
				);

				CREATE INDEX IF NOT EXISTS idx_security_scores_created_at ON security_scores(created_at);
				CREATE INDEX IF NOT EXISTS idx_security_scores_score ON security_scores(score);
			`,
			Down: `
				-- Rollback security scores table
				DROP TABLE IF EXISTS security_scores;
			`,
		},
		{
			Version:     5,
			Description: "Add policies table for policy export",
			Up: `
				-- Policies table for storing policy definitions (used by exporter)
				CREATE TABLE IF NOT EXISTS policies (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					description TEXT,
					cwe TEXT NOT NULL DEFAULT '[]',
					severity TEXT NOT NULL,
					action TEXT NOT NULL,
					enabled BOOLEAN NOT NULL DEFAULT 1,
					created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
				);

				CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
				CREATE INDEX IF NOT EXISTS idx_policies_severity ON policies(severity);
			`,
			Down: `
				DROP TABLE IF EXISTS policies;
			`,
		},
	}
}
