-- Coding Agent CLI Database Schema

-- Runs table: stores scan execution metadata
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    duration INTEGER,
    status TEXT NOT NULL DEFAULT 'running',
    tool_name TEXT,
    offline_verified BOOLEAN DEFAULT 0,
    vuln_db_hash TEXT,
    config_hash TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at);

-- Findings raw table: stores tool-native output
CREATE TABLE IF NOT EXISTS findings_raw (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_finding_id TEXT,
    message TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity TEXT,
    confidence TEXT,
    rule_id TEXT,
    category TEXT,
    raw_json TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_raw_run_id ON findings_raw(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_raw_severity ON findings_raw(severity);
CREATE INDEX IF NOT EXISTS idx_findings_raw_file_path ON findings_raw(file_path);

-- Findings normalized table: CWE-aligned, dedupable findings
CREATE TABLE IF NOT EXISTS findings_normalized (
    norm_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    cwe_id TEXT,
    cwe_description TEXT,
    severity TEXT NOT NULL,
    confidence TEXT,
    code_fingerprint TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    description TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (finding_id) REFERENCES findings_raw(finding_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_normalized_cwe ON findings_normalized(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_normalized_severity ON findings_normalized(severity);
CREATE INDEX IF NOT EXISTS idx_findings_normalized_fingerprint ON findings_normalized(code_fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_normalized_run_id ON findings_normalized(run_id);

-- Dedupe clusters table: groups duplicate findings
CREATE TABLE IF NOT EXISTS dedupe_clusters (
    cluster_id TEXT PRIMARY KEY,
    code_fingerprint TEXT NOT NULL UNIQUE,
    norm_finding_ids TEXT NOT NULL, -- JSON array of finding IDs
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_dedupe_fingerprint ON dedupe_clusters(code_fingerprint);

-- Issues table: unique vulnerabilities across runs
CREATE TABLE IF NOT EXISTS issues (
    issue_id TEXT PRIMARY KEY,
    code_fingerprint TEXT NOT NULL,
    cwe_id TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- open, fixed, waived, false_positive
    file_path TEXT NOT NULL,
    line_number INTEGER,
    description TEXT,
    opened_ts INTEGER NOT NULL,
    closed_ts INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);
CREATE INDEX IF NOT EXISTS idx_issues_severity ON issues(severity);
CREATE INDEX IF NOT EXISTS idx_issues_fingerprint ON issues(code_fingerprint);

-- Fix events table: tracks remediation actions
CREATE TABLE IF NOT EXISTS fix_events (
    event_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    event_type TEXT NOT NULL, -- fixed, waived, false_positive
    commit_hash TEXT,
    fix_quality_score REAL,
    fix_description TEXT,
    fixed_by TEXT,
    timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (issue_id) REFERENCES issues(issue_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fix_events_issue_id ON fix_events(issue_id);
CREATE INDEX IF NOT EXISTS idx_fix_events_timestamp ON fix_events(timestamp);

-- Policy decisions table: governance audit trail
CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    action TEXT NOT NULL, -- deny, warn, allow
    reason TEXT,
    waiver_id TEXT,
    timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (finding_id) REFERENCES findings_normalized(norm_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_finding ON policy_decisions(finding_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_policy ON policy_decisions(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_action ON policy_decisions(action);

-- Waivers table: exception management
CREATE TABLE IF NOT EXISTS waivers (
    waiver_id TEXT PRIMARY KEY,
    finding_id TEXT,
    code_fingerprint TEXT,
    reason TEXT NOT NULL,
    expires INTEGER NOT NULL,
    approved_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', -- active, expired, revoked
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_waivers_finding ON waivers(finding_id);
CREATE INDEX IF NOT EXISTS idx_waivers_fingerprint ON waivers(code_fingerprint);
CREATE INDEX IF NOT EXISTS idx_waivers_status ON waivers(status);
CREATE INDEX IF NOT EXISTS idx_waivers_expires ON waivers(expires);

-- Provenance table: tamper-evident lineage
CREATE TABLE IF NOT EXISTS provenance (
    prov_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL, -- run, finding, decision, waiver
    entity_id TEXT NOT NULL,
    integrity_hash TEXT NOT NULL,
    previous_hash TEXT,
    collection_ts INTEGER NOT NULL,
    metadata TEXT, -- JSON
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_provenance_entity ON provenance(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_provenance_timestamp ON provenance(collection_ts);

-- LLM cache table: cache remediation guidance
CREATE TABLE IF NOT EXISTS llm_cache (
    cache_id TEXT PRIMARY KEY,
    code_fingerprint TEXT NOT NULL UNIQUE,
    cwe_id TEXT,
    prompt_hash TEXT NOT NULL,
    response TEXT NOT NULL,
    model_name TEXT NOT NULL,
    tokens_used INTEGER,
    inference_time INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_llm_cache_fingerprint ON llm_cache(code_fingerprint);
CREATE INDEX IF NOT EXISTS idx_llm_cache_cwe ON llm_cache(cwe_id);
CREATE INDEX IF NOT EXISTS idx_llm_cache_expires ON llm_cache(expires_at);
