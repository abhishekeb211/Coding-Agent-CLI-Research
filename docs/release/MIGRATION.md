# Migration Guide

## Migrating to v1.0.0

This is the first major release of Coding Agent CLI. If you were using pre-release versions, follow this guide to migrate.

## From Pre-Release Versions

### Database Schema Changes

The database schema has been finalized in v1.0.0. If you have an existing database from a pre-release version:

**Option 1: Start Fresh (Recommended)**
```bash
# Backup old database
mv ~/.coding-agent-cli/findings.db ~/.coding-agent-cli/findings.db.backup

# Run new scan (will create new database)
coding-agent-cli scan /path/to/code
```

**Option 2: Manual Migration**
```bash
# Export findings from old database
sqlite3 ~/.coding-agent-cli/findings.db.backup ".dump findings" > findings.sql

# Create new database with v1.0 schema
coding-agent-cli scan /path/to/code

# Import old findings (may require manual adjustments)
# Review findings.sql and adjust to new schema if needed
```

### Configuration File Changes

Configuration file format is now stable. Update your `config.yaml`:

**Old Format (Pre-release)**:
```yaml
scanners: ["bandit", "semgrep"]
output_format: "json"
```

**New Format (v1.0.0)**:
```yaml
scanners:
  - bandit
  - semgrep

output:
  format: json
  file: scan-results.json
```

### Policy File Changes

Policy file format is now stable. Update your policy files:

**Old Format (Pre-release)**:
```yaml
rules:
  - name: block-sql
    cwe: CWE-89
    action: block
```

**New Format (v1.0.0)**:
```yaml
policies:
  - id: block-sql
    name: Block SQL Injection
    action: deny
    cwe:
      - CWE-89
```

### Command-Line Changes

Some command-line flags have been renamed for consistency:

| Old Flag | New Flag | Notes |
|----------|----------|-------|
| `--output-format` | `--format` | Shorter flag name |
| `--policy-file` | `--policy` | Shorter flag name |
| `--no-llm` | `--offline` | More descriptive |

### Breaking Changes

1. **Database Schema**: New schema not compatible with pre-release versions
2. **Policy Format**: Policy files must use new YAML structure
3. **Configuration Format**: Config files must use new nested structure
4. **CLI Flags**: Some flags renamed (see table above)

### Data Migration Steps

1. **Export Old Data**
   ```bash
   # Export findings to JSON
   coding-agent-cli-old findings export --format json --output old-findings.json
   ```

2. **Install v1.0.0**
   ```bash
   # Download and install new version
   wget https://github.com/coding-agent/cli/releases/download/v1.0.0/coding-agent-cli-1.0.0-linux-amd64.tar.gz
   tar -xzf coding-agent-cli-1.0.0-linux-amd64.tar.gz
   sudo mv coding-agent-cli /usr/local/bin/
   ```

3. **Update Configuration**
   ```bash
   # Update config.yaml to new format
   # See Configuration File Changes section above
   ```

4. **Update Policies**
   ```bash
   # Update policy files to new format
   # See Policy File Changes section above
   ```

5. **Run New Scan**
   ```bash
   # Run scan with new version
   coding-agent-cli scan /path/to/code
   ```

6. **Verify Results**
   ```bash
   # Verify findings are captured correctly
   coding-agent-cli findings list
   ```

## No Breaking Changes

The following features have **no breaking changes**:

- Scanner output formats (Bandit, Semgrep)
- SARIF output format
- CWE mappings
- Finding structure
- Report formats (JSON, Markdown, HTML, CSV)

## Rollback Procedure

If you need to rollback to a pre-release version:

1. **Backup v1.0.0 Database**
   ```bash
   mv ~/.coding-agent-cli/findings.db ~/.coding-agent-cli/findings-v1.0.db
   ```

2. **Restore Old Database**
   ```bash
   mv ~/.coding-agent-cli/findings.db.backup ~/.coding-agent-cli/findings.db
   ```

3. **Reinstall Old Version**
   ```bash
   # Install your previous version
   ```

4. **Restore Old Configuration**
   ```bash
   # Restore old config.yaml and policy files
   ```

## Getting Help

If you encounter issues during migration:

1. Check the [Troubleshooting Guide](../user-guide/09-troubleshooting.md)
2. Review the [Configuration Guide](../user-guide/03-configuration.md)
3. Open an issue on GitHub: https://github.com/coding-agent/cli/issues

## Future Migrations

Starting with v1.0.0, we commit to:
- Semantic versioning
- Clear migration guides for breaking changes
- Backward compatibility within major versions
- Database migration scripts when needed
