# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-03

### Added

#### Phase 1: Project Foundation
- Initial project structure and Go module setup
- CLI framework using Cobra
- Configuration management with Viper
- Logging with zerolog
- SQLite database integration

#### Phase 2: Scanner Integration
- Bandit scanner plugin for Python security analysis
- Semgrep scanner plugin for multi-language analysis
- Scanner orchestrator for managing multiple scanners
- Raw finding storage and retrieval
- Scanner output parsing and normalization

#### Phase 3: CWE Mapping & SARIF
- CWE mapping for 100+ scanner rules
- Pattern-based CWE detection for unknown rules
- SARIF 2.1.0 compliant output generation
- CWE metadata extraction from scanner outputs
- OWASP Top 10 mapping support

#### Phase 4: LLM Integration
- Mock LLM provider for testing
- Remediation guidance generation
- Response caching for performance
- PII redaction before LLM calls
- Prompt template system

#### Phase 5: Policy Engine
- YAML-based policy definition
- Policy evaluation engine
- Waiver management system
- Compliance reporting
- Multiple policy actions (deny, warn, allow)

#### Phase 6: Reporting & CLI
- JSON report generation
- SARIF report generation
- Markdown report generation
- HTML report generation
- CSV export functionality
- CLI commands: scan, findings, policy, report
- Database statistics and queries

#### Phase 7: Testing & Documentation
- Comprehensive unit tests (>70% coverage)
- Integration tests for end-to-end workflows
- Performance benchmarks
- Complete user documentation
- Developer guides and API reference
- Policy writing guide
- Multi-platform build system

### Features

- **Multi-Scanner Support**: Integrate Bandit and Semgrep
- **CWE Normalization**: Map findings to CWE categories
- **Policy Enforcement**: Define and enforce security policies
- **AI Remediation**: Generate remediation guidance with LLM
- **Multiple Output Formats**: JSON, SARIF, Markdown, HTML, CSV
- **Offline Mode**: Scan without external dependencies
- **Finding Deduplication**: Track unique vulnerabilities
- **Waiver Management**: Handle false positives and accepted risks
- **Compliance Reporting**: Generate compliance reports
- **Database Persistence**: Store and query findings

### Security

- PII redaction before LLM calls
- Secure credential handling
- Input validation and sanitization
- SQL injection prevention

### Performance

- Parallel scanner execution
- LLM response caching
- Efficient database queries
- Optimized finding deduplication

## [1.2.0] - 2026-06-01

### Added

#### Web Dashboard & REST API
- Browser-based web dashboard for viewing findings and analytics
- Responsive UI with light and dark theme support
- Progressive Web App (PWA) with offline support
- REST API with full programmatic access to all functionality
- API versioning with `/api/v1` prefix
- OpenAPI/Swagger documentation for all endpoints
- Rate limiting and request logging for API security
- Pagination, filtering, and sorting for list endpoints

#### Real LLM Provider Integrations
- OpenAI provider with GPT-4 and GPT-3.5-turbo support
- Anthropic provider with Claude 3 Opus, Sonnet, and Haiku support
- Ollama provider for local LLM inference
- Provider fallback chain for reliability
- Cost estimation before making API calls
- Retry logic with exponential backoff
- Enhanced caching and PII redaction

#### Additional Scanner Plugins
- gosec scanner for Go code security analysis
- eslint-plugin-security scanner for JavaScript/TypeScript
- Parallel scanner execution for improved performance
- Scanner-specific configuration options
- Enhanced CWE mapping for new scanners

#### Advanced Analytics
- Trend analysis showing findings over time
- Mean Time to Remediation (MTTR) calculation
- Security score based on findings and severity
- Hotspot analysis identifying files with most findings
- New vs. resolved findings tracking
- Top CWE categories analysis
- Scanner effectiveness metrics
- Analytics API endpoints and web UI visualizations

#### Custom Report Templates
- Go template engine for custom report generation
- Default templates for HTML, Markdown, and PDF
- Compliance templates for OWASP Top 10, PCI-DSS, HIPAA
- Template validation and testing utilities
- Template variables for findings, scans, policies, and trends
- Custom template functions and filters

#### Enhanced Policy Engine
- Glob pattern matching for file paths (*, **)
- Regex pattern support for advanced matching
- Exclusion patterns (negative matching)
- Directory-based policy rules
- Pattern testing utility
- Case-sensitive and case-insensitive matching

#### CI/CD Platform Integrations
- GitHub Actions integration with Docker-based action
- SARIF upload to GitHub Security tab
- Pull request comments with scan results
- Status checks for PR blocking
- GitLab CI integration with CI/CD templates
- GitLab Security Reports (SAST format)
- Merge request integration with notes and widgets
- Docker images for CI/CD environments

#### Webhook System
- HTTP POST notifications for scan events
- Configurable event triggers (scan_complete, critical_finding, policy_violation)
- Multiple webhook URL support
- Retry logic with exponential backoff (up to 3 attempts)
- HMAC signature authentication
- Webhook delivery logging and history
- Pre-built integrations for Slack, Discord, Microsoft Teams

#### Database Enhancements
- Schema migration system with version tracking
- Rollback capability for failed migrations
- New tables: scan_metrics, finding_trends, webhook_config, webhook_deliveries
- Performance indexes on findings and new tables
- Connection pooling for better performance
- Automatic migration from v1.0.0 schema

#### Export/Import Functionality
- Export findings to JSON, CSV, and Excel formats
- Export policies to portable YAML format
- Import findings from SARIF and JSON
- Import policies from templates
- Bulk export/import operations
- Data validation before import
- Filtering during export (date range, severity)

#### New CLI Commands
- `serve` - Start web dashboard server
- `analytics trends` - View finding trends over time
- `analytics score` - View security score
- `analytics hotspots` - View files with most findings
- `analytics mttr` - View mean time to remediation
- `webhook list/add/test/deliveries` - Manage webhooks
- `cache stats/clear` - Manage caches
- `template list/validate/render` - Manage report templates
- `export findings/policies` - Export data
- `import findings/policies` - Import data
- `migrate` - Run database migrations

### Changed

#### Performance Improvements
- Incremental scanning with git-based change detection
- 30% faster scan times for large codebases (>50K LOC)
- 20% reduction in memory usage during scans
- Optimized database queries with new indexes
- Streaming for large result sets
- Parallel processing for scanner execution
- File result caching for unchanged files

#### LLM Integration Improvements
- Enhanced provider interface with better error handling
- Improved cost estimation and tracking
- Better fallback behavior when providers are unavailable
- Enhanced PII redaction patterns
- Configurable cost limits per scan

#### Configuration Updates
- New web server configuration section
- Enhanced LLM provider configuration with real providers
- Updated scanner configuration with parallel execution
- New webhook configuration section
- Backward compatible with v1.0.0 configuration files

### Fixed
- Database locking issues under concurrent access
- Scanner timeout handling for large codebases
- Memory leaks in long-running processes
- Race conditions in parallel scanner execution
- Policy evaluation edge cases with complex patterns

### Security
- API rate limiting to prevent abuse
- Input validation and sanitization for all endpoints
- SQL injection prevention in new queries
- XSS prevention in web dashboard
- CSRF protection for state-changing operations
- Secure webhook signature verification with HMAC
- API token encryption at rest (when authentication enabled)

### Deprecated
- Mock LLM provider (still available but real providers recommended)
- Simple scanner configuration format (use new format with `enabled` list)

### Migration Notes

**Upgrading from v1.0.0:**
- Database schema is automatically migrated on first run
- Backup your database before upgrading: `cp ~/.coding-agent-cli/findings.db ~/.coding-agent-cli/findings.db.backup`
- All v1.0.0 commands and configuration remain compatible
- New configuration options have sensible defaults
- See [Migration Guide](docs/user-guide/16-v1.2-migration.md) for detailed instructions

**Breaking Changes:**
- None! v1.2.0 is fully backward compatible with v1.0.0

**New Dependencies:**
- gosec (optional, for Go scanning)
- eslint-plugin-security (optional, for JS/TS scanning)
- OpenAI/Anthropic API keys (optional, for real LLM providers)

## [Unreleased]

### Planned Features
- Authentication and authorization system (optional)
- Multi-user support with role-based access control
- OAuth2/OIDC integration
- Additional scanner plugins (trivy, checkov)
- Advanced search and filtering
- Custom dashboard widgets
- Scheduled scanning
- Email notifications
