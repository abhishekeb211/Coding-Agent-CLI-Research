# Release Notes - Version 1.2.0

**Release Date**: June 1, 2026

## Overview

Coding Agent CLI v1.2.0 is a major feature release that transforms the tool from a command-line application into a comprehensive security platform. This release introduces a browser-based web dashboard, REST API for programmatic access, real LLM provider integrations (OpenAI, Anthropic, Ollama), additional scanner plugins (gosec, eslint-plugin-security), advanced analytics with trending, CI/CD platform integrations (GitHub Actions, GitLab CI), webhook notifications, and significant performance improvements.

Building on the solid foundation of v1.0.0, this release maintains full backward compatibility while adding enterprise-grade features for teams and organizations.

## Quality Metrics

### Test Coverage
- **Overall Coverage**: 60%+ (up from 49.4% in v1.0.0)
- **Core Packages**: 70%+ coverage maintained
- **cmd Package**: 70%+ coverage (up from 8.1%)
- **plugins Package**: 70%+ coverage (up from 21-28%)
- **Test Status**: All tests passing (100% pass rate)
- **Known Critical Bugs**: Zero

### Performance Improvements
- **Scan Time**: 30% faster for large codebases (>50K LOC)
- **Memory Usage**: 20% reduction during scans
- **API Response Time**: <200ms for most endpoints
- **Database Queries**: <50ms with new indexes

### Code Quality
- Comprehensive unit and integration tests
- Property-based tests for complex logic
- Performance benchmarks for critical paths
- Enhanced documentation (30+ files)
- OpenAPI/Swagger API documentation

## Major New Features

### 1. Web Dashboard

A modern, responsive web interface for viewing findings and analytics:

- **Browser-Based UI**: Access via http://localhost:8080
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Theme Support**: Light and dark themes with automatic switching
- **Progressive Web App**: Offline support after initial load
- **Real-Time Updates**: Live scan status and finding updates
- **Interactive Charts**: Visualize trends, severity distribution, and CWE categories
- **Finding Management**: Sort, filter, and search findings
- **Scan History**: View and compare historical scans

**Getting Started:**
```bash
# Start the web server
coding-agent-cli serve --port 8080

# Open browser to http://localhost:8080
```

### 2. REST API

Full programmatic access to all functionality:

- **API Versioning**: `/api/v1` prefix for stability
- **Complete Coverage**: All CLI operations available via API
- **OpenAPI Documentation**: Interactive Swagger UI at `/api/docs`
- **Pagination & Filtering**: Efficient data retrieval
- **Rate Limiting**: Protection against abuse
- **Request Logging**: Full audit trail
- **Standard HTTP Methods**: RESTful design with GET, POST, PUT, DELETE

**Key Endpoints:**
- `POST /api/v1/scans` - Trigger new scan
- `GET /api/v1/scans` - List scan runs
- `GET /api/v1/findings` - List findings with filtering
- `GET /api/v1/analytics/trends` - Get trend data
- `POST /api/v1/webhooks` - Configure webhooks

**Example:**
```bash
# Trigger a scan via API
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"path": "./src", "scanners": ["bandit", "semgrep"]}'

# Get findings
curl http://localhost:8080/api/v1/findings?severity=critical,high
```

### 3. Real LLM Provider Integrations

Production-ready AI integrations for remediation guidance:

- **OpenAI**: GPT-4 and GPT-3.5-turbo support
- **Anthropic**: Claude 3 Opus, Sonnet, and Haiku support
- **Ollama**: Local LLM inference for privacy-sensitive environments
- **Provider Fallback**: Automatic failover between providers
- **Cost Estimation**: Preview costs before making API calls
- **Enhanced Caching**: Reduce API costs and improve performance
- **Retry Logic**: Exponential backoff for reliability

**Configuration:**
```yaml
llm:
  provider: openai  # or anthropic, ollama, mock
  openai:
    api_key: ${OPENAI_API_KEY}
    model: gpt-4
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    model: claude-3-sonnet-20240229
  ollama:
    base_url: http://localhost:11434
    model: llama2
```

### 4. Additional Scanner Plugins

Expanded language and security coverage:

- **gosec**: Go security scanner with 60+ rules
- **eslint-plugin-security**: JavaScript/TypeScript security analysis
- **Parallel Execution**: All scanners run concurrently
- **Enhanced CWE Mapping**: Improved accuracy for new scanners
- **Scanner Configuration**: Per-scanner options and rules

**Supported Scanners:**
- Bandit (Python)
- Semgrep (Multi-language)
- gosec (Go)
- eslint-plugin-security (JavaScript/TypeScript)

**Usage:**
```bash
# Scan with all scanners
coding-agent-cli scan ./src --scanners bandit,semgrep,gosec,eslint

# Scan Go code with gosec
coding-agent-cli scan ./src --scanners gosec
```

### 5. Advanced Analytics

Comprehensive security metrics and trending:

- **Trend Analysis**: Findings over time by severity
- **MTTR Calculation**: Mean Time to Remediation tracking
- **Security Score**: Overall security posture metric
- **Hotspot Analysis**: Files with most findings
- **New vs. Resolved**: Track finding lifecycle
- **Top CWE Categories**: Most common vulnerability types
- **Scanner Effectiveness**: Findings per scanner metrics
- **Export Capabilities**: CSV/JSON export for external analysis

**CLI Commands:**
```bash
# View trends
coding-agent-cli analytics trends --days 30

# View security score
coding-agent-cli analytics score

# View hotspots
coding-agent-cli analytics hotspots --limit 10

# View MTTR
coding-agent-cli analytics mttr
```

### 6. Custom Report Templates

Flexible reporting for compliance and customization:

- **Template Engine**: Go template-based system
- **Default Templates**: HTML, Markdown, PDF
- **Compliance Templates**: OWASP Top 10, PCI-DSS, HIPAA
- **Custom Functions**: Filters, formatters, and helpers
- **Template Validation**: Syntax checking before use
- **Template Variables**: Access to findings, scans, policies, trends

**Example:**
```bash
# List available templates
coding-agent-cli template list

# Validate custom template
coding-agent-cli template validate my-template.tmpl

# Generate report with custom template
coding-agent-cli report --template my-template.tmpl --output report.html
```

### 7. Enhanced Policy Engine

Advanced pattern matching for fine-grained control:

- **Glob Patterns**: Match files with `*` and `**` wildcards
- **Regex Support**: Advanced pattern matching
- **Exclusion Patterns**: Negative matching with `exclude`
- **Directory Matching**: Apply policies to entire directories
- **Pattern Testing**: Utility to test patterns before deployment

**Example Policy:**
```yaml
rules:
  - name: "Allow test files to have lower severity"
    patterns:
      include:
        - "**/*_test.go"
        - "**/test_*.py"
      exclude:
        - "**/vendor/**"
    severity: medium
    action: allow
```

### 8. CI/CD Platform Integrations

Seamless integration with popular CI/CD platforms:

#### GitHub Actions
- Docker-based action for easy integration
- SARIF upload to GitHub Security tab
- Pull request comments with scan results
- Status checks for PR blocking
- Caching support for faster runs

**Example Workflow:**
```yaml
- uses: coding-agent/scan-action@v1
  with:
    path: ./src
    scanners: bandit,semgrep,gosec
    fail-on: critical,high
    upload-sarif: true
```

#### GitLab CI
- CI/CD template for quick setup
- GitLab Security Reports (SAST format)
- Merge request integration
- Docker image for CI environments

**Example Pipeline:**
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/coding-agent/cli/main/.gitlab-ci-template.yml'

security_scan:
  extends: .security_scan
  variables:
    SCAN_PATH: ./src
```

### 9. Webhook System

Real-time notifications for security events:

- **Event Triggers**: scan_complete, critical_finding, policy_violation
- **Multiple Webhooks**: Configure multiple endpoints
- **Retry Logic**: Up to 3 attempts with exponential backoff
- **HMAC Authentication**: Secure webhook verification
- **Delivery Logging**: Full audit trail
- **Pre-built Integrations**: Slack, Discord, Microsoft Teams

**Configuration:**
```bash
# Add webhook
coding-agent-cli webhook add \
  --url https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --events scan_complete,critical_finding \
  --secret your-secret-key

# Test webhook
coding-agent-cli webhook test webhook-id

# View delivery history
coding-agent-cli webhook deliveries webhook-id
```

### 10. Database Enhancements

Improved data management and performance:

- **Schema Migrations**: Automatic version tracking and upgrades
- **Rollback Support**: Safe migration with rollback capability
- **New Tables**: scan_metrics, finding_trends, webhook_config, webhook_deliveries
- **Performance Indexes**: Optimized queries for common operations
- **Connection Pooling**: Better concurrency handling
- **Automatic Backup**: Database backup before migrations

### 11. Export/Import Functionality

Flexible data portability:

- **Export Formats**: JSON, CSV, Excel
- **Import Formats**: SARIF, JSON
- **Bulk Operations**: Export/import multiple scans
- **Data Validation**: Verify data integrity before import
- **Filtering**: Export specific date ranges or severities

**Examples:**
```bash
# Export findings to Excel
coding-agent-cli export findings --format excel --output findings.xlsx

# Export policies
coding-agent-cli export policies --output policies.yaml

# Import findings from SARIF
coding-agent-cli import findings --format sarif --input results.sarif

# Import policies from template
coding-agent-cli import policies --input template-policies.yaml
```

## System Requirements

### Minimum Requirements
- **OS**: Linux, macOS, or Windows
- **Memory**: 1 GB RAM (up from 512 MB)
- **Disk**: 200 MB free space (up from 100 MB)
- **Browser**: Modern browser for web dashboard (Chrome, Firefox, Safari, Edge)

### Recommended Requirements
- **OS**: Linux (Ubuntu 20.04+), macOS (11+), Windows 10+
- **Memory**: 4 GB RAM
- **Disk**: 1 GB free space
- **Browser**: Latest version of Chrome, Firefox, Safari, or Edge

### Dependencies

**Required:**
- Python 3.8+ (for Bandit, Semgrep)

**Optional Scanners:**
- Bandit 1.7.0+ (`pip install bandit`)
- Semgrep 1.0.0+ (`pip install semgrep`)
- gosec 2.15.0+ (`go install github.com/securego/gosec/v2/cmd/gosec@latest`)
- eslint-plugin-security (`npm install -g eslint eslint-plugin-security`)

**Optional LLM Providers:**
- OpenAI API key (for GPT-4/GPT-3.5)
- Anthropic API key (for Claude 3)
- Ollama (for local LLM inference)

## Supported Platforms

### Pre-built Binaries
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

### Docker Images
- `coding-agent/cli:1.2.0`
- `coding-agent/cli:latest`

### Supported Scanners
- Bandit 1.7.0+
- Semgrep 1.0.0+
- gosec 2.15.0+
- eslint-plugin-security 2.0.0+

### Supported Languages
- Python (Bandit, Semgrep)
- JavaScript/TypeScript (Semgrep, eslint-plugin-security)
- Go (Semgrep, gosec)
- Java (Semgrep)
- Ruby (Semgrep)
- C/C++ (Semgrep)
- And more via Semgrep

## Breaking Changes

**None!** Version 1.2.0 is fully backward compatible with v1.0.0.

- All v1.0.0 commands work unchanged
- Configuration files are compatible
- Database schema is automatically migrated
- Deprecated features still work with warnings

## Migration Guide

### Upgrading from v1.0.0

**Step 1: Backup Your Database**
```bash
cp ~/.coding-agent-cli/findings.db ~/.coding-agent-cli/findings.db.backup
```

**Step 2: Install v1.2.0**
```bash
# Download and install new version
wget https://github.com/coding-agent/cli/releases/download/v1.2.0/coding-agent-cli-1.2.0-linux-amd64.tar.gz
tar -xzf coding-agent-cli-1.2.0-linux-amd64.tar.gz
sudo mv coding-agent-cli /usr/local/bin/
```

**Step 3: Run Migration**
```bash
# Migration happens automatically on first run
coding-agent-cli scan ./src

# Or run migration explicitly
coding-agent-cli migrate
```

**Step 4: Update Configuration (Optional)**
```bash
# Add new configuration options for v1.2 features
# See docs/user-guide/16-v1.2-migration.md for details
```

**Step 5: Install New Scanners (Optional)**
```bash
# Install gosec for Go scanning
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Install eslint-plugin-security for JS/TS scanning
npm install -g eslint eslint-plugin-security
```

**Step 6: Configure LLM Providers (Optional)**
```bash
# Set API keys for real LLM providers
export OPENAI_API_KEY=your-key-here
export ANTHROPIC_API_KEY=your-key-here
```

For detailed migration instructions, see [Migration Guide](../user-guide/16-v1.2-migration.md).

## Known Issues

### Minor Issues
- Web dashboard may take 3-5 seconds to load on first access (subsequent loads are faster due to PWA caching)
- Large Excel exports (>10,000 findings) may take several seconds to generate
- Ollama provider requires Ollama server to be running locally

### Workarounds
- For faster web dashboard loading, use the `--preload` flag when starting the server
- For large exports, use CSV format instead of Excel
- For Ollama, ensure the server is started with `ollama serve`

### Planned Fixes
- Optimize web dashboard initial load time (v1.2.1)
- Improve Excel export performance (v1.2.1)
- Add automatic Ollama server detection (v1.2.1)

## Security Considerations

### New Security Features
- API rate limiting to prevent abuse
- Input validation and sanitization for all endpoints
- XSS prevention in web dashboard
- CSRF protection for state-changing operations
- Secure webhook signature verification with HMAC
- API token encryption at rest (when authentication enabled)

### Best Practices
- Store API keys in environment variables, not config files
- Use HTTPS when exposing the web server to networks
- Configure webhook secrets for secure notifications
- Enable rate limiting in production environments
- Regularly update scanner dependencies
- Review API access logs for suspicious activity

### Data Privacy
- PII is automatically redacted before LLM calls
- Findings stored locally in SQLite database
- No data sent to external services (except LLM if enabled)
- Web dashboard data stays on your machine
- API access is local by default (localhost:8080)

## Getting Started

### Quick Start with Web Dashboard
```bash
# Install v1.2.0
wget https://github.com/coding-agent/cli/releases/download/v1.2.0/coding-agent-cli-1.2.0-linux-amd64.tar.gz
tar -xzf coding-agent-cli-1.2.0-linux-amd64.tar.gz
sudo mv coding-agent-cli /usr/local/bin/

# Start web server
coding-agent-cli serve --port 8080

# Open browser to http://localhost:8080

# Run a scan (from another terminal or via web UI)
coding-agent-cli scan /path/to/code
```

### Quick Start with REST API
```bash
# Start API server
coding-agent-cli serve --port 8080

# Trigger scan via API
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"path": "./src", "scanners": ["bandit", "semgrep"]}'

# View findings
curl http://localhost:8080/api/v1/findings

# View API documentation
open http://localhost:8080/api/docs
```

### Quick Start with CI/CD

**GitHub Actions:**
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: coding-agent/scan-action@v1
        with:
          path: ./src
          scanners: bandit,semgrep,gosec
          fail-on: critical,high
          upload-sarif: true
```

**GitLab CI:**
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/coding-agent/cli/main/.gitlab-ci-template.yml'

security_scan:
  extends: .security_scan
```

### Documentation
- [Installation Guide](../user-guide/01-installation.md)
- [Quickstart Guide](../user-guide/02-quickstart.md)
- [Web Dashboard Guide](../user-guide/10-web-dashboard.md)
- [REST API Guide](../user-guide/11-rest-api.md)
- [Scanner Guide](../user-guide/12-scanners.md)
- [CI/CD Integration Guide](../user-guide/13-cicd-integration.md)
- [Webhook Guide](../user-guide/14-webhooks.md)
- [Migration Guide](../user-guide/16-v1.2-migration.md)
- [API Reference](../developer-guide/rest-api-reference.md)

## Performance Benchmarks

### Scan Time Improvements
| Codebase Size | v1.0.0 | v1.2.0 | Improvement |
|---------------|--------|--------|-------------|
| 10K LOC       | ~5 min | ~3 min | 40% faster  |
| 50K LOC       | ~20 min| ~14 min| 30% faster  |
| 100K LOC      | ~45 min| ~32 min| 29% faster  |

### Memory Usage Improvements
| Operation     | v1.0.0 | v1.2.0 | Improvement |
|---------------|--------|--------|-------------|
| Scan (10K LOC)| 800 MB | 640 MB | 20% less    |
| Scan (50K LOC)| 1.5 GB | 1.2 GB | 20% less    |
| API Server    | N/A    | 150 MB | N/A         |

### API Performance
| Endpoint              | Response Time |
|-----------------------|---------------|
| GET /api/v1/findings  | <100ms        |
| GET /api/v1/scans     | <50ms         |
| POST /api/v1/scans    | <200ms        |
| GET /api/v1/analytics | <150ms        |

## Acknowledgments

Special thanks to:
- The Bandit, Semgrep, gosec, and ESLint teams for their excellent security scanners
- OpenAI and Anthropic for their powerful LLM APIs
- The Ollama team for enabling local LLM inference
- The OWASP community for CWE and security guidance
- All contributors, testers, and early adopters
- The open-source community for feedback and bug reports

## Support

- **Documentation**: https://github.com/coding-agent/cli/tree/main/docs
- **Issues**: https://github.com/coding-agent/cli/issues
- **Discussions**: https://github.com/coding-agent/cli/discussions
- **API Docs**: http://localhost:8080/api/docs (when server is running)

## What's Next

### Planned for v1.2.1 (Bug Fixes & Polish)
- Optimize web dashboard initial load time
- Improve Excel export performance
- Add automatic Ollama server detection
- Enhanced error messages
- Bug fixes based on user feedback

### Planned for v1.3 (Authentication & Multi-User)
- Authentication and authorization system
- Multi-user support with role-based access control
- OAuth2/OIDC integration
- User management UI
- API token management

### Planned for v1.4 (Advanced Features)
- Additional scanner plugins (trivy, checkov)
- Advanced search and filtering
- Custom dashboard widgets
- Scheduled scanning
- Email notifications
- Vulnerability correlation and deduplication

### Long-Term Roadmap
- Machine learning for false positive detection
- Integration with vulnerability databases (NVD, CVE)
- Advanced remediation workflows
- Team collaboration features
- Enterprise features (SSO, audit logs, compliance reporting)

## License

MIT License - See LICENSE file for details

---

**Thank you for using Coding Agent CLI!** We're excited to see how you use these new features to improve your security posture. Please share your feedback and report any issues on GitHub.
