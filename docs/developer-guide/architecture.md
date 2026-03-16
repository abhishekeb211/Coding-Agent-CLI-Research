# Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Interface                        │
│                  (cmd/root.go, cmd/*.go)                │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│                Scanner Orchestrator                      │
│              (internal/scanner/orchestrator.go)          │
│  - Manages scanner plugins                              │
│  - Aggregates findings                                  │
│  - Normalizes results                                   │
└────────┬──────────────────────────┬─────────────────────┘
         │                          │
┌────────┴────────┐        ┌────────┴────────┐
│  Scanner Plugins │        │   CWE Mapper    │
│  - Bandit       │        │  (internal/cwe) │
│  - Semgrep      │        │  - Maps rules   │
│  - gosec        │        │    to CWEs      │
│  - eslint       │        └─────────────────┘
│  - safety       │
│  (plugins/*)    │
└─────────────────┘
         │
┌────────┴────────────────────────────────────────────────┐
│                  Storage Layer                           │
│              (internal/storage/database.go)              │
│  - SQLite database                                      │
│  - Finding persistence                                  │
│  - Deduplication                                        │
└────────┬────────────────────────────────────────────────┘
         │
┌────────┴────────────────────────────────────────────────┐
│              Policy Engine                               │
│           (internal/policy/*.go)                         │
│  - Policy evaluation                                    │
│  - Waiver management                                    │
│  - Compliance reporting                                 │
└────────┬────────────────────────────────────────────────┘
         │
┌────────┴────────────────────────────────────────────────┐
│                LLM Integration                           │
│              (internal/llm/*.go)                         │
│  - Remediation generation                               │
│  - Response caching                                     │
│  - PII redaction                                        │
└────────┬────────────────────────────────────────────────┘
         │
┌────────┴────────────────────────────────────────────────┐
│              Report Generation                           │
│           (internal/sarif/sarif.go)                      │
│  - JSON, SARIF, Markdown, HTML, CSV                    │
└─────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Input**: User specifies target path and scanners
2. **Scanning**: Orchestrator runs scanner plugins
3. **Normalization**: Findings mapped to CWE categories
4. **Storage**: Findings persisted to database
5. **Enrichment**: LLM generates remediation (optional)
6. **Policy Evaluation**: Policies applied to findings
7. **Reporting**: Results exported in requested format

## Serve and API

The `serve` command starts a Chi HTTP server (default `http://localhost:8080`). The REST API uses the same storage and orchestrator as the CLI. It exposes:

- **OpenAPI/Swagger**: `/api/docs`
- **API routes**: `/api/v1/*` for scans, findings, policies, reports
- **Analytics** (API only, no CLI subcommand): trends, MTTR, security score, hotspots via `internal/analytics`

Analytics are available only through the API when the server is running.

## Key Components

### Scanner Orchestrator
- Manages scanner lifecycle
- Runs scanners in parallel
- Aggregates and deduplicates findings
- Normalizes findings to common format

### CWE Mapper
- Maps scanner-specific rule IDs to CWE IDs
- Provides CWE descriptions
- Supports pattern matching for unknown rules

### Storage Layer
- SQLite database for persistence
- Tracks scan runs and findings
- Supports deduplication by code fingerprint
- Maintains finding history

### Policy Engine
- Loads and validates policies
- Evaluates findings against rules
- Applies waivers
- Generates compliance reports

### LLM Integration
- Generates remediation guidance
- Caches responses for performance
- Redacts PII before sending to LLM
- Supports multiple providers

### Report Generation
- SARIF 2.1.0 compliant output
- Multiple format support
- Customizable templates
- CI/CD integration friendly

## Extension Points

### Adding a Scanner Plugin
Implement the `Scanner` interface:
```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, path string) ([]RawFinding, error)
    IsAvailable() bool
}
```

### Adding an LLM Provider
Implement the `LLMProvider` interface:
```go
type LLMProvider interface {
    GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error)
    IsAvailable() bool
    Close() error
}
```

### Adding a Report Format
Implement format conversion in `internal/scanner/types.go`:
```go
func (r *ScanResult) toCustomFormat() ([]byte, error) {
    // Convert to custom format
}
```
