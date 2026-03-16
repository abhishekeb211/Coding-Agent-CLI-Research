# Design Document: v1.2 Release - Web UI & Advanced Features

## Overview

Version 1.2 introduces a comprehensive web-based interface, real LLM integrations, expanded scanner support, and CI/CD platform integrations while maintaining the offline-first architecture and backward compatibility with v1.0.0.

### Design Principles

- **Backward Compatibility**: All v1.0.0 features continue to work unchanged
- **Progressive Enhancement**: Web UI is optional; CLI remains fully functional
- **Modular Architecture**: New features are loosely coupled and independently deployable
- **Multiple Fallbacks**: Each major feature has 2-3 implementation alternatives
- **Performance First**: Optimizations throughout to handle large codebases
- **Security by Default**: Authentication optional but secure when enabled
- **API-First Design**: Web UI consumes same API available to users

### Architecture Evolution

```
v1.0.0 Architecture:
CLI → Scanner Orchestrator → Plugins → Database → Reports

v1.2.0 Architecture:
┌─────────────────────────────────────────────────────────┐
│                     Presentation Layer                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   CLI Tool   │  │  REST API    │  │ Web Dashboard│ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                     Business Logic Layer                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  Scanner     │  │  Analytics   │  │  Template    │ │
│  │ Orchestrator │  │   Engine     │  │   Engine     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  Policy      │  │  LLM         │  │  Webhook     │ │
│  │  Engine      │  │  Manager     │  │  System      │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                     Data Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  Database    │  │  Cache       │  │  File        │ │
│  │  (SQLite/PG) │  │  (Memory)    │  │  Storage     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                     Integration Layer                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  Scanner     │  │  LLM         │  │  CI/CD       │ │
│  │  Plugins     │  │  Providers   │  │  Platforms   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Component Designs

### 1. REST API Layer

**Primary Design (Option A): Go net/http with chi router**

```go
// File: internal/api/server.go
package api

type Server struct {
    router     *chi.Mux
    db         *storage.Database
    scanner    *scanner.Orchestrator
    analytics  *analytics.Engine
    config     *Config
}

func NewServer(config *Config) (*Server, error) {
    s := &Server{
        router: chi.NewRouter(),
        config: config,
    }
    
    // Middleware
    s.router.Use(middleware.Logger)
    s.router.Use(middleware.Recoverer)
    s.router.Use(middleware.RealIP)
    s.router.Use(middleware.Timeout(60 * time.Second))
    
    // Routes
    s.setupRoutes()
    
    return s, nil
}
```

func (s *Server) setupRoutes() {
    s.router.Route("/api/v1", func(r chi.Router) {
        r.Post("/scans", s.handleCreateScan)
        r.Get("/scans", s.handleListScans)
        r.Get("/scans/{id}", s.handleGetScan)
        r.Get("/findings", s.handleListFindings)
        r.Get("/findings/{id}", s.handleGetFinding)
        r.Post("/policies/validate", s.handleValidatePolicy)
        r.Get("/analytics/trends", s.handleGetTrends)
    })
}

// Fallback Options:
// Option B: Gin framework - faster development, more features
// Option C: Echo framework - lightweight, good middleware
// Option D: Minimal JSON-RPC over stdin/stdout
```

### 2. Web Dashboard

**Primary Design (Option A): React SPA**

Directory structure:
```
web/
├── src/
│   ├── components/
│   │   ├── Dashboard.tsx
│   │   ├── FindingsList.tsx
│   │   ├── FindingDetail.tsx
│   │   ├── ScanHistory.tsx
│   │   └── Analytics.tsx
│   ├── api/
│   │   └── client.ts
│   ├── hooks/
│   │   └── useFindings.ts
│   └── App.tsx
├── public/
└── package.json
```

**Fallback Options:**
- Option B: Server-side templates with htmx
- Option C: Vanilla JS with Web Components
- Option D: Enhanced static HTML reports

### 3. LLM Provider System

**Architecture:**
```go
// File: internal/llm/providers.go
package llm

type Provider interface {
    GenerateRemediation(ctx context.Context, finding Finding) (string, error)
    EstimateCost(finding Finding) (float64, error)
    Name() string
}

type OpenAIProvider struct {
    client *openai.Client
    model  string
    cache  *Cache
}

type AnthropicProvider struct {
    client *anthropic.Client
    model  string
    cache  *Cache
}

type OllamaProvider struct {
    baseURL string
    model   string
}
```

**Fallback Strategy:**
1. Try primary provider (OpenAI/Anthropic)
2. If fails, try secondary provider
3. If all fail, use cached response
4. If no cache, use mock provider

### 4. Scanner Plugin System Enhancement

**New Plugins:**
```go
// File: plugins/gosec/gosec.go
package gosec

type Plugin struct {
    execPath string
    config   Config
}

// File: plugins/eslint/eslint.go
package eslint

type Plugin struct {
    execPath string
    config   Config
}
```

**Plugin Interface (unchanged):**
```go
type Plugin interface {
    Name() string
    Scan(ctx context.Context, path string) ([]Finding, error)
    Version() string
}
```

### 5. Analytics Engine

**Design:**
```go
// File: internal/analytics/engine.go
package analytics

type Engine struct {
    db *storage.Database
}

type TrendData struct {
    Dates      []time.Time
    Critical   []int
    High       []int
    Medium     []int
    Low        []int
}

func (e *Engine) GetTrends(start, end time.Time) (*TrendData, error)
func (e *Engine) GetTopCWEs(limit int) ([]CWEStat, error)
func (e *Engine) GetMTTR() (time.Duration, error)
func (e *Engine) GetSecurityScore() (float64, error)
```

### 6. Template Engine

**Design:**
```go
// File: internal/templates/engine.go
package templates

type Engine struct {
    templates map[string]*template.Template
    funcMap   template.FuncMap
}

func (e *Engine) Render(name string, data interface{}) (string, error)
func (e *Engine) LoadTemplate(path string) error
func (e *Engine) ValidateTemplate(content string) error
```

### 7. Database Schema Evolution

**Migration System:**
```go
// File: internal/storage/migrations.go
package storage

type Migration struct {
    Version int
    Up      string
    Down    string
}

var migrations = []Migration{
    {
        Version: 2,
        Up: `
            CREATE TABLE scan_metrics (
                id INTEGER PRIMARY KEY,
                scan_id TEXT NOT NULL,
                total_findings INTEGER,
                critical INTEGER,
                high INTEGER,
                medium INTEGER,
                low INTEGER,
                scan_duration INTEGER,
                created_at TIMESTAMP
            );
            CREATE INDEX idx_scan_metrics_scan_id ON scan_metrics(scan_id);
        `,
        Down: `DROP TABLE scan_metrics;`,
    },
}
```


### 8. CI/CD Integration

**GitHub Actions:**
```yaml
# File: .github/actions/scan/action.yml
name: 'Security Scan'
description: 'Run Coding Agent CLI security scan'
inputs:
  path:
    description: 'Path to scan'
    required: true
  scanners:
    description: 'Comma-separated scanner list'
    default: 'bandit,semgrep'
  fail-on:
    description: 'Severity levels to fail on'
    default: 'critical,high'
runs:
  using: 'docker'
  image: 'Dockerfile'
```

**GitLab CI:**
```yaml
# File: .gitlab-ci-template.yml
.security_scan:
  image: coding-agent/cli:latest
  script:
    - coding-agent-cli scan $CI_PROJECT_DIR
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### 9. Webhook System

**Design:**
```go
// File: internal/webhooks/manager.go
package webhooks

type Manager struct {
    db     *storage.Database
    client *http.Client
    queue  chan Delivery
}

type Webhook struct {
    ID     string
    URL    string
    Events []string
    Secret string
}

type Delivery struct {
    WebhookID string
    Event     string
    Payload   interface{}
    Attempt   int
}

func (m *Manager) Trigger(event string, payload interface{}) error
func (m *Manager) Retry(delivery Delivery) error
```

### 10. Performance Optimizations

**Incremental Scanning:**
```go
// File: internal/scanner/incremental.go
package scanner

type IncrementalScanner struct {
    cache     *FileCache
    gitClient *git.Client
}

func (s *IncrementalScanner) GetChangedFiles() ([]string, error) {
    // Use git diff to find changed files
    return s.gitClient.Diff("HEAD~1", "HEAD")
}

func (s *IncrementalScanner) ScanIncremental(path string) ([]Finding, error) {
    changed := s.GetChangedFiles()
    // Only scan changed files
    return s.ScanFiles(changed)
}
```

**Database Optimizations:**
```sql
-- Add indexes for common queries
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_cwe ON findings(cwe_id);
CREATE INDEX idx_findings_created ON findings(created_at);
CREATE INDEX idx_findings_run_id ON findings(run_id);

-- Add composite indexes
CREATE INDEX idx_findings_run_severity ON findings(run_id, severity);
```

## Data Models

### API Request/Response Models

```go
// File: internal/api/models.go
package api

type ScanRequest struct {
    Path     string   `json:"path"`
    Scanners []string `json:"scanners"`
    Policies []string `json:"policies"`
}

type ScanResponse struct {
    ScanID   string    `json:"scan_id"`
    Status   string    `json:"status"`
    Started  time.Time `json:"started"`
}

type FindingsResponse struct {
    Findings []Finding  `json:"findings"`
    Total    int        `json:"total"`
    Page     int        `json:"page"`
    PageSize int        `json:"page_size"`
}

type TrendsResponse struct {
    Dates    []string `json:"dates"`
    Critical []int    `json:"critical"`
    High     []int    `json:"high"`
    Medium   []int    `json:"medium"`
    Low      []int    `json:"low"`
}
```

### Database Models

```go
// File: internal/storage/models.go
package storage

type ScanMetric struct {
    ID            int64
    ScanID        string
    TotalFindings int
    Critical      int
    High          int
    Medium        int
    Low           int
    ScanDuration  int64
    CreatedAt     time.Time
}

type WebhookConfig struct {
    ID        string
    URL       string
    Events    string // JSON array
    Secret    string
    Enabled   bool
    CreatedAt time.Time
}

type WebhookDelivery struct {
    ID        int64
    WebhookID string
    Event     string
    Payload   string
    Status    string
    Attempts  int
    CreatedAt time.Time
}
```

## Error Handling Strategy

### API Errors

```go
type APIError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
}

// Standard error codes
const (
    ErrCodeInvalidRequest   = "INVALID_REQUEST"
    ErrCodeNotFound         = "NOT_FOUND"
    ErrCodeUnauthorized     = "UNAUTHORIZED"
    ErrCodeInternalError    = "INTERNAL_ERROR"
    ErrCodeScannerFailed    = "SCANNER_FAILED"
    ErrCodeLLMFailed        = "LLM_FAILED"
)
```

### Fallback Chain

```
Primary Action → Fallback 1 → Fallback 2 → Error Response

Example: LLM Remediation
OpenAI → Anthropic → Cache → Mock → Error
```

## Testing Strategy

### Unit Tests
- API handlers with mock dependencies
- LLM providers with mock HTTP clients
- Scanner plugins with fixture outputs
- Analytics calculations with test data
- Template rendering with sample data

### Integration Tests
- End-to-end API workflows
- Web dashboard user flows
- CI/CD integration scenarios
- Webhook delivery and retry
- Database migrations

### Performance Tests
- API endpoint latency (<200ms)
- Scan time improvements (30% faster)
- Memory usage reduction (20% less)
- Database query performance (<50ms)
- Concurrent request handling

## Security Considerations

### API Security
- Rate limiting per IP/token
- Input validation and sanitization
- SQL injection prevention
- XSS prevention in web UI
- CSRF protection for state-changing operations

### Authentication (Optional)
- Bcrypt password hashing
- JWT with short expiration
- Secure session management
- API token rotation
- Audit logging

### LLM Security
- PII redaction before API calls
- API key encryption at rest
- Cost limits per request
- Timeout enforcement
- Response validation

## Deployment Options

### Standalone Binary (Default)
```bash
coding-agent-cli serve --port 8080
```

### Docker Container
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o coding-agent-cli

FROM alpine:latest
COPY --from=builder /app/coding-agent-cli /usr/local/bin/
EXPOSE 8080
CMD ["coding-agent-cli", "serve"]
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coding-agent
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: coding-agent
        image: coding-agent/cli:v1.2.0
        ports:
        - containerPort: 8080
```

## Migration Path from v1.0.0

### Automatic Migration
1. Detect v1.0.0 database schema
2. Run migrations automatically on first v1.2.0 start
3. Backup database before migration
4. Validate migration success
5. Rollback on failure

### Configuration Migration
- v1.0.0 config files remain compatible
- New config options have sensible defaults
- Deprecated options show warnings
- Migration guide in documentation

### CLI Compatibility
- All v1.0.0 commands work unchanged
- New commands are additive
- Flags maintain backward compatibility
- Deprecated flags show warnings

## Conclusion

The v1.2 design provides a robust, scalable architecture with multiple fallback options for each major feature. The modular design allows incremental implementation and deployment, reducing risk while delivering value quickly.

Key design decisions:
- API-first approach enables multiple frontends
- Backward compatibility ensures smooth upgrades
- Multiple implementation options reduce risk
- Performance optimizations throughout
- Security by default with optional authentication
- Comprehensive testing strategy
