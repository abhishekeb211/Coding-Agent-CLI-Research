# Testing Guide

## Test Organization

```
.
├── internal/
│   ├── scanner/
│   │   ├── orchestrator.go
│   │   └── orchestrator_test.go
│   ├── storage/
│   │   ├── database.go
│   │   └── database_test.go
│   └── testutil/
│       └── helpers.go
├── testdata/
│   ├── vulnerable-code/
│   ├── scanner-outputs/
│   └── policies/
└── tests/
    └── integration/
        └── scan_workflow_test.go
```

## Running Tests

### How to run tests

Run from the repository root.

| What | Command |
|------|---------|
| **Full phase loop** (build check + all phases + integration) | **Windows:** `scripts\test-phases.bat` — **Linux/macOS:** `./scripts/test-phases.sh` |
| **Unit tests only** | `go test ./...` |
| **Integration tests only** | `go test -tags=integration ./tests/integration/...` |

### All Tests
```bash
go test ./...
```

### Specific Package
```bash
go test ./internal/scanner/...
```

### With Coverage
```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### With Race Detector
```bash
go test -race ./...
```

### Integration Tests
```bash
go test -tags=integration ./tests/integration/...
```

### Phase-based test runs

You can check implementation (build) and run tests per development phase and per-package subtask using the automated phase scripts. Run from the repository root.

**Linux/macOS:**
```bash
./scripts/test-phases.sh
```

**Windows:**
```bat
scripts\test-phases.bat
```

The scripts:

1. Run a global implementation check: `go build ./...`
2. For each of the 7 phases, build that phase’s packages and run tests per package (subtask), then report pass/fail
3. Phase 7 runs integration tests with `-tags=integration`

Phase-to-package mapping:

| Phase | Focus | Packages (test targets) |
|-------|--------|---------------------------|
| 1 | Foundation | `./cmd/...`, `./internal/storage/...` |
| 2 | Scanner integration | `./internal/scanner/...`, `./plugins/bandit/...`, `./plugins/semgrep/...` |
| 3 | Normalization | `./internal/cwe/...`, `./internal/sarif/...` |
| 4 | LLM | `./internal/llm/...` |
| 5 | Policy engine | `./internal/policy/...` |
| 6 | CLI and reporting | `./cmd/...`, `./internal/importer/...`, `./internal/exporter/...` |
| 7 | Testing and docs | `./tests/integration/...` (with `-tags=integration`) |

Exit code is 0 only if all phase builds and all subtask tests pass.

### Verbose Output
```bash
go test -v ./...
```

## Writing Tests

### Table-Driven Tests

```go
func TestMapRuleToCWE(t *testing.T) {
    tests := []struct {
        name     string
        ruleID   string
        category string
        want     string
    }{
        {
            name:     "SQL injection",
            ruleID:   "B608",
            category: "",
            want:     "CWE-89",
        },
        // More test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := MapRuleToCWE(tt.ruleID, tt.category)
            if got != tt.want {
                t.Errorf("MapRuleToCWE() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Test Helpers

```go
// Use testutil helpers
func TestDatabase(t *testing.T) {
    db := testutil.CreateTestDB(t)
    defer db.Close()

    // Test database operations
}
```

### Test Fixtures

```go
func TestParser(t *testing.T) {
    data := testutil.LoadFixture(t, "scanner-outputs/bandit-sample.json")
    
    findings, err := Parse(data)
    if err != nil {
        t.Fatalf("Parse() error = %v", err)
    }
}
```

## Test Coverage Goals

- **Overall**: >70% coverage
- **Critical Paths**: 100% coverage
- **Error Handling**: All error paths tested
- **Edge Cases**: Boundary conditions tested

## Integration Testing

### Setup

```go
// +build integration

package integration

func TestEndToEndScan(t *testing.T) {
    // Setup
    tmpDir := t.TempDir()
    
    // Execute
    cmd := exec.Command("coding-agent-cli", "scan", tmpDir)
    output, err := cmd.CombinedOutput()
    
    // Verify
    if err != nil {
        t.Fatalf("Scan failed: %v\n%s", err, output)
    }
}
```

## Mocking

### Mock LLM Provider

```go
type MockLLMProvider struct {
    Responses map[string]string
}

func (m *MockLLMProvider) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error) {
    if resp, ok := m.Responses[req.CWEID]; ok {
        return &RemediationResponse{
            Explanation: resp,
        }, nil
    }
    return nil, errors.New("no mock response")
}
```

## Best Practices

### Test Isolation
- Each test should be independent
- Use `t.TempDir()` for temporary files
- Clean up resources in defer statements

### Test Naming
- Use descriptive test names
- Include what is being tested
- Include expected behavior

### Error Testing
```go
if (err != nil) != tt.wantErr {
    t.Errorf("Function() error = %v, wantErr %v", err, tt.wantErr)
}
```

### Parallel Tests
```go
func TestParallel(t *testing.T) {
    t.Parallel()
    // Test code
}
```
