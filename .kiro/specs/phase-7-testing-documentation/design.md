# Design Document: Phase 7 - Testing & Documentation

## Overview

Phase 7 represents the final phase of the Coding Agent CLI project, transforming the functional tool into a production-ready, well-tested, and thoroughly documented security scanning solution. This phase focuses on three critical areas:

1. **Comprehensive Testing**: Achieving >70% code coverage through unit tests, integration tests, and performance benchmarks
2. **Complete Documentation**: Creating user guides, API documentation, policy writing guides, and architecture documentation
3. **Release Preparation**: Building multi-platform binaries, verifying release artifacts, and preparing for v1.0.0 launch

The design leverages Go's built-in testing framework (`testing` package), table-driven test patterns, and standard documentation tools (godoc) to ensure maintainability and consistency with Go ecosystem conventions.

### Design Principles

- **Test Pyramid**: More unit tests than integration tests, focused benchmarks for critical paths
- **Test Isolation**: Each test is independent and can run in parallel
- **Realistic Fixtures**: Test data mirrors real-world scanner outputs and policy files
- **Documentation as Code**: API documentation lives with code (godoc comments)
- **Automation First**: All tests and builds run automatically in CI/CD

## Architecture

### Testing Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Test Suite                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Unit Tests  │  │ Integration  │  │  Benchmarks  │     │
│  │              │  │    Tests     │  │              │     │
│  │  - scanner/  │  │              │  │  - Scan time │     │
│  │  - storage/  │  │  - E2E scan  │  │  - Memory    │     │
│  │  - cwe/      │  │  - Multi-    │  │  - DB perf   │     │
│  │  - sarif/    │  │    scanner   │  │  - LLM cache │     │
│  │  - llm/      │  │  - Policy    │  │              │     │
│  │  - policy/   │  │    enforce   │  │              │     │
│  │  - plugins/  │  │  - Reports   │  │              │     │
│  │  - commands/ │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Test Fixtures & Helpers                  │  │
│  │                                                        │  │
│  │  - Sample vulnerable code                            │  │
│  │  - Scanner output samples (Bandit, Semgrep)         │  │
│  │  - Policy YAML files                                 │  │
│  │  - Mock LLM providers                                │  │
│  │  - Test database helpers                             │  │
│  │  - SARIF validation samples                          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Documentation Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Documentation System                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │     User     │  │  Developer   │  │   Release    │     │
│  │     Docs     │  │     Docs     │  │    Docs      │     │
│  │              │  │              │  │              │     │
│  │  - README    │  │  - godoc     │  │  - CHANGELOG │     │
│  │  - INSTALL   │  │  - ARCH.md   │  │  - RELEASE   │     │
│  │  - USAGE     │  │  - PLUGIN.md │  │    NOTES     │     │
│  │  - CONFIG    │  │  - API.md    │  │  - MIGRATION │     │
│  │  - POLICY    │  │              │  │              │     │
│  │  - TROUBLE   │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Build and Release Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Build System                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Cross-Platform Builds                    │  │
│  │                                                        │  │
│  │  Linux (amd64, arm64)                                │  │
│  │  macOS (amd64, arm64)                                │  │
│  │  Windows (amd64)                                     │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Release Artifact Generation                 │  │
│  │                                                        │  │
│  │  - Binaries with version info                        │  │
│  │  - SHA256 checksums                                  │  │
│  │  - Compressed archives (tar.gz, zip)                │  │
│  │  - README and LICENSE                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            Release Verification                       │  │
│  │                                                        │  │
│  │  - Version check                                     │  │
│  │  - Help command test                                 │  │
│  │  - Basic scan test                                   │  │
│  │  - Checksum validation                               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Test Framework Components

#### Unit Test Structure

Each package will have corresponding test files following Go conventions:

```go
// File: internal/scanner/orchestrator_test.go
package scanner

import (
    "testing"
)

// Table-driven test pattern
func TestOrchestrator_Run(t *testing.T) {
    tests := []struct {
        name    string
        config  Config
        want    []Finding
        wantErr bool
    }{
        {
            name: "single scanner success",
            config: Config{
                Scanners: []string{"bandit"},
                Path: "./testdata/sample.py",
            },
            want: []Finding{/* expected findings */},
            wantErr: false,
        },
        // More test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

#### Integration Test Structure

Integration tests will be in a separate `integration_test` package:

```go
// File: tests/integration/scan_workflow_test.go
// +build integration

package integration

import (
    "testing"
)

func TestEndToEndScanWorkflow(t *testing.T) {
    // Setup: Create temp directory, database
    // Execute: Run complete scan
    // Verify: Check findings, database, reports
    // Cleanup: Remove temp files
}
```

#### Benchmark Structure

```go
// File: internal/scanner/orchestrator_bench_test.go
package scanner

import (
    "testing"
)

func BenchmarkOrchestrator_ScanLargeCodebase(b *testing.B) {
    // Setup large codebase fixture
    for i := 0; i < b.N; i++ {
        // Run scan
    }
}
```

### 2. Test Fixtures and Helpers

#### Test Data Organization

```
testdata/
├── vulnerable-code/
│   ├── sql-injection.py
│   ├── xss-vulnerability.js
│   ├── hardcoded-secrets.py
│   └── command-injection.go
├── scanner-outputs/
│   ├── bandit-sample.json
│   ├── semgrep-sample.json
│   └── empty-results.json
├── policies/
│   ├── valid-policy.yaml
│   ├── invalid-syntax.yaml
│   └── complex-policy.yaml
├── configs/
│   ├── valid-config.yaml
│   ├── minimal-config.yaml
│   └── invalid-config.yaml
└── sarif/
    ├── valid-sarif.json
    └── sarif-with-results.json
```

#### Test Helper Functions

```go
// File: internal/testutil/helpers.go
package testutil

import (
    "database/sql"
    "testing"
)

// CreateTestDB creates an in-memory SQLite database for testing
func CreateTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        t.Fatalf("failed to create test database: %v", err)
    }
    
    // Run schema migrations
    // ...
    
    return db
}

// LoadFixture loads a test fixture file
func LoadFixture(t *testing.T, path string) []byte {
    data, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("failed to load fixture %s: %v", path, err)
    }
    return data
}

// MockLLMProvider creates a mock LLM provider for testing
type MockLLMProvider struct {
    Responses map[string]string
}

func (m *MockLLMProvider) GenerateRemediation(finding Finding) (string, error) {
    if resp, ok := m.Responses[finding.ID]; ok {
        return resp, nil
    }
    return "Mock remediation guidance", nil
}
```

### 3. Documentation Components

#### User Documentation Structure

```
docs/
├── user-guide/
│   ├── 01-installation.md
│   ├── 02-quickstart.md
│   ├── 03-configuration.md
│   ├── 04-scanning.md
│   ├── 05-findings.md
│   ├── 06-policies.md
│   ├── 07-reports.md
│   ├── 08-llm-integration.md
│   └── 09-troubleshooting.md
├── developer-guide/
│   ├── architecture.md
│   ├── plugin-development.md
│   ├── api-reference.md
│   ├── contributing.md
│   └── testing.md
├── policy-guide/
│   ├── policy-syntax.md
│   ├── policy-examples.md
│   ├── compliance-frameworks.md
│   └── best-practices.md
└── release/
    ├── CHANGELOG.md
    ├── RELEASE_NOTES_v1.0.md
    └── MIGRATION.md
```

#### Godoc Comment Standards

All exported functions, types, and packages must have godoc comments:

```go
// Package scanner provides orchestration for multiple security scanners.
// It manages scanner plugins, aggregates findings, and normalizes results
// to a common format with CWE mappings.
package scanner

// Orchestrator coordinates multiple security scanners and aggregates their findings.
// It supports parallel execution, error handling, and result normalization.
type Orchestrator struct {
    // plugins contains registered scanner plugins
    plugins map[string]Plugin
    
    // config holds orchestrator configuration
    config Config
}

// Run executes all configured scanners against the target path and returns
// aggregated findings. It runs scanners in parallel when possible and handles
// errors gracefully, continuing with remaining scanners if one fails.
//
// Example:
//   orch := NewOrchestrator(config)
//   findings, err := orch.Run(ctx, "/path/to/code")
//   if err != nil {
//       log.Fatal(err)
//   }
func (o *Orchestrator) Run(ctx context.Context, path string) ([]Finding, error) {
    // Implementation
}
```

### 4. Build System Components

#### Build Script Structure

```bash
#!/bin/bash
# build.sh - Multi-platform build script

VERSION="1.0.0"
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

for platform in "${PLATFORMS[@]}"; do
    GOOS=${platform%/*}
    GOARCH=${platform#*/}
    
    output="coding-agent-cli-${VERSION}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        output="${output}.exe"
    fi
    
    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "-X main.Version=$VERSION" \
        -o "dist/$output" \
        .
    
    # Generate checksum
    sha256sum "dist/$output" > "dist/$output.sha256"
    
    # Create archive
    if [ "$GOOS" = "windows" ]; then
        zip "dist/coding-agent-cli-${VERSION}-${GOOS}-${GOARCH}.zip" \
            "dist/$output" README.md LICENSE
    else
        tar czf "dist/coding-agent-cli-${VERSION}-${GOOS}-${GOARCH}.tar.gz" \
            -C dist "$output" -C .. README.md LICENSE
    fi
done
```

#### Version Embedding

```go
// File: main.go
package main

var (
    // Version is set during build via -ldflags
    Version = "dev"
    
    // BuildTime is set during build via -ldflags
    BuildTime = "unknown"
)

func main() {
    rootCmd.Version = fmt.Sprintf("%s (built %s)", Version, BuildTime)
    // ...
}
```

## Data Models

### Test Result Models

```go
// TestResult represents the outcome of a test execution
type TestResult struct {
    Package    string
    TestName   string
    Passed     bool
    Duration   time.Duration
    Output     string
    Coverage   float64
}

// BenchmarkResult represents performance benchmark data
type BenchmarkResult struct {
    Name           string
    Iterations     int
    NsPerOp        int64
    BytesPerOp     int64
    AllocsPerOp    int64
    MemoryMB       float64
    DurationSec    float64
}

// CoverageReport represents code coverage analysis
type CoverageReport struct {
    Package        string
    TotalLines     int
    CoveredLines   int
    CoveragePercent float64
    UncoveredFuncs []string
}
```

### Documentation Models

```go
// DocSection represents a documentation section
type DocSection struct {
    Title       string
    Content     string
    Subsections []DocSection
    CodeExamples []CodeExample
}

// CodeExample represents a code snippet in documentation
type CodeExample struct {
    Language    string
    Code        string
    Description string
}

// APIDoc represents API documentation for a package
type APIDoc struct {
    Package     string
    Description string
    Functions   []FunctionDoc
    Types       []TypeDoc
    Examples    []CodeExample
}
```

### Build Artifact Models

```go
// BuildArtifact represents a compiled binary
type BuildArtifact struct {
    Platform    string  // e.g., "linux/amd64"
    Filename    string
    Version     string
    Size        int64
    Checksum    string  // SHA256
    BuildTime   time.Time
}

// ReleasePackage represents a complete release package
type ReleasePackage struct {
    Version     string
    Artifacts   []BuildArtifact
    Changelog   string
    ReleaseNotes string
    Documentation map[string]string  // filename -> content
}
```

## Correctness Properties


*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Test Failure Messages Are Informative

*For any* test that fails, the error message should clearly indicate the failure reason, the expected vs actual values, and the location (file and line number) of the failure.

**Validates: Requirements 1.10**

### Property 2: Memory Usage Stays Within Bounds

*For any* codebase scanned by the CLI tool, peak memory usage during the scan operation should remain below 2GB regardless of codebase size or complexity.

**Validates: Requirements 4.4**

### Property 3: LLM Cache Achieves Target Hit Rate

*For any* set of findings with repeated similar vulnerabilities, when LLM caching is enabled, the cache hit rate should be at least 50%, demonstrating effective caching of remediation guidance.

**Validates: Requirements 4.8**

### Property 4: Performance Regressions Are Detected

*For any* benchmark result that exceeds the established performance target by more than 20%, the test system should automatically flag it as a regression and report it clearly.

**Validates: Requirements 4.12**

### Property 5: Build Artifacts Are Complete and Valid

*For any* release artifact produced by the build system, it should:
- Contain embedded version information accessible via --version flag
- Be statically linked with no external runtime dependencies
- Have an accompanying SHA256 checksum file
- Be packaged with README and LICENSE files
- Execute successfully on its target platform
- Be compressed in the appropriate archive format (tar.gz for Unix, zip for Windows)

**Validates: Requirements 9.4, 9.5, 9.6, 9.7, 9.8, 9.9**

### Property 6: Build Failures Provide Clear Diagnostics

*For any* build process failure, the error message should clearly indicate which platform failed, what step failed (compilation, linking, packaging), and the specific error reason to enable quick debugging.

**Validates: Requirements 9.10**

### Property 7: Release Artifacts Pass Functional Verification

*For any* release artifact, it should successfully:
- Display correct version information when invoked with --version
- Execute the help command without errors
- Perform a basic scan operation on sample code
- Generate reports in all supported formats (JSON, SARIF, Markdown, HTML, CSV)
- Load and parse configuration files correctly
- Handle missing scanner dependencies gracefully with helpful error messages

**Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6**

### Property 8: Release Packages Have Integrity

*For any* release package, the checksum files should match their corresponding binaries, archive files should extract without errors, and extracted contents should include all expected files (binary, README, LICENSE).

**Validates: Requirements 10.7, 10.8, 10.9**

### Property 9: Release Artifacts Are Self-Contained

*For any* release artifact, it should execute successfully on a clean system without requiring pre-installed dependencies (beyond OS-level libraries), demonstrating true portability.

**Validates: Requirements 10.9**

### Property 10: Failed Verifications Block Release

*For any* release verification check that fails, the release process should immediately halt and report the specific failure with sufficient detail to diagnose the issue.

**Validates: Requirements 10.10**

### Property 11: CI Test Failures Are Well-Reported

*For any* test failure in the CI environment, the system should provide detailed logs including the test name, failure message, stack trace, and relevant context to enable developers to reproduce and fix the issue.

**Validates: Requirements 11.4**

### Property 12: Performance Regressions Trigger Notifications

*For any* benchmark test that detects a performance regression (execution time or memory usage exceeding targets), the system should automatically notify maintainers through the configured notification channel.

**Validates: Requirements 11.10**

### Property 13: Test Fixtures Are Isolated

*For any* test that uses fixtures, the fixtures should be isolated such that running tests in parallel or in any order produces the same results, with no test affecting another test's fixture state.

**Validates: Requirements 12.10**

## Error Handling

### Test Execution Errors

**Scenario**: Test panics or crashes unexpectedly

**Handling**:
- Go's testing framework automatically recovers from panics in tests
- Panic stack traces are captured and reported
- Other tests continue execution (isolation)
- CI build fails if any test panics

**Example**:
```go
func TestWithRecovery(t *testing.T) {
    defer func() {
        if r := recover(); r != nil {
            t.Errorf("Test panicked: %v", r)
        }
    }()
    // Test code that might panic
}
```

### Build Errors

**Scenario**: Cross-compilation fails for a target platform

**Handling**:
- Build script captures GOOS/GOARCH that failed
- Compiler error output is preserved and displayed
- Build continues for other platforms (fail-fast disabled)
- Final summary shows which platforms succeeded/failed
- Exit code indicates overall build status

**Example**:
```bash
# Build script error handling
if ! GOOS=$GOOS GOARCH=$GOARCH go build -o "$output" .; then
    echo "❌ Build failed for $GOOS/$GOARCH"
    echo "Error: $(cat build.log)"
    FAILED_BUILDS+=("$GOOS/$GOARCH")
    continue
fi
```

### Documentation Generation Errors

**Scenario**: godoc generation fails or produces warnings

**Handling**:
- Validate all exported symbols have documentation comments
- Use `go vet` to catch documentation issues
- CI fails if documentation is missing for exported APIs
- Provide clear error messages indicating which symbols lack docs

**Example**:
```bash
# Check for missing documentation
go vet ./... 2>&1 | grep "exported.*should have comment"
if [ $? -eq 0 ]; then
    echo "❌ Missing documentation for exported symbols"
    exit 1
fi
```

### Benchmark Failures

**Scenario**: Benchmark exceeds time limit or runs out of memory

**Handling**:
- Set reasonable timeouts for benchmarks (e.g., 10 minutes)
- Monitor memory usage and fail gracefully if limit exceeded
- Report partial results if benchmark times out
- Distinguish between benchmark failure and performance regression

**Example**:
```go
func BenchmarkWithTimeout(b *testing.B) {
    timeout := time.After(10 * time.Minute)
    
    for i := 0; i < b.N; i++ {
        select {
        case <-timeout:
            b.Fatal("Benchmark exceeded timeout")
        default:
            // Run benchmark iteration
        }
    }
}
```

### Fixture Loading Errors

**Scenario**: Test fixture file is missing or corrupted

**Handling**:
- Check fixture file existence before loading
- Validate fixture content format (JSON, YAML parsing)
- Provide clear error messages indicating which fixture failed
- Fail fast for fixture errors (can't run tests without fixtures)

**Example**:
```go
func LoadFixture(t *testing.T, path string) []byte {
    data, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("Failed to load fixture %s: %v\nEnsure testdata directory is present", path, err)
    }
    
    // Validate fixture format if applicable
    if strings.HasSuffix(path, ".json") {
        if !json.Valid(data) {
            t.Fatalf("Fixture %s contains invalid JSON", path)
        }
    }
    
    return data
}
```

### CI Integration Errors

**Scenario**: CI environment lacks required tools or permissions

**Handling**:
- Check for required tools (go, git, etc.) at CI start
- Validate environment variables are set
- Provide clear error messages for missing prerequisites
- Document CI environment requirements in README

**Example**:
```yaml
# CI configuration with error handling
- name: Check Prerequisites
  run: |
    if ! command -v go &> /dev/null; then
      echo "❌ Go is not installed"
      exit 1
    fi
    if [ -z "$GITHUB_TOKEN" ]; then
      echo "❌ GITHUB_TOKEN not set"
      exit 1
    fi
```

## Testing Strategy

### Test Organization

The testing strategy follows the test pyramid principle with three layers:

```
        /\
       /  \
      / B  \      Benchmarks (Performance)
     /______\     - Scan time benchmarks
    /        \    - Memory usage benchmarks
   /   IT     \   - Database performance
  /____________\  - Cache effectiveness
 /              \
/   Unit Tests   \ Unit Tests (Functionality)
\________________/ - Package-level tests
                   - Function-level tests
                   - Edge cases
                   - Error handling
```

### Unit Testing Approach

**Coverage Target**: Minimum 70% code coverage across all packages

**Test Organization**:
- Each package has a corresponding `_test.go` file
- Table-driven tests for functions with multiple scenarios
- Subtests using `t.Run()` for better organization and parallel execution
- Test helpers in `internal/testutil` package

**Example Test Structure**:
```go
func TestScanner_Parse(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    []Finding
        wantErr bool
    }{
        {
            name: "valid bandit output",
            input: `{"results": [...]}`,
            want: []Finding{...},
            wantErr: false,
        },
        {
            name: "empty output",
            input: `{"results": []}`,
            want: []Finding{},
            wantErr: false,
        },
        {
            name: "invalid json",
            input: `{invalid}`,
            want: nil,
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel() // Run subtests in parallel
            
            got, err := Parse(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Parse() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

**Packages to Test**:
1. `internal/scanner` - Orchestrator, plugin management, finding aggregation
2. `internal/storage` - Database operations, migrations, queries
3. `internal/cwe` - CWE mapping, data integrity
4. `internal/sarif` - SARIF generation, format compliance
5. `internal/llm` - Prompt generation, response parsing, caching, redaction
6. `internal/policy` - Policy parsing, rule evaluation, waivers, compliance
7. `plugins/bandit` - Bandit integration, output parsing
8. `plugins/semgrep` - Semgrep integration, output parsing
9. `cmd/*` - CLI commands, argument parsing, output formatting

### Integration Testing Approach

**Test Organization**:
- Integration tests in `tests/integration/` directory
- Build tag `// +build integration` to separate from unit tests
- Run with: `go test -tags=integration ./tests/integration/...`

**Test Scenarios**:

1. **End-to-End Scan Workflow**
   - Setup: Create temp directory with vulnerable code
   - Execute: Run complete scan with multiple scanners
   - Verify: Check findings in database, validate normalization
   - Cleanup: Remove temp files and database

2. **Multi-Scanner Integration**
   - Setup: Configure Bandit and Semgrep
   - Execute: Run both scanners on same codebase
   - Verify: Findings are merged, duplicates removed, CWE mapped
   - Cleanup: Remove temp data

3. **Policy Enforcement Workflow**
   - Setup: Create policy file with rules
   - Execute: Run scan with policy enforcement
   - Verify: Policy violations reported, waivers applied
   - Cleanup: Remove temp files

4. **Report Generation Workflow**
   - Setup: Database with sample findings
   - Execute: Generate reports in all formats
   - Verify: Reports contain correct data, proper formatting
   - Cleanup: Remove generated reports

5. **LLM Remediation Workflow**
   - Setup: Mock LLM provider with canned responses
   - Execute: Request remediation for findings
   - Verify: Remediation cached, retrieved correctly
   - Cleanup: Clear cache

**Example Integration Test**:
```go
// +build integration

func TestEndToEndScanWorkflow(t *testing.T) {
    // Setup
    tmpDir := t.TempDir()
    dbPath := filepath.Join(tmpDir, "test.db")
    
    // Create vulnerable test file
    testFile := filepath.Join(tmpDir, "test.py")
    os.WriteFile(testFile, []byte(`
        import os
        password = "hardcoded123"
        os.system("rm -rf " + user_input)
    `), 0644)
    
    // Execute scan
    cmd := exec.Command("./coding-agent-cli",
        "scan", tmpDir,
        "--db", dbPath,
        "--scanners", "bandit",
        "--output", filepath.Join(tmpDir, "results.json"),
    )
    output, err := cmd.CombinedOutput()
    if err != nil {
        t.Fatalf("Scan failed: %v\n%s", err, output)
    }
    
    // Verify findings in database
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        t.Fatalf("Failed to open database: %v", err)
    }
    defer db.Close()
    
    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count)
    if err != nil {
        t.Fatalf("Failed to query findings: %v", err)
    }
    
    if count == 0 {
        t.Error("Expected findings but got none")
    }
    
    // Verify findings have CWE mappings
    var unmappedCount int
    err = db.QueryRow("SELECT COUNT(*) FROM findings WHERE cwe_id IS NULL").Scan(&unmappedCount)
    if err != nil {
        t.Fatalf("Failed to query unmapped findings: %v", err)
    }
    
    if unmappedCount > 0 {
        t.Errorf("Found %d findings without CWE mappings", unmappedCount)
    }
}
```

### Performance Benchmarking Approach

**Benchmark Organization**:
- Benchmark functions in `_bench_test.go` files
- Run with: `go test -bench=. -benchmem ./...`
- Track results over time using benchstat or similar tools

**Benchmark Scenarios**:

1. **Scan Time Benchmarks**
   - Small codebase (1K LOC): Target <30 seconds
   - Medium codebase (10K LOC): Target <5 minutes
   - Large codebase (50K LOC): Target <20 minutes

2. **Memory Usage Benchmarks**
   - Track allocations per operation
   - Monitor peak memory usage
   - Target: <2GB for any codebase size

3. **Database Performance Benchmarks**
   - Finding insertion: Target <1ms per finding
   - Finding retrieval: Target <100ms for 10K findings
   - Query with filters: Target <200ms

4. **LLM Cache Benchmarks**
   - Cache hit rate: Target >50% for repeated findings
   - Cache lookup time: Target <10ms
   - Cache storage time: Target <50ms

5. **Report Generation Benchmarks**
   - JSON report: Target <100ms for 1K findings
   - HTML report: Target <200ms for 1K findings
   - CSV export: Target <150ms for 1K findings

**Example Benchmark**:
```go
func BenchmarkScanner_ScanMediumCodebase(b *testing.B) {
    // Setup: Create 10K LOC test codebase
    tmpDir := setupTestCodebase(b, 10000)
    defer os.RemoveAll(tmpDir)
    
    scanner := NewOrchestrator(Config{
        Scanners: []string{"bandit"},
    })
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        _, err := scanner.Run(context.Background(), tmpDir)
        if err != nil {
            b.Fatalf("Scan failed: %v", err)
        }
    }
}

func BenchmarkDatabase_QueryFindings(b *testing.B) {
    // Setup: Database with 10K findings
    db := setupTestDB(b, 10000)
    defer db.Close()
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        rows, err := db.Query("SELECT * FROM findings WHERE severity = ?", "high")
        if err != nil {
            b.Fatalf("Query failed: %v", err)
        }
        rows.Close()
    }
}
```

### Test Fixtures and Test Data

**Fixture Organization**:
```
testdata/
├── vulnerable-code/
│   ├── sql-injection.py       # SQL injection vulnerability
│   ├── xss-vulnerability.js   # XSS vulnerability
│   ├── hardcoded-secrets.py   # Hardcoded credentials
│   ├── command-injection.go   # Command injection
│   └── path-traversal.java    # Path traversal
├── scanner-outputs/
│   ├── bandit-sample.json     # Sample Bandit output
│   ├── semgrep-sample.json    # Sample Semgrep output
│   ├── empty-results.json     # Empty scan results
│   └── malformed.json         # Invalid JSON for error testing
├── policies/
│   ├── valid-policy.yaml      # Valid policy file
│   ├── invalid-syntax.yaml    # YAML syntax errors
│   ├── complex-policy.yaml    # Complex rules and waivers
│   └── empty-policy.yaml      # Empty policy file
├── configs/
│   ├── valid-config.yaml      # Valid configuration
│   ├── minimal-config.yaml    # Minimal configuration
│   └── invalid-config.yaml    # Invalid configuration
└── sarif/
    ├── valid-sarif.json       # Valid SARIF 2.1.0
    └── sarif-with-results.json # SARIF with findings
```

**Test Helper Functions**:
```go
// internal/testutil/helpers.go

// CreateTestDB creates an in-memory SQLite database with schema
func CreateTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        t.Fatalf("failed to create test database: %v", err)
    }
    
    // Run schema migrations
    schema, err := os.ReadFile("../../internal/storage/schema.sql")
    if err != nil {
        t.Fatalf("failed to read schema: %v", err)
    }
    
    _, err = db.Exec(string(schema))
    if err != nil {
        t.Fatalf("failed to create schema: %v", err)
    }
    
    return db
}

// InsertTestFindings inserts sample findings into database
func InsertTestFindings(t *testing.T, db *sql.DB, count int) []string {
    var ids []string
    
    for i := 0; i < count; i++ {
        id := fmt.Sprintf("test-finding-%d", i)
        _, err := db.Exec(`
            INSERT INTO findings (id, cwe_id, severity, file_path, line_number, description)
            VALUES (?, ?, ?, ?, ?, ?)
        `, id, "CWE-89", "high", "test.py", i+1, "Test finding")
        
        if err != nil {
            t.Fatalf("failed to insert test finding: %v", err)
        }
        
        ids = append(ids, id)
    }
    
    return ids
}

// LoadFixture loads a test fixture file
func LoadFixture(t *testing.T, path string) []byte {
    data, err := os.ReadFile(filepath.Join("testdata", path))
    if err != nil {
        t.Fatalf("failed to load fixture %s: %v", path, err)
    }
    return data
}

// MockLLMProvider provides canned responses for testing
type MockLLMProvider struct {
    Responses map[string]string
    CallCount int
}

func (m *MockLLMProvider) GenerateRemediation(ctx context.Context, finding Finding) (string, error) {
    m.CallCount++
    
    if resp, ok := m.Responses[finding.CWE]; ok {
        return resp, nil
    }
    
    return "Mock remediation guidance for " + finding.CWE, nil
}

func (m *MockLLMProvider) IsAvailable() bool {
    return true
}
```

### CI/CD Integration

**GitHub Actions Workflow**:
```yaml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Nightly benchmarks

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
          cache: true
      
      - name: Run unit tests
        run: go test -v -race -coverprofile=coverage.out ./...
      
      - name: Check coverage
        run: |
          coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Coverage: $coverage%"
          if (( $(echo "$coverage < 70" | bc -l) )); then
            echo "❌ Coverage below 70%"
            exit 1
          fi
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.out

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install scanners
        run: |
          pip install bandit semgrep
      
      - name: Build CLI
        run: go build -o coding-agent-cli .
      
      - name: Run integration tests
        run: go test -v -tags=integration ./tests/integration/...

  benchmarks:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Run benchmarks
        run: go test -bench=. -benchmem -run=^$ ./... | tee benchmark.txt
      
      - name: Store benchmark results
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'go'
          output-file-path: benchmark.txt
          github-token: ${{ secrets.GITHUB_TOKEN }}
          auto-push: true
```

### Documentation Testing

**Documentation Validation**:
- All exported functions, types, and packages must have godoc comments
- Documentation examples must compile and run successfully
- Links in documentation must be valid

**Validation Script**:
```bash
#!/bin/bash
# validate-docs.sh

echo "Checking for missing documentation..."

# Check for undocumented exports
undocumented=$(go vet ./... 2>&1 | grep "exported.*should have comment" || true)
if [ -n "$undocumented" ]; then
    echo "❌ Found undocumented exports:"
    echo "$undocumented"
    exit 1
fi

echo "✅ All exports are documented"

# Test documentation examples
echo "Testing documentation examples..."
go test -run=Example ./...

echo "✅ All documentation examples pass"

# Validate markdown links
echo "Checking markdown links..."
find docs -name "*.md" -exec markdown-link-check {} \;

echo "✅ All documentation links are valid"
```

### Test Execution Commands

**Run all unit tests**:
```bash
go test -v ./...
```

**Run tests with coverage**:
```bash
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

**Run integration tests**:
```bash
go test -v -tags=integration ./tests/integration/...
```

**Run benchmarks**:
```bash
go test -bench=. -benchmem ./...
```

**Run specific package tests**:
```bash
go test -v ./internal/scanner/...
```

**Run tests in parallel**:
```bash
go test -v -parallel=4 ./...
```

**Run tests with race detector**:
```bash
go test -v -race ./...
```

