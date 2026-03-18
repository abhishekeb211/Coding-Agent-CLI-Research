# Error Correction Implementation Plan

## Overview

This document identifies all GitHub Actions CI/CD failures in the Coding Agent CLI repository, categorizes them by root cause, maps them to the flow architecture, and provides a prioritized implementation plan for resolution.

**Date**: 2026-03-18  
**Repository**: abhishekeb211/Coding-Agent-CLI-Research  
**Affected Workflows**: Build and Test, Test Suite, Security Scan

---

## Flow Architecture Context

The Coding Agent CLI follows a modular pipeline architecture:

```
CLI (cmd/) → Scanner Orchestrator (internal/scanner/)
                ├── Plugin Layer (plugins/bandit, semgrep, gosec, eslint, safety)
                ├── CWE Mapper (internal/cwe/)
                └── Normalized Findings
                        ├── Storage (internal/storage/) ── SQLite
                        ├── Policy Engine (internal/policy/)
                        ├── LLM Integration (internal/llm/)
                        │     ├── OpenAI Provider
                        │     ├── Anthropic Provider
                        │     ├── Ollama Provider
                        │     └── Mock Provider + Cache + Redactor
                        ├── Report Generator (internal/sarif/)
                        ├── Analytics Engine (internal/analytics/)
                        └── REST API (internal/api/) ── Chi HTTP Server
```

**CI/CD Pipeline**:
```
push/PR → build-test.yml ─── Build binary + Run all tests
        → test.yml ───────── Unit Tests, Integration Tests, Lint, Benchmarks, Multi-platform Build
        → security-scan.yml ─ Self-scan via Docker Action + SARIF upload
```

---

## Error Categories

### Category 1: Go Version Mismatch (CRITICAL)

| File | Current Value | Required Value | Impact |
|------|--------------|----------------|--------|
| `go.mod` | `go 1.25.0` | — (source of truth) | Defines minimum Go version |
| `Dockerfile` | `golang:1.24-alpine` | `golang:1.25-alpine` | Docker build fails: `go.mod requires go >= 1.25.0` |
| `.github/workflows/build-test.yml` | `go-version: '1.24'` | `go-version: '1.25'` | Build uses wrong Go version |
| `.github/workflows/test.yml` (all jobs) | `go-version: '1.21'` | `go-version: '1.25'` | All test jobs use incompatible Go version |

**Root Cause**: `go.mod` requires Go 1.25.0 but Dockerfile and all workflow files reference older Go versions (1.21 or 1.24).

**Architecture Impact**: Affects the entire CI/CD pipeline — no workflow can build the project.

---

### Category 2: Deprecated GitHub Actions (HIGH)

| File | Action | Current Version | Required Version | Status |
|------|--------|----------------|-----------------|--------|
| `test.yml` | `actions/checkout` | `@v3` | `@v4` | Deprecated (Node.js 20) |
| `test.yml` | `actions/setup-go` | `@v4` | `@v5` | Deprecated (Node.js 20) |
| `test.yml` | `actions/setup-python` | `@v4` | `@v5` | Deprecated (Node.js 20) |
| `test.yml` | `actions/upload-artifact` | `@v3` | `@v4` | **Completely broken** — v3 no longer accepted |
| `test.yml` | `codecov/codecov-action` | `@v3` | `@v4` | Deprecated |
| `test.yml` | `benchmark-action/github-action-benchmark` | `@v1` | `@v1` | OK (latest) |

**Root Cause**: `test.yml` was written with outdated action versions. The `build-test.yml` and `security-scan.yml` already use `@v4`/`@v5`.

**Architecture Impact**: Build artifact uploads fail completely (v3 deprecated). Node.js 20 deprecation warnings on all other actions.

---

### Category 3: Compilation Errors in Source Code (HIGH)

#### 3a. Missing comma in composite literal
- **File**: `internal/llm/openai_provider_test.go:171`
- **Error**: `missing ',' in composite literal`
- **Cause**: Long string literal in test struct makes the Go parser fail to detect end of field
- **Component**: LLM Integration layer (test file)

#### 3b. Missing `fmt` import
- **File**: `internal/analytics/engine_test.go`
- **Error**: `undefined: fmt` at lines 1349, 1350, 1362, 1466, 1467, 1468, 1481, 1590, 1591, 1604
- **Cause**: Test file uses `fmt.Sprintf()` and `fmt.Errorf()` but does not import the `"fmt"` package
- **Component**: Analytics Engine (test file)

#### 3c. Unused import
- **File**: `internal/api/middleware_test.go:7`
- **Error**: `"time" imported and not used`
- **Cause**: `time` package was imported but is not referenced anywhere in the test
- **Component**: REST API middleware (test file)

#### 3d. Redundant newline in fmt.Println
- **File**: `examples/ollama-provider-example.go:21,46`
- **Error**: `fmt.Println arg list ends with redundant newline`
- **Cause**: `fmt.Println("...\n")` — Println already appends a newline, so `\n` in the string is redundant
- **Component**: Example code

---

### Category 4: Integration Test API Mismatches (HIGH)

**File**: `tests/integration/llm_workflow_test.go`

The integration test file references an outdated LLM API that no longer exists. The actual API uses `Manager`/`NewManager` pattern with `RemediationRequest`/`RemediationResponse`, but the tests reference a non-existent `Client`/`NewClient` pattern.

| Line | Error | Expected (current API) | Test Uses (outdated) |
|------|-------|----------------------|---------------------|
| 19 | `unknown field Response in struct literal of type llm.MockProvider` | `NewMockProvider(config)` | `&llm.MockProvider{Response: "..."}` |
| 23 | `undefined: llm.NewClient` | `llm.NewManager(config)` | `llm.NewClient(...)` |
| 26 | `undefined: scanner.Finding` | `scanner.NormalizedFinding` or `scanner.RawFinding` | `scanner.Finding{...}` |
| 58 | `not enough arguments in call to llm.NewCache` | `llm.NewCache(cacheDir, enabled)` | `llm.NewCache(cachePath)` |
| 75 | `undefined: user_id` | String literal `"user_id"` | Bare identifier `user_id` |
| 85-86 | `MockProvider has no field or method CallCount` | No call tracking in current MockProvider | `mockProvider.CallCount` |

**Root Cause**: The integration tests were written against a planned/prototyped API that was never implemented. The actual LLM package evolved with a different architecture (Manager pattern with provider chain, not Client pattern).

**Architecture Impact**: All 7 LLM integration tests fail to compile, blocking the entire integration test job.

---

### Category 5: Docker Build Failure (CRITICAL)

- **File**: `Dockerfile`
- **Error**: `go: go.mod requires go >= 1.25.0 (running go 1.24.13; GOTOOLCHAIN=local)`
- **Cause**: Same as Category 1 — Go version mismatch
- **Impact**: Security scan workflow (`security-scan.yml`) fails because it uses the Docker action (`uses: ./`)

---

## Prioritized Implementation Plan

### Phase 1: Critical Infrastructure Fixes (Immediate)

These fixes unblock all CI workflows.

| # | Task | Files | Effort | Priority |
|---|------|-------|--------|----------|
| 1.1 | Update Dockerfile Go version to 1.25 | `Dockerfile` | 5 min | CRITICAL |
| 1.2 | Update `build-test.yml` Go version to 1.25 | `.github/workflows/build-test.yml` | 5 min | CRITICAL |
| 1.3 | Update `test.yml` Go version to 1.25 (all jobs) | `.github/workflows/test.yml` | 10 min | CRITICAL |
| 1.4 | Update deprecated actions in `test.yml` | `.github/workflows/test.yml` | 10 min | CRITICAL |

### Phase 2: Compilation Error Fixes (High)

These fixes allow the codebase to compile cleanly.

| # | Task | Files | Effort | Priority |
|---|------|-------|--------|----------|
| 2.1 | Fix missing comma in openai_provider_test.go | `internal/llm/openai_provider_test.go` | 5 min | HIGH |
| 2.2 | Add `"fmt"` import to engine_test.go | `internal/analytics/engine_test.go` | 5 min | HIGH |
| 2.3 | Remove unused `"time"` import from middleware_test.go | `internal/api/middleware_test.go` | 5 min | HIGH |
| 2.4 | Fix redundant newlines in ollama example | `examples/ollama-provider-example.go` | 5 min | HIGH |

### Phase 3: Integration Test Alignment (High)

Rewrite integration tests to match the actual LLM package API.

| # | Task | Files | Effort | Priority |
|---|------|-------|--------|----------|
| 3.1 | Rewrite `TestLLMRemediationGeneration` to use Manager API | `tests/integration/llm_workflow_test.go` | 30 min | HIGH |
| 3.2 | Rewrite `TestLLMCachingBehavior` to use NewCache(dir, bool) | `tests/integration/llm_workflow_test.go` | 30 min | HIGH |
| 3.3 | Fix all remaining integration test functions | `tests/integration/llm_workflow_test.go` | 60 min | HIGH |

### Phase 4: Verification

| # | Task | Effort | Priority |
|---|------|--------|----------|
| 4.1 | Run `go build ./...` to verify compilation | 5 min | REQUIRED |
| 4.2 | Run `go vet ./...` to verify linting passes | 5 min | REQUIRED |
| 4.3 | Run `go test ./...` to verify test execution | 15 min | REQUIRED |
| 4.4 | Verify Docker build succeeds | 5 min | REQUIRED |

---

## Error-to-Architecture Mapping

```
┌──────────────────────────────────────────────────────────────────┐
│                     CI/CD Pipeline Errors                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  build-test.yml ──→ [Cat 1: Go 1.24 vs 1.25]                    │
│                                                                   │
│  test.yml ─────→ [Cat 1: Go 1.21 vs 1.25]                       │
│             ├──→ [Cat 2: Deprecated actions v3]                   │
│             ├──→ [Cat 3a: openai_provider_test.go compile error]  │
│             ├──→ [Cat 3b: engine_test.go missing fmt import]      │
│             ├──→ [Cat 3c: middleware_test.go unused import]        │
│             ├──→ [Cat 3d: ollama example vet warnings]            │
│             └──→ [Cat 4: llm_workflow_test.go API mismatch]       │
│                                                                   │
│  security-scan.yml ──→ [Cat 5: Dockerfile Go 1.24 vs 1.25]      │
│                                                                   │
├──────────────────────────────────────────────────────────────────┤
│              Source Code Component Mapping                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  internal/llm/ ──────── openai_provider_test.go (Cat 3a)         │
│  internal/analytics/ ── engine_test.go (Cat 3b)                   │
│  internal/api/ ──────── middleware_test.go (Cat 3c)               │
│  examples/ ──────────── ollama-provider-example.go (Cat 3d)      │
│  tests/integration/ ─── llm_workflow_test.go (Cat 4)              │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Success Criteria

- [ ] All three GitHub Actions workflows pass (Build and Test, Test Suite, Security Scan)
- [ ] `go build ./...` succeeds locally
- [ ] `go vet ./...` reports no issues
- [ ] `gofmt` reports no formatting issues
- [ ] Docker build succeeds
- [ ] Unit tests pass (`go test ./...`)
- [ ] Integration tests compile and run

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Go 1.25 not available in GitHub Actions | Low | High | Use `go-version: '1.25'` which resolves to latest 1.25.x |
| Go 1.25 Docker image not available | Low | High | Verify `golang:1.25-alpine` exists on Docker Hub |
| Integration test rewrite breaks test intent | Medium | Medium | Preserve original test logic, only update API calls |
| Pre-existing test failures unrelated to CI | High | Low | Focus only on compilation and API mismatch errors |
