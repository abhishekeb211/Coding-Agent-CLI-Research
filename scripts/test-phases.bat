@echo off
REM Phase-based implementation check and automated test loop for Coding Agent CLI.
REM Run from repository root: scripts\test-phases.bat

setlocal enabledelayedexpansion
set FAILED=0

echo ==========================================
echo Coding Agent CLI - Phase implementation check and tests
echo ==========================================
echo.

REM Step 1: Global implementation check
echo Step 1: Global build (implementation check)
go build ./...
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Implementation check failed. Fix build before running phase tests.
    exit /b 1
)
echo   OK
echo.

REM Step 2: Phase loop with subtasks
echo Step 2: Phase loop (build + test per phase)
echo.

REM Phase 1: Foundation
echo --- Phase 1: Foundation ---
go build ./cmd/... ./internal/storage/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./cmd/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/storage/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
echo.

REM Phase 2: Scanner integration
echo --- Phase 2: Scanner integration ---
go build ./internal/scanner/... ./plugins/bandit/... ./plugins/semgrep/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/scanner/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./plugins/bandit/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./plugins/semgrep/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
echo.

REM Phase 3: Normalization
echo --- Phase 3: Normalization ---
go build ./internal/cwe/... ./internal/sarif/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/cwe/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/sarif/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
echo.

REM Phase 4: LLM
echo --- Phase 4: LLM ---
go build ./internal/llm/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/llm/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
echo.

REM Phase 5: Policy engine
echo --- Phase 5: Policy engine ---
go build ./internal/policy/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/policy/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
echo.

REM Phase 6: CLI and reporting
echo --- Phase 6: CLI and reporting ---
go build ./cmd/... ./internal/importer/... ./internal/exporter/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./cmd/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/importer/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
go test -v -count=1 ./internal/exporter/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
echo.

REM Phase 7: Integration tests
echo --- Phase 7: Testing and docs (integration tests) ---
go test -v -count=1 -tags=integration ./tests/integration/...
if %ERRORLEVEL% NEQ 0 set FAILED=1
echo.

REM Summary
echo ==========================================
echo Summary
echo ==========================================
if %FAILED% EQU 0 (
    echo All phases and subtasks PASSED.
    endlocal
    exit /b 0
) else (
    echo One or more phase builds or subtasks FAILED.
    endlocal
    exit /b 1
)
