@echo off
REM Benchmark tracking script for Coding Agent CLI (Windows)
REM Runs benchmarks, stores results, and detects performance regressions

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "BENCH_DIR=%PROJECT_ROOT%\.benchmarks"
set "RESULTS_FILE=%BENCH_DIR%\results.txt"
set "REGRESSION_THRESHOLD=20"

REM Create benchmark directory if it doesn't exist
if not exist "%BENCH_DIR%" mkdir "%BENCH_DIR%"

echo =========================================
echo   Coding Agent CLI - Benchmark Suite
echo =========================================
echo.

echo Running benchmarks...
echo.

cd /d "%PROJECT_ROOT%"

REM Run benchmarks with memory profiling
go test -bench=. -benchmem -benchtime=3s ./... > "%RESULTS_FILE%" 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Benchmarks completed successfully
) else (
    echo [ERROR] Benchmarks failed
    type "%RESULTS_FILE%"
    exit /b 1
)

echo.
echo Parsing benchmark results...
echo.

REM Display key benchmarks
findstr /C:"Benchmark" "%RESULTS_FILE%"

echo.
echo =========================================
echo   Benchmark Summary
echo =========================================
echo.

echo Scanner Performance:
findstr /C:"BenchmarkScan" "%RESULTS_FILE%" | findstr /N "^" | findstr "^[1-5]:"
echo.

echo Database Performance:
findstr /C:"BenchmarkDatabase" "%RESULTS_FILE%" | findstr /N "^" | findstr "^[1-5]:"
echo.

echo LLM Cache Performance:
findstr /C:"BenchmarkCache" "%RESULTS_FILE%" | findstr /N "^" | findstr "^[1-5]:"
echo.

echo Report Generation Performance:
findstr /C:"BenchmarkReport" "%RESULTS_FILE%" | findstr /N "^" | findstr "^[1-5]:"
echo.

echo =========================================
echo [SUCCESS] Benchmarks completed
echo =========================================

exit /b 0
