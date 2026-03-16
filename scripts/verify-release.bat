@echo off
REM Release verification script for Windows

setlocal enabledelayedexpansion

set VERSION=1.0.0
set DIST_DIR=dist
set BINARY=%DIST_DIR%\coding-agent-cli-%VERSION%-windows-amd64.exe
set CHECKSUM=%BINARY%.sha256

echo Verifying Release Artifacts v%VERSION%
echo ========================================
echo.

set FAILED=0

REM Check 1: Binary exists
echo Checking binary exists...
if exist "%BINARY%" (
    echo [32m✓ Binary exists[0m
) else (
    echo [31m✗ Binary not found[0m
    set FAILED=1
)

REM Check 2: Version information
echo Checking version information...
"%BINARY%" --version | findstr "%VERSION%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [32m✓ Version information correct[0m
) else (
    echo [31m✗ Version information failed[0m
    set FAILED=1
)

REM Check 3: Help command
echo Checking help command...
"%BINARY%" --help >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [32m✓ Help command works[0m
) else (
    echo [31m✗ Help command failed[0m
    set FAILED=1
)

REM Check 4: Checksum file exists
echo Checking checksum file...
if exist "%CHECKSUM%" (
    echo [32m✓ Checksum file exists[0m
) else (
    echo [31m✗ Checksum file not found[0m
    set FAILED=1
)

REM Check 5: Basic functionality test
echo Checking basic functionality...
"%BINARY%" scan --help >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [32m✓ Basic functionality works[0m
) else (
    echo [31m✗ Basic functionality failed[0m
    set FAILED=1
)

echo.
echo ========================================
echo Verification Summary
echo ========================================
echo.

if %FAILED% EQU 0 (
    echo [32mAll verification checks passed![0m
    echo.
    echo Release artifacts are ready for distribution.
    exit /b 0
) else (
    echo [31mSome verification checks failed![0m
    echo.
    echo Please fix the issues before releasing.
    exit /b 1
)

endlocal
