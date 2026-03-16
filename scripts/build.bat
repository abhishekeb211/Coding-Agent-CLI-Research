@echo off
REM Multi-platform build script for Coding Agent CLI (Windows)

setlocal enabledelayedexpansion

set VERSION=1.0.0
set DIST_DIR=dist

echo Building Coding Agent CLI v%VERSION%
echo ========================================
echo.

REM Create dist directory
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

REM Build for Windows (current platform)
echo Building for windows/amd64...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
set OUTPUT=%DIST_DIR%\coding-agent-cli-%VERSION%-windows-amd64.exe

go build -ldflags "-X main.Version=%VERSION%" -o "%OUTPUT%" .

if %ERRORLEVEL% EQU 0 (
    echo [32m✓ Build successful[0m
    
    REM Generate SHA256 checksum
    certutil -hashfile "%OUTPUT%" SHA256 | findstr /v ":" | findstr /v "CertUtil" > "%OUTPUT%.sha256"
    echo [32m✓ Checksum generated[0m
    
    REM Test binary
    "%OUTPUT%" --version >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo [32m✓ Binary verification passed[0m
    ) else (
        echo [31m✗ Binary verification failed[0m
    )
    
    echo.
    echo ========================================
    echo Build completed successfully!
    echo ========================================
    echo.
    echo Binary: %OUTPUT%
    echo Checksum: %OUTPUT%.sha256
    echo.
    
) else (
    echo [31m✗ Build failed[0m
    exit /b 1
)

endlocal
