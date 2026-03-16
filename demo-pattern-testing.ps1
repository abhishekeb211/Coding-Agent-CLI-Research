# Demo script for the pattern testing utility
# This script demonstrates how to use the new 'policy test-patterns' command

Write-Host "=== Pattern Testing Utility Demo ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This demo shows how to use the new 'policy test-patterns' command"
Write-Host "to test pattern matching rules from a policy file."
Write-Host ""

# Check if Go is available
$goAvailable = Get-Command go -ErrorAction SilentlyContinue

if ($goAvailable) {
    Write-Host "Building the CLI..." -ForegroundColor Yellow
    go build -o coding-agent-cli.exe main.go
    Write-Host "✓ Build complete" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "⚠ Go is not installed. Showing command examples only." -ForegroundColor Yellow
    Write-Host ""
}

# Example 1: Basic usage
Write-Host "Example 1: Basic Pattern Testing" -ForegroundColor Green
Write-Host "Command: .\coding-agent-cli.exe policy test-patterns examples\policy-with-patterns.yaml .\internal"
Write-Host ""
if (Test-Path ".\coding-agent-cli.exe") {
    .\coding-agent-cli.exe policy test-patterns examples\policy-with-patterns.yaml .\internal
} else {
    Write-Host "Expected output:"
    Write-Host "  - Shows matching files for each policy"
    Write-Host "  - Shows excluded files"
    Write-Host "  - Provides summary statistics"
}
Write-Host ""
Write-Host "---" -ForegroundColor Gray
Write-Host ""

# Example 2: Verbose mode
Write-Host "Example 2: Verbose Mode" -ForegroundColor Green
Write-Host "Command: .\coding-agent-cli.exe policy test-patterns examples\policy-with-patterns.yaml .\cmd --verbose"
Write-Host ""
if (Test-Path ".\coding-agent-cli.exe") {
    .\coding-agent-cli.exe policy test-patterns examples\policy-with-patterns.yaml .\cmd --verbose
} else {
    Write-Host "Expected output:"
    Write-Host "  - Shows matching files"
    Write-Host "  - Shows excluded files"
    Write-Host "  - Shows unmatched files (verbose only)"
    Write-Host "  - More detailed information"
}
Write-Host ""
Write-Host "---" -ForegroundColor Gray
Write-Host ""

# Example 3: Custom limit
Write-Host "Example 3: Custom Display Limit" -ForegroundColor Green
Write-Host "Command: .\coding-agent-cli.exe policy test-patterns examples\policy-with-patterns.yaml .\ --limit 5"
Write-Host ""
if (Test-Path ".\coding-agent-cli.exe") {
    .\coding-agent-cli.exe policy test-patterns examples\policy-with-patterns.yaml .\ --limit 5
} else {
    Write-Host "Expected output:"
    Write-Host "  - Shows only 5 files per category"
    Write-Host "  - Displays '... and X more' for additional files"
}
Write-Host ""
Write-Host "---" -ForegroundColor Gray
Write-Host ""

# Show help
Write-Host "Example 4: Command Help" -ForegroundColor Green
Write-Host "Command: .\coding-agent-cli.exe policy test-patterns --help"
Write-Host ""
if (Test-Path ".\coding-agent-cli.exe") {
    .\coding-agent-cli.exe policy test-patterns --help
} else {
    Write-Host "Expected output:"
    Write-Host "  Usage: coding-agent-cli policy test-patterns [policy-file] [path]"
    Write-Host "  "
    Write-Host "  Test pattern matching rules from a policy file against files in a directory."
    Write-Host "  Shows which files match the include patterns and which are excluded."
    Write-Host "  "
    Write-Host "  Flags:"
    Write-Host "    -h, --help            help for test-patterns"
    Write-Host "    -l, --limit int       Maximum number of files to display (default 100)"
    Write-Host "    -v, --verbose         Show detailed matching information"
}
Write-Host ""

Write-Host "=== Demo Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Key Features:" -ForegroundColor Yellow
Write-Host "  ✓ Tests pattern matching without running a full scan"
Write-Host "  ✓ Shows which files match include patterns"
Write-Host "  ✓ Shows which files are excluded"
Write-Host "  ✓ Supports verbose mode for detailed output"
Write-Host "  ✓ Configurable display limits"
Write-Host "  ✓ Works with any policy file and directory"
Write-Host ""
Write-Host "Use Cases:" -ForegroundColor Yellow
Write-Host "  - Validate pattern syntax before running scans"
Write-Host "  - Debug why certain files are included/excluded"
Write-Host "  - Preview policy effects on your codebase"
Write-Host "  - Test new pattern rules"
