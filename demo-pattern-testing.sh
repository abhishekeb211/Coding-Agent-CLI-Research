#!/bin/bash

# Demo script for the pattern testing utility
# This script demonstrates how to use the new 'policy test-patterns' command

echo "=== Pattern Testing Utility Demo ==="
echo ""
echo "This demo shows how to use the new 'policy test-patterns' command"
echo "to test pattern matching rules from a policy file."
echo ""

# Build the CLI (if Go is available)
if command -v go &> /dev/null; then
    echo "Building the CLI..."
    go build -o coding-agent-cli main.go
    echo "✓ Build complete"
    echo ""
else
    echo "⚠ Go is not installed. Showing command examples only."
    echo ""
fi

# Example 1: Basic usage
echo "Example 1: Basic Pattern Testing"
echo "Command: ./coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./internal"
echo ""
if [ -f "./coding-agent-cli" ]; then
    ./coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./internal
else
    echo "Expected output:"
    echo "  - Shows matching files for each policy"
    echo "  - Shows excluded files"
    echo "  - Provides summary statistics"
fi
echo ""
echo "---"
echo ""

# Example 2: Verbose mode
echo "Example 2: Verbose Mode"
echo "Command: ./coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./cmd --verbose"
echo ""
if [ -f "./coding-agent-cli" ]; then
    ./coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./cmd --verbose
else
    echo "Expected output:"
    echo "  - Shows matching files"
    echo "  - Shows excluded files"
    echo "  - Shows unmatched files (verbose only)"
    echo "  - More detailed information"
fi
echo ""
echo "---"
echo ""

# Example 3: Custom limit
echo "Example 3: Custom Display Limit"
echo "Command: ./coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./ --limit 5"
echo ""
if [ -f "./coding-agent-cli" ]; then
    ./coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./ --limit 5
else
    echo "Expected output:"
    echo "  - Shows only 5 files per category"
    echo "  - Displays '... and X more' for additional files"
fi
echo ""
echo "---"
echo ""

# Show help
echo "Example 4: Command Help"
echo "Command: ./coding-agent-cli policy test-patterns --help"
echo ""
if [ -f "./coding-agent-cli" ]; then
    ./coding-agent-cli policy test-patterns --help
else
    echo "Expected output:"
    echo "  Usage: coding-agent-cli policy test-patterns [policy-file] [path]"
    echo "  "
    echo "  Test pattern matching rules from a policy file against files in a directory."
    echo "  Shows which files match the include patterns and which are excluded."
    echo "  "
    echo "  Flags:"
    echo "    -h, --help            help for test-patterns"
    echo "    -l, --limit int       Maximum number of files to display (default 100)"
    echo "    -v, --verbose         Show detailed matching information"
fi
echo ""

echo "=== Demo Complete ==="
echo ""
echo "Key Features:"
echo "  ✓ Tests pattern matching without running a full scan"
echo "  ✓ Shows which files match include patterns"
echo "  ✓ Shows which files are excluded"
echo "  ✓ Supports verbose mode for detailed output"
echo "  ✓ Configurable display limits"
echo "  ✓ Works with any policy file and directory"
echo ""
echo "Use Cases:"
echo "  - Validate pattern syntax before running scans"
echo "  - Debug why certain files are included/excluded"
echo "  - Preview policy effects on your codebase"
echo "  - Test new pattern rules"
