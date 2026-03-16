# Pattern Testing Utility - Manual Test Guide

## Overview
The `policy test-patterns` command has been implemented to test pattern matching rules from a policy file against files in a directory.

## Command Usage

```bash
coding-agent-cli policy test-patterns [policy-file] [path]
```

### Flags
- `--verbose, -v`: Show detailed matching information including unmatched files
- `--limit, -l`: Maximum number of files to display (default: 100)

## Example Usage

### Basic Usage
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./internal
```

### With Verbose Output
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./internal --verbose
```

### With Custom Limit
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./internal --limit 50
```

## Output Format

The command displays:

1. **Header**: Shows the policy file and target path being tested
2. **Policy Details**: For each enabled policy with patterns:
   - Policy name and ID
   - Action (deny/warn/allow)
   - Include patterns (prefixed with `+`)
   - Exclude patterns (prefixed with `-`)
3. **Matching Results**:
   - ✓ Matching files (files that match include patterns and not excluded)
   - ✗ Excluded files (files explicitly excluded by exclude patterns)
   - ○ Unmatched files (shown only with --verbose flag)
4. **Summary**: Total counts of policies and files tested

## Example Output

```
=== Pattern Matching Test ===
Policy file: examples/policy-with-patterns.yaml
Target path: ./internal
Total files found: 45

--- Policy 1: SQL Injection - Production Code ---
ID: strict-sql-injection-prod
Action: deny
Include patterns:
  + **/*.go
  + **/*.py
Exclude patterns:
  - **/*_test.go
  - **/test_*.py
  - vendor/**
  - testdata/**

Matching files: 32
  ✓ internal/policy/patterns.go
  ✓ internal/policy/matcher.go
  ✓ internal/policy/types.go
  ... and 29 more (use --limit to show more)

Excluded files: 10
  ✗ internal/policy/patterns_test.go
  ✗ internal/policy/matcher_test.go
  ... and 8 more (use --limit to show more)

--- Policy 2: XSS in Web Files ---
ID: xss-web-files
Action: deny
Include patterns:
  + web/**/*.go
  + api/**/*.go
  + internal/api/**/*.go

Matching files: 5
  ✓ internal/api/handlers.go
  ✓ internal/api/server.go
  ✓ internal/api/middleware.go
  ✓ internal/api/routes.go
  ✓ internal/api/models.go

=== Summary ===
Enabled policies: 6
Policies with patterns: 6
Total files tested: 45

Tip: Use --verbose flag to see unmatched files and more details
```

## Test Scenarios

### Test 1: Basic Pattern Matching
Test that the command correctly identifies files matching glob patterns.

**Command:**
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./internal
```

**Expected:** Should show matching Go files and exclude test files.

### Test 2: Exclusion Patterns
Test that exclude patterns properly filter out files.

**Command:**
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./plugins
```

**Expected:** Should exclude vendor directories and test files.

### Test 3: Multiple Policies
Test that multiple policies are evaluated independently.

**Command:**
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./
```

**Expected:** Should show results for all enabled policies with patterns.

### Test 4: Verbose Mode
Test that verbose mode shows additional details.

**Command:**
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./cmd --verbose
```

**Expected:** Should show unmatched files in addition to matched and excluded files.

### Test 5: Custom Limit
Test that the limit flag controls output size.

**Command:**
```bash
coding-agent-cli policy test-patterns examples/policy-with-patterns.yaml ./ --limit 5
```

**Expected:** Should show only 5 files per category with "... and X more" message.

## Implementation Details

### Files Modified
- `cmd/policy.go`: Added `policyTestPatternsCmd` and `runPolicyTestPatterns` function
- `cmd/policy_test.go`: Added comprehensive tests for the new command

### Key Features
1. **Pattern Compilation**: Uses the existing `PatternMatcher` from `internal/policy/patterns.go`
2. **File Walking**: Recursively walks the target directory to find all files
3. **Pattern Evaluation**: Tests each file against include and exclude patterns
4. **Categorization**: Separates files into matched, excluded, and unmatched categories
5. **Output Formatting**: Provides clear, readable output with symbols (✓, ✗, ○)
6. **Flags**: Supports verbose mode and custom display limits

### Error Handling
- Validates that policy file exists
- Validates that target path exists
- Validates YAML syntax
- Validates policy structure
- Handles pattern compilation errors gracefully

## Integration with Existing Code

The command integrates seamlessly with:
- `internal/policy/patterns.go`: Uses `PatternMatcher` for pattern matching
- `internal/policy/matcher.go`: Uses `MatchesFilePath` for policy evaluation
- `internal/policy/types.go`: Uses `Policy` and `PolicySet` types

## Testing

The implementation includes comprehensive unit tests:
- `TestPolicyTestPatternsCommand`: Verifies command exists
- `TestPolicyTestPatternsRequiresArgs`: Verifies argument validation
- `TestPolicyTestPatternsNonExistentFile`: Tests error handling
- `TestPolicyTestPatternsValidInput`: Tests successful execution
- `TestPolicyTestPatternsInvalidYAML`: Tests YAML parsing errors
- `TestPolicyTestPatternsWithVerboseFlag`: Tests flag existence
- `TestPolicyTestPatternsMultiplePolicies`: Tests multiple policy handling

## Fallback Option

If the CLI command proves difficult to use or test, users can manually test patterns by:
1. Creating a test policy file
2. Running a scan with the policy
3. Observing which files are included/excluded in the results

However, the CLI command provides a much better user experience by showing pattern matching results without running a full scan.
