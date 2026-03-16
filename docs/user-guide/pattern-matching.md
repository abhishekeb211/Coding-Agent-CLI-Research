# File Path Pattern Matching

Version 1.2 introduces powerful file path pattern matching capabilities for policies. This allows you to apply different security policies to different parts of your codebase.

## Overview

Pattern matching enables you to:
- Apply stricter policies to production code
- Relax policies for test files
- Exclude vendor/third-party code
- Target specific directories or file types
- Combine multiple patterns with include/exclude rules

## Pattern Syntax

### Wildcards

- `*` - Matches any characters except path separator
- `**` - Matches any characters including path separators (recursive)

### Examples

| Pattern | Matches | Description |
|---------|---------|-------------|
| `*.go` | `main.go`, `util.go` | All .go files in root |
| `**/*.go` | `src/main.go`, `pkg/util/helper.go` | All .go files anywhere |
| `src/**/*.go` | `src/main.go`, `src/pkg/util.go` | All .go files under src/ |
| `**/*_test.go` | `main_test.go`, `pkg/util_test.go` | All test files anywhere |
| `**/test_*.py` | `test_main.py`, `tests/test_util.py` | All test files starting with test_ |
| `vendor/**` | `vendor/pkg/lib.go` | All files in vendor directory |
| `src/**/test_*` | `src/test_main.go`, `src/pkg/test_util.go` | Files starting with test_ under src/ |

## Policy Configuration

### Basic Structure

```yaml
policies:
  - id: "my-policy"
    name: "My Policy"
    description: "Policy description"
    cwe:
      - "CWE-89"
    severity: "high"
    action: "deny"
    enabled: true
    patterns:
      include:
        - "**/*.go"
      exclude:
        - "**/*_test.go"
```

### Pattern Fields

- `include` (optional): List of patterns that files must match
- `exclude` (optional): List of patterns that files must not match

### Matching Rules

1. **No patterns**: Policy applies to all files
2. **Include only**: File must match at least one include pattern
3. **Exclude only**: File must not match any exclude pattern
4. **Both**: File must match include AND not match exclude

## Common Use Cases

### 1. Strict Production, Relaxed Tests

```yaml
policies:
  # Strict for production code
  - id: "sql-injection-prod"
    name: "SQL Injection - Production"
    cwe: ["CWE-89"]
    severity: "high"
    action: "deny"
    enabled: true
    patterns:
      include:
        - "**/*.go"
      exclude:
        - "**/*_test.go"
        - "testdata/**"

  # Relaxed for test code
  - id: "sql-injection-test"
    name: "SQL Injection - Tests"
    cwe: ["CWE-89"]
    severity: "high"
    action: "warn"
    enabled: true
    patterns:
      include:
        - "**/*_test.go"
```

### 2. Exclude Vendor Code

```yaml
policies:
  - id: "vendor-exclusion"
    name: "Vendor Exclusion"
    cwe: ["*"]
    severity: ""
    action: "allow"
    enabled: true
    patterns:
      include:
        - "vendor/**"
        - "node_modules/**"
        - "third_party/**"
```

### 3. Target Specific Directories

```yaml
policies:
  - id: "critical-auth"
    name: "Critical Auth Findings"
    cwe: ["*"]
    severity: "critical"
    action: "deny"
    enabled: true
    patterns:
      include:
        - "**/auth/**"
        - "**/authentication/**"
        - "**/security/**"
```

### 4. Language-Specific Policies

```yaml
policies:
  # Go files
  - id: "go-security"
    name: "Go Security"
    cwe: ["CWE-89", "CWE-79"]
    severity: "high"
    action: "deny"
    enabled: true
    patterns:
      include:
        - "**/*.go"
      exclude:
        - "vendor/**"

  # JavaScript/TypeScript files
  - id: "js-security"
    name: "JavaScript Security"
    cwe: ["CWE-79", "CWE-94"]
    severity: "high"
    action: "deny"
    enabled: true
    patterns:
      include:
        - "**/*.js"
        - "**/*.ts"
        - "**/*.jsx"
        - "**/*.tsx"
      exclude:
        - "node_modules/**"
        - "dist/**"
```

## Pattern Validation

Patterns are validated when policies are loaded. Invalid patterns will cause policy loading to fail with a clear error message.

### Valid Patterns
- `*.go`
- `**/*.py`
- `src/**`
- `**/test_*.go`

### Invalid Patterns
- `` (empty)
- `***/*.go` (triple star)

## Implementation Details

### Fallback Strategy

The pattern matcher uses a multi-level fallback strategy:

1. **Primary**: doublestar library (when available)
2. **Fallback 1**: `filepath.Match` for simple patterns
3. **Fallback 2**: Simple prefix/suffix matching

This ensures pattern matching works even if the doublestar library is not available.

### Path Normalization

- All paths are normalized to use forward slashes (`/`)
- Windows paths (`\`) are automatically converted
- Patterns are case-sensitive

### Performance

- Patterns are compiled once when policies are loaded
- Pattern matching is optimized for common cases
- Exclude patterns short-circuit evaluation

## Examples

See `examples/policy-with-patterns.yaml` for a complete example policy file demonstrating various pattern matching scenarios.

## Migration from v1.0

Existing policies without patterns continue to work unchanged. The `patterns` field is optional and backward compatible.

To add pattern matching to existing policies:

```yaml
# Before (v1.0)
policies:
  - id: "sql-injection"
    name: "SQL Injection"
    cwe: ["CWE-89"]
    action: "deny"
    enabled: true

# After (v1.2)
policies:
  - id: "sql-injection"
    name: "SQL Injection"
    cwe: ["CWE-89"]
    action: "deny"
    enabled: true
    patterns:  # New field
      include:
        - "**/*.go"
      exclude:
        - "**/*_test.go"
```

## Troubleshooting

### Pattern Not Matching

1. Check path separators (use `/` not `\`)
2. Verify pattern syntax (no `***`)
3. Test with simpler patterns first
4. Check if exclude patterns are blocking

### Performance Issues

1. Use specific patterns instead of `**/*`
2. Add exclude patterns for large directories
3. Limit the number of patterns per policy

## Best Practices

1. **Be Specific**: Use specific patterns to reduce false positives
2. **Exclude Early**: Put exclude patterns for large directories (vendor, node_modules)
3. **Test Patterns**: Use the pattern testing utility to verify patterns
4. **Document Intent**: Add clear descriptions to policies with patterns
5. **Layer Policies**: Use multiple policies with different patterns for fine-grained control

## Related Documentation

- [Policy Configuration](./policies.md)
- [Policy Examples](../../examples/policy-with-patterns.yaml)
- [Requirements 7.1-7.10](../../.kiro/specs/v1.2-release/requirements.md)
