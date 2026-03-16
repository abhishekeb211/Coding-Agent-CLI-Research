# CWE Mapper

This package provides CWE (Common Weakness Enumeration) mapping functionality for security scanner findings.

## Mapping Strategy

The CWE mapper uses a multi-layered approach to map scanner findings to CWE IDs:

1. **Scanner Metadata Extraction**: First, try to extract CWE from scanner metadata
   - gosec provides CWE information directly in its output
   - Format: `{"cwe": {"id": "22", "url": "..."}}`

2. **Exact Rule Match**: Look up the rule ID in the `RuleToCWEMap`
   - Covers all known rules from Bandit, gosec, eslint-plugin-security, and Semgrep

3. **Pattern Matching**: Use case-insensitive pattern matching on rule IDs
   - Matches keywords like "sql", "xss", "command", "path", etc.
   - Handles custom or unknown rule IDs

4. **Category-Based Mapping**: Use the finding category as a fallback
   - Maps categories like "injection", "crypto", "auth" to appropriate CWEs

5. **Unknown Fallback**: Return `CWE-000` if no mapping is found

## Supported Scanners

### Bandit (Python)
- **Rules**: B101-B703
- **Coverage**: 60+ rules mapped
- **Examples**:
  - B608 → CWE-89 (SQL Injection)
  - B602 → CWE-78 (Command Injection)
  - B105 → CWE-798 (Hardcoded Credentials)

### gosec (Go)
- **Rules**: G101-G601
- **Coverage**: 30+ rules mapped
- **CWE Extraction**: gosec provides CWE directly in output (preferred)
- **Examples**:
  - G101 → CWE-798 (Hardcoded Credentials)
  - G204 → CWE-78 (Command Injection)
  - G304 → CWE-22 (Path Traversal)

### eslint-plugin-security (JavaScript/TypeScript)
- **Rules**: 12 security rules
- **Coverage**: 100% of security plugin rules
- **Examples**:
  - security/detect-unsafe-regex → CWE-1333 (ReDoS)
  - security/detect-child-process → CWE-78 (Command Injection)
  - security/detect-eval-with-expression → CWE-94 (Code Injection)

### Semgrep
- **Rules**: Common security patterns
- **Coverage**: 20+ common patterns
- **Examples**:
  - python.lang.security.audit.sqli → CWE-89
  - javascript.lang.security.audit.xss → CWE-79
  - python.lang.security.audit.path-traversal → CWE-22

### Safety (Python Dependencies)
- **Rules**: CVE-based findings
- **Mapping**: All CVEs map to CWE-1035 (Using Vulnerable Components)

## Usage

### In Scanner Orchestrator

```go
// The orchestrator automatically uses the CWE mapper
func (o *Orchestrator) normalizeFindings(rawFindings []RawFinding, runID string) []NormalizedFinding {
    for _, raw := range rawFindings {
        // Try to extract CWE from scanner metadata first
        cweID := cwe.ExtractCWEFromMetadata(raw.RawJSON)
        if cweID == "" {
            // Fall back to rule-based mapping
            cweID = cwe.MapRuleToCWE(raw.RuleID, raw.Category)
        }
        // ...
    }
}
```

### Direct Usage

```go
import "github.com/coding-agent/cli/internal/cwe"

// Map a rule ID to CWE
cweID := cwe.MapRuleToCWE("G101", "credentials")
// Returns: "CWE-798"

// Extract CWE from scanner metadata
metadata := map[string]interface{}{
    "cwe": map[string]interface{}{
        "id": "22",
        "url": "https://cwe.mitre.org/data/definitions/22.html",
    },
}
cweID := cwe.ExtractCWEFromMetadata(metadata)
// Returns: "CWE-22"
```

## Pattern Matching Examples

The mapper uses intelligent pattern matching for unknown rules:

| Pattern | CWE | Description |
|---------|-----|-------------|
| `*sql*`, `*sqli*` | CWE-89 | SQL Injection |
| `*xss*`, `*cross-site*` | CWE-79 | Cross-Site Scripting |
| `*command*`, `*exec*`, `*shell*` | CWE-78 | Command Injection |
| `*path*`, `*traversal*` | CWE-22 | Path Traversal |
| `*password*`, `*secret*`, `*credential*` | CWE-798 | Hardcoded Credentials |
| `*crypto*`, `*md5*`, `*sha1*` | CWE-327 | Weak Cryptography |
| `*pickle*`, `*deserial*` | CWE-502 | Deserialization |
| `*random*`, `*prng*` | CWE-330 | Weak Random |
| `*xxe*`, `*xml*` | CWE-611 | XML External Entity |
| `*redirect*` | CWE-601 | Open Redirect |
| `*ssrf*` | CWE-918 | Server-Side Request Forgery |

## Testing

The package includes comprehensive tests:

- `TestMapRuleToCWE`: Tests exact rule mappings and pattern matching
- `TestGosecRuleMappings`: Tests all gosec rules
- `TestESLintRuleMappings`: Tests all eslint-plugin-security rules
- `TestExtractCWEFromMetadata`: Tests CWE extraction from metadata
- `TestGosecCWEExtraction`: Tests gosec-specific CWE extraction
- `TestRuleToCWEMapCompleteness`: Validates all mappings in the map

Run tests:
```bash
go test ./internal/cwe -v
```

## Adding New Mappings

To add mappings for a new scanner:

1. Add exact rule mappings to `RuleToCWEMap` in `mapper.go`
2. Add pattern matching logic if needed (for dynamic rules)
3. Add tests in `mapper_test.go`
4. Update this README with the new scanner information

Example:
```go
// In mapper.go
var RuleToCWEMap = map[string]string{
    // ... existing mappings ...
    
    // New scanner rules
    "NEW-001": "CWE-89",  // SQL Injection
    "NEW-002": "CWE-78",  // Command Injection
}
```

## References

- [CWE List](https://cwe.mitre.org/data/index.html)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [gosec Rules](https://github.com/securego/gosec#available-rules)
- [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security)
- [Bandit Rules](https://bandit.readthedocs.io/en/latest/plugins/index.html)
