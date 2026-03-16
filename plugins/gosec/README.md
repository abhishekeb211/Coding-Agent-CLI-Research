# gosec Scanner Plugin

This plugin integrates [gosec](https://github.com/securego/gosec) - a Go security scanner that inspects source code for security problems by scanning the Go AST.

## Features

- Scans Go source code for security vulnerabilities
- Maps findings to CWE categories
- Supports all gosec rule IDs (G101-G601)
- Handles scanner not installed scenario gracefully
- Parses gosec JSON output format

## Installation

To use this plugin, you need to have gosec installed:

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Verify installation
gosec --version
```

## Usage

The gosec plugin is automatically registered when the CLI starts. If gosec is not installed, the plugin will be skipped.

```bash
# Scan with gosec (and other available scanners)
coding-agent-cli scan ./my-go-project

# Scan with only gosec
coding-agent-cli scan ./my-go-project --scanners gosec

# Scan with gosec and other scanners
coding-agent-cli scan ./my-go-project --scanners gosec,semgrep
```

## Supported Vulnerability Types

The gosec plugin detects various security issues in Go code:

### Credentials & Secrets (G101-G102)
- G101: Hardcoded credentials
- G102: Network binding to all interfaces

### Unsafe Operations (G103-G110)
- G103: Use of unsafe block
- G104: Unhandled errors
- G105: Integer overflow
- G106: SSH host key verification
- G107: SSRF via HTTP requests
- G108: Profiling endpoint exposed
- G109: Integer conversion issues
- G110: Decompression bomb

### Injection Vulnerabilities (G201-G204)
- G201: SQL query construction
- G202: SQL string concatenation
- G203: HTML template issues
- G204: Command injection

### File Operations (G301-G307)
- G301: Insecure file permissions (mkdir)
- G302: Insecure file permissions (chmod)
- G303: Insecure temp file creation
- G304: Path traversal
- G305: Path traversal in zip extraction
- G306: Insecure file permissions (write)
- G307: Deferred file close without error check

### Cryptography (G401-G404)
- G401: Weak crypto (MD5)
- G402: Insecure TLS configuration
- G403: Weak crypto (DES)
- G404: Weak random number generator

### Import Blocklist (G501-G505)
- G501: Import of MD5
- G502: Import of DES
- G503: Import of RC4
- G504: Import of SHA1
- G505: Import of MD4

### Memory Safety (G601)
- G601: Implicit memory aliasing in for loop

## CWE Mappings

All gosec findings are automatically mapped to CWE (Common Weakness Enumeration) categories:

| gosec Rule | CWE | Description |
|------------|-----|-------------|
| G101 | CWE-798 | Hardcoded credentials |
| G107 | CWE-918 | Server-Side Request Forgery |
| G201, G202 | CWE-89 | SQL Injection |
| G204 | CWE-78 | Command Injection |
| G304, G305 | CWE-22 | Path Traversal |
| G401, G403 | CWE-327 | Weak Cryptography |
| G404 | CWE-330 | Weak Random Number Generator |
| ... | ... | ... |

See `internal/cwe/mapper.go` for complete mappings.

## Output Format

The plugin converts gosec findings to the standard RawFinding format:

```json
{
  "id": "uuid",
  "tool_name": "gosec",
  "message": "Potential hardcoded credentials",
  "file_path": "main.go",
  "line_number": 10,
  "severity": "high",
  "confidence": "high",
  "rule_id": "G101",
  "category": "credentials",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Error Handling

The plugin handles several error scenarios:

1. **Scanner not installed**: Plugin is skipped, no error
2. **Invalid path**: Returns error with clear message
3. **Parse error**: Returns error if gosec output is malformed
4. **No findings**: Returns empty array (not an error)

## Testing

Run the plugin tests:

```bash
go test ./plugins/gosec/... -v
```

## Example

Scan a vulnerable Go project:

```bash
# Create a test file with vulnerabilities
cat > main.go << 'EOF'
package main

import (
    "crypto/md5"
    "fmt"
)

const apiKey = "secret123"  // G101: Hardcoded credential

func main() {
    // G401: Weak crypto
    hash := md5.New()
    hash.Write([]byte("data"))
    fmt.Printf("%x\n", hash.Sum(nil))
}
EOF

# Scan with gosec
coding-agent-cli scan . --scanners gosec

# Output will show:
# - G101: Hardcoded credentials (CWE-798)
# - G401: Weak cryptographic hash (CWE-327)
```

## Requirements

- Go 1.21 or higher
- gosec v2.x installed and in PATH

## References

- [gosec GitHub Repository](https://github.com/securego/gosec)
- [gosec Documentation](https://securego.io/)
- [CWE Database](https://cwe.mitre.org/)
