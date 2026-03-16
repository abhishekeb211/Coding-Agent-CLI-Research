# Scanner Plugins

## Overview

Coding Agent CLI supports multiple security scanners through a plugin architecture. Each scanner specializes in different languages and vulnerability types.

## Supported Scanners

### Bandit (Python)

**Language**: Python  
**Focus**: Python-specific security issues

**Installation**:
```bash
pip install bandit
```

**Verify**:
```bash
bandit --version
```

**Detects**:
- SQL injection
- Command injection
- Hardcoded passwords
- Insecure cryptography
- Path traversal
- XML vulnerabilities

### Semgrep (Multi-language)

**Languages**: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++  
**Focus**: Pattern-based security and code quality

**Installation**:
```bash
pip install semgrep
```

**Verify**:
```bash
semgrep --version
```

**Detects**:
- OWASP Top 10 vulnerabilities
- Security anti-patterns
- Code quality issues
- Custom rule violations

### gosec (Go)

**Language**: Go  
**Focus**: Go-specific security issues

**Installation**:
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

**Verify**:
```bash
gosec --version
```

**Detects**:
- SQL injection
- Command injection
- Weak cryptography
- Insecure random number generation
- File inclusion vulnerabilities
- Unsafe reflection

### eslint-plugin-security (JavaScript/TypeScript)

**Languages**: JavaScript, TypeScript  
**Focus**: JavaScript security patterns

**Installation**:
```bash
npm install -g eslint eslint-plugin-security
```

**Verify**:
```bash
eslint --version
```

**Detects**:
- XSS vulnerabilities
- Prototype pollution
- Regular expression DoS
- Unsafe eval usage
- Command injection
- Path traversal

## Scanner Configuration

### Selecting Scanners

**Command line**:
```bash
coding-agent-cli scan ./code --scanners bandit,semgrep,gosec
```

**Configuration file**:
```yaml
# config.yaml
scanners:
  enabled:
    - bandit
    - semgrep
    - gosec
    - eslint
```

### Scanner-Specific Options

#### Bandit Configuration

```yaml
scanners:
  bandit:
    config_file: .bandit
    exclude_dirs:
      - tests
      - vendor
    severity_level: medium
    confidence_level: medium
```

#### Semgrep Configuration

```yaml
scanners:
  semgrep:
    config: auto  # or path to rules
    rules:
      - p/security-audit
      - p/owasp-top-ten
    exclude:
      - "*.test.js"
      - "node_modules/"
    timeout: 300
```

#### gosec Configuration

```yaml
scanners:
  gosec:
    exclude_dirs:
      - vendor
      - testdata
    tests: false  # exclude test files
    severity: medium
```

#### ESLint Configuration

```yaml
scanners:
  eslint:
    config_file: .eslintrc.json
    plugins:
      - security
    ignore_path: .eslintignore
```

## Parallel Execution

Scanners run in parallel by default for better performance:

```bash
# All scanners run simultaneously
coding-agent-cli scan ./code --scanners bandit,semgrep,gosec,eslint
```

Disable parallel execution:
```yaml
scanners:
  parallel: false
```

## Scanner Output

Each scanner's findings are:
1. Normalized to a common format
2. Mapped to CWE categories
3. Deduplicated using SHA256 fingerprints
4. Stored in the database

View findings by scanner:
```bash
coding-agent-cli findings list --scanner bandit
```

## CWE Mapping

All scanner findings are mapped to Common Weakness Enumeration (CWE) categories:

| Scanner | CWE Coverage |
|---------|--------------|
| Bandit | 30+ CWEs |
| Semgrep | 50+ CWEs |
| gosec | 25+ CWEs |
| ESLint | 20+ CWEs |

View findings by CWE:
```bash
coding-agent-cli findings list --cwe CWE-89
```

## Troubleshooting

### Scanner Not Found

If a scanner is not installed:

```
Error: Scanner 'gosec' not found
Please install: go install github.com/securego/gosec/v2/cmd/gosec@latest
```

**Solution**: Install the missing scanner using the provided command.

### Scanner Timeout

For large codebases, scanners may timeout:

```yaml
scanners:
  timeout: 600  # 10 minutes
```

### Scanner Errors

View detailed scanner errors:
```bash
coding-agent-cli scan ./code --verbose
```

### Incompatible Scanner Version

Update scanners to the latest version:

```bash
# Bandit
pip install --upgrade bandit

# Semgrep
pip install --upgrade semgrep

# gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# ESLint
npm update -g eslint eslint-plugin-security
```

## Custom Scanner Plugins

### Creating a Plugin

Implement the `Scanner` interface:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, path string) ([]Finding, error)
    Version() string
}
```

Example plugin:

```go
package myscanner

type Plugin struct {
    execPath string
}

func (p *Plugin) Name() string {
    return "myscanner"
}

func (p *Plugin) Scan(ctx context.Context, path string) ([]Finding, error) {
    // Execute scanner
    // Parse output
    // Return findings
}

func (p *Plugin) Version() string {
    return "1.0.0"
}
```

### Registering a Plugin

```go
import "github.com/coding-agent/cli/internal/scanner"

func init() {
    scanner.Register("myscanner", &myscanner.Plugin{})
}
```

See [Plugin Development Guide](../developer-guide/plugin-development.md) for details.

## Scanner Comparison

| Feature | Bandit | Semgrep | gosec | ESLint |
|---------|--------|---------|-------|--------|
| Languages | Python | Multi | Go | JS/TS |
| Speed | Fast | Medium | Fast | Fast |
| Accuracy | High | Very High | High | Medium |
| Custom Rules | Limited | Yes | Limited | Yes |
| Active Development | Yes | Yes | Yes | Yes |

## Best Practices

1. **Use multiple scanners**: Different scanners find different issues
2. **Keep scanners updated**: New vulnerability patterns are added regularly
3. **Configure exclusions**: Exclude test files and vendor directories
4. **Review false positives**: Use policies to suppress known false positives
5. **Customize rules**: Add project-specific security rules

## Performance Tips

- **Exclude unnecessary directories**: vendor, node_modules, test files
- **Use incremental scanning**: Only scan changed files
- **Adjust timeout values**: For large codebases
- **Run scanners in parallel**: Default behavior for best performance

## Next Steps

- Configure [Policies](06-policies.md) for scanner findings
- Set up [LLM Integration](08-llm-integration.md) for remediation
- Learn about [Performance Optimization](15-performance.md)
