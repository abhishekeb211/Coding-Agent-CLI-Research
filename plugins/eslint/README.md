# ESLint Security Plugin

This plugin integrates [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) into the Coding Agent CLI for scanning JavaScript and TypeScript code for security vulnerabilities.

## Overview

The ESLint security scanner detects common security issues in JavaScript/TypeScript code including:

- **Code Injection**: Detection of `eval()` and similar dangerous functions
- **Command Injection**: Detection of unsafe `child_process` usage
- **Path Traversal**: Detection of non-literal filesystem paths
- **XSS**: Detection of disabled template escaping
- **ReDoS**: Detection of unsafe regular expressions
- **Weak Randomness**: Detection of `crypto.pseudoRandomBytes()`
- **Prototype Pollution**: Detection of object injection vulnerabilities
- **Timing Attacks**: Detection of possible timing attack vectors
- **CSRF**: Detection of missing CSRF protection

## Installation

### Prerequisites

1. **Node.js and npm**: Required to install and run ESLint
   ```bash
   # Check if Node.js is installed
   node --version
   npm --version
   ```

2. **ESLint**: Install globally or in your project
   ```bash
   # Global installation (recommended for CLI usage)
   npm install -g eslint
   
   # Or project-local installation
   npm install --save-dev eslint
   ```

3. **eslint-plugin-security**: Install the security plugin
   ```bash
   # Global installation
   npm install -g eslint-plugin-security
   
   # Or project-local installation
   npm install --save-dev eslint-plugin-security
   ```

### Verification

Verify the installation:
```bash
eslint --version
```

## Usage

The ESLint scanner is automatically detected and used when scanning JavaScript/TypeScript projects:

```bash
# Scan a project (auto-detects available scanners)
coding-agent-cli scan ./my-js-project

# Explicitly use only eslint
coding-agent-cli scan ./my-js-project --scanners eslint

# Combine with other scanners
coding-agent-cli scan ./my-project --scanners eslint,semgrep
```

## Supported File Extensions

- `.js` - JavaScript
- `.jsx` - React JSX
- `.ts` - TypeScript
- `.tsx` - React TypeScript

## Security Rules

The plugin enables the following security rules from eslint-plugin-security:

| Rule ID | Description | CWE Mapping |
|---------|-------------|-------------|
| `security/detect-unsafe-regex` | Detects potentially unsafe regular expressions | CWE-1333 (ReDoS) |
| `security/detect-buffer-noassert` | Detects calls to buffer with noAssert flag | CWE-120 (Buffer Overflow) |
| `security/detect-child-process` | Detects instances of child_process | CWE-78 (Command Injection) |
| `security/detect-disable-mustache-escape` | Detects object.escapeMarkup = true | CWE-79 (XSS) |
| `security/detect-eval-with-expression` | Detects eval() with variable | CWE-94 (Code Injection) |
| `security/detect-no-csrf-before-method-override` | Detects Express csrf middleware setup issues | CWE-352 (CSRF) |
| `security/detect-non-literal-fs-filename` | Detects variable in filename argument of fs calls | CWE-22 (Path Traversal) |
| `security/detect-non-literal-regexp` | Detects RegExp(variable) | CWE-1333 (ReDoS) |
| `security/detect-non-literal-require` | Detects require(variable) | CWE-94 (Code Injection) |
| `security/detect-object-injection` | Detects variable[key] access | CWE-1321 (Prototype Pollution) |
| `security/detect-possible-timing-attacks` | Detects insecure comparisons | CWE-208 (Timing Attack) |
| `security/detect-pseudoRandomBytes` | Detects pseudoRandomBytes() | CWE-330 (Weak Random) |

## Output Format

The scanner produces findings in the standard RawFinding format:

```json
{
  "id": "uuid",
  "tool_name": "eslint",
  "message": "eval can be harmful",
  "file_path": "src/app.js",
  "line_number": 42,
  "severity": "high",
  "confidence": "medium",
  "rule_id": "security/detect-eval-with-expression",
  "category": "code-injection",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Severity Mapping

ESLint severity levels are mapped as follows:

- ESLint Error (2) → `high`
- ESLint Warning (1) → `medium`
- ESLint Info (0) → `low`

## Configuration

The scanner runs with a predefined security-focused configuration and does not use project-specific `.eslintrc` files. This ensures consistent security scanning across all projects.

## Troubleshooting

### Scanner Not Found

If you see "eslint not found in PATH":

1. Verify ESLint is installed:
   ```bash
   eslint --version
   ```

2. If using local installation, ensure it's in your project's `node_modules/.bin/`:
   ```bash
   ./node_modules/.bin/eslint --version
   ```

3. Add to PATH or install globally:
   ```bash
   npm install -g eslint eslint-plugin-security
   ```

### No Findings Detected

If the scanner runs but finds no issues:

1. Verify eslint-plugin-security is installed:
   ```bash
   npm list -g eslint-plugin-security
   ```

2. Check that your files have supported extensions (`.js`, `.jsx`, `.ts`, `.tsx`)

3. Run ESLint manually to verify it works:
   ```bash
   eslint --plugin security --rule "security/detect-eval-with-expression:error" yourfile.js
   ```

### Parse Errors

If you see JSON parsing errors:

1. Ensure you're using a recent version of ESLint (8.0+)
2. Check that your JavaScript/TypeScript files are syntactically valid
3. The scanner may skip files with syntax errors

## Limitations

- **Configuration**: The scanner uses a fixed security configuration and ignores project `.eslintrc` files
- **Plugins**: Only eslint-plugin-security rules are included; other ESLint plugins are not loaded
- **Performance**: Large projects may take time to scan; consider using incremental scanning
- **False Positives**: Some rules (like `detect-object-injection`) may produce false positives

## Integration with Other Scanners

ESLint complements other scanners:

- **Semgrep**: Provides broader language support and custom rules
- **Bandit**: For Python-specific security issues
- **Gosec**: For Go-specific security issues

Use multiple scanners for comprehensive coverage:

```bash
coding-agent-cli scan ./project --scanners eslint,semgrep,bandit
```

## References

- [eslint-plugin-security GitHub](https://github.com/eslint-community/eslint-plugin-security)
- [ESLint Documentation](https://eslint.org/docs/latest/)
- [CWE Database](https://cwe.mitre.org/)

## Contributing

To add new rules or improve the scanner:

1. Update the rule list in `eslint.go`
2. Add CWE mappings in `internal/cwe/mapper.go`
3. Update category mappings in `extractCategory()`
4. Add tests in `eslint_test.go`
5. Update this README
