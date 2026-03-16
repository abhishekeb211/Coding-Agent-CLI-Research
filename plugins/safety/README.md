# Safety Scanner Plugin

This plugin integrates the [Safety](https://pypi.org/project/safety/) security scanner for Python dependency vulnerability scanning.

## Overview

Safety checks Python dependencies for known security vulnerabilities by comparing installed packages against a database of known vulnerabilities. It's particularly useful for identifying vulnerable third-party packages in Python projects.

## Installation

Install Safety using pip:

```bash
pip install safety
```

Or using pipx for isolated installation:

```bash
pipx install safety
```

Verify installation:

```bash
safety --version
```

## Usage

The Safety scanner automatically runs when:
1. Safety is installed and available in PATH
2. A `requirements.txt` file exists in the target directory
3. The scanner is not explicitly excluded

### Example

```bash
# Scan a Python project
coding-agent-cli scan ./my-python-project

# Scan with only safety
coding-agent-cli scan ./my-python-project --scanners safety

# Scan with multiple scanners
coding-agent-cli scan ./my-python-project --scanners bandit,safety
```

## Output Format

Safety findings include:
- **Package name**: The vulnerable package
- **Installed version**: The version currently in use
- **Vulnerability ID**: CVE or Safety database ID
- **Advisory**: Description of the vulnerability
- **Affected versions**: Version ranges affected by the vulnerability
- **Severity**: Inferred from advisory text (high/medium/low)

## CWE Mapping

The plugin maps vulnerabilities to CWE categories based on:
1. Advisory text analysis (SQL injection, XSS, RCE, etc.)
2. Category-based mapping for common vulnerability types
3. Default to CWE-1035 (Using Vulnerable Components) for general dependency issues

## Limitations

- Requires `requirements.txt` file in the project root
- Severity is inferred from advisory text (Safety doesn't always provide CVSS scores)
- Only scans Python dependencies, not code itself
- Requires internet connection to check vulnerability database (unless using cached database)

## Configuration

No additional configuration required. The scanner uses default Safety settings.

## Example Finding

```json
{
  "id": "abc-123",
  "tool_name": "safety",
  "message": "Package django version 2.2.0 has known vulnerabilities. Django before 2.2.2 allows SQL Injection. CVE: CVE-2019-12308. Affected versions: <2.2.2",
  "file_path": "requirements.txt",
  "line_number": 0,
  "severity": "medium",
  "confidence": "high",
  "rule_id": "CVE-2019-12308",
  "category": "sql-injection"
}
```

## Troubleshooting

### Scanner not found
If Safety is not detected:
1. Verify installation: `safety --version`
2. Check PATH: `which safety` (Unix) or `where safety` (Windows)
3. Reinstall if necessary: `pip install --upgrade safety`

### No findings reported
If no vulnerabilities are found:
1. Ensure `requirements.txt` exists in the target directory
2. Check that the file contains package specifications
3. Verify Safety database is up to date: `safety check --update`

### False positives
Safety reports confirmed CVEs, so false positives are rare. However:
1. Check if the vulnerability applies to your usage
2. Review the advisory details
3. Consider using waivers in policy configuration if needed

## References

- [Safety Documentation](https://docs.pyup.io/docs/safety-20-documentation)
- [Safety GitHub](https://github.com/pyupio/safety)
- [PyUp.io Vulnerability Database](https://pyup.io/safety/)
