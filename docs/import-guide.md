# Import Guide

This guide explains how to import security findings and policies into the Coding Agent CLI.

## Overview

The import functionality allows you to:
- Import findings from SARIF (Static Analysis Results Interchange Format) files
- Import findings from JSON files (Coding Agent format or findings arrays)
- Import policies from YAML files
- Import policies from pre-defined templates
- Validate import files without actually importing
- Handle conflicts with existing data using different modes
- Associate imported findings with specific scan runs

## Import Types

### Findings Import
Import security findings from external scanners and tools. See the [Findings Import](#findings-import) section below.

### Policy Import
Import security policies from YAML files or templates. See the [Policy Import](#policy-import) section or the detailed [Policy Import Guide](policy-import-guide.md).

---

# Findings Import

## Supported Formats

### SARIF Format

SARIF is a standard format for static analysis results. The importer supports SARIF 2.1.0 format.

Example SARIF file:
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Example Scanner",
          "version": "1.0.0"
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "level": "error",
          "message": {
            "text": "SQL injection vulnerability detected"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/database.py"
                },
                "region": {
                  "startLine": 42
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### JSON Format

The importer supports two JSON formats:

#### 1. Scan Result Format
Complete scan result with metadata:
```json
{
  "run_id": "scan-123",
  "target_path": "/path/to/code",
  "findings": [
    {
      "id": "finding-1",
      "cwe_id": "CWE-89",
      "cwe_description": "SQL Injection",
      "severity": "high",
      "confidence": "high",
      "code_fingerprint": "abc123",
      "file_path": "src/database.py",
      "line_number": 42,
      "description": "SQL injection vulnerability"
    }
  ]
}
```

#### 2. Findings Array Format
Simple array of findings:
```json
[
  {
    "id": "finding-1",
    "cwe_id": "CWE-89",
    "cwe_description": "SQL Injection",
    "severity": "high",
    "confidence": "high",
    "code_fingerprint": "abc123",
    "file_path": "src/database.py",
    "line_number": 42,
    "description": "SQL injection vulnerability"
  }
]
```

## Import Modes

The importer supports three conflict resolution modes:

### Replace Mode (default)
Replaces existing findings with the same fingerprint.
```bash
coding-agent-cli import results.sarif --mode replace
```

### Merge Mode
Imports findings even if they already exist, creating duplicate entries with different run IDs.
```bash
coding-agent-cli import results.sarif --mode merge
```

### Skip Mode
Skips importing findings that already exist.
```bash
coding-agent-cli import results.sarif --mode skip
```

## CLI Usage

### Basic Import

Import from SARIF file:
```bash
coding-agent-cli import results.sarif
```

Import from JSON file:
```bash
coding-agent-cli import findings.json
```

### Specify Format

Auto-detection usually works, but you can specify the format explicitly:
```bash
coding-agent-cli import results.json --format sarif
coding-agent-cli import findings.json --format json
```

### Validate Without Importing

Check if a file is valid without actually importing:
```bash
coding-agent-cli import results.sarif --validate-only
```

### Custom Run ID

Associate findings with a specific scan run:
```bash
coding-agent-cli import results.sarif --run-id my-scan-123
```

### Specify Target Path

Set the target path that was scanned:
```bash
coding-agent-cli import results.sarif --target-path /path/to/code
```

### Specify Tool Name

Set the name of the tool that generated the findings:
```bash
coding-agent-cli import results.sarif --tool-name "My Scanner"
```

### Complete Example

```bash
coding-agent-cli import results.sarif \
  --format sarif \
  --mode merge \
  --run-id external-scan-2024-01 \
  --target-path /home/user/project \
  --tool-name "External Scanner"
```

## API Usage

### Import Endpoint

**POST** `/api/v1/findings/import`

Request body:
```json
{
  "format": "sarif",
  "mode": "replace",
  "run_id": "scan-123",
  "target_path": "/path/to/code",
  "tool_name": "External Scanner",
  "data": "<base64 encoded file content or raw JSON>"
}
```

Response:
```json
{
  "run_id": "scan-123",
  "total_findings": 10,
  "imported_findings": 8,
  "skipped_findings": 2,
  "failed_findings": 0,
  "errors": []
}
```

## Validation Rules

The importer validates imported data to ensure quality:

### Required Fields

Each finding must have:
- `cwe_id`: CWE identifier (e.g., "CWE-89")
- `file_path`: Path to the file containing the vulnerability
- `severity`: Severity level (critical, high, medium, low)
- `description`: Description of the finding

### SARIF Validation

SARIF files must:
- Include a version field
- Contain at least one run
- Have valid tool information
- Include locations for each result

### JSON Validation

JSON files must:
- Be valid JSON format
- Match either ScanResult or findings array schema
- Include required fields for each finding

## Conflict Resolution

When importing findings that already exist (based on code fingerprint):

### Replace Mode
1. Checks if finding exists
2. Deletes existing finding
3. Imports new finding

### Merge Mode
1. Checks if finding exists
2. Imports new finding with different ID
3. Both findings coexist with different run IDs

### Skip Mode
1. Checks if finding exists
2. Skips import if exists
3. Only imports new findings

## Fingerprinting

Findings are identified by their code fingerprint, which is generated from:
- File path
- Line number
- CWE ID

If a fingerprint is not provided in the import file, one is automatically generated.

## Best Practices

1. **Validate First**: Use `--validate-only` to check files before importing
2. **Use Merge Mode for Historical Data**: When importing multiple scans over time
3. **Use Replace Mode for Updates**: When re-importing the same scan with corrections
4. **Specify Run IDs**: For better tracking and organization
5. **Include Tool Names**: To identify the source of findings

## Troubleshooting

### Import Fails with "Invalid SARIF"
- Check that the SARIF version is 2.1.0
- Ensure all required fields are present
- Validate against the SARIF schema

### Import Fails with "Invalid JSON"
- Verify JSON syntax is correct
- Check that required fields are present
- Ensure the format matches expected schema

### Findings Not Appearing
- Check the run ID used for import
- Verify findings were not skipped due to mode
- Check error messages in import result

### Duplicate Findings
- Use skip mode to avoid duplicates
- Check fingerprint generation
- Consider using replace mode instead of merge

## Examples

### Import from GitHub Security Scanning

GitHub exports SARIF files from security scanning:
```bash
# Download SARIF from GitHub
gh api repos/owner/repo/code-scanning/analyses/123 \
  --jq '.sarif' > github-scan.sarif

# Import into Coding Agent CLI
coding-agent-cli import github-scan.sarif \
  --tool-name "GitHub Security Scanning" \
  --run-id github-scan-$(date +%Y%m%d)
```

### Import from GitLab SAST

GitLab exports findings in JSON format:
```bash
# Convert GitLab format to Coding Agent format (custom script)
./convert-gitlab-sast.sh gl-sast-report.json > findings.json

# Import
coding-agent-cli import findings.json \
  --tool-name "GitLab SAST" \
  --mode merge
```

### Batch Import Multiple Files

```bash
# Import all SARIF files in a directory
for file in scans/*.sarif; do
  coding-agent-cli import "$file" \
    --mode merge \
    --tool-name "$(basename $file .sarif)"
done
```

## See Also

- [Export Guide](export-guide.md) - Exporting findings
- [API Documentation](api-documentation.md) - REST API reference
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) - Official SARIF docs


---

# Policy Import

## Overview

Import security policies from YAML files or pre-defined templates to configure your security scanning rules.

## Quick Start

### Import from YAML File
```bash
coding-agent-cli import policies.yaml --type policies
```

### Import from Template
```bash
# List available templates
coding-agent-cli import --type policies --list-templates

# Import a template
coding-agent-cli import owasp-top10 --type policies --format template
```

### Validate Before Importing
```bash
coding-agent-cli import policies.yaml --type policies --validate-only
```

## Policy File Format

Policies are defined in YAML format:

```yaml
policies:
  - id: sql-injection-critical
    name: "SQL Injection Prevention"
    description: "Prevent SQL injection vulnerabilities"
    cwe: ["89"]
    severity: critical
    action: deny
    enabled: true

  - id: xss-prevention
    name: "XSS Prevention"
    description: "Prevent cross-site scripting"
    cwe: ["79"]
    severity: high
    action: deny
    enabled: true
```

### Required Fields
- `id`: Unique identifier
- `name`: Human-readable name
- `description`: What the policy does
- `cwe`: Array of CWE IDs
- `severity`: critical, high, medium, or low
- `action`: deny, warn, or allow
- `enabled`: true or false

## Import Options

### Overwrite Existing Policies
```bash
coding-agent-cli import policies.yaml --type policies --overwrite
```

### Custom Template Directory
```bash
coding-agent-cli import my-template --type policies --format template --template-dir /path/to/templates
```

## Available Templates

Common pre-defined templates include:
- `owasp-top10` - OWASP Top 10 security risks
- `sql-injection` - SQL injection prevention
- `xss-prevention` - Cross-site scripting prevention
- `hipaa-secrets` - HIPAA compliance for secrets

List all available templates:
```bash
coding-agent-cli import --type policies --list-templates
```

## Examples

### Example 1: Import Custom Policies
```bash
# Create policies.yaml
cat > policies.yaml << EOF
policies:
  - id: custom-rule
    name: "Custom Security Rule"
    description: "My custom rule"
    cwe: ["89"]
    severity: high
    action: deny
    enabled: true
EOF

# Import
coding-agent-cli import policies.yaml --type policies
```

### Example 2: Import and Overwrite
```bash
# Import new version of policies, replacing existing ones
coding-agent-cli import updated-policies.yaml --type policies --overwrite
```

### Example 3: Validate First
```bash
# Validate
coding-agent-cli import policies.yaml --type policies --validate-only

# If valid, import
coding-agent-cli import policies.yaml --type policies
```

## Detailed Documentation

For comprehensive policy import documentation, including:
- Detailed YAML format specifications
- Validation rules
- Error handling
- Best practices
- CI/CD integration examples

See the [Policy Import Guide](policy-import-guide.md).

## See Also

- [Policy Import Guide](policy-import-guide.md) - Detailed policy import documentation
- [Policy Configuration Guide](policy-guide.md) - Policy configuration and management
- [Export Guide](export-guide.md) - Exporting findings and policies
