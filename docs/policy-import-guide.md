# Policy Import Guide

This guide explains how to import security policies into the Coding Agent CLI.

## Overview

The policy import feature allows you to:
- Import policies from YAML files
- Import policies from pre-defined templates
- Validate policies before importing
- Manage existing policies (skip or overwrite)

## Import from YAML Files

### Basic Import

Import policies from a YAML file:

```bash
coding-agent-cli import policies.yaml --type policies
```

### YAML Format

Policy files should follow this format:

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
    name: "Cross-Site Scripting Prevention"
    description: "Prevent XSS vulnerabilities"
    cwe: ["79"]
    severity: high
    action: deny
    enabled: true
```

### Required Fields

Each policy must include:
- `id`: Unique identifier for the policy
- `name`: Human-readable name
- `description`: Description of what the policy does
- `cwe`: Array of CWE IDs this policy applies to
- `severity`: Severity level (critical, high, medium, low)
- `action`: Action to take (deny, warn, allow)
- `enabled`: Whether the policy is active (true/false)

## Import from Templates

### List Available Templates

See all available policy templates:

```bash
coding-agent-cli import --type policies --list-templates
```

### Import a Template

Import a pre-defined template:

```bash
coding-agent-cli import owasp-top10 --type policies --format template
```

### Custom Template Directory

Use a custom template directory:

```bash
coding-agent-cli import my-template --type policies --format template --template-dir /path/to/templates
```

## Validation

### Validate Before Importing

Check if a policy file is valid without importing:

```bash
coding-agent-cli import policies.yaml --type policies --validate-only
```

This will:
- Parse the YAML file
- Validate all policy fields
- Check for duplicate IDs
- Report any errors

### Validation Rules

Policies are validated for:
- Required fields present
- Valid severity levels
- Valid actions (deny, warn, allow)
- At least one CWE specified
- Unique policy IDs within the file

## Managing Existing Policies

### Skip Existing Policies (Default)

By default, existing policies are skipped:

```bash
coding-agent-cli import policies.yaml --type policies
```

Output:
```
✓ Policy import completed
  Total policies: 5
  Imported: 3
  Skipped: 2
  Failed: 0
```

### Overwrite Existing Policies

Replace existing policies with the same ID:

```bash
coding-agent-cli import policies.yaml --type policies --overwrite
```

This will:
- Delete the existing policy
- Import the new policy with the same ID

## Examples

### Example 1: Import OWASP Top 10 Policies

```bash
# List available templates
coding-agent-cli import --type policies --list-templates

# Import OWASP Top 10
coding-agent-cli import owasp-top10 --type policies --format template
```

### Example 2: Import Custom Policies

Create a file `my-policies.yaml`:

```yaml
policies:
  - id: custom-sql-injection
    name: "Custom SQL Injection Rule"
    description: "Block SQL injection in our codebase"
    cwe: ["89"]
    severity: critical
    action: deny
    enabled: true
```

Import it:

```bash
coding-agent-cli import my-policies.yaml --type policies
```

### Example 3: Validate and Import

First validate, then import:

```bash
# Validate
coding-agent-cli import policies.yaml --type policies --validate-only

# If validation passes, import
coding-agent-cli import policies.yaml --type policies
```

### Example 4: Update Existing Policies

Update existing policies with new versions:

```bash
coding-agent-cli import updated-policies.yaml --type policies --overwrite
```

## Error Handling

### Common Errors

**File not found:**
```
Error: file not found: policies.yaml
```
Solution: Check the file path is correct.

**Invalid YAML:**
```
Error: failed to parse YAML: yaml: line 5: did not find expected key
```
Solution: Check YAML syntax is correct.

**Missing required field:**
```
Error: invalid policy set: invalid policy test-policy: policy name is required
```
Solution: Ensure all required fields are present.

**Duplicate policy ID:**
```
Error: invalid policy set: duplicate policy ID: sql-injection
```
Solution: Ensure all policy IDs are unique within the file.

**Invalid action:**
```
Error: invalid policy test-policy: policy action must be deny, warn, or allow
```
Solution: Use only valid actions: deny, warn, or allow.

### Partial Import

If some policies fail to import, the command will:
- Import all valid policies
- Skip or fail invalid policies
- Report errors for each failed policy

Example output:
```
✓ Policy import completed
  Total policies: 5
  Imported: 3
  Skipped: 0
  Failed: 2

Errors:
  - invalid policy test-1: policy name is required
  - invalid policy test-2: policy action must be deny, warn, or allow
```

## Best Practices

1. **Validate First**: Always use `--validate-only` before importing to catch errors early.

2. **Use Templates**: Start with pre-defined templates and customize them for your needs.

3. **Version Control**: Keep your policy files in version control to track changes.

4. **Descriptive IDs**: Use clear, descriptive policy IDs like `sql-injection-critical` instead of `policy-1`.

5. **Document Policies**: Include detailed descriptions explaining what each policy does and why.

6. **Test Policies**: After importing, run a scan to verify policies work as expected.

7. **Backup Before Overwrite**: When using `--overwrite`, ensure you have a backup of existing policies.

## Integration with CI/CD

### GitHub Actions

```yaml
- name: Import Security Policies
  run: |
    coding-agent-cli import owasp-top10 --type policies --format template
    coding-agent-cli import custom-policies.yaml --type policies
```

### GitLab CI

```yaml
import_policies:
  script:
    - coding-agent-cli import owasp-top10 --type policies --format template
    - coding-agent-cli import custom-policies.yaml --type policies
```

## Troubleshooting

### Policy Not Applied

If a policy is imported but not applied during scans:

1. Check if the policy is enabled:
   ```yaml
   enabled: true
   ```

2. Verify the CWE IDs match findings from your scanners.

3. Check the policy action is appropriate (deny, warn, allow).

### Template Not Found

If a template cannot be found:

1. List available templates:
   ```bash
   coding-agent-cli import --type policies --list-templates
   ```

2. Check the template name matches exactly (case-sensitive).

3. Verify the template directory exists and contains YAML files.

## See Also

- [Policy Configuration Guide](policy-guide.md)
- [Import Guide](import-guide.md) - For importing findings
- [Examples](../examples/policies/) - Example policy files
