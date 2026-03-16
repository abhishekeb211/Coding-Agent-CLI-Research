# Policy Guide

## Policy Basics

Policies define security rules and enforcement actions for your codebase.

## Creating a Policy

Create `policy.yaml`:

```yaml
policies:
  - id: block-sql-injection
    name: Block SQL Injection
    description: Deny SQL injection vulnerabilities
    enabled: true
    action: deny
    severity: high
    cwe:
      - CWE-89

  - id: warn-xss
    name: Warn on XSS
    description: Warn about cross-site scripting
    enabled: true
    action: warn
    severity: medium
    cwe:
      - CWE-79
```

## Policy Actions

- `deny`: Block the finding (exit code 1)
- `warn`: Warn about the finding (exit code 0)
- `allow`: Allow the finding (no action)

## Policy Matching

Policies match findings based on:
- **CWE ID**: Specific vulnerability types
- **Severity**: Minimum severity level
- **File patterns**: File path patterns (future)

## Using Policies

Validate a policy file:
```bash
coding-agent-cli policy validate policy.yaml
```

Run scan with policy:
```bash
coding-agent-cli scan /path --policy policy.yaml
```

## Waivers

Create waivers for false positives:

```yaml
waivers:
  - id: waiver-1
    finding_id: finding-abc-123
    reason: False positive - input is sanitized
    approved_by: security-team
    expires: 2025-12-31
```

## Example Policies

See `examples/policies/` for:
- OWASP Top 10 policy
- CWE Top 25 policy
- PCI-DSS compliance policy
