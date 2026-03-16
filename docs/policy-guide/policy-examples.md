# Policy Examples

## Simple Policy

Block SQL injection:

```yaml
policies:
  - id: block-sql-injection
    name: Block SQL Injection
    action: deny
    cwe:
      - CWE-89
```

## Intermediate Policy

Block multiple injection types:

```yaml
policies:
  - id: block-injections
    name: Block All Injections
    description: Deny SQL, command, and code injection
    enabled: true
    action: deny
    severity: high
    cwe:
      - CWE-89   # SQL Injection
      - CWE-78   # Command Injection
      - CWE-94   # Code Injection
```

## Advanced Policy

Comprehensive security policy:

```yaml
policies:
  # Critical vulnerabilities - block
  - id: block-critical
    name: Block Critical Vulnerabilities
    action: deny
    severity: critical
    cwe:
      - CWE-89   # SQL Injection
      - CWE-78   # Command Injection
      - CWE-798  # Hardcoded Credentials

  # High severity - block
  - id: block-high
    name: Block High Severity
    action: deny
    severity: high
    cwe:
      - CWE-79   # XSS
      - CWE-22   # Path Traversal
      - CWE-502  # Deserialization

  # Medium severity - warn
  - id: warn-medium
    name: Warn Medium Severity
    action: warn
    severity: medium
    cwe:
      - CWE-327  # Weak Crypto
      - CWE-330  # Weak Random

  # Low severity - allow with tracking
  - id: track-low
    name: Track Low Severity
    action: allow
    severity: low
    cwe:
      - "*"  # All CWEs
```

## Policy with Waivers

```yaml
policies:
  - id: block-sql
    name: Block SQL Injection
    action: deny
    cwe:
      - CWE-89

waivers:
  - id: waiver-legacy-code
    finding_id: finding-abc-123
    reason: Legacy code scheduled for refactor in Q2
    approved_by: security-team@company.com
    expires: 2025-06-30
```
