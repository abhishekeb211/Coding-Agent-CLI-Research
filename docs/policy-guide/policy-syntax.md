# Policy Syntax Reference

## Policy Structure

```yaml
policies:
  - id: unique-policy-id
    name: Human-Readable Name
    description: Detailed description
    enabled: true
    action: deny|warn|allow
    severity: critical|high|medium|low
    cwe:
      - CWE-89
      - CWE-79
```

## Required Fields

- `id`: Unique identifier for the policy
- `name`: Human-readable policy name
- `action`: Enforcement action (deny, warn, allow)
- `cwe`: List of CWE IDs to match

## Optional Fields

- `description`: Detailed policy description
- `enabled`: Enable/disable policy (default: true)
- `severity`: Minimum severity level to match

## Actions

### deny
Blocks the finding and causes scan to fail (exit code 1).

### warn
Warns about the finding but allows scan to succeed (exit code 0).

### allow
Explicitly allows the finding (no action taken).

## CWE Matching

### Exact Match
```yaml
cwe:
  - CWE-89  # Matches only CWE-89
```

### Wildcard Match
```yaml
cwe:
  - 89*  # Matches CWE-89, CWE-890, CWE-891, etc.
```

### Multiple CWEs
```yaml
cwe:
  - CWE-89
  - CWE-79
  - CWE-78
```

## Severity Matching

Policies match findings with severity >= specified level:

```yaml
severity: high  # Matches high and critical
severity: medium  # Matches medium, high, and critical
```

## Complete Example

```yaml
policies:
  - id: owasp-a03-injection
    name: OWASP A03 - Injection
    description: Block all injection vulnerabilities
    enabled: true
    action: deny
    severity: high
    cwe:
      - CWE-89   # SQL Injection
      - CWE-78   # Command Injection
      - CWE-79   # XSS
      - CWE-94   # Code Injection

  - id: warn-weak-crypto
    name: Weak Cryptography Warning
    description: Warn about weak cryptographic algorithms
    enabled: true
    action: warn
    severity: medium
    cwe:
      - CWE-327  # Weak Crypto
```
