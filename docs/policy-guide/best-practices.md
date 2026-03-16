# Policy Best Practices

## Policy Organization

### Start Simple
Begin with a basic policy targeting critical vulnerabilities:

```yaml
policies:
  - id: critical-only
    name: Block Critical Vulnerabilities
    action: deny
    severity: critical
    cwe:
      - CWE-89
      - CWE-78
      - CWE-798
```

### Expand Gradually
Add more policies over time as your security posture matures.

### Use Multiple Files
Organize policies by category:
- `policies/injection.yaml`
- `policies/crypto.yaml`
- `policies/auth.yaml`

## Policy Testing

### Test Before Enforcing
Test policies in warn mode first:

```yaml
policies:
  - id: new-policy
    action: warn  # Test first
    cwe:
      - CWE-79
```

After validation, change to deny:
```yaml
action: deny  # Enforce after testing
```

### Validate Syntax
Always validate policy files:
```bash
coding-agent-cli policy validate policy.yaml
```

## Policy Maintenance

### Review Regularly
- Review policies quarterly
- Update CWE lists as new vulnerabilities emerge
- Remove obsolete policies

### Version Control
- Store policies in version control
- Track changes with meaningful commit messages
- Use pull requests for policy changes

### Document Decisions
Add clear descriptions to policies:
```yaml
description: |
  Blocks SQL injection vulnerabilities per OWASP A03.
  Applies to all database queries.
  No exceptions without security team approval.
```

## Severity Guidelines

### Critical
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Hardcoded Credentials (CWE-798)

### High
- XSS (CWE-79)
- Path Traversal (CWE-22)
- Deserialization (CWE-502)

### Medium
- Weak Cryptography (CWE-327)
- Weak Random (CWE-330)

### Low
- Information Disclosure
- Minor configuration issues

## Action Guidelines

### Use deny for:
- Critical and high severity vulnerabilities
- Compliance requirements
- Known exploitable vulnerabilities

### Use warn for:
- Medium severity issues
- New policy rollouts
- Informational findings

### Use allow for:
- Explicitly accepted risks
- Low severity findings
- Development environments

## Waiver Management

### Minimize Waivers
Waivers should be rare and well-justified.

### Set Expiration Dates
All waivers must expire:
```yaml
expires: 2025-12-31
```

### Require Approval
Waivers need security team approval:
```yaml
approved_by: security-team@company.com
```

## CI/CD Integration

### Fail Fast
Configure CI to fail on policy violations:
```bash
coding-agent-cli scan . --policy ci-policy.yaml || exit 1
```

### Separate Policies
Use different policies for different environments:
- `ci-policy.yaml` - Strict for CI/CD
- `dev-policy.yaml` - Lenient for development
- `prod-policy.yaml` - Comprehensive for production

## Common Pitfalls

### Too Strict Too Soon
Don't block everything immediately. Start with critical issues.

### No Testing
Always test policies before enforcing.

### Ignoring False Positives
Address false positives with waivers, don't disable policies.

### No Documentation
Document why policies exist and what they protect against.

### Stale Waivers
Review and remove expired waivers regularly.
