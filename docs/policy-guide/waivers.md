# Waiver Management

## What are Waivers?

Waivers allow you to temporarily or permanently exempt specific findings from policy enforcement. Use waivers for:
- False positives
- Accepted risks
- Findings scheduled for future remediation

## Waiver Syntax

```yaml
waivers:
  - id: unique-waiver-id
    finding_id: finding-to-waive
    reason: Explanation for waiver
    approved_by: approver-email
    expires: 2025-12-31
```

## Creating Waivers

Create `waivers.yaml`:

```yaml
waivers:
  - id: waiver-false-positive-1
    finding_id: finding-abc-123
    reason: False positive - input is validated upstream
    approved_by: security-team@company.com
    expires: 2025-12-31

  - id: waiver-legacy-code
    finding_id: finding-xyz-789
    reason: Legacy code scheduled for refactor in Q2 2025
    approved_by: tech-lead@company.com
    expires: 2025-06-30
```

## Using Waivers

Apply waivers during scan:
```bash
coding-agent-cli scan /path --policy policy.yaml --waivers waivers.yaml
```

## Waiver Lifecycle

1. **Active**: Waiver is valid and applied
2. **Expired**: Waiver past expiration date (not applied)
3. **Revoked**: Waiver manually revoked (not applied)

## Best Practices

### Document Thoroughly
Always provide clear reasons for waivers:
```yaml
reason: "False positive - user input sanitized by framework middleware (line 45)"
```

### Set Expiration Dates
All waivers should have expiration dates:
```yaml
expires: 2025-12-31  # Review annually
```

### Require Approval
Waivers should be approved by security team:
```yaml
approved_by: security-team@company.com
```

### Track Waivers
Maintain waiver history in version control.

## Waiver Approval Workflow

1. Developer identifies false positive or accepted risk
2. Developer creates waiver with justification
3. Security team reviews and approves
4. Waiver added to `waivers.yaml`
5. Waiver tracked in version control
6. Waiver reviewed before expiration

## Example Scenarios

### False Positive
```yaml
- id: waiver-fp-sanitized-input
  finding_id: finding-sql-123
  reason: Input sanitized by ORM - false positive
  approved_by: security@company.com
  expires: 2026-01-01
```

### Accepted Risk
```yaml
- id: waiver-accepted-risk
  finding_id: finding-crypto-456
  reason: MD5 used for non-security checksums only
  approved_by: security@company.com
  expires: 2025-12-31
```

### Scheduled Remediation
```yaml
- id: waiver-scheduled-fix
  finding_id: finding-xss-789
  reason: Fix scheduled for v2.0 release (Q2 2025)
  approved_by: product@company.com
  expires: 2025-06-30
```
